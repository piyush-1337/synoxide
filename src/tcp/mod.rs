use std::collections::HashMap;
use std::collections::VecDeque;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;

use crate::parser::tcp::{ControlBits, PseudoIpHeader, TcpHeader};
use crate::utils::calculate_checksum;
use crate::{IPHeader, Parser};

mod handshake;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnectionId {
    pub src_ip: [u8; 4],
    pub src_port: u16,
    pub dest_ip: [u8; 4],
    pub dest_port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TcpStateMode {
    SynReceived,
    Established,
    Closed,
}

#[derive(Debug, Clone, Copy, Default)]
struct SendState {
    nxt: u32,
    iss: u32,
}

#[derive(Debug, Clone, Copy, Default)]
struct RecvState {
    nxt: u32,
    irs: u32,
}

#[derive(Debug, Clone, Copy)]
struct TcpState {
    mode: TcpStateMode,
    send: SendState,
    recv: RecvState,
}

/// Per-connection shared data between the packet loop and TcpStream.
struct ConnectionHandle {
    state: TcpState,
    recv_buf: VecDeque<u8>,
    peer_closed: bool,
}

/// Interior state shared between TcpListener, packet-loop thread, and TcpStreams.
struct StackInner {
    connections: HashMap<ConnectionId, Arc<(Mutex<ConnectionHandle>, Condvar)>>,
    pending_accept: VecDeque<ConnectionId>,
    listen_port: u16,
}

pub struct TcpListener {
    inner: Arc<(Mutex<StackInner>, Condvar)>,
    writer: Arc<Mutex<tun::Device>>,
    _packet_thread: thread::JoinHandle<()>,
}

pub struct TcpStream {
    conn_id: ConnectionId,
    handle: Arc<(Mutex<ConnectionHandle>, Condvar)>,
    writer: Arc<Mutex<tun::Device>>,
}

// ── wire helpers ────────────────────────────────────────────────────────────

fn build_tcp_segment(
    conn_id: &ConnectionId,
    state: &TcpState,
    flags: ControlBits,
    payload: &[u8],
) -> Vec<u8> {
    let tcp_header_len: u16 = 20;
    let tcp_total = tcp_header_len + payload.len() as u16;

    let pseudo = PseudoIpHeader::new(
        u32::from_be_bytes(conn_id.dest_ip),
        u32::from_be_bytes(conn_id.src_ip),
        tcp_total,
    );

    let mut tcp = TcpHeader {
        src_port: conn_id.dest_port,
        dest_port: conn_id.src_port,
        seq_nu: state.send.nxt,
        ack_nu: state.recv.nxt,
        data_offset: (tcp_header_len / 4) as u8,
        reserved: 0,
        control_bits: flags,
        window: 10000,
        checksum: 0,
        urgent_pointer: 0,
        options: &[],
    };

    let mut cksum_buf = Vec::with_capacity(12 + tcp_total as usize);
    cksum_buf.extend_from_slice(&pseudo.to_bytes());
    cksum_buf.extend_from_slice(&tcp.to_bytes());
    cksum_buf.extend_from_slice(payload);

    tcp.checksum = calculate_checksum(&cksum_buf);

    let mut ip = IPHeader {
        version: 4,
        header_len: 5,
        tos: 0,
        total_len: 20 + tcp_total,
        id: 0,
        flags: [false, false, false],
        offset: 0,
        time_to_live: 64,
        protocol: 6,
        header_checksum: 0,
        source_addr: conn_id.dest_ip,
        dest_addr: conn_id.src_ip,
        options_and_padding: vec![],
    };
    ip.recalculate_checksum();

    let mut out = ip.to_bytes();
    out.extend(tcp.to_bytes());
    out.extend_from_slice(payload);
    out
}

fn ack_flags() -> ControlBits {
    ControlBits {
        cwr: false, ece: false, urg: false,
        ack: true, psh: false, rst: false, syn: false, fin: false,
    }
}

fn psh_ack_flags() -> ControlBits {
    ControlBits {
        cwr: false, ece: false, urg: false,
        ack: true, psh: true, rst: false, syn: false, fin: false,
    }
}

fn fin_ack_flags() -> ControlBits {
    ControlBits {
        cwr: false, ece: false, urg: false,
        ack: true, psh: false, rst: false, syn: false, fin: true,
    }
}

// ── packet loop ─────────────────────────────────────────────────────────────

/// The packet loop uses its own dup'd file descriptor for reading, so it never
/// contends with TcpStream writers for the tun device lock.
fn packet_loop(
    inner: Arc<(Mutex<StackInner>, Condvar)>,
    writer: Arc<Mutex<tun::Device>>,
    mut reader: File,
) {
    let mut buf = [0u8; 1504];

    loop {
        let n = match reader.read(&mut buf) {
            Ok(n) => n,
            Err(_) => continue,
        };

        let packet = &buf[..n];
        let mut parser = Parser::new(packet);

        let ip_header = match parser.parse_ip_header() {
            Ok(h) => h,
            Err(_) => continue,
        };

        let listen_port = inner.0.lock().unwrap().listen_port;

        if ip_header.protocol != 6 {
            continue;
        }

        let tcp_header = match parser.parse_tcp_header() {
            Ok(h) => h,
            Err(_) => continue,
        };

        if tcp_header.dest_port != listen_port {
            continue;
        }

        let conn_id = ConnectionId {
            src_ip: ip_header.source_addr,
            src_port: tcp_header.src_port,
            dest_ip: ip_header.dest_addr,
            dest_port: tcp_header.dest_port,
        };

        let ip_hdr_len = (ip_header.header_len as u16) * 4;
        let tcp_hdr_len = (tcp_header.data_offset as u16) * 4;
        let payload_len = ip_header.total_len.saturating_sub(ip_hdr_len + tcp_hdr_len) as usize;
        let payload_start = (ip_hdr_len + tcp_hdr_len) as usize;
        let payload = if payload_len > 0 && packet.len() >= payload_start + payload_len {
            &packet[payload_start..payload_start + payload_len]
        } else {
            &[]
        };

        handle_tcp_packet(&inner, &writer, &conn_id, &ip_header, &tcp_header, payload);
    }
}

fn handle_tcp_packet(
    inner: &Arc<(Mutex<StackInner>, Condvar)>,
    writer: &Arc<Mutex<tun::Device>>,
    conn_id: &ConnectionId,
    ip_header: &IPHeader,
    tcp_header: &TcpHeader,
    payload: &[u8],
) {
    let (stack_lock, accept_cvar) = &**inner;
    let mut stack = stack_lock.lock().unwrap();

    if let Some(conn_handle) = stack.connections.get(conn_id).cloned() {
        // Drop the stack lock before touching the connection handle — we only
        // need the stack lock for the HashMap lookup.
        drop(stack);

        let (handle_lock, data_cvar) = &*conn_handle;
        let mut handle = handle_lock.lock().unwrap();

        match handle.state.mode {
            TcpStateMode::SynReceived => {
                if tcp_header.control_bits.ack {
                    handle.state.mode = TcpStateMode::Established;
                    let mut stack = stack_lock.lock().unwrap();
                    stack.pending_accept.push_back(*conn_id);
                    accept_cvar.notify_one();
                }
            }
            TcpStateMode::Established => {
                if !payload.is_empty() && tcp_header.seq_nu == handle.state.recv.nxt {
                    handle.state.recv.nxt = handle.state.recv.nxt.wrapping_add(payload.len() as u32);
                    handle.recv_buf.extend(payload);
                    data_cvar.notify_one();

                    let seg = build_tcp_segment(conn_id, &handle.state, ack_flags(), &[]);
                    let _ = writer.lock().unwrap().write_all(&seg);
                }

                if tcp_header.control_bits.fin {
                    handle.state.recv.nxt = handle.state.recv.nxt.wrapping_add(1);
                    handle.peer_closed = true;
                    handle.state.mode = TcpStateMode::Closed;
                    data_cvar.notify_one();

                    let seg = build_tcp_segment(conn_id, &handle.state, fin_ack_flags(), &[]);
                    let _ = writer.lock().unwrap().write_all(&seg);
                }
            }
            TcpStateMode::Closed => {}
        }
    } else if tcp_header.control_bits.syn {
        let state = handshake::handshake(ip_header, tcp_header, &mut *writer.lock().unwrap());
        match state {
            Ok(state) => {
                let conn_handle = Arc::new((
                    Mutex::new(ConnectionHandle {
                        state,
                        recv_buf: VecDeque::new(),
                        peer_closed: false,
                    }),
                    Condvar::new(),
                ));
                stack.connections.insert(*conn_id, conn_handle);
            }
            Err(e) => eprintln!("handshake failed: {}", e),
        }
    }
}

// ── TcpListener ─────────────────────────────────────────────────────────────

impl TcpListener {
    pub fn bind(port: u16, dev: tun::Device) -> io::Result<Self> {
        // Dup the file descriptor so the reader thread has its own handle.
        unsafe extern "C" { safe fn dup(fd: i32) -> i32; }
        let read_fd = dup(dev.as_raw_fd());
        if read_fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let reader = unsafe { File::from_raw_fd(read_fd) };

        let writer = Arc::new(Mutex::new(dev));

        let stack = StackInner {
            connections: HashMap::new(),
            pending_accept: VecDeque::new(),
            listen_port: port,
        };
        let inner = Arc::new((Mutex::new(stack), Condvar::new()));

        let packet_inner = Arc::clone(&inner);
        let packet_writer = Arc::clone(&writer);
        let _packet_thread = thread::spawn(move || {
            packet_loop(packet_inner, packet_writer, reader);
        });

        Ok(Self {
            inner,
            writer,
            _packet_thread,
        })
    }

    /// Blocks until a new connection completes the 3-way handshake.
    pub fn accept(&self) -> io::Result<TcpStream> {
        let (lock, cvar) = &*self.inner;

        let conn_id = {
            let mut stack = lock.lock().unwrap();
            loop {
                if let Some(id) = stack.pending_accept.pop_front() {
                    break id;
                }
                stack = cvar.wait(stack).unwrap();
            }
        };

        let handle = {
            let stack = lock.lock().unwrap();
            Arc::clone(stack.connections.get(&conn_id).unwrap())
        };

        Ok(TcpStream {
            conn_id,
            handle,
            writer: Arc::clone(&self.writer),
        })
    }
}

// ── TcpStream ───────────────────────────────────────────────────────────────

impl Read for TcpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let (lock, cvar) = &*self.handle;
        let mut handle = lock.lock().unwrap();

        loop {
            if !handle.recv_buf.is_empty() {
                let n = buf.len().min(handle.recv_buf.len());
                for (i, b) in handle.recv_buf.drain(..n).enumerate() {
                    buf[i] = b;
                }
                return Ok(n);
            }

            if handle.peer_closed {
                return Ok(0); // EOF
            }

            handle = cvar.wait(handle).unwrap();
        }
    }
}

impl Write for TcpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let (lock, _) = &*self.handle;
        let mut handle = lock.lock().unwrap();

        if handle.peer_closed || handle.state.mode == TcpStateMode::Closed {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "connection closed"));
        }

        let seg = build_tcp_segment(&self.conn_id, &handle.state, psh_ack_flags(), buf);
        handle.state.send.nxt = handle.state.send.nxt.wrapping_add(buf.len() as u32);

        self.writer.lock().unwrap().write_all(&seg)?;

        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
