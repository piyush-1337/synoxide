use crate::{IPHeader, parser::tcp::TcpHeader, tcp::handle::TcpHandle};

mod handle;
mod handshake;

#[derive(Debug, Clone, Copy)]
pub enum TcpStateMode {
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
    Closed,
}

#[derive(Debug, Clone, Copy, Default)]
struct SendState {
    /// last send that was send but wasn't ack'd
    una: u32,
    /// next seq_nu to send
    nxt: u32,
    /// max byte we can send
    wnd: u16,
    /// sequence number where the urgent data ends
    up: u32,
    /// segment_seq_nu for last window update
    wl1: u32,
    /// segment_ack_nu for last window update
    wl2: u32,
    /// initial send seq_nu
    iss: u32,
}

#[derive(Debug, Clone, Copy, Default)]
struct RecvState {
    /// next seq_nu to we expect to receive
    nxt: u32,
    /// max byte we can recv
    wnd: u16,
    /// urgent pointer
    up: u32,
    /// initial recv seq_nu
    irs: u32,
}

#[derive(Debug, Clone, Copy)]
struct TcpState {
    mode: TcpStateMode,
    send: SendState,
    recv: RecvState,
}

pub fn handle_recv(ip_header: IPHeader, tcp_header: TcpHeader, dev: tun::Device) -> TcpHandle {
    assert!(tcp_header.control_bits.syn);

    handshake::handshake(ip_header, tcp_header, dev)
}
