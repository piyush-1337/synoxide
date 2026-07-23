use std::io::Write;
use crate::{
    IPHeader,
    parser::tcp::{PseudoIpHeader, TcpHeader},
    tcp::{RecvState, SendState, TcpState, TcpStateMode},
    utils::calculate_checksum,
};

pub fn handshake(
    ip_header: &IPHeader,
    tcp_header: &TcpHeader,
    writer: &mut dyn Write,
) -> std::io::Result<TcpState> {
    let send = SendState {
        iss: 10000,
        nxt: 10001,
    };
    let recv = RecvState {
        nxt: tcp_header.seq_nu + 1,
        irs: tcp_header.seq_nu,
    };
    let state = TcpState {
        mode: TcpStateMode::SynReceived,
        send,
        recv,
    };

    let tcp_header_len: u16 = 20;

    let pseudo = PseudoIpHeader::new(
        u32::from_be_bytes(ip_header.dest_addr),
        u32::from_be_bytes(ip_header.source_addr),
        tcp_header_len,
    );

    let mut reply_tcp = TcpHeader {
        src_port: tcp_header.dest_port,
        dest_port: tcp_header.src_port,
        seq_nu: send.iss,
        ack_nu: recv.nxt,
        data_offset: (tcp_header_len / 4) as u8,
        reserved: 0,
        control_bits: crate::parser::tcp::ControlBits {
            cwr: false, ece: false, urg: false,
            ack: true, psh: false, rst: false, syn: true, fin: false,
        },
        window: 10000,
        checksum: 0,
        urgent_pointer: 0,
        options: &[],
    };

    let mut cksum_buf = Vec::with_capacity(12 + tcp_header_len as usize);
    cksum_buf.extend_from_slice(&pseudo.to_bytes());
    cksum_buf.extend_from_slice(&reply_tcp.to_bytes());

    reply_tcp.checksum = calculate_checksum(&cksum_buf);

    let mut reply_ip = IPHeader {
        version: 4,
        header_len: 5,
        tos: 0,
        total_len: 20 + tcp_header_len,
        id: 0,
        flags: [false, false, false],
        offset: 0,
        time_to_live: 64,
        protocol: 6,
        header_checksum: 0,
        source_addr: ip_header.dest_addr,
        dest_addr: ip_header.source_addr,
        options_and_padding: vec![],
    };
    reply_ip.recalculate_checksum();

    let mut final_reply = reply_ip.to_bytes();
    final_reply.extend(reply_tcp.to_bytes());

    writer.write_all(&final_reply)?;

    Ok(state)
}
