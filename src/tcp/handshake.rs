use crate::{
    IPHeader,
    parser::tcp::{PseudoIpHeader, TcpHeader},
    tcp::{RecvState, SendState, TcpState, TcpStateMode, handle::TcpHandle},
    utils::calculate_checksum,
};

pub fn handshake(
    mut ip_header: IPHeader,
    mut tcp_header: TcpHeader,
    dev: tun::Device,
) -> TcpHandle {
    let mode = TcpStateMode::SynReceived;
    let send = SendState {
        wnd: tcp_header.window,
        iss: 10000,
        una: 10000,
        nxt: 10001,
        ..Default::default()
    };
    let recv = RecvState {
        nxt: tcp_header.seq_nu + 1,
        irs: tcp_header.seq_nu,
        ..Default::default()
    };
    let state = TcpState { mode, send, recv };

    std::mem::swap(&mut ip_header.source_addr, &mut ip_header.dest_addr);
    std::mem::swap(&mut tcp_header.src_port, &mut tcp_header.dest_port);
    tcp_header.seq_nu = send.iss;
    tcp_header.ack_nu = recv.nxt;

    let tcp_header_len = 20 + tcp_header.options.len() as u16;

    let pseudo_ip_header = PseudoIpHeader::new(
        u32::from_be_bytes(ip_header.source_addr),
        u32::from_be_bytes(ip_header.dest_addr),
        tcp_header_len,
    );

    tcp_header.checksum = 0;
    tcp_header.control_bits.syn = true;
    tcp_header.control_bits.ack = true;
    tcp_header.data_offset = (tcp_header_len / 4) as u8;

    let mut buf = Vec::with_capacity(12 + tcp_header_len as usize);
    buf.extend_from_slice(&pseudo_ip_header.to_bytes());
    buf.extend_from_slice(&tcp_header.to_bytes());

    let checksum = calculate_checksum(&buf);
    tcp_header.checksum = checksum;
    let checksum = checksum.to_be_bytes();
    buf[28] = checksum[0];
    buf[29] = checksum[1];


    unimplemented!()
}
