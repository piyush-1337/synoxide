use crate::error::{Result, SynoxideError};

#[derive(Debug)]
pub struct TCPHeader<'a> {
    src_port: u16,
    dest_port: u16,
    seq_nu: u32,
    ack_nu: u32,
    /// actually 4 bits
    data_offset: u8,
    /// actually 4 bits
    reserved: u8,
    control_bits: [bool; 8],
    window: u16,
    checksum: u16,
    urgent_pointer: u16,
    options: &'a [u8],
}

pub fn parse(payload: &[u8]) -> Result<TCPHeader> {
    if payload.len() < 20 {
        return Err(SynoxideError::Parse(format!(
            "tcp header size must be at least 20 bytes, received: {} bytes",
            payload.len()
        )));
    }

    let src_port = u16::from_be_bytes(payload[0..2].try_into().unwrap());
    let dest_port = u16::from_be_bytes(payload[2..4].try_into().unwrap());

    let seq_nu = u32::from_be_bytes(payload[4..8].try_into().unwrap());
    let ack_nu = u32::from_be_bytes(payload[8..12].try_into().unwrap());

    let mut byte = payload[12];
    let data_offset = byte >> 4;
    let reserved = byte & 0b0000_1111;

    byte = payload[13];
    let control_bits: [bool; 8] = [
        (byte & 0b1000_0000) != 0, // CWR
        (byte & 0b0100_0000) != 0, // ECE
        (byte & 0b0010_0000) != 0, // URG
        (byte & 0b0001_0000) != 0, // ACK
        (byte & 0b0000_1000) != 0, // PSH
        (byte & 0b0000_0100) != 0, // RST
        (byte & 0b0000_0010) != 0, // SYN
        (byte & 0b0000_0001) != 0, // FIN
    ];

    let window = u16::from_be_bytes(payload[14..16].try_into().unwrap());
    let checksum = u16::from_be_bytes(payload[16..18].try_into().unwrap());
    let urgent_pointer = u16::from_be_bytes(payload[18..20].try_into().unwrap());

    let options = &payload[20..];

    Ok(TCPHeader {
        src_port,
        dest_port,
        seq_nu,
        ack_nu,
        data_offset,
        reserved,
        control_bits,
        window,
        checksum,
        urgent_pointer,
        options,
    })
}
