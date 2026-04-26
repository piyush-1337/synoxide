use crate::error::{Result, SynoxideError};

#[derive(Debug)]
pub struct UDPHeader {
    pub source_port: u16,
    pub dest_port: u16,
    pub length: u16,
    pub checksum: u16,
}

pub fn parse(payload: &[u8]) -> Result<UDPHeader> {
    if payload.len() < 8 {
        return Err(SynoxideError::Parse(
            "not enough length to parse udp header".to_string(),
        ));
    }

    let source_port = u16::from_be_bytes(payload[0..2].try_into().unwrap());
    let dest_port = u16::from_be_bytes(payload[2..4].try_into().unwrap());
    let length = u16::from_be_bytes(payload[4..6].try_into().unwrap());
    let checksum = u16::from_be_bytes(payload[6..8].try_into().unwrap());

    println!("udp data: {:?}", &payload[8..]);

    Ok(UDPHeader {
        source_port,
        dest_port,
        length,
        checksum
    })
}
