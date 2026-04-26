use crate::error::{Result, SynoxideError};

#[derive(Debug)]
pub struct InternetHeader {
    pub version: u8,
    pub header_len: u8,
    pub tos: u8,
    pub total_len: u16,

    // These are related to fragments
    pub id: u16,
    pub flags: [bool; 3],
    pub offset: u16,
    pub time_to_live: u8, // starts with 255 and gets decremented on every hop(router)?

    pub protocol: u8,
    pub header_checksum: u16,
    pub source_addr: [u8; 4],
    pub dest_addr: [u8; 4],
    pub options_and_padding: Vec<u8>,
}

pub fn parse(payload: &[u8]) -> Result<(InternetHeader, usize)> {
    if payload.len() < 20 {
        return Err(SynoxideError::Parse(
            "Payload too small for standard IPv4 header".to_string(),
        ));
    }

    let version = payload[0] >> 4;

    if version != 4 {
        return Err(SynoxideError::Parse("not an ipv4 packet, skip".to_string()));
    }

    let header_len = payload[0] & 0x0f;

    if header_len < 5 {
        return Err(SynoxideError::Parse(format!(
            "Invalid IPv4 header length: {} (must be at least 5)",
            header_len
        )));
    }

    let tos = payload[1];

    let total_len = u16::from_be_bytes(payload[2..4].try_into().unwrap());
    let id = u16::from_be_bytes(payload[4..6].try_into().unwrap());

    let flags_byte = payload[6];
    let flags = [
        (flags_byte & 0x80) != 0,
        (flags_byte & 0x40) != 0,
        (flags_byte & 0x20) != 0,
    ];

    let offset_bytes = [payload[6] & 0x1f, payload[7]];
    let offset = u16::from_be_bytes(offset_bytes);

    let time_to_live = payload[8];
    let protocol = payload[9];
    let header_checksum = u16::from_be_bytes(payload[10..12].try_into().unwrap());

    let source_addr: [u8; 4] = payload[12..16].try_into().unwrap();
    let dest_addr: [u8; 4] = payload[16..20].try_into().unwrap();

    let total_header_bytes = (header_len as usize) * 4;

    if payload.len() < total_header_bytes {
        return Err(SynoxideError::Parse(
            "Payload smaller than indicated IHL".to_string(),
        ));
    }

    let options_and_padding = payload[20..total_header_bytes].to_vec();

    let header = InternetHeader {
        version,
        header_len,
        tos,
        total_len,
        id,
        flags,
        offset,
        time_to_live,
        protocol,
        header_checksum,
        source_addr,
        dest_addr,
        options_and_padding,
    };

    Ok((header, total_header_bytes))
}
