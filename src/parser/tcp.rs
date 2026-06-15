use crate::error::{Result, SynoxideError};

#[derive(Debug)]
pub struct TcpHeader<'a> {
    pub src_port: u16,
    pub dest_port: u16,
    pub seq_nu: u32,
    pub ack_nu: u32,
    /// actually 4 bits
    pub data_offset: u8,
    /// actually 4 bits
    pub reserved: u8,
    pub control_bits: ControlBits,
    pub window: u16,
    pub checksum: u16,
    pub urgent_pointer: u16,
    pub options: &'a [u8],
}

#[derive(Debug)]
pub struct ControlBits {
    pub cwr: bool,
    pub ece: bool,
    pub urg: bool,
    pub ack: bool,
    pub psh: bool,
    pub rst: bool,
    pub syn: bool,
    pub fin: bool,
}

impl ControlBits {
    pub fn to_u8(&self) -> u8 {
        let mut flags = 0u8;
        if self.cwr {
            flags |= 0x80;
        }
        if self.ece {
            flags |= 0x40;
        }
        if self.urg {
            flags |= 0x20;
        }
        if self.ack {
            flags |= 0x10;
        }
        if self.psh {
            flags |= 0x08;
        }
        if self.rst {
            flags |= 0x04;
        }
        if self.syn {
            flags |= 0x02;
        }
        if self.fin {
            flags |= 0x01;
        }
        flags
    }
}

pub struct PseudoIpHeader {
    source_ip: u32,
    dest_ip: u32,
    /// always set to 0x00
    reserved_byte: u8,
    /// set to 0x06 for tcp
    protocol: u8,
    /// total length of tcp header + payload, with no options and payload this is 20
    tcp_length: u16,
}

impl PseudoIpHeader {
    pub fn new(source_ip: u32, dest_ip: u32, tcp_length: u16) -> Self {
        Self {
            source_ip,
            dest_ip,
            reserved_byte: 0,
            protocol: 0x06,
            tcp_length,
        }
    }

    pub fn to_bytes(&self) -> [u8; 12] {
        let mut buf = [0u8; 12];
        buf[0..4].copy_from_slice(&self.source_ip.to_be_bytes());
        buf[4..8].copy_from_slice(&self.dest_ip.to_be_bytes());
        buf[8] = self.reserved_byte;
        buf[9] = self.protocol;
        buf[10..12].copy_from_slice(&self.tcp_length.to_be_bytes());

        buf
    }
}

impl<'a> TcpHeader<'a> {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(20 + self.options.len());

        bytes.extend_from_slice(&self.src_port.to_be_bytes());
        bytes.extend_from_slice(&self.dest_port.to_be_bytes());

        bytes.extend_from_slice(&self.seq_nu.to_be_bytes());
        bytes.extend_from_slice(&self.ack_nu.to_be_bytes());

        let offset_and_reserved = (self.data_offset << 4) | (self.reserved & 0x0F);
        bytes.push(offset_and_reserved);

        bytes.push(self.control_bits.to_u8());

        bytes.extend_from_slice(&self.window.to_be_bytes());
        bytes.extend_from_slice(&self.checksum.to_be_bytes());
        bytes.extend_from_slice(&self.urgent_pointer.to_be_bytes());

        bytes.extend_from_slice(self.options);

        bytes
    }
}

pub fn parse(payload: &'_ [u8]) -> Result<TcpHeader<'_>> {
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
    let control_bits = ControlBits {
        cwr: (byte & 0b1000_0000) != 0, // CWR
        ece: (byte & 0b0100_0000) != 0, // ECE
        urg: (byte & 0b0010_0000) != 0, // URG
        ack: (byte & 0b0001_0000) != 0, // ACK
        psh: (byte & 0b0000_1000) != 0, // PSH
        rst: (byte & 0b0000_0100) != 0, // RST
        syn: (byte & 0b0000_0010) != 0, // SYN
        fin: (byte & 0b0000_0001) != 0, // FIN
    };

    let window = u16::from_be_bytes(payload[14..16].try_into().unwrap());
    let checksum = u16::from_be_bytes(payload[16..18].try_into().unwrap());
    let urgent_pointer = u16::from_be_bytes(payload[18..20].try_into().unwrap());

    let options = &payload[20..];

    Ok(TcpHeader {
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
