use std::{
    io::{Cursor, Read},
    ops::{Deref, DerefMut},
};

use crate::error::{Result, SynoxideError};

pub struct Parser<'a> {
    inner: Cursor<&'a [u8]>,
}

impl<'a> DerefMut for Parser<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl<'a> Deref for Parser<'a> {
    type Target = Cursor<&'a [u8]>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

#[derive(Debug)]
pub struct InternetHeader {
    pub version: u8,
    pub header_len: u8,
    pub tos: u8,
    pub total_len: u16,
    pub id: u16,
    pub flags: [bool; 3],
    pub offset: u16,
    pub time_to_live: u8,
    pub protocol: u8,
    pub header_checksum: u16,
    pub source_addr: [u8; 4],
    pub dest_addr: [u8; 4],
    pub options_and_padding: Vec<u8>,
}

impl<'a> Parser<'a> {
    pub fn new(payload: &'a [u8]) -> Self {
        let inner = Cursor::new(payload);
        Self { inner }
    }

    pub fn parse_header(&mut self) -> Result<InternetHeader> {
        let mut byte = [0u8; 1];
        let mut two_byte = [0u8; 2];

        self.read_exact(&mut byte)
            .map_err(|e| SynoxideError::Parse(e.to_string()))?;

        let version = byte[0] >> 4;
        let header_len = byte[0] & 0x0f;

        if header_len < 5 {
            return Err(SynoxideError::Parse(format!(
                "Invalid IPv4 header length: {} (must be at least 5)",
                header_len
            )));
        }

        self.read_exact(&mut byte)
            .map_err(|e| SynoxideError::Parse(e.to_string()))?;
        let tos = byte[0];

        self.read_exact(&mut two_byte)
            .map_err(|e| SynoxideError::Parse(e.to_string()))?;
        let total_len = u16::from_be_bytes(two_byte);

        self.read_exact(&mut two_byte)
            .map_err(|e| SynoxideError::Parse(e.to_string()))?;
        let id = u16::from_be_bytes(two_byte);

        self.read_exact(&mut two_byte)
            .map_err(|e| SynoxideError::Parse(e.to_string()))?;

        let flags_byte = two_byte[0];
        let flags = [
            (flags_byte & 0x80) != 0,
            (flags_byte & 0x40) != 0,
            (flags_byte & 0x20) != 0,
        ];

        two_byte[0] &= 0x1f;
        let offset = u16::from_be_bytes(two_byte);

        self.read_exact(&mut byte)
            .map_err(|e| SynoxideError::Parse(e.to_string()))?;
        let time_to_live = byte[0];

        self.read_exact(&mut byte)
            .map_err(|e| SynoxideError::Parse(e.to_string()))?;
        let protocol = byte[0];

        self.read_exact(&mut two_byte)
            .map_err(|e| SynoxideError::Parse(e.to_string()))?;
        let header_checksum = u16::from_be_bytes(two_byte);

        let mut four_byte = [0u8; 4];
        self.read_exact(&mut four_byte)
            .map_err(|e| SynoxideError::Parse(e.to_string()))?;
        let source_addr = four_byte;

        self.read_exact(&mut four_byte)
            .map_err(|e| SynoxideError::Parse(e.to_string()))?;
        let dest_addr = four_byte;

        let options_len = ((header_len as usize) * 4) - 20;
        let mut options_and_padding = vec![0u8; options_len];
        if options_len > 0 {
            self.read_exact(&mut options_and_padding)
                .map_err(|e| SynoxideError::Parse(e.to_string()))?;
        }

        Ok(InternetHeader {
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
        })
    }
}
