pub mod icmp_header;
pub mod ip_header;
pub mod udp;

use crate::{
    error::{Result, SynoxideError},
    parser::udp::UDPHeader,
};

pub use icmp_header::{IcmpHeader, IcmpPayload};
pub use ip_header::IPHeader;

#[derive(Debug, Default)]
pub struct Parser<'a> {
    payload: &'a [u8],

    ip_header_end: Option<usize>,
}

impl<'a> Parser<'a> {
    pub fn new(payload: &'a [u8]) -> Self {
        Parser {
            payload,
            ..Default::default()
        }
    }

    pub fn parse_ip_header(&mut self) -> Result<IPHeader> {
        let (header, end) = ip_header::parse(self.payload)?;
        self.ip_header_end = Some(end);
        Ok(header)
    }

    pub fn parse_icmp_header(&mut self) -> Result<IcmpHeader> {
        let Some(ip_header_end) = self.ip_header_end else {
            return Err(SynoxideError::Parse(
                "Please parse internet_header first".to_string(),
            ));
        };

        let header = icmp_header::parse(&self.payload[ip_header_end..])?;
        Ok(header)
    }

    pub fn parse_udp_header(&mut self) -> Result<UDPHeader> {
        let Some(ip_header_end) = self.ip_header_end else {
            return Err(SynoxideError::Parse(
                "Please parse internet_header first".to_string(),
            ));
        };

        let header = udp::parse(&self.payload[ip_header_end..])?;
        Ok(header)
    }
}
