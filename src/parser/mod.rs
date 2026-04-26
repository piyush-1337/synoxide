pub mod icmp_header;
pub mod internet_header;

use crate::{
    error::{Result, SynoxideError},
    parser::{icmp_header::IcmpHeader, internet_header::InternetHeader},
};

#[derive(Debug, Default)]
pub struct Parser<'a> {
    payload: &'a [u8],

    internet_header_end: Option<usize>,
    icmp_header_end: Option<usize>,
}

impl<'a> Parser<'a> {
    pub fn new(payload: &'a [u8]) -> Self {
        Parser {
            payload,
            ..Default::default()
        }
    }

    pub fn parse_internet_header(&mut self) -> Result<InternetHeader> {
        let (header, end) = internet_header::parse(self.payload)?;
        self.internet_header_end = Some(end);
        Ok(header)
    }

    pub fn parse_icmp_header(&mut self) -> Result<IcmpHeader> {
        let Some(internet_header_end) = self.internet_header_end else {
            return Err(SynoxideError::Parse("Please parse internet_header first".to_string()));
        };

        let header = icmp_header::parse(&self.payload[internet_header_end..])?;
        self.icmp_header_end = Some(internet_header_end + 8);
        Ok(header)
    }
}
