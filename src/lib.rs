use crate::{
    error::{Result, SynoxideError},
    parser::{IcmpHeader, InternetHeader},
};

mod error;
mod parser;

pub fn parse_internet_header(payload: &[u8]) -> Result<(InternetHeader, &[u8])> {
    InternetHeader::parse(payload)
}

pub fn parse_icmp_header(payload: &[u8]) -> Result<(IcmpHeader, &[u8])> {
    IcmpHeader::parse(payload)
}
