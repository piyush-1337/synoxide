use crate::{
    error::Result,
    parser::{InternetHeader, Parser},
};

mod error;
mod parser;

pub fn parse_header(payload: &[u8]) -> Result<InternetHeader> {
    Parser::new(payload).parse_header()
}
