use crate::{
    error::{Result, SynoxideError},
    parser::ip_header::{self, IPHeader},
    utils::calculate_checksum,
};

#[derive(Debug)]
pub struct IcmpHeader {
    pub icmp_type: u8,
    pub code: u8,
    pub checksum: u16,
    pub payload: IcmpPayload,
}

// right now these are the only ones supported
#[derive(Debug)]
pub enum IcmpPayload {
    Echo {
        identifier: u16,
        sequence_number: u16,
        data: Vec<u8>,
    },
    DestinationUnreachable {
        unused: u32, // Should be 0
        original_ip_header: IPHeader,
        original_data_prefix: [u8; 8],
    },
    TimeExceeded {
        unused: u32, // Should be 0
        original_ip_header: IPHeader,
        original_data_prefix: [u8; 8],
    },
}

pub fn parse(payload: &[u8]) -> Result<IcmpHeader> {
    if payload.len() < 8 {
        return Err(SynoxideError::Parse(
            "Payload too small for ICMP header".to_string(),
        ));
    }

    let icmp_type = payload[0];
    let code = payload[1];
    let checksum = u16::from_be_bytes(payload[2..4].try_into().unwrap());

    let payload = match icmp_type {
        0 | 8 => {
            let identifier = u16::from_be_bytes(payload[4..6].try_into().unwrap());
            let sequence_number = u16::from_be_bytes(payload[6..8].try_into().unwrap());
            IcmpPayload::Echo {
                identifier,
                sequence_number,
                data: payload[8..].to_vec(),
            }
        }

        3 => {
            let unused = u32::from_be_bytes(payload[4..8].try_into().unwrap());
            let ip_header = ip_header::parse(payload)?;
            let original_ip_header = ip_header.0;
            let original_data_prefix = payload[ip_header.1 + 8..].try_into().unwrap();

            IcmpPayload::DestinationUnreachable {
                unused,
                original_ip_header,
                original_data_prefix,
            }
        }

        11 => {
            let unused = u32::from_be_bytes(payload[4..8].try_into().unwrap());
            let ip_header = ip_header::parse(payload)?;
            let original_ip_header = ip_header.0;
            let original_data_prefix = payload[ip_header.1 + 8..].try_into().unwrap();

            IcmpPayload::TimeExceeded {
                unused,
                original_ip_header,
                original_data_prefix,
            }
        }

        icmp_type => {
            return Err(SynoxideError::Parse(format!(
                "this type is not implemented yet: {}",
                icmp_type
            )));
        }
    };

    Ok(IcmpHeader {
        icmp_type,
        code,
        checksum,
        payload,
    })
}

impl IcmpHeader {
    pub fn recalculate_checksum(&mut self) {
        self.checksum = 0;
        let checksum = calculate_checksum(&self.to_bytes());
        self.checksum = checksum;
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();

        buffer.push(self.icmp_type);
        buffer.push(self.code);
        buffer.extend_from_slice(&self.checksum.to_be_bytes());

        match &self.payload {
            IcmpPayload::Echo {
                identifier,
                sequence_number,
                data,
            } => {
                buffer.extend_from_slice(&identifier.to_be_bytes());
                buffer.extend_from_slice(&sequence_number.to_be_bytes());
                buffer.extend_from_slice(data);
            }
            IcmpPayload::DestinationUnreachable { .. } => {
                unimplemented!("Serialization for DestinationUnreachable not yet needed");
            }
            IcmpPayload::TimeExceeded { .. } => {
                unimplemented!("Serialization for TimeExceeded not yet needed");
            }
        }

        buffer
    }
}
