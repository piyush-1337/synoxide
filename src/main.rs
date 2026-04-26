use std::io::{Read, Write};

use synoxide::{IcmpPayload, Parser};
use tun::Configuration;

fn main() -> anyhow::Result<()> {
    let mut config = Configuration::default();

    config
        .tun_name("tun0")
        .address((10, 0, 0, 1))
        .netmask((255, 255, 255, 0))
        .up();

    config.platform_config(|config| {
        config.ensure_root_privileges(true);
    });

    let mut dev = tun::create(&config).expect("Failed to create TUN device");
    let mut buf = [0u8; 1504];

    loop {
        let n = dev.read(&mut buf).expect("Failed to read from device");
        let packet = &buf[..n];
        let mut parser = Parser::new(packet);

        let ip_header = match parser.parse_ip_header() {
            Ok(header) => header,
            Err(e) => {
                eprintln!("{e}");
                continue;
            }
        };

        println!("ip_header: {:?}", ip_header);

        match ip_header.protocol {
            1 => {
                let icmp_header = match parser.parse_icmp_header() {
                    Ok(header) => header,
                    Err(e) => {
                        eprintln!("{e}");
                        continue;
                    }
                };

                println!("icmp_header: {:?}", icmp_header);

                if let IcmpPayload::Echo { .. } = icmp_header.payload
                    && icmp_header.icmp_type == 8
                {
                    let mut reply_ip = ip_header;
                    std::mem::swap(&mut reply_ip.source_addr, &mut reply_ip.dest_addr);
                    reply_ip.recalculate_checksum();

                    let mut reply_icmp = icmp_header;
                    reply_icmp.icmp_type = 0;
                    reply_icmp.recalculate_checksum();

                    let mut final_reply = reply_ip.to_bytes();
                    final_reply.extend(reply_icmp.to_bytes());

                    dev.write_all(&final_reply)?;
                    println!("sent echo reply");
                }
            }

            6 => {
                println!("tcp not implemented")
            }

            17 => {
                println!("udp not implemented")
            }
            _ => eprintln!("not implemented protocol: {}", ip_header.protocol),
        }
    }
}
