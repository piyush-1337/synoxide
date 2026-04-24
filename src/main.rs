use std::io::Read;

use synoxide::{parse_icmp_header, parse_internet_header};
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

        let (internet_header, remaining) = match parse_internet_header(packet) {
            Ok(header) => header,
            Err(e) => {
                eprintln!("{e}");
                continue;
            }
        };

        println!("internet_header: {:?}", internet_header);

        match internet_header.protocol {
            1 => {
                let (icmp_header, remaining) = match parse_icmp_header(remaining) {
                    Ok(header) => header,
                    Err(e) => {
                        eprintln!("{e}");
                        continue;
                    }
                };

                println!("icmp_header: {:?}", icmp_header);
            }

            6 => {
                println!("tcp not implemented")
            }

            17 => {
                println!("udp not implemented")
            }
            _ => eprintln!("not implemented protocol: {}", internet_header.protocol),
        }
    }
}
