use std::io::Read;

use synoxide::Parser;
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

        let internet_header = match parser.parse_internet_header() {
            Ok(header) => header,
            Err(e) => {
                eprintln!("{e}");
                continue;
            }
        };

        println!("internet_header: {:?}", internet_header);

        match internet_header.protocol {
            1 => {
                let icmp_header = match parser.parse_icmp_header() {
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
