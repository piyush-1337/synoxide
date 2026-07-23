use std::io::{Read, Write};

use synoxide::tcp::TcpListener;
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

    let dev = tun::create(&config)?;

    let listener = TcpListener::bind(8080, dev)?;
    println!("listening on 10.0.0.2:8080");

    loop {
        let mut stream = listener.accept()?;
        println!("accepted connection");

        std::thread::spawn(move || {
            let mut buf = [0u8; 1024];

            loop {
                let n = match stream.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(e) => {
                        eprintln!("read error: {}", e);
                        break;
                    }
                };

                if let Err(e) = stream.write_all(&buf[..n]) {
                    eprintln!("write error: {}", e);
                    break;
                }
            }

            println!("connection closed");
        });
    }
}
