# Synoxide

Synoxide is a user space network stack implementation using linux tun interface

## Build and dev-env

- Nix dev shell
```bash
nix develop
```

- Build and run
```bash
# elevated privileges to create tun interface
sudo cargo run
```

## Testing

Get the tun ip (eg, 10.0.0.1)
```bash
ip a
```

- ICMP (ping)
```bash
ping -c 3 10.0.0.2
```

- UDP
```bash
nc -u 10.0.0.2 8080
your message
```

- TCP (not implemented yet)
```bash
nc 10.0.0.2 8080
```
