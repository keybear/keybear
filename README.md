<div align="center">
   <h1>keybear</h1>

   <img src="assets/logo.svg" alt="Keybear"/>

   Self-hosted password server.

   <a href="https://actions-badge.atrox.dev/keybear/keybear/goto"><img src="https://github.com/keybear/keybear/workflows/CI/badge.svg" alt="Build Status"/></a>
   <a href="https://github.com/keybear/keybear/releases"><img src="https://img.shields.io/crates/d/keybear.svg" alt="Downloads"/></a>
   <a href="https://crates.io/crates/keybear"><img src="https://img.shields.io/crates/v/keybear.svg" alt="Version"/></a>
   <a href="https://codecov.io/gh/keybear/keybear"><img src="https://codecov.io/gh/keybear/keybear/branch/main/graph/badge.svg?token=32C44QK5R9" alt="Coverage"/></a>
   <a href="https://github.com/rust-secure-code/safety-dance/"><img src="https://img.shields.io/badge/unsafe-forbidden-brightgreen.svg" alt="Unsafe"/></a>
</div>

## Features

- 100% self-hosted, you control your data
- Built on well-tested & -used software, a bridge between [pass](https://www.passwordstore.org/) and [Tor](https://www.torproject.org/)
- No complicated router/DNS setup needed, possible to be used behind a firewall
- Untrackable/obfuscated server IP, perfect for running it at home
- Low resource usage, can be easily run on a Raspberry Pi

## Setup from source (easy)

For hosting a keybear instance we assume you are using a Debian derived OS (Debian, Ubuntu, Mint, etc.).

Install the `cargo deb` prequisite for building a `.deb` package:

```bash
cargo install cargo-deb
```

Build the installation package:

```bash
cargo deb
```

Let Tor load our configuration for the onion service, add the following line to `/etc/tor/torrc`:

```conf
%include /etc/tor/torrc.d/keybear.conf
```

```bash
echo "%include /etc/tor/torrc.d/keybear.conf" | sudo tee -a /etc/tor/torrc
```

Install the package:

```bash
sudo dpkg -i target/debian/keybear*.deb
```

Ensure that the systemd service is running:

```bash
sudo systemctl status keybear.service
```

Restart the Tor service to enable the hidden service:

```bash
sudo systemctl restart tor.service
```

## Building from source (advanced)

### Cargo

Install the keybear binary:

```bash
cargo install keybear
```

Create a symbolic link in `/usr/local/bin`:

```bash
ln -s $HOME/.cargo/bin/keybear /usr/local/bin/keybear 
```

## Setup (advanced)

### Tor

Install Tor:

```bash
sudo apt install tor
```

Configure a hidden Tor onion service, add the following lines to `/etc/tor/torrc`:

```conf
HiddenServiceDir /var/lib/tor/keybear
HiddenServicePort 5219 127.0.0.1:52477
```

```bash
printf "HiddenServiceDir /var/lib/tor/keybear\nHiddenServicePort 5219 127.0.0.1:52477" | sudo tee -a /etc/tor/torrc
```

Restart Tor:

```bash
sudo systemctl restart tor.service
```

### Systemd

Copy the service file to `/usr/lib/systemd/system`:

```bash
sudo cp keybear.service /usr/lib/systemd/system/
```

Tell systemd to look for the new service file, to start it everytime we boot and to start it now:

```bash
sudo systemctl daemon-reload
sudo systemctl enable keybear.service
sudo systemctl start keybear.service
```

Verify that the service is running:

```bash
sudo systemctl status keybear.service
```

## Credits

Logo and name credits go to [@rottier](https://github.com/rottier).
