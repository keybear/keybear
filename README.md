<div align="center">
   <h1>keybear</h1>

   <img src="assets/logo.svg" alt="Keybear"/>

   Self-hosted password server.
</div>

## Features

- 100% self-hosted, you control your data
- Built on well-tested & -used software, a bridge between [pass](https://www.passwordstore.org/) and [Tor](https://www.torproject.org/)
- No complicated router/DNS setup needed, possible to be used behind a firewall
- Untrackable/obfuscated server IP, perfect for running it at home
- Low resource usage, can be easily run on a Raspberry Pi

## Installing

### Cargo

```bash
cargo install keybear
```

## Setup

For hosting a keybear instance we assume you are using a Debian derived OS (Debian, Ubuntu, Mint, etc.).

### Tor

Install Tor:

```bash
sudo apt install tor
```

Configure a hidden Tor onion service, add the following lines to `/etc/tor/torrc`:

```torrc
HiddenServiceDir /var/lib/tor/keybear
HiddenServicePort 5219 127.0.0.1:52477
```

```bash
printf "HiddenServiceDir /var/lib/tor/keybear\nHiddenServicePort 5219 127.0.0.1:52477" | sudo tee -a /etc/tor/torrc
```

Restart Tor:

```bash
sudo service tor restart
```

## Credits

Logo and name credits go to [@rottier](https://github.com/rottier).
