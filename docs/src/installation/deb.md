# Building a debian package

## Prerequisites

A Rust installation is required for this step.  Installation instructions can be found here: [rustup.rs](https://rustup.rs/)

Install the `cargo deb` prequisite for building a `.deb` package:

```bash
cargo install cargo-deb
```

We also need to clone our repository somewhere:

```bash
git clone https://github.com/keybear/keybear && cd keybear
```

## Build

Build the installation package:

```bash
cargo deb
```

This will produce a `.deb` package in the `target/debian` folder.

## Install the package

Install the package:

```bash
sudo dpkg -i target/debian/keybear*.deb
```
Installing the package should start the systemd service, ensure it's running without any errors:

```bash
sudo systemctl status keybear.service
```

## Configure Tor

Let Tor load our configuration for the onion service, add the following line to `/etc/tor/torrc`:

```conf
%include /etc/keybear/torrc
```

```bash
echo "%include /etc/keybear/torrc" | sudo tee -a /etc/tor/torrc
```

Restart the Tor service to enable the hidden service:

```bash
sudo systemctl restart tor.service
```

## From source (advanced)

### Cargo

Install the keybear binary:

```bash
cargo install keybear
```

Create a symbolic link in `/usr/local/bin`:

```bash
ln -s $HOME/.cargo/bin/keybear /usr/local/bin/keybear 
```
