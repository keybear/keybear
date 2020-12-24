# Installing it manually using Cargo

## Prerequisites

A Rust installation is required for this step.  Installation instructions can be found here: [rustup.rs](https://rustup.rs/)

## Cargo

Install the package using Cargo:

```bash
git clone https://github.com/keybear/keybear.git
cd keybear
cargo install
```

## Tor

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

## Systemd

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
