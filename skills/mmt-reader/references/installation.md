# Installing mmtReader

Read this only when `mmtReader --version` fails. mmtReader needs the MMT-DPI library at `/opt/mmt/dpi/` (version 1.8.0 or newer) plus libpcap.

## 1. Locate an existing build

```bash
for dir in . ~/workspace/mmt/mmt-reader /opt/mmt/mmt-reader /usr/local/src/mmt-reader; do
  if [ -f "$dir/mmtReader" ]; then echo "Found source at $dir"; break; fi
done
```

If no directory matches, **stop and ask the user** for the mmtReader source path or binary location. Do not download the tool from any other source.

## 2. Install from that source

```bash
cd "$dir"
sudo ./install.sh --mmt-reader-only   # MMT-DPI already at /opt/mmt/dpi/
sudo ./install.sh                     # full install: deps + MMT-DPI + mmtReader
make build && sudo make install       # build without the install script
```

`install.sh` and `make install` write outside the repo and need `sudo`. Show the user which of the three commands you intend to run and get confirmation before running it.

## 3. Verify — installation is done when both commands exit 0

```bash
mmtReader --version      # prints "mmtReader version: 0.4.0" and "MMT-DPI SDK version: 1.8.0 (42cac8b7)"
mmtReader analyze -h     # prints help with no error
```

If `--version` still fails after install, report the exact stderr to the user rather than retrying with different flags.

## Install-time failures

| Symptom | Cause and fix |
|---------|---------------|
| `MMT-DPI library not found` | MMT-DPI is absent from `/opt/mmt/dpi/` — run the full `sudo ./install.sh` |
| `libpcap` header errors during `make` | Missing dev package — `sudo apt install libpcap-dev` |
| `MMT-DPI SDK ≥ 1.8.0 required` from `make` | Installed SDK is too old — reinstall the SDK, or point the build elsewhere with `make MMT_DPI=/path/to/sdk` |
| `install.sh: Permission denied` | Re-run with `sudo`, after confirming with the user |
