#!/usr/bin/env bash
# One-time setup on Fedora: install rtl-sdr + multimon-ng and free the RTL2832
# dongle from the DVB-T kernel driver so rtl_fm can claim it.
set -e

echo "[*] Installing rtl-sdr + multimon-ng ..."
if ! sudo dnf install -y rtl-sdr multimon-ng; then
  echo
  echo "[!] dnf could not install one of them (multimon-ng is sometimes absent)."
  echo "    Build multimon-ng from source:"
  echo "      sudo dnf install -y git gcc make cmake pulseaudio-libs-devel"
  echo "      git clone https://github.com/EliasOenal/multimon-ng"
  echo "      cd multimon-ng && mkdir build && cd build"
  echo "      cmake -DCMAKE_INSTALL_PREFIX=/usr/local .. && make && sudo make install"
  echo
fi

echo "[*] Blacklisting the DVB-T driver that grabs the dongle ..."
sudo tee /etc/modprobe.d/blacklist-rtlsdr.conf >/dev/null <<'EOF'
# RTL2832 used as an SDR, not a DVB-T tuner
blacklist dvb_usb_rtl28xxu
blacklist rtl2832
blacklist rtl2830
EOF

echo "[*] Unloading it now (harmless if it is not loaded) ..."
sudo modprobe -r dvb_usb_rtl28xxu 2>/dev/null || true
sudo modprobe -r rtl2832 2>/dev/null || true

echo
echo "[*] Testing the dongle ..."
if command -v rtl_test >/dev/null; then
  rtl_test -t || true
else
  echo "    rtl_test not on PATH - rtl-sdr install may have failed."
fi

echo
echo "[OK] If rtl_test still says 'usb_claim_interface error -6' or 'device busy',"
echo "     unplug and replug the dongle (or reboot) so the blacklist takes effect,"
echo "     then run:  python3 pager_sniffer.py"
