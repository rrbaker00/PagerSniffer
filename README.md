# pager_sniffer

RTL-SDR → `rtl_fm` → `multimon-ng` → live web UI for capturing **POCSAG** and
**FLEX** pager traffic during a CTF and reading the message contents (where the
flag lives).

* Cycles a list of frequencies (so a single dongle covers several channels), or
  camps on one.
* Decodes POCSAG 512/1200/2400 **and** FLEX on every dwell — whichever protocol
  is on that channel gets picked up.
* Web page at `http://127.0.0.1:8080`:
  * top: a live **time × frequency graph** — one dot per packet (cyan = POCSAG,
    magenta = FLEX, yellow = flag hit), the dashed line is the currently tuned
    frequency, and the bottom strip shows packet flow (packets per 5 s).
  * below: a **scrollable log** of every decoded message, with filter,
    auto-scroll toggle, and anything matching `word{...}` highlighted and pinned
    to a FLAGS panel.
* Everything is also written to `captures.jsonl` and flag hits to `flags.txt`,
  so nothing is lost if the browser is closed.
* **Raw-signal monitor** (on by default): measures the tuned channel's FM audio
  energy ~10x/s straight off the `rtl_fm` stream, so the web UI shows *every*
  transmission on the channel — a live level trace (dBFS) in its own graph lane,
  plus a `SIGNAL` "carrier" row in the log for each burst — even when
  `multimon-ng` decodes nothing (idle band, weak signal, or a mode/protocol it
  doesn't speak). A flat trace sitting on the noise floor = the channel really
  is idle. Header shows the current level; `signals` counts detected carriers.

> RX only. Use it only against traffic you are authorised to receive — the CTF
> range, a lab transmitter, or your own equipment. In the UK, real pager
> networks carry personal data; do not point this at them.

---

## 1. Install (Fedora)

```bash
cd ~/projects/pager_sniffer
chmod +x setup.sh scan.sh
./setup.sh
```

`setup.sh` installs `rtl-sdr` + `multimon-ng` and blacklists the `dvb_usb_rtl28xxu`
kernel driver that otherwise grabs your dongle (your `lsusb -t` shows it bound
right now). **Unplug/replug the dongle** afterwards so the blacklist takes effect.

Check it:

```bash
rtl_test -t          # should list "Realtek RTL2832U" and a tuner, no "device busy"
```

Nothing else to install — the sniffer itself is stdlib-only Python 3.

## 2. Run

```bash
python3 pager_sniffer.py
```

Open <http://127.0.0.1:8080>.

### Test the UI without the SDR

```bash
python3 pager_sniffer.py --simulate
```

Generates fake POCSAG/FLEX traffic (including a `flag{...}`) so you can confirm
the graph and log work before fighting with RF.

## 3. Two capture modes (both are built in)

| Mode | Command | Use when |
|---|---|---|
| **Cycle** | `python3 pager_sniffer.py` | You don't yet know the exact channel. Rotates the `channels_mhz` list, `dwell_seconds` each. |
| **Fast cycle** | `python3 pager_sniffer.py --dwell 8` | Sweep more channels quicker, at the cost of more retune gaps. |
| **Camp** | `python3 pager_sniffer.py --freq 153.3500` | You know where the flag is transmitted — never miss anything on that channel. |

You can switch **live from the web UI** — `cycle` / `camp` / `next »` buttons and
the dwell box — no restart needed.

Handy flags: `--gain 40` (or `--gain agc`), `--ppm -2` (crystal correction),
`--channels 153.35,153.275,458.6875`, `--port 9000`.

## 4. Finding the right channel

The CTF hint is *industrial factory* / *hospital / emergency services*, i.e. a
UK **on-site paging** system. Sweep for the active carrier first:

```bash
./scan.sh 138M 155M      # VHF on-site + wide-area paging
./scan.sh 449M 470M      # UHF on-site (458 MHz) + wide-area (466 MHz)
```

then camp on the strongest bin: `python3 pager_sniffer.py --freq <MHz>`.

### UK paging channel reference

Defaults in `config.json` (VHF, POCSAG, on-site + wide-area slant):

```
138.150  wide-area paging (often active — good canary)
138.780  on-site paging
153.025 153.150 153.200 153.275 153.350 153.400 153.425   on-site / wide-area band
161.175  on-site paging
```

UHF on-site paging (very common in modern factories & hospitals) — swap these
into `channels_mhz` or pass `--channels`:

```
458.500  458.5375 458.575 458.6125 458.650 458.6875 458.725
458.7625 458.800  458.8375 458.875  458.9125 458.950
466.075  466.175  466.20625 466.23125    (wide-area / e*Message)
```

Low-band industrial on-site paging (26 / 31 / 49 MHz) needs the RTL-SDR
**direct-sampling** mod / Q-branch and is not in the defaults.

## 5. config.json

| key | meaning |
|---|---|
| `mode` | `cycle` or `camp` |
| `dwell_seconds` | seconds per channel in cycle mode |
| `camp_freq_mhz` | channel used in camp mode |
| `channels_mhz` | list cycled in cycle mode (editable live from the UI) |
| `gain` | tuner gain dB, or `"agc"` / `null` for hardware AGC |
| `ppm` | frequency correction for your dongle's crystal error |
| `decoders` | multimon-ng demods, default POCSAG512/1200/2400 + FLEX |
| `flag_regex` | what to highlight; default matches `anything{...}` |
| `graph_window_seconds` | how much history the graph shows |
| `signal_monitor` | show the raw channel-level trace + `SIGNAL` carrier events (default `true`) |
| `signal_threshold_db` | dB above the rolling noise floor to call it a carrier (default 6) |
| `signal_min_event_ms` | ignore carrier blips shorter than this (default 300) |

## 6. Troubleshooting

* **"rtl_fm exited immediately … device busy"** – DVB driver still loaded, or
  another SDR app (GQRX, SDR++, a browser SDR tab) holds the dongle. Run
  `./setup.sh`, unplug/replug, close other apps. See `rtl_fm.log`.
* **No packets at all** – check the **signal lane** on the graph first. Flat
  line on the noise floor + no `SIGNAL` rows = nothing is transmitting on that
  channel (wrong channel — run `./scan.sh` — or antenna not resonant for the
  band). A moving trace / `SIGNAL` carrier rows but still no decoded text = the
  RF is there but it isn't POCSAG/FLEX, is too weak, or needs `--ppm`. The
  "modified antenna": tell me its band and I'll set `channels_mhz` to match. Try
  `--gain 49` for weak signals, `--gain agc` if strong local signals overload.
  Tune the detector with `signal_threshold_db` (default 6 dB over floor) in
  `config.json`, or turn it off with `"signal_monitor": false`.
* **Garbled text / partial messages** – set `ppm` (find it with
  `rtl_test -p`), lower `dwell` won't help; camp instead of cycle so you catch
  full batches.
* **Graph empty but log fills** – channels list has one frequency far from the
  rest; the Y axis auto-ranges, it's fine.
* **Browser on another machine** – start with `--host 0.0.0.0` and open
  `http://<this-box-ip>:8080` (only on a trusted network).

## 7. Files written

```
captures.jsonl     every decoded packet, one JSON object per line
flags.txt          flag-regex hits, human readable
rtl_fm.log         rtl_fm stderr (tuning / device errors)
multimon-ng.log    multimon-ng stderr (enabled demods / warnings)
```
