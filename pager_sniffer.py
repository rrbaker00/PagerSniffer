#!/usr/bin/env python3
"""
pager_sniffer.py - RTL-SDR pager capture + live web UI for CTF use.

Pipeline:  rtl_fm (NBFM)  ->  multimon-ng (POCSAG512/1200/2400 + FLEX)  ->  parser
           -> in-memory history + captures.jsonl + Server-Sent-Events feed
           -> web/index.html  (frequency/time graph + scrollable message log)

RX only. Use only against traffic you are authorised to receive (CTF range,
lab transmitter, your own gear). See README.md.

Stdlib only - no pip installs. Needs external binaries: rtl_fm, multimon-ng
(run ./setup.sh on Fedora).
"""

import argparse
import array
import atexit
import json
import math
import os
import queue
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
from collections import deque
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

HERE = os.path.dirname(os.path.abspath(__file__))

# multimon-ng (and rtl_fm) block-buffer stdout when it is a pipe rather than a
# TTY, so decoded lines can sit unseen in a ~4 KB buffer for minutes and are
# lost entirely when the child is killed on retune. Force unbuffered output.
_STDBUF = ["stdbuf", "-o0"] if shutil.which("stdbuf") else []

DEFAULT_CONFIG = {
    "host": "127.0.0.1",
    "port": 8080,
    "mode": "camp",                  # "cycle" | "camp"
    "dwell_seconds": 20,             # per-channel time in cycle mode
    "camp_freq_mhz": 153.350,        # used when mode == "camp"
    "gain": 40,                      # dB; null/"agc" -> hardware AGC
    "ppm": 0,                        # frequency correction (crystal error)
    "sample_rate": 22050,            # multimon-ng wants 22050 Hz s16 mono raw
    "device_index": 0,
    "fm_extra": ["-E", "dc"],        # extra rtl_fm flags
    "decoders": ["POCSAG512", "POCSAG1200", "POCSAG2400", "FLEX"],
    "flag_regex": r"([A-Za-z0-9_]{1,16}\{[^}\r\n]{1,200}\})",
    "channels_mhz": [138.150, 138.780, 153.025, 153.150, 153.200,
                     153.275, 153.350, 153.400, 153.425, 161.175],
    "log_file": "captures.jsonl",
    "flags_file": "flags.txt",
    "backlog": 400,
    "graph_window_seconds": 180,

    # --- raw-signal monitor -------------------------------------------------- #
    # Measures the FM audio energy of the *tuned* channel ~10x/second straight
    # from the rtl_fm PCM stream, so the web UI shows every transmission on the
    # channel as a live level trace + "carrier" events even when multimon-ng
    # decodes nothing (idle band, unknown mode, weak signal, wrong protocol).
    "signal_monitor": True,
    "signal_sample_hz": 10,          # level measurements per second
    "signal_emit_hz": 10,            # max level samples pushed to the browser /s
    "signal_threshold_db": 6.0,      # dB over noise floor to call it a carrier
    "signal_close_db": 3.0,          # drop below floor+this to end the carrier
    "signal_min_event_ms": 300,      # ignore carrier blips shorter than this
    "signal_debounce_ms": 150,       # sustain the threshold this long each way
    "signal_floor_percentile": 20,   # noise floor = this pct of a 30 s window
}

# --------------------------------------------------------------------------- #
# Parsing multimon-ng output
# --------------------------------------------------------------------------- #

POCSAG_RE = re.compile(
    r"^POCSAG(?P<baud>\d+):\s+Address:\s*(?P<addr>\d+)\s+Function:\s*(?P<func>\d+)"
    r"(?:\s+(?P<type>Alpha|Numeric|Skyper|Bitfield):\s?(?P<msg>.*))?\s*$"
)

FLEX_RE = re.compile(
    r"^FLEX[:|]\s*"
    r"(?:(?P<ts>\d{4}-\d\d-\d\d[ T]\d\d:\d\d:\d\d)\s+)?"
    r"(?:(?P<rate>\d{3,4}/\d(?:/\w)?(?:/\w)?)\s+)?"
    r"(?:(?P<frame>[0-9]{1,4}\.[0-9]{1,4}\.[0-9A-Za-z]+|[0-9.]+)\s+)?"
    r"\[?(?P<capcode>\d{4,10})\]?\s*"
    r"(?:(?P<type>ALN|NUM|TON|SPN|GPN|BIN)\s+)?"
    r"(?P<msg>.*?)\s*$"
)


def make_record(freq, proto, addr, func, typ, msg, raw, flag_re):
    now = time.time()
    rec = {
        "ts": now,
        "time": datetime.fromtimestamp(now).strftime("%H:%M:%S"),
        "date": datetime.fromtimestamp(now).strftime("%Y-%m-%d"),
        "freq_mhz": round(float(freq), 4),
        "protocol": proto,
        "address": addr or "",
        "function": func,
        "type": typ or "",
        "message": msg or "",
        "raw": raw,
    }
    for hay in (msg, raw):
        if not hay:
            continue
        m = flag_re.search(hay)
        if m:
            rec["flag_hit"] = True
            rec["flag"] = m.group(0)
            break
    return rec


def parse_line(line, freq, flag_re):
    line = line.rstrip("\r\n")
    if not line.strip():
        return None

    m = POCSAG_RE.match(line)
    if m:
        msg = (m.group("msg") or "").strip()
        return make_record(freq, "POCSAG" + m.group("baud"), m.group("addr"),
                           int(m.group("func")), m.group("type"), msg, line, flag_re)

    if line.startswith("FLEX"):
        m = FLEX_RE.match(line)
        if m:
            proto = "FLEX"
            if m.group("rate"):
                proto = "FLEX-" + m.group("rate").split("/")[0]
            rec = make_record(freq, proto, m.group("capcode"), None,
                              m.group("type"), (m.group("msg") or "").strip(),
                              line, flag_re)
            if m.group("frame"):
                rec["frame"] = m.group("frame")
            return rec
        # Unparsed FLEX line - keep it anyway, it may hold the flag.
        return make_record(freq, "FLEX", "", None, "",
                           line.split(":", 1)[-1].strip(), line, flag_re)

    # Everything else from multimon-ng (banners, warnings) is ignored here;
    # rtl_fm/multimon-ng stderr is captured to *.log files.
    return None


# --------------------------------------------------------------------------- #
# Sniffer core
# --------------------------------------------------------------------------- #

class Sniffer:
    def __init__(self, cfg):
        self.cfg = cfg
        self.flag_re = re.compile(cfg["flag_regex"])
        self.clients = set()                       # set[queue.Queue]
        self.clients_lock = threading.Lock()
        self.history = deque(maxlen=8000)
        self.counter = 0
        self.stats = {"total": 0, "pocsag": 0, "flex": 0, "flags": 0, "signals": 0}
        self.mode = cfg["mode"]
        self.camp_freq = float(cfg["camp_freq_mhz"])
        self.current_freq = None
        self.started = time.time()
        self.capture_live = False
        self.simulate = False
        self.preflight_result = {"ran": False}
        self.stop_flag = threading.Event()
        self.retune_flag = threading.Event()
        self._procs = []
        self._proc_lock = threading.Lock()
        self.logf = open(os.path.join(HERE, cfg["log_file"]), "a",
                         buffering=1, encoding="utf-8")

        # -- raw-signal monitor ---------------------------------------------- #
        self.sig_on = bool(cfg.get("signal_monitor", True))
        self.sig_hz = max(2, int(cfg.get("signal_sample_hz", 10)))
        self.sig_emit_hz = max(1, min(self.sig_hz,
                                      int(cfg.get("signal_emit_hz", 10))))
        self.sig_open_db = float(cfg.get("signal_threshold_db", 6.0))
        self.sig_close_db = float(cfg.get("signal_close_db",
                                          min(self.sig_open_db, 3.0)))
        self.sig_min_ms = float(cfg.get("signal_min_event_ms", 300))
        self.sig_floor_pct = float(cfg.get("signal_floor_percentile", 20))
        _dbnc = float(cfg.get("signal_debounce_ms", 150))
        self._sig_need = max(1, round(self.sig_hz * _dbnc / 1000.0))
        self._lvl_hist = deque(maxlen=int(self.sig_hz * 30))
        self._carrier_on = False
        self._carrier_cnt = 0
        self._carrier_t0 = 0.0
        self._carrier_peak_dbfs = -140.0
        self._carrier_peak_snr = 0.0
        self._last_sig_emit = 0.0
        self.last_signal = None

    # -- fan-out ---------------------------------------------------------- #
    def emit(self, rec):
        self.counter += 1
        rec["id"] = self.counter
        self.stats["total"] += 1
        if rec["protocol"].startswith("POCSAG"):
            self.stats["pocsag"] += 1
        elif rec["protocol"].startswith("FLEX"):
            self.stats["flex"] += 1
        elif rec["protocol"] == "SIGNAL":
            self.stats["signals"] += 1
        if rec.get("flag_hit"):
            self.stats["flags"] += 1
            self._save_flag(rec)

        self.history.append(rec)
        try:
            self.logf.write(json.dumps(rec, ensure_ascii=False) + "\n")
        except Exception:
            pass

        dead = []
        with self.clients_lock:
            for q in self.clients:
                try:
                    q.put_nowait(rec)
                except queue.Full:
                    dead.append(q)
            for q in dead:
                self.clients.discard(q)

        if rec.get("flag_hit"):
            print(f"\033[93m[FLAG]\033[0m {rec['freq_mhz']} MHz  {rec['protocol']}  "
                  f"cap={rec['address']}  {rec.get('flag') or rec['message']!r}",
                  flush=True)

    def _save_flag(self, rec):
        try:
            with open(os.path.join(HERE, self.cfg["flags_file"]), "a",
                      encoding="utf-8") as f:
                f.write(f"{rec['date']} {rec['time']}  {rec['freq_mhz']} MHz  "
                        f"{rec['protocol']}  cap={rec['address']}  "
                        f"{rec.get('flag')}  |  {rec['message']}\n")
        except Exception:
            pass

    # -- state ---------------------------------------------------------- #
    def state(self):
        return {
            "mode": self.mode,
            "current_freq_mhz": self.current_freq,
            "camp_freq_mhz": self.camp_freq,
            "channels_mhz": self.cfg["channels_mhz"],
            "dwell_seconds": self.cfg["dwell_seconds"],
            "graph_window_seconds": self.cfg["graph_window_seconds"],
            "decoders": self.cfg["decoders"],
            "stats": self.stats,
            "started": self.started,
            "now": time.time(),
            "capture_live": self.capture_live,
            "simulate": self.simulate,
            "preflight": self.preflight_result,
            "gain": self.cfg["gain"],
            "ppm": self.cfg["ppm"],
            "signal_monitor": self.sig_on,
            "signal_threshold_db": self.sig_open_db,
            "signal": self.last_signal or {
                "ts": time.time(), "freq_mhz": self.current_freq,
                "dbfs": None, "floor": None, "snr": None, "active": False},
        }

    def _broadcast_state(self):
        st = self.state()
        with self.clients_lock:
            for q in list(self.clients):
                try:
                    q.put_nowait({"__state__": st})
                except queue.Full:
                    pass

    # -- runtime control from the web UI ------------------------------- #
    def control(self, qs):
        cmd = (qs.get("cmd") or [""])[0]
        if cmd == "camp":
            f = (qs.get("freq") or [None])[0]
            if f:
                try:
                    self.camp_freq = round(float(f), 4)
                except ValueError:
                    pass
            self.mode = "camp"
            self.retune_flag.set()
        elif cmd == "cycle":
            self.mode = "cycle"
            self.retune_flag.set()
        elif cmd == "next":
            self.retune_flag.set()
        elif cmd == "dwell":
            try:
                self.cfg["dwell_seconds"] = max(3, int(float(qs["v"][0])))
            except (KeyError, ValueError):
                pass
        elif cmd == "add_channel":
            try:
                f = round(float(qs["freq"][0]), 4)
                if f not in self.cfg["channels_mhz"]:
                    self.cfg["channels_mhz"].append(f)
                    self.cfg["channels_mhz"].sort()
            except (KeyError, ValueError):
                pass
        elif cmd == "del_channel":
            try:
                f = round(float(qs["freq"][0]), 4)
                if f in self.cfg["channels_mhz"]:
                    self.cfg["channels_mhz"].remove(f)
            except (KeyError, ValueError):
                pass
        elif cmd == "clear":
            self.history.clear()
        self._broadcast_state()
        return self.state()

    # -- capture ------------------------------------------------------- #
    def _rtl_fm_cmd(self, freq_mhz):
        c = self.cfg
        cmd = _STDBUF + ["rtl_fm", "-f", f"{freq_mhz:.4f}M", "-M", "fm",
                         "-s", str(c["sample_rate"]), "-l", "0"]
        if c.get("device_index") is not None:
            cmd += ["-d", str(c["device_index"])]
        g = c.get("gain")
        if g is not None and str(g).lower() not in ("agc", "auto", "none"):
            cmd += ["-g", str(g)]
        if c.get("ppm"):
            cmd += ["-p", str(c["ppm"])]
        cmd += list(c.get("fm_extra") or [])
        cmd += ["-"]
        return cmd

    def _multimon_cmd(self):
        cmd = _STDBUF + ["multimon-ng", "-t", "raw"]
        for d in self.cfg["decoders"]:
            cmd += ["-a", d]
        cmd += ["-f", "alpha", "-"]
        return cmd

    def run_channel(self, freq, duration):
        """Tune `freq` (MHz) and pump decoded lines until `duration` s elapses
        (duration <= 0 means run until stop/retune)."""
        self.current_freq = round(float(freq), 4)
        self._sig_reset()
        self._broadcast_state()

        rtl_log = open(os.path.join(HERE, "rtl_fm.log"), "ab")
        mm_log = open(os.path.join(HERE, "multimon-ng.log"), "ab")
        try:
            rtl = subprocess.Popen(self._rtl_fm_cmd(freq), stdout=subprocess.PIPE,
                                   stderr=rtl_log, bufsize=0)
        except FileNotFoundError:
            print("\033[91m[!] rtl_fm not found - run ./setup.sh\033[0m", flush=True)
            return False
        # When the signal monitor is on, rtl_fm's PCM is pumped through this
        # process (measuring channel energy) and on into multimon-ng; otherwise
        # the two are wired mouth-to-tail as before.
        pump = self.sig_on
        try:
            mm = subprocess.Popen(
                self._multimon_cmd(),
                stdin=(subprocess.PIPE if pump else rtl.stdout),
                stdout=subprocess.PIPE, stderr=mm_log, bufsize=-1)
        except FileNotFoundError:
            rtl.kill()
            print("\033[91m[!] multimon-ng not found - run ./setup.sh\033[0m", flush=True)
            return False
        if not pump:
            rtl.stdout.close()                   # only multimon-ng holds the pipe

        with self._proc_lock:
            self._procs = [rtl, mm]

        time.sleep(0.4)
        if rtl.poll() is not None:
            self.capture_live = False
            print(f"\033[91m[!] rtl_fm exited immediately on {freq} MHz "
                  f"(rc={rtl.returncode}). Check rtl_fm.log - usually 'device busy' "
                  f"(kill other SDR apps / unplug-replug) or driver not blacklisted.\033[0m",
                  flush=True)
            self._kill(rtl, mm)
            time.sleep(1.0)
            return False
        self.capture_live = True

        killer = threading.Event()

        def watchdog():
            end = time.monotonic() + duration if duration and duration > 0 else None
            while not killer.wait(0.2):
                if self.stop_flag.is_set() or self.retune_flag.is_set():
                    break
                if end and time.monotonic() >= end:
                    break
                if self.mode == "camp" and duration and duration > 0:
                    break                        # switched to camp mid-cycle
            self._kill(rtl, mm)

        def pump_pcm():
            """rtl_fm PCM -> multimon-ng stdin, measuring channel energy en route
            so idle/undecodable transmissions still show on the web UI."""
            chunk = max(2, (int(self.cfg["sample_rate"]) // self.sig_hz)) * 2
            src, dst, acc = rtl.stdout, mm.stdin, bytearray()
            try:
                while not killer.is_set():
                    b = src.read(65536)
                    if not b:
                        break
                    try:
                        dst.write(b)
                        dst.flush()
                    except (BrokenPipeError, OSError, ValueError):
                        break
                    acc += b
                    while len(acc) >= chunk:
                        self._level_sample(acc[:chunk])
                        del acc[:chunk]
            except (OSError, ValueError):
                pass
            finally:
                try:
                    dst.close()
                except Exception:
                    pass

        pt = None
        if pump:
            pt = threading.Thread(target=pump_pcm, daemon=True)
            pt.start()

        wt = threading.Thread(target=watchdog, daemon=True)
        wt.start()
        try:
            for raw in mm.stdout:
                line = (raw.decode("utf-8", "replace")
                        if isinstance(raw, (bytes, bytearray)) else raw)
                rec = parse_line(line, self.current_freq, self.flag_re)
                if rec:
                    self.emit(rec)
        except (ValueError, OSError):
            pass
        finally:
            killer.set()
            self._kill(rtl, mm)
            if pt:
                pt.join(timeout=1.5)
            wt.join(timeout=1.5)
            self._sig_flush()          # emit an in-progress carrier before teardown
            with self._proc_lock:
                self._procs = []
            for fh in (rtl_log, mm_log):
                try:
                    fh.close()
                except Exception:
                    pass
        return True

    # -- raw-signal monitor -------------------------------------------------- #
    def _sig_reset(self):
        self._lvl_hist.clear()
        self._carrier_on = False
        self._carrier_cnt = 0
        self._carrier_peak_dbfs = -140.0
        self._carrier_peak_snr = 0.0
        self.last_signal = None

    def _level_sample(self, pcm):
        a = array.array("h")
        try:
            a.frombytes(bytes(pcm))
        except ValueError:
            return
        if sys.byteorder == "big":
            a.byteswap()
        n = len(a)
        if not n:
            return
        ss = 0
        for x in a:
            ss += x * x
        rms = math.sqrt(ss / n)
        dbfs = 20.0 * math.log10(rms / 32768.0) if rms > 0.5 else -96.0
        self._on_level(dbfs)

    def _on_level(self, dbfs):
        now = time.time()
        self._lvl_hist.append(dbfs)
        ordered = sorted(self._lvl_hist)
        floor = ordered[int(len(ordered) * self.sig_floor_pct / 100.0)]
        snr = dbfs - floor
        need = self._sig_need

        if not self._carrier_on:
            if snr >= self.sig_open_db:
                self._carrier_cnt += 1
                if self._carrier_cnt >= need:
                    self._carrier_on = True
                    self._carrier_cnt = 0
                    self._carrier_t0 = now - need / self.sig_hz
                    self._carrier_peak_dbfs = dbfs
                    self._carrier_peak_snr = snr
            else:
                self._carrier_cnt = 0
        else:
            self._carrier_peak_dbfs = max(self._carrier_peak_dbfs, dbfs)
            self._carrier_peak_snr = max(self._carrier_peak_snr, snr)
            if snr <= self.sig_close_db:
                self._carrier_cnt += 1
                if self._carrier_cnt >= need:
                    self._carrier_on = False
                    self._carrier_cnt = 0
                    dur = (now - need / self.sig_hz) - self._carrier_t0
                    if dur * 1000.0 >= self.sig_min_ms:
                        self._emit_carrier_event(self._carrier_t0, max(dur, 0.1),
                                                 self._carrier_peak_dbfs,
                                                 self._carrier_peak_snr)
            else:
                self._carrier_cnt = 0

        self.last_signal = {
            "ts": now, "freq_mhz": self.current_freq,
            "dbfs": round(dbfs, 1), "floor": round(floor, 1),
            "snr": round(snr, 1), "active": self._carrier_on,
        }
        if now - self._last_sig_emit >= 1.0 / self.sig_emit_hz:
            self._last_sig_emit = now
            self._emit_signal_sample(self.last_signal)

    def _emit_signal_sample(self, sample):
        with self.clients_lock:
            for q in list(self.clients):
                try:
                    q.put_nowait({"__signal__": sample})
                except queue.Full:
                    pass

    def _emit_carrier_event(self, t0, dur, peak_dbfs, peak_snr):
        msg = (f"carrier {dur:.1f}s  peak {peak_dbfs:+.0f} dBFS  "
               f"(+{peak_snr:.0f} dB over noise floor) — undecoded RF activity")
        rec = make_record(self.current_freq, "SIGNAL", "", None, "carrier",
                          msg, f"SIGNAL: {self.current_freq:.4f} MHz  {msg}",
                          self.flag_re)
        rec["ts"] = t0
        rec["time"] = datetime.fromtimestamp(t0).strftime("%H:%M:%S")
        rec["date"] = datetime.fromtimestamp(t0).strftime("%Y-%m-%d")
        rec["duration_s"] = round(dur, 2)
        rec["peak_dbfs"] = round(peak_dbfs, 1)
        rec["snr_db"] = round(peak_snr, 1)
        self.emit(rec)
        print(f"\033[95m[SIGNAL]\033[0m {self.current_freq:.4f} MHz  carrier "
              f"{dur:.1f}s  peak {peak_dbfs:+.0f} dBFS (+{peak_snr:.0f} dB)",
              flush=True)

    def _sig_flush(self):
        """Close out a carrier that is still open when the channel tears down."""
        if not self._carrier_on:
            return
        self._carrier_on = False
        dur = time.time() - self._carrier_t0
        if dur * 1000.0 >= self.sig_min_ms:
            self._emit_carrier_event(self._carrier_t0, max(dur, 0.1),
                                     self._carrier_peak_dbfs,
                                     self._carrier_peak_snr)

    def _kill(self, *procs):
        for p in procs:
            if p and p.poll() is None:
                try:
                    p.terminate()
                except Exception:
                    pass
        for p in procs:
            if not p:
                continue
            try:
                p.wait(timeout=2)
            except Exception:
                try:
                    p.kill()
                except Exception:
                    pass

    def preflight(self):
        """One-shot startup check: can the SDR be opened, and is there any RF
        energy in the band we are about to monitor? A flat spectrum usually
        means the antenna is not connected (or the wrong band / a dead channel)."""
        res = {"ran": True, "ok": False, "level": "error", "msg": ""}
        if not shutil.which("rtl_power"):
            return {"ran": True, "ok": True, "level": "warn",
                    "msg": "rtl_power not installed - skipped antenna/RF check"}

        # In camp mode only the camped channel matters; in cycle mode sweep the
        # list, but don't let one far-flung entry blow the span out to 300 MHz.
        if self.mode == "camp":
            chans = [self.camp_freq]
        else:
            chans = list(self.cfg["channels_mhz"]) or [self.camp_freq]
            chans.sort()
            if len(chans) > 2 and chans[-1] - chans[0] > 12:
                mid = chans[len(chans) // 2]
                chans = [f for f in chans if abs(f - mid) <= 6] or [mid]
        lo, hi = min(chans) - 0.25, max(chans) + 0.25
        if hi - lo < 0.6:
            lo, hi = lo - 0.4, hi + 0.4
        tmp = os.path.join(HERE, ".preflight.csv")
        cmd = ["rtl_power", "-f", f"{lo:.4f}M:{hi:.4f}M:5k", "-i", "2", "-1"]
        g = self.cfg.get("gain")
        if g is not None and str(g).lower() not in ("agc", "auto", "none"):
            cmd += ["-g", str(g)]
        if self.cfg.get("device_index") is not None:
            cmd += ["-d", str(self.cfg["device_index"])]
        cmd += [tmp]

        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=25)
        except FileNotFoundError:
            res["msg"] = "rtl_power missing"
            return res
        except subprocess.TimeoutExpired:
            res["msg"] = "SDR did not respond in 25 s - unplug/replug the dongle"
            return res

        err = (p.stderr or "").strip()
        if p.returncode != 0 or "usb_claim_interface" in err or "No supported devices" in err:
            tail = err.splitlines()[-1] if err else f"exit {p.returncode}"
            res["msg"] = f"cannot open SDR: {tail}"
            try:
                os.remove(tmp)
            except OSError:
                pass
            return res

        vals = []
        try:
            with open(tmp, encoding="utf-8") as f:
                for line in f:
                    cols = line.split(",")
                    if len(cols) > 6:
                        for x in cols[6:]:
                            x = x.strip()
                            if x:
                                try:
                                    vals.append(float(x))
                                except ValueError:
                                    pass
        except OSError:
            pass
        finally:
            try:
                os.remove(tmp)
            except OSError:
                pass

        time.sleep(0.5)  # let rtl_power fully release the device

        if not vals:
            return {"ran": True, "ok": True, "level": "warn",
                    "msg": "SDR opened OK but rtl_power returned no data"}

        vals.sort()
        floor = vals[len(vals) // 2]
        peak = vals[-1]
        span = peak - floor
        band = f"{lo:.2f}-{hi:.2f} MHz"
        if span < 3.0:
            return {"ran": True, "ok": False, "level": "warn",
                    "msg": (f"{band} spectrum is flat (peak {peak:.0f} / floor "
                            f"{floor:.0f} dB, {span:.1f} dB spread) - antenna may be "
                            f"disconnected, wrong band, or the channel is just idle")}
        return {"ran": True, "ok": True, "level": "ok",
                "msg": (f"RF present in {band}: peak {peak:.0f} dB, floor "
                        f"{floor:.0f} dB ({span:.1f} dB spread)")}

    def capture_main(self):
        if not shutil.which("rtl_fm") or not shutil.which("multimon-ng"):
            self.preflight_result = {
                "ran": True, "ok": False, "level": "error",
                "msg": ("rtl_fm and/or multimon-ng not installed - run ./setup.sh "
                        "(or start with --simulate to test the UI)")}
            print("\033[91m[!] rtl_fm and/or multimon-ng missing. Web UI is up, "
                  "but there is NO live capture. Run ./setup.sh, then restart "
                  "(or use --simulate to test the UI).\033[0m", flush=True)
            self._broadcast_state()
            return

        print("  running antenna / RF check ...", flush=True)
        self.preflight_result = self.preflight()
        pf = self.preflight_result
        colour = {"ok": "\033[92m", "warn": "\033[93m",
                  "error": "\033[91m"}.get(pf.get("level"), "")
        print(f"  {colour}[antenna check] {pf.get('msg', '')}\033[0m", flush=True)
        self._broadcast_state()

        while not self.stop_flag.is_set():
            if self.mode == "camp":
                self.retune_flag.clear()
                self.run_channel(self.camp_freq, 0)
            else:
                chans = list(self.cfg["channels_mhz"]) or [self.camp_freq]
                for freq in chans:
                    if self.stop_flag.is_set() or self.mode == "camp":
                        break
                    self.retune_flag.clear()
                    self.run_channel(freq, self.cfg["dwell_seconds"])
            time.sleep(0.15)

    # -- simulate (no SDR) ------------------------------------------------ #
    def simulate_main(self):
        import random
        self.simulate = True
        self.capture_live = True
        msgs = [
            ("POCSAG1200", "WARD 4 CRASH CALL - TEAM TO RESUS BAY 2"),
            ("POCSAG1200", "LINE 3 CONVEYOR FAULT - E-STOP TRIGGERED ZONE 7"),
            ("POCSAG512",  "PORTER REQUIRED MAIN THEATRES LEVEL 2 ASAP"),
            ("POCSAG1200", "BOILER HOUSE HIGH PRESSURE ALARM - ATTEND NOW"),
            ("FLEX-1600",  "SECURITY TO A&E RECEPTION - CODE BLACK"),
            ("POCSAG1200", "DR PATEL BLEEP 2245 PLEASE CALL SWITCHBOARD"),
            ("POCSAG1200", "PACKING HALL - PALLET WRAPPER JAM STATION 4"),
            ("FLEX-1600",  "MAINTENANCE CALLOUT - CHILLER 2 LOW FLOW"),
            ("POCSAG1200", "flag{p4g3r_tr4ff1c_1s_n0t_pr1v4t3}"),
            ("POCSAG512",  "COLD STORE DOOR OPEN 12 MIN - TEMP RISING"),
        ]
        next_pkt = time.time() + random.uniform(0.5, 2.6)
        burst_until = 0.0
        while not self.stop_flag.is_set():
            self.retune_flag.clear()
            if self.mode == "camp":
                freq = self.camp_freq
            else:
                freq = random.choice(self.cfg["channels_mhz"])
            self.current_freq = freq

            now = time.time()
            due = now >= next_pkt
            if due:
                burst_until = now + random.uniform(0.6, 1.6)
            # fake a channel level: quiet noise floor, a burst around each packet
            base = random.gauss(-58, 1.2)
            if now < burst_until:
                base += random.uniform(16, 26)
            self._on_level(base)

            if due:
                proto, text = random.choice(msgs)
                cap = str(random.randint(100000, 2097151))
                fn = random.randint(0, 3)
                raw = (f"{proto.split('-')[0]}: Address: {cap:>8}  Function: {fn}  "
                       f"Alpha:   {text}")
                self.emit(make_record(freq, proto, cap, fn, "Alpha", text, raw,
                                      self.flag_re))
                next_pkt = now + random.uniform(0.6, 3.0)
                if random.random() < 0.15:
                    self._broadcast_state()
            time.sleep(0.1)


# --------------------------------------------------------------------------- #
# HTTP + SSE
# --------------------------------------------------------------------------- #

class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    sniffer = None

    def log_message(self, *a):
        pass

    # -- helpers -------------------------------------------------------- #
    def _send_bytes(self, body, ctype, code=200):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(body)
        except OSError:
            pass

    def _json(self, obj, code=200):
        self._send_bytes(json.dumps(obj, ensure_ascii=False).encode("utf-8"),
                         "application/json; charset=utf-8", code)

    def _file(self, rel, ctype):
        try:
            with open(os.path.join(HERE, rel), "rb") as f:
                body = f.read()
        except OSError:
            self.send_error(404)
            return
        self._send_bytes(body, ctype)

    # -- routing ------------------------------------------------------- #
    def do_GET(self):
        u = urlparse(self.path)
        if u.path in ("/", "/index.html"):
            return self._file("web/index.html", "text/html; charset=utf-8")
        if u.path == "/events":
            return self._sse()
        if u.path == "/api/state":
            return self._json(self.sniffer.state())
        if u.path == "/api/packets":
            qs = parse_qs(u.query)
            since = int((qs.get("since") or ["0"])[0])
            return self._json([r for r in list(self.sniffer.history)
                               if r["id"] > since])
        if u.path == "/api/control":
            return self._json(self.sniffer.control(parse_qs(u.query)))
        self.send_error(404)

    # -- SSE --------------------------------------------------------- #
    def _sse(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        s = self.sniffer
        q = queue.Queue(maxsize=2000)
        with s.clients_lock:
            s.clients.add(q)
        try:
            self.wfile.write(b"retry: 2000\n\n")
            self._event("state", s.state())
            for r in list(s.history)[-int(s.cfg["backlog"]):]:
                self._event("packet", r)
            last_ping = time.time()
            while not s.stop_flag.is_set():
                try:
                    item = q.get(timeout=1.0)
                    if isinstance(item, dict) and "__state__" in item:
                        self._event("state", item["__state__"])
                    elif isinstance(item, dict) and "__signal__" in item:
                        self._event("signal", item["__signal__"])
                    else:
                        self._event("packet", item)
                except queue.Empty:
                    pass
                if time.time() - last_ping >= 10:
                    self.wfile.write(b": ping\n\n")
                    self.wfile.flush()
                    self._event("state", s.state())
                    last_ping = time.time()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            with s.clients_lock:
                s.clients.discard(q)

    def _event(self, name, obj):
        data = json.dumps(obj, ensure_ascii=False)
        self.wfile.write(f"event: {name}\ndata: {data}\n\n".encode("utf-8"))
        self.wfile.flush()


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #

def load_config(path):
    cfg = dict(DEFAULT_CONFIG)
    if path and os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            user = json.load(f)
        cfg.update({k: v for k, v in user.items() if not k.startswith("_")})
    return cfg


def main():
    ap = argparse.ArgumentParser(description="RTL-SDR pager sniffer + web UI")
    ap.add_argument("--config", default=os.path.join(HERE, "config.json"))
    ap.add_argument("--mode", choices=["cycle", "camp"])
    ap.add_argument("--freq", type=float, help="camp on this MHz (implies --mode camp)")
    ap.add_argument("--dwell", type=float, help="per-channel seconds in cycle mode")
    ap.add_argument("--gain", help="tuner gain dB, or 'agc'")
    ap.add_argument("--ppm", type=int, help="frequency correction ppm")
    ap.add_argument("--device", type=int, help="rtl-sdr device index")
    ap.add_argument("--channels", help="comma list of MHz to cycle, overrides config")
    ap.add_argument("--host")
    ap.add_argument("--port", type=int)
    ap.add_argument("--simulate", action="store_true",
                    help="generate fake packets, no SDR (UI test)")
    a = ap.parse_args()

    cfg = load_config(a.config)
    if a.mode:
        cfg["mode"] = a.mode
    if a.freq is not None:
        cfg["mode"] = "camp"
        cfg["camp_freq_mhz"] = a.freq
    if a.dwell is not None:
        cfg["dwell_seconds"] = a.dwell
    if a.gain is not None:
        cfg["gain"] = None if a.gain.lower() in ("agc", "auto", "none") else a.gain
    if a.ppm is not None:
        cfg["ppm"] = a.ppm
    if a.device is not None:
        cfg["device_index"] = a.device
    if a.channels:
        cfg["channels_mhz"] = [round(float(x), 4) for x in a.channels.split(",") if x.strip()]
    if a.host:
        cfg["host"] = a.host
    if a.port:
        cfg["port"] = a.port

    s = Sniffer(cfg)
    Handler.sniffer = s

    # Make sure rtl_fm / multimon-ng never outlive us and keep the SDR locked
    # (orphaned rtl_fm is the usual cause of "usb_claim_interface error -6").
    def _cleanup():
        s.stop_flag.set()
        with s._proc_lock:
            s._kill(*s._procs)
    atexit.register(_cleanup)

    def _on_term(*_):
        _cleanup()
        raise SystemExit(0)
    signal.signal(signal.SIGTERM, _on_term)
    try:
        signal.signal(signal.SIGHUP, _on_term)
    except (AttributeError, ValueError):
        pass

    worker = threading.Thread(
        target=s.simulate_main if a.simulate else s.capture_main, daemon=True)
    worker.start()

    httpd = ThreadingHTTPServer((cfg["host"], cfg["port"]), Handler)
    httpd.daemon_threads = True
    url = f"http://{cfg['host']}:{cfg['port']}/"
    print("\n  \033[96mpager-sniffer\033[0m")
    print(f"  open        {url}")
    print(f"  mode        {cfg['mode']}")
    print(f"  channels    {cfg['channels_mhz']}")
    print(f"  dwell       {cfg['dwell_seconds']}s   gain {cfg['gain']}   ppm {cfg['ppm']}")
    print(f"  decoders    {' '.join(cfg['decoders'])}")
    if a.simulate:
        print("  \033[93m[SIMULATE]\033[0m fake packets - no SDR in use")
    print("  Ctrl-C to stop\n")
    try:
        httpd.serve_forever()
    except (KeyboardInterrupt, SystemExit):
        print("\n  stopping...")
    finally:
        _cleanup()
        httpd.shutdown()
        try:
            s.logf.close()
        except Exception:
            pass


if __name__ == "__main__":
    main()
