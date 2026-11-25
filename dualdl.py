"""
DualLink Downloader v3 - downloads one file over several network adapters at once
(e.g. USB-tether "Ethernet" + Wi-Fi) by splitting it into pieces (HTTP Range
requests) and forcing each connection out of one specific adapter.

IMPORTANT: this only goes faster if the adapters reach the internet through
independent links. If both go through the same router/ISP plan, that plan's
speed is still the ceiling. Use "Test adapters" in the Networks window to check.

Window:      python dualdl.py                (needs:  pip install psutil)
Command line (no window, least RAM):
    python dualdl.py URL OUT --ips IP1 IP2 [--primary IP1]
                     [--secondary equal|light|backup|off] [--conns 4]

Primary / other adapters:
    equal  - same number of connections as the primary
    light  - about a third of the primary's connections (saves mobile data)
    backup - idle until the primary stalls or fails, then takes over
"""
import os
import sys
import json
import time
import ssl
import socket
import struct
import threading
import collections
import re
import mimetypes
import http.client
from urllib.parse import urlsplit, urljoin

CHUNK = 4 * 1024 * 1024
BUF = 256 * 1024
UA = "DualLinkDownloader/3.0"
MAX_TRIES = 25
STALL_SECONDS = 4          # backup mode: primary this slow for this long => start secondary
STALL_BPS = 100_000        # ...slower than 100 KB/s
GIVE_UP = 8                # a helper adapter quits after this many failures in a row
IS_WIN = sys.platform == "win32"

IFINDEX = {}               # ip -> Windows interface index
_CTX = None


def load_ifindex():
    """Map every local IPv4 address to its interface index (Windows only)."""
    if not IS_WIN:
        return {}
    m = {}
    try:
        import ctypes
        size = ctypes.c_ulong(0)
        ctypes.windll.iphlpapi.GetIpAddrTable(None, ctypes.byref(size), False)
        buf = ctypes.create_string_buffer(size.value)
        if ctypes.windll.iphlpapi.GetIpAddrTable(buf, ctypes.byref(size), False) == 0:
            n = struct.unpack_from("<I", buf, 0)[0]
            for i in range(n):
                addr, idx = struct.unpack_from("<II", buf, 4 + i * 24)
                m[socket.inet_ntoa(struct.pack("<I", addr))] = idx
    except Exception:
        pass
    IFINDEX.update(m)
    return m


NOFORCE = set()


def _open(host, port, timeout, src):
    """TCP connect that leaves through the adapter that owns `src`.
    First tries to force the interface (Windows routes by destination otherwise); if that
    attempt fails, falls back to a plain bind, which works on some tethering adapters."""
    idx = IFINDEX.get(src) if (IS_WIN and src and src not in NOFORCE) else None
    if not idx:
        return _open1(host, port, timeout, src, None)
    try:
        return _open1(host, port, min(timeout, 6), src, idx)
    except OSError:
        NOFORCE.add(src)
        try:
            return _open1(host, port, timeout, src, None)
        except OSError:
            NOFORCE.discard(src)
            raise


def _open1(host, port, timeout, src, idx):
    last = None
    for fam, st, pr, _, sa in socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM):
        s = socket.socket(fam, st, pr)
        try:
            s.settimeout(timeout)
            if src:
                if idx:
                    s.setsockopt(socket.IPPROTO_IP, 31, struct.pack("!I", idx))
                s.bind((src, 0))
            try:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)
            except OSError:
                pass
            s.connect(sa)
            return s
        except OSError as e:
            s.close()
            last = e
    raise last or OSError("host not found")


def _ctx():
    global _CTX
    if _CTX is None:
        _CTX = ssl.create_default_context()
    return _CTX


class _HTTP(http.client.HTTPConnection):
    src = None

    def connect(self):
        self.sock = _open(self.host, self.port, self.timeout, self.src)


class _HTTPS(http.client.HTTPSConnection):
    src = None

    def connect(self):
        s = _open(self.host, self.port, self.timeout, self.src)
        self.sock = _ctx().wrap_socket(s, server_hostname=self.host)


def _connect(url, src_ip, timeout=15):
    p = urlsplit(url)
    c = (_HTTPS if p.scheme == "https" else _HTTP)(p.hostname, p.port, timeout=timeout)
    c.src = src_ip
    path = (p.path or "/") + ("?" + p.query if p.query else "")
    return c, path


def short_err(e):
    s = str(e) or e.__class__.__name__
    if isinstance(e, socket.timeout) or "timed out" in s:
        return "connection timed out"
    if s.startswith("HTTP 403") or s.startswith("HTTP 401"):
        return "server refused this adapter (" + s[:8] + ")"
    if "10051" in s or "10065" in s or "unreachable" in s.lower():
        return "no route to the internet on this adapter"
    if "10049" in s or "cannot assign" in s.lower():
        return "adapter address not available"
    if "gaierror" in s or "getaddrinfo" in s or "Name or service" in s:
        return "DNS lookup failed"
    return s[:80]


def safe_name(n):
    n = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", n or "").strip(" .")
    if len(n) > 100:
        base, ext = os.path.splitext(n)
        n = base[:90] + ext[:10]
    return n or "download.bin"


def better_name(cur, url, meta):
    """Pick a sensible file name: Content-Disposition > URL name > type-based fallback."""
    cd, ctype = meta
    if cd:
        m = re.search(r"filename\*=(?:UTF-8'')?([^;]+)", cd, re.I) or re.search(r'filename="?([^";]+)"?', cd, re.I)
        if m:
            from urllib.parse import unquote
            return safe_name(unquote(m.group(1).strip().strip('"')))
    base, ext = os.path.splitext(cur)
    if (not ext or len(ext) > 8 or len(base) > 60) and ctype:
        ext2 = mimetypes.guess_extension(ctype.split(";")[0].strip()) or ""
        return safe_name("download" + ext2) if len(base) > 60 or not base else safe_name(base + ext2)
    return cur


def unique_dest(dest):
    folder, name = os.path.split(dest)
    base, ext = os.path.splitext(name)
    p, i = dest, 1
    while os.path.exists(p) or os.path.exists(p + ".part"):
        p = os.path.join(folder, f"{base} ({i}){ext}")
        i += 1
    return p


def probe(url, src_ip=None):
    """Follow redirects; return (final_url, total_size or None, supports_ranges)."""
    for _ in range(8):
        conn, path = _connect(url, src_ip)
        try:
            conn.request("GET", path, headers={"Range": "bytes=0-0", "User-Agent": UA})
            r = conn.getresponse()
            if r.status in (301, 302, 303, 307, 308):
                r.read()
                url = urljoin(url, r.getheader("Location"))
                continue
            meta = (r.getheader("Content-Disposition"), r.getheader("Content-Type"))
            if r.status == 206:
                r.read()
                return url, int(r.getheader("Content-Range").split("/")[1]), True, meta
            if r.status == 200:
                cl = r.getheader("Content-Length")
                return url, int(cl) if cl else None, False, meta
            raise RuntimeError(f"HTTP {r.status} {r.reason}")
        finally:
            conn.close()
    raise RuntimeError("Too many redirects")


class Limiter:
    """Shared bandwidth cap (bytes/sec). rate=0 means unlimited."""

    def __init__(self, rate=0):
        self.rate = rate
        self.lock = threading.Lock()
        self.next = 0.0

    def take(self, n):
        r = self.rate
        if not r:
            return
        with self.lock:
            now = time.time()
            self.next = max(self.next, now - 0.25) + n / r
            wait = self.next - now
        if wait > 0:
            time.sleep(wait)


class Pieces:
    """Hands out byte ranges on demand (tiny memory use, any file size)."""

    def __init__(self, total, chunk, skip=()):
        self.total, self.chunk, self.next = total, chunk, 0
        self.skip = set(skip)
        self.retry = collections.deque()
        self.inflight = 0
        self.cv = threading.Condition()

    def get(self, cancel):
        with self.cv:
            while not cancel.is_set():
                while self.next in self.skip:
                    self.next += self.chunk
                if self.retry:
                    p = self.retry.popleft()
                elif self.next < self.total:
                    s = self.next
                    e = min(s + self.chunk, self.total) - 1
                    self.next = e + 1
                    p = (s, e, 0)
                elif self.inflight > 0:
                    self.cv.wait(0.5)
                    continue
                else:
                    return None
                self.inflight += 1
                return p
        return None

    def done(self):
        with self.cv:
            self.inflight -= 1
            self.cv.notify_all()

    def release(self, p):
        with self.cv:
            self.retry.appendleft(p)
            self.inflight -= 1
            self.cv.notify_all()

    def fail(self, p, count=True):
        with self.cv:
            self.retry.append((p[0], p[1], p[2] + (1 if count else 0)))
            self.inflight -= 1
            self.cv.notify_all()


class Download:
    def __init__(self, url, dest, ips, conns_per_ip=4, primary=None,
                 secondary_mode="equal", on_progress=None, limiter=None, on_info=None, auto_name=False, resume=False):
        self.auto_name = auto_name
        self.resume = resume
        self.done_starts = set()
        self.pausing = False
        self.single = False
        self.paused = threading.Event()
        self.base = 0
        if not IFINDEX:
            load_ifindex()
        self.limiter = limiter
        self.url, self.dest = url, dest
        self.primary = primary if primary in ips else ips[0]
        self.secondaries = [i for i in ips if i != self.primary]
        self.mode = secondary_mode
        self.conns = conns_per_ip
        self.on_progress = on_progress or (lambda *a: None)
        self.on_info = on_info or (lambda *a: None)
        self.cancel_flag = threading.Event()
        self.error = None
        self.primary_failures = 0
        self.primary_out = threading.Event()
        self.lock = threading.Lock()
        self.bytes_by_ip = {i: 0 for i in ips}
        self.err_by_ip = {}
        self.threads = []
        self.urls = {}

    def cancel(self):
        self.cancel_flag.set()

    def _worker(self, ip, pieces, part_path):
        conn = path = None
        streak = 0
        buf = bytearray(BUF)
        mv = memoryview(buf)
        try:
            with open(part_path, "r+b") as f:
                while not self.cancel_flag.is_set():
                    if ip == self.primary and self.primary_out.is_set():
                        return
                    p = pieces.get(self.cancel_flag)
                    if p is None:
                        return
                    start, end, tries = p
                    try:
                        if conn is None:
                            u = self.urls.get(ip)
                            if u is None:
                                # many sites tie the final link to the requester's IP, so each
                                # adapter must follow the redirects itself to get its own link
                                u = self.urls[ip] = probe(self.url, ip)[0]
                            conn, path = _connect(u, ip)
                        conn.request("GET", path, headers={
                            "Range": f"bytes={start}-{end}", "User-Agent": UA})
                        r = conn.getresponse()
                        if r.status != 206:
                            raise RuntimeError(f"HTTP {r.status}")
                        pos = start
                        while pos <= end and not self.cancel_flag.is_set():
                            if ip == self.primary and self.primary_out.is_set():
                                conn.close()
                                conn = None
                                pieces.release((start, end, tries))
                                return
                            n = r.readinto(mv[:min(BUF, end - pos + 1)])
                            if not n:
                                raise RuntimeError("connection closed early")
                            f.seek(pos)
                            f.write(mv[:n])
                            pos += n
                            if self.limiter:
                                self.limiter.take(n)
                            with self.lock:
                                self.bytes_by_ip[ip] += n
                            streak = 0
                            self.err_by_ip.pop(ip, None)
                        if pos <= end:
                            raise RuntimeError("cancelled")
                        with self.lock:
                            self.done_starts.add(start)
                        pieces.done()
                    except Exception as e:
                        try:
                            conn.close()
                        except Exception:
                            pass
                        conn = None
                        if self.cancel_flag.is_set():
                            pieces.done()
                            return
                        self.err_by_ip[ip] = short_err(e)
                        streak += 1
                        # server answered a ranged request with something else (throttle, expired
                        # link): fetch a fresh link next time and back off before retrying
                        if str(e).startswith("HTTP"):
                            self.urls.pop(ip, None)
                        if ip == self.primary:
                            self.primary_failures += 1
                        # a helper adapter's trouble must not kill the whole download
                        helper = ip != self.primary
                        if not helper and tries + 1 >= MAX_TRIES:
                            self.error = f"{short_err(e)} (piece at {start})"
                            self.cancel_flag.set()
                            pieces.done()
                            return
                        pieces.fail(p, count=not helper)
                        if helper and streak >= GIVE_UP:
                            return
                        time.sleep(min(1.5 * streak, 20 if str(e).startswith('HTTP') else 5))
        finally:
            if conn:
                conn.close()

    def _spawn(self, ip, n, pieces, part):
        for _ in range(n):
            t = threading.Thread(target=self._worker, args=(ip, pieces, part), daemon=True)
            t.start()
            self.threads.append(t)

    def _report(self, done, total, speeds):
        self.on_progress(done, total, speeds, dict(self.bytes_by_ip), dict(self.err_by_ip))

    def run(self):
        order = [self.primary] + self.secondaries
        last_err = None
        for ip in order:
            try:
                self.final_url, total, ranged, meta = probe(self.url, ip)
                if ip != self.primary:
                    self.primary = ip
                    self.secondaries = [i for i in order if i != ip]
                break
            except Exception as e:
                last_err = e
                self.err_by_ip[ip] = short_err(e)
        else:
            raise RuntimeError(short_err(last_err))
        if self.auto_name:
            folder, cur = os.path.split(self.dest)
            nn = better_name(cur, self.final_url, meta)
            if nn != cur:
                self.dest = unique_dest(os.path.join(folder, nn))
        self.urls[self.primary] = self.final_url
        self.on_info(total or 0, ranged, self.dest)
        part = self.dest + ".part"
        if not ranged or not total:
            return self._single(part)
        workers = 1 + (len(self.secondaries) if self.mode != "off" else 0)
        big = 32 * 1024 * 1024 if total > 2_000_000_000 else CHUNK   # fewer requests on big files
        chunk = max(256 * 1024, min(big, total // (workers * self.conns * 4)))
        st = self._load_state(part, total)
        if st:
            chunk, self.done_starts = st
        else:
            # do NOT pre-allocate: reserving a 90 GB file can stall for a very long time on Windows
            with open(part, "wb"):
                pass
        self.base = sum(min(chunk, total - s) for s in self.done_starts)
        pieces = Pieces(total, chunk, self.done_starts)

        self._spawn(self.primary, self.conns, pieces, part)
        backup_started = False
        if self.mode in ("equal", "light"):
            n = self.conns if self.mode == "equal" else max(1, self.conns // 3)
            for ip in self.secondaries:
                self._spawn(ip, n, pieces, part)
            backup_started = True

        last = dict(self.bytes_by_ip)
        t0 = time.time()
        stalled = 0.0
        while any(t.is_alive() for t in self.threads):
            time.sleep(0.25)
            now = time.time()
            with self.lock:
                cur = dict(self.bytes_by_ip)
            dt = max(now - t0, 1e-6)
            speeds = {ip: (cur[ip] - last[ip]) / dt for ip in cur}
            last, t0 = cur, now
            if self.mode == "backup" and not backup_started:
                work_left = pieces.next < total or bool(pieces.retry)
                slow = speeds[self.primary] < STALL_BPS
                stalled = stalled + dt if (slow and work_left) else 0
                if stalled >= STALL_SECONDS or self.primary_failures >= 1:
                    self.primary_out.set()
                    for ip in self.secondaries:
                        self._spawn(ip, self.conns, pieces, part)
                    backup_started = True
            self._report(self.base + sum(cur.values()), total, speeds)
        if self.pausing and not self.error:
            self._save_state(part, total, chunk)
            raise RuntimeError("paused")
        if self.error or self.cancel_flag.is_set():
            raise RuntimeError(self.error or "cancelled")
        if os.path.getsize(part) != total or self.base + sum(self.bytes_by_ip.values()) < total:
            raise RuntimeError("download incomplete")
        os.replace(part, self.dest)
        try:
            os.remove(self.dest + ".dlstate")
        except OSError:
            pass
        self._report(total, total, {ip: 0 for ip in self.bytes_by_ip})

    def _save_state(self, part, total, chunk):
        with open(self.dest + ".dlstate", "w") as f:
            json.dump({"total": total, "chunk": chunk, "done": sorted(self.done_starts)}, f)

    def _load_state(self, part, total):
        if not self.resume:
            return None
        try:
            with open(self.dest + ".dlstate") as f:
                s = json.load(f)
            if s["total"] == total and os.path.exists(part):
                return s["chunk"], set(s["done"])
        except Exception:
            pass
        return None

    def _single(self, part):
        self.single = True
        ip = self.primary
        conn, path = _connect(self.final_url, ip)
        try:
            conn.request("GET", path, headers={"User-Agent": UA})
            r = conn.getresponse()
            total = int(r.getheader("Content-Length") or 0)
            done, last, t0 = 0, 0, time.time()
            with open(part, "wb") as f:
                while not self.cancel_flag.is_set():
                    while self.paused.is_set() and not self.cancel_flag.is_set():
                        time.sleep(0.2)      # soft pause: stop reading, keep the connection open
                    data = r.read(BUF)
                    if not data:
                        break
                    f.write(data)
                    done += len(data)
                    if self.limiter:
                        self.limiter.take(len(data))
                    self.bytes_by_ip[ip] = done
                    if time.time() - t0 >= 0.25:
                        self._report(done, total, {ip: (done - last) / (time.time() - t0)})
                        last, t0 = done, time.time()
            if self.cancel_flag.is_set():
                raise RuntimeError("cancelled")
            os.replace(part, self.dest)
            self._report(done, done, {ip: 0})
        finally:
            conn.close()


def public_ip(src_ip):
    """Which public IP does the internet see for traffic leaving this adapter?"""
    if not IFINDEX:
        load_ifindex()
    c, path = _connect("https://api.ipify.org/", src_ip, 10)
    try:
        c.request("GET", path, headers={"User-Agent": UA})
        return c.getresponse().read().decode()[:40]
    finally:
        c.close()


def list_adapters():
    import psutil
    out = []
    stats = psutil.net_if_stats()
    for name, addrs in psutil.net_if_addrs().items():
        if name in stats and not stats[name].isup:
            continue
        for a in addrs:
            if a.family.name == "AF_INET" and not a.address.startswith(("127.", "169.254.")):
                out.append((name, a.address))
                break
    return out


VIRTUAL_HINTS = ("vethernet", "vmware", "virtualbox", "loopback", "wsl", "hyper-v",
                 "bluetooth", "tailscale", "zerotier", "docker", "vpn", "tap-", "npcap")


def is_virtual(name):
    n = name.lower()
    return any(h in n for h in VIRTUAL_HINTS)


def _stdio():
    """A windowed .exe has no stdin/stdout; attach the pipes the window gave us."""
    try:
        if sys.stdout is None:
            sys.stdout = open(1, "w", buffering=1, closefd=False)
        if sys.stdin is None:
            sys.stdin = open(0, "r", closefd=False)
    except Exception:
        pass


def engine_main(cfg_json):
    """Runs one download in this (separate) process; talks to the window via JSON lines."""
    _stdio()
    cfg = json.loads(cfg_json)
    out = sys.stdout
    lim = Limiter(int(cfg.get("limit") or 0))

    def emit(o):
        try:
            out.write(json.dumps(o) + "\n")
            out.flush()
        except Exception:
            pass

    d = Download(cfg["url"], cfg["dest"], cfg["ips"], cfg.get("conns", 4), cfg.get("primary"),
                 cfg.get("mode", "equal"), limiter=lim,
                 on_progress=lambda dn, tt, sp, by, er: emit(
                     {"t": "p", "done": dn, "total": tt, "speeds": sp, "bytes": by, "err": er}),
                 auto_name=cfg.get("auto", False), resume=cfg.get("resume", False),
                 on_info=lambda tt, rg, dest: emit({"t": "info", "total": tt, "ranged": rg, "dest": dest}))

    def reader():
        try:
            for line in sys.stdin:
                if line.startswith("LIMIT "):
                    lim.rate = int(float(line.split()[1]))
                elif line.startswith("PAUSE"):
                    if d.single:
                        d.paused.set()
                        emit({"t": "state", "paused": True})
                    else:
                        d.pausing = True
                        d.cancel()
                        return
                elif line.startswith("RESUME"):
                    d.paused.clear()
                    emit({"t": "state", "paused": False})
        except Exception:
            pass
        d.cancel()          # window closed or asked us to stop

    threading.Thread(target=reader, daemon=True).start()
    try:
        d.run()
        emit({"t": "end", "ok": True, "msg": ""})
    except Exception as e:
        d.cancel()
        if str(e) == "paused":
            emit({"t": "end", "ok": False, "msg": "paused"})
            return
        for ext in (".part", ".dlstate"):
            try:
                if os.path.exists(d.dest + ext):
                    os.remove(d.dest + ext)
            except OSError:
                pass
        emit({"t": "end", "ok": False, "msg": short_err(e) if str(e) != "cancelled" else "cancelled"})


def torrent_main(cfg_json):
    """Magnet-link download with libtorrent, using every selected adapter."""
    _stdio()
    cfg = json.loads(cfg_json)

    def emit(o):
        try:
            sys.stdout.write(json.dumps(o) + "\n")
            sys.stdout.flush()
        except Exception:
            pass
    try:
        import libtorrent as lt
    except Exception:
        emit({"t": "end", "ok": False, "msg": "Torrent support missing. Run:  py -m pip install libtorrent"})
        return
    stop = threading.Event()
    box = {"pause": None, "limit": None}

    def reader():
        try:
            for line in sys.stdin:
                if line.startswith("PAUSE"):
                    box["pause"] = True
                elif line.startswith("RESUME"):
                    box["pause"] = False
                elif line.startswith("LIMIT "):
                    box["limit"] = int(float(line.split()[1]))
        except Exception:
            pass
        stop.set()
    threading.Thread(target=reader, daemon=True).start()
    try:
        ips = cfg.get("ips") or []
        sett = {"listen_interfaces": "0.0.0.0:6881",
                "download_rate_limit": int(cfg.get("limit") or 0),
                "alert_mask": 0}
        if ips:
            sett["outgoing_interfaces"] = ",".join(ips)
        ses = lt.session(sett)
        p = lt.parse_magnet_uri(cfg["url"])
        p.save_path = cfg["folder"]
        h = ses.add_torrent(p)
        if cfg.get("seq"):
            h.set_sequential_download(True)
        sent = False
        while not stop.is_set():
            if box["pause"] is not None:
                if box["pause"]:
                    h.pause()
                else:
                    h.resume()
                emit({"t": "state", "paused": box["pause"]})
                box["pause"] = None
            if box["limit"] is not None:
                ses.apply_settings({"download_rate_limit": box["limit"]})
                box["limit"] = None
            st = h.status()
            if not sent and st.has_metadata:
                sent = True
                emit({"t": "info", "total": st.total_wanted, "ranged": True,
                      "dest": os.path.join(cfg["folder"], st.name)})
            emit({"t": "p", "done": st.total_wanted_done, "total": st.total_wanted,
                  "speeds": {"all": float(st.download_rate)}, "bytes": {"all": st.total_wanted_done},
                  "err": {}, "peers": st.num_peers})
            if st.has_metadata and st.is_finished:
                ses.remove_torrent(h)
                emit({"t": "end", "ok": True, "msg": ""})
                return
            time.sleep(0.5)
        ses.remove_torrent(h, lt.options_t.delete_files)
        emit({"t": "end", "ok": False, "msg": "cancelled"})
    except Exception as e:
        emit({"t": "end", "ok": False, "msg": str(e)[:100]})


def diag(url, ips):
    """py dualdl.py --diag URL IP1 IP2 : shows exactly what happens on each adapter."""
    load_ifindex()
    print("Interface ids:", {i: IFINDEX.get(i) for i in ips})
    for ip in ips:
        for label, force in (("forced route", True), ("plain bind  ", False)):
            if force:
                NOFORCE.discard(ip)
            else:
                NOFORCE.add(ip)
            t0 = time.time()
            try:
                if force:
                    # no silent fallback in this test: use the forced route only
                    NOFORCE.discard(ip)
                fin, total, ranged, meta = probe(url, ip)
                t1 = time.time() - t0
                conn, path = _connect(fin, ip, 20)
                conn.request("GET", path, headers={"Range": "bytes=0-4999999", "User-Agent": UA})
                r = conn.getresponse()
                n, t2 = 0, time.time()
                while n < 5_000_000 and time.time() - t2 < 8:
                    b = r.read(65536)
                    if not b:
                        break
                    n += len(b)
                dt = max(time.time() - t2, 1e-3)
                print(f"{ip:16} {label}: probe ok {t1:.1f}s (ranged={ranged}) | GET HTTP {r.status} | "
                      f"{n / 1e6:.2f} MB in {dt:.1f}s = {n / dt / 1e6:.2f} MB/s")
                conn.close()
            except Exception as ex:
                print(f"{ip:16} {label}: FAILED after {time.time() - t0:.1f}s -> {type(ex).__name__}: {ex}")
            sys.stdout.flush()
    print("Done.")


def main_cli():
    import argparse
    ap = argparse.ArgumentParser(description="DualLink Downloader (command-line mode)")
    ap.add_argument("url")
    ap.add_argument("out")
    ap.add_argument("--ips", nargs="+", required=True)
    ap.add_argument("--primary")
    ap.add_argument("--secondary", choices=["equal", "light", "backup", "off"], default="equal")
    ap.add_argument("--conns", type=int, default=4)
    a = ap.parse_args()
    d = Download(a.url, a.out, a.ips, a.conns, a.primary, a.secondary,
                 on_progress=lambda dn, tt, sp, by, er: print(
                     f"\r{dn / 1e6:.1f}/{tt / 1e6:.1f} MB  " +
                     "  ".join(f"{i}: {s / 1e6:.2f} MB/s" for i, s in sp.items()) +
                     ("  !! " + "; ".join(f"{i}: {m}" for i, m in er.items()) if er else "") + "    ",
                     end="", flush=True))
    d.run()
    print("\nDone:", a.out)


# Engine / command-line modes return here, BEFORE tkinter is imported (saves RAM).
if __name__ == "__main__" and len(sys.argv) > 1:
    if sys.argv[1] == "--engine":
        engine_main(sys.argv[2])
    elif sys.argv[1] == "--diag":
        diag(sys.argv[2], sys.argv[3:])
    elif sys.argv[1] == "--torrent":
        torrent_main(sys.argv[2])
    else:
        main_cli()
    sys.exit(0)

# ======================= GUI =======================
import re
import math
import base64
import zlib
import shutil
import subprocess
import tkinter as tk
import tkinter.font as tkfont
from tkinter import filedialog
from urllib.parse import unquote

APP_NAME = "Twinflow"
ICON_B64 = "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"

THEMES = {
    "dark": dict(bg="#071012", card="#0d1b1e", card2="#13282c", line="#1a3a40", text="#e9f7f5",
                 muted="#78a0a1", accent="#18d4b0", accent2="#1fb2ea", accent_text="#02201c",
                 danger="#ff6b7a", warn="#f4c25b", ok="#34e0a1", track="#16323a", dark=True),
    "light": dict(bg="#eef6f5", card="#ffffff", card2="#e3f1ef", line="#cfe4e1", text="#0b2a2d",
                  muted="#5b8284", accent="#0fb59a", accent2="#1594c9", accent_text="#ffffff",
                  danger="#d6455d", warn="#b27a00", ok="#12a373", track="#d6e9e6", dark=False),
}
THEMES["midnight"] = dict(bg="#090b14", card="#10141f", card2="#192033", line="#252d45", text="#e8ecf8",
                          muted="#7f8bab", accent="#18d4b0", accent2="#1fb2ea", accent_text="#02201c",
                          danger="#ff6b7a", warn="#f4c25b", ok="#34e0a1", track="#1c2438", dark=True)
THEMES["amoled"] = dict(bg="#000000", card="#0b0b0d", card2="#151518", line="#232327", text="#f2f2f4",
                        muted="#8a8a92", accent="#18d4b0", accent2="#1fb2ea", accent_text="#02201c",
                        danger="#ff6b7a", warn="#f4c25b", ok="#34e0a1", track="#1a1a1e", dark=True)
THEME_NAMES = [("dark", "Dark"), ("light", "Light"), ("midnight", "Midnight"), ("amoled", "AMOLED")]
# key: (name, colour 1, colour 2). The two colours also tell your adapters apart, so they differ in hue.
ACCENTS = {
    "teal": ("Teal", "#18d4b0", "#1fb2ea"),
    "ember": ("Ember Orange", "#f2704a", "#fbbf24"),
    "sky": ("Sky Blue", "#38bdf8", "#818cf8"),
    "mint": ("Cyber Mint", "#10b981", "#38bdf8"),
    "violet": ("Electric Violet", "#a855f7", "#38bdf8"),
    "ruby": ("Crimson Ruby", "#f43f5e", "#fb923c"),
    "titanium": ("Titanium", "#e2e8f0", "#64748b"),
}
SEG_KEYS = ["accent", "accent2", "warn", "ok"]

DEFAULTS = dict(folder=os.path.join(os.path.expanduser("~"), "Downloads"), conns=16, ver=2,
                max_active=2, limit_mb=0, units="MB/s", theme="dark", accent="teal", custom="#ff6a3d", mode="equal",
                primary=None, use=None)
MODES = [("equal", "Equal share"), ("light", "Light help"), ("backup", "Backup only")]
MODE_HELP = {
    "equal": "Other adapters get the same number of connections as the primary.",
    "light": "Other adapters get about a third of the primary's connections (saves data).",
    "backup": "Other adapters stay idle until the primary stalls or fails.",
}

S = 1.0


def valid_hex(h):
    h = (h or "").strip()
    if re.fullmatch(r"#?[0-9a-fA-F]{6}", h):
        return "#" + h.lstrip("#").lower()
    return None


def hue_shift(h, deg):
    import colorsys
    r, g_, b = [x / 255 for x in rgb(h)]
    hh, ll, ss = colorsys.rgb_to_hls(r, g_, b)
    r, g_, b = colorsys.hls_to_rgb((hh + deg / 360.0) % 1.0, ll, ss)
    return "#%02x%02x%02x" % (int(r * 255), int(g_ * 255), int(b * 255))


def lum(h):
    r, g_, b = rgb(h)
    return (0.299 * r + 0.587 * g_ + 0.114 * b) / 255


def accent_pair(cfg):
    if cfg.get("accent") == "custom":
        c1 = valid_hex(cfg.get("custom")) or "#ff6a3d"
        return c1, hue_shift(c1, 45)
    a = ACCENTS.get(cfg.get("accent"), ACCENTS["teal"])
    return a[1], a[2]


def palette(cfg):
    p = dict(THEMES.get(cfg.get("theme"), THEMES["dark"]))
    c1, c2 = accent_pair(cfg)
    if not p["dark"]:
        c1, c2 = mix(c1, "#000000", .12), mix(c2, "#000000", .12)
    p.update(accent=c1, accent2=c2, accent_text="#06121a" if lum(c1) > 0.62 else "#ffffff")
    return p


def sc(v):
    return int(round(v * S))


def cfg_path():
    base = os.environ.get("APPDATA") or os.path.join(os.path.expanduser("~"), ".config")
    d = os.path.join(base, "DualLink")
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, "settings.json")


def load_cfg():
    c = dict(DEFAULTS)
    try:
        with open(cfg_path()) as f:
            c.update(json.load(f))
    except Exception:
        pass
    if c.get("ver", 1) < 2:          # older settings files saved 4 connections: too few for fast links
        c["conns"], c["ver"] = max(16, c.get("conns", 16)), 2
    return c


def save_cfg(c):
    try:
        with open(cfg_path(), "w") as f:
            json.dump(c, f, indent=1)
    except Exception:
        pass


def human(n):
    n = float(n)
    for u in ("B", "KB", "MB", "GB", "TB"):
        if n < 1000 or u == "TB":
            return f"{n:.0f} {u}" if u == "B" else f"{n:.1f} {u}"
        n /= 1000


def spd(bps, units):
    return (bps * 8 / 1e6, "Mbps") if units == "Mbps" else (bps / 1e6, "MB/s")


def fmt_speed(bps, units):
    v, u = spd(bps, units)
    return f"{v:.1f} {u}"


def fmt_dur(sec):
    sec = int(sec)
    if sec >= 3600:
        return f"{sec // 3600}:{sec % 3600 // 60:02d}:{sec % 60:02d}"
    return f"{sec // 60}:{sec % 60:02d}"


def fmt_eta(sec):
    sec = int(sec)
    if sec < 60:
        return f"{sec}s left"
    if sec < 3600:
        return f"{sec // 60}m {sec % 60:02d}s left"
    if sec < 86400:
        return f"{sec // 3600}h {sec % 3600 // 60:02d}m left"
    return f"{sec // 86400}d {sec % 86400 // 3600}h left"


def name_from_url(url):
    return safe_name(unquote(urlsplit(url).path.rsplit("/", 1)[-1]))


def unique_path(folder, name):
    base, ext = os.path.splitext(name)
    p, i = os.path.join(folder, name), 1
    while os.path.exists(p) or os.path.exists(p + ".part"):
        p = os.path.join(folder, f"{base} ({i}){ext}")
        i += 1
    return p


# ---------- colour + image helpers (pure Python: no Pillow needed, no extra RAM) ----------
def rgb(h):
    h = h.lstrip("#")
    return int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)


def mix(a, b, t):
    ra, rb = rgb(a), rgb(b)
    return "#%02x%02x%02x" % tuple(int(round(ra[i] + (rb[i] - ra[i]) * t)) for i in range(3))


_IMG = {}
_COV = {}


def _png(w, h, rows):
    raw = b"".join(b"\x00" + r for r in rows)

    def ch(t, d):
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xffffffff)
    return (b"\x89PNG\r\n\x1a\n" + ch(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 6, 0, 0, 0)) +
            ch(b"IDAT", zlib.compress(raw, 1)) + ch(b"IEND", b""))


def _photo(key, w, h, rows):
    im = tk.PhotoImage(data=base64.b64encode(_png(w, h, rows)))
    _IMG[key] = im
    return im


def _corner_cov(r):
    if r in _COV:
        return _COV[r]
    rows = []
    for y in range(r):
        row = []
        for x in range(r):
            c = 0
            for sy in range(4):
                for sx in range(4):
                    px, py = x + (sx + .5) / 4, y + (sy + .5) / 4
                    if (px - r) ** 2 + (py - r) ** 2 <= r * r:
                        c += 1
            row.append(c / 16.0)
        rows.append(row)
    _COV[r] = rows
    return rows


def corner(r, color, pos, inverse=False):
    """r x r anti-aliased quarter circle. pos: tl tr bl br. inverse = the part OUTSIDE the arc."""
    key = ("c", r, color, pos, inverse)
    if key in _IMG:
        return _IMG[key]
    cov = _corner_cov(r)
    cr, cg, cb = rgb(color)
    rows = []
    for y in range(r):
        yy = y if pos[0] == "t" else r - 1 - y
        row = bytearray()
        for x in range(r):
            xx = x if pos[1] == "l" else r - 1 - x
            a = cov[yy][xx]
            a = 1 - a if inverse else a
            row += bytes((cr, cg, cb, int(a * 255 + .5)))
        rows.append(bytes(row))
    return _photo(key, r, r, rows)


def rr_img(w, h, r, fill, fill2=None, border=None):
    """Whole anti-aliased rounded rectangle (solid, or horizontal gradient fill->fill2)."""
    key = ("rr", w, h, r, fill, fill2, border)
    if key in _IMG:
        return _IMG[key]
    r = max(1, min(r, w // 2, h // 2))
    cov = _corner_cov(r)
    inner_r = max(1, r - 1)
    icov = _corner_cov(inner_r) if border else None
    f1, f2 = rgb(fill), rgb(fill2 or fill)
    bc = rgb(border) if border else None
    cols = []
    for x in range(w):
        t = x / max(1, w - 1)
        cols.append(tuple(f1[i] + (f2[i] - f1[i]) * t for i in range(3)))
    rows = []
    for y in range(h):
        row = bytearray()
        for x in range(w):
            ox = x if x < r else (w - 1 - x if x >= w - r else r)
            oy = y if y < r else (h - 1 - y if y >= h - r else r)
            a = cov[oy][ox] if (ox < r and oy < r) else 1.0
            c = cols[x]
            if border:
                ix, iy = x - 1, y - 1
                iw, ih = w - 2, h - 2
                if ix < 0 or iy < 0 or ix >= iw or iy >= ih:
                    k = 0.0
                else:
                    jx = ix if ix < inner_r else (iw - 1 - ix if ix >= iw - inner_r else inner_r)
                    jy = iy if iy < inner_r else (ih - 1 - iy if iy >= ih - inner_r else inner_r)
                    k = icov[jy][jx] if (jx < inner_r and jy < inner_r) else 1.0
                c = tuple(bc[i] + (c[i] - bc[i]) * k for i in range(3))
            row += bytes((int(c[0] + .5), int(c[1] + .5), int(c[2] + .5), int(a * 255 + .5)))
        rows.append(bytes(row))
    return _photo(key, w, h, rows)


def card(c, x1, y1, x2, y2, r, color, tag):
    """Rounded card made of 2 rectangles + 4 AA corner images (cheap to draw and move)."""
    x1, y1, x2, y2 = int(x1), int(y1), int(x2), int(y2)
    ids = [c.create_rectangle(x1 + r, y1, x2 - r, y2, fill=color, width=0, tags=tag),
           c.create_rectangle(x1, y1 + r, x2, y2 - r, fill=color, width=0, tags=tag)]
    for pos, (x, y, a) in {"tl": (x1, y1, "nw"), "tr": (x2, y1, "ne"),
                           "bl": (x1, y2, "sw"), "br": (x2, y2, "se")}.items():
        ids.append(c.create_image(x, y, image=corner(r, color, pos), anchor=a, tags=tag))
    return ids


def clip(font, s, w):
    if font.measure(s) <= w:
        return s
    while s and font.measure(s + "...") > w:
        s = s[:-1]
    return s + "..."


def merge_glyph(c, cx, cy, size, color, width, tag=None):
    """Logo glyph: two streams curving into one."""
    u = size / 2.0
    kw = dict(fill=color, width=width, capstyle="round", joinstyle="round", tags=tag)
    for s in (-1, 1):
        c.create_line(cx + s * .5 * u, cy - .72 * u, cx + s * .5 * u, cy - .3 * u, cx, cy - .02 * u,
                      cx, cy + .12 * u, smooth=True, splinesteps=24, **kw)
        r = width * .95
        c.create_oval(cx + s * .5 * u - r, cy - .72 * u - r, cx + s * .5 * u + r, cy - .72 * u + r,
                      fill=color, width=0, tags=tag)
    c.create_line(cx, cy + .05 * u, cx, cy + .6 * u, **kw)
    c.create_line(cx - .32 * u, cy + .3 * u, cx, cy + .62 * u, cx + .32 * u, cy + .3 * u, **kw)
    c.create_line(cx - .42 * u, cy + .95 * u, cx + .42 * u, cy + .95 * u, **kw)


def dark_titlebar(win, P):
    if not IS_WIN:
        return
    try:
        import ctypes
        win.update_idletasks()
        hwnd = ctypes.windll.user32.GetParent(win.winfo_id())
        dw = ctypes.windll.dwmapi.DwmSetWindowAttribute

        def setattr_(a, v):
            x = ctypes.c_int(v)
            dw(hwnd, a, ctypes.byref(x), 4)
        setattr_(20, 1 if P["dark"] else 0)
        r, g, b = rgb(P["bg"])
        setattr_(35, r | g << 8 | b << 16)
        r, g, b = rgb(P["text"])
        setattr_(36, r | g << 8 | b << 16)
    except Exception:
        pass


# ---------- widgets ----------
class Btn(tk.Canvas):
    """Rounded button. kind: accent (gradient) | ghost | danger."""

    def __init__(self, parent, text, cmd, P, F, kind="ghost", w=None, h=36, bg=None, dot=None):
        h = sc(h)
        pad = sc(18)
        tw = F.measure(text)
        w = sc(w) if w else tw + pad * 2 + (sc(16) if dot else 0)
        super().__init__(parent, width=w, height=h, bg=bg or P["bg"], highlightthickness=0, bd=0,
                         cursor="hand2")
        r = h // 2 if kind == "accent" else sc(10)
        if kind == "accent":
            n, hv = ((P["accent"], P["accent2"]), (mix(P["accent"], "#ffffff", .16), mix(P["accent2"], "#ffffff", .16)))
            tc = P["accent_text"]
        elif kind == "danger":
            n = (mix(P["danger"], P["bg"], .82),) * 2
            hv = (mix(P["danger"], P["bg"], .68),) * 2
            tc = P["danger"]
        else:
            n, hv, tc = (P["card2"],) * 2, (P["line"],) * 2, P["text"]
        self._n, self._h = rr_img(w, h, r, n[0], n[1]), rr_img(w, h, r, hv[0], hv[1])
        self._bg = self.create_image(0, 0, image=self._n, anchor="nw")
        x = w // 2
        if dot:
            self.create_oval(pad - 2, h // 2 - sc(4), pad - 2 + sc(8), h // 2 + sc(4), fill=dot, width=0)
            x = (w + sc(16)) // 2
        self.txt = self.create_text(x, h // 2, text=text, fill=tc, font=F)
        self.bind("<Enter>", lambda e: self.itemconfigure(self._bg, image=self._h))
        self.bind("<Leave>", lambda e: self.itemconfigure(self._bg, image=self._n))
        self.bind("<Button-1>", lambda e: cmd())


class Field(tk.Canvas):
    def __init__(self, parent, var, P, F, w, bg, h=38, show=None):
        w, h = sc(w), sc(h)
        super().__init__(parent, width=w, height=h, bg=bg, highlightthickness=0, bd=0)
        self._i0 = rr_img(w, h, sc(10), P["card2"], border=P["line"])
        self._i1 = rr_img(w, h, sc(10), P["card2"], border=P["accent"])
        self._bg = self.create_image(0, 0, image=self._i0, anchor="nw")
        self.entry = tk.Entry(self, textvariable=var, bd=0, highlightthickness=0, relief="flat",
                              bg=P["card2"], fg=P["text"], insertbackground=P["accent"],
                              selectbackground=P["accent"], selectforeground=P["accent_text"],
                              font=F, show=show)
        self.create_window(sc(12), h // 2, window=self.entry, anchor="w", width=w - sc(24))
        self.entry.bind("<FocusIn>", lambda e: self.itemconfigure(self._bg, image=self._i1))
        self.entry.bind("<FocusOut>", lambda e: self.itemconfigure(self._bg, image=self._i0))


class Area(tk.Canvas):
    """Multi-line text box with the same rounded look as Field."""

    def __init__(self, parent, P, F, w, bg, lines=3):
        w = sc(w)
        h = F.metrics("linespace") * lines + sc(20)
        super().__init__(parent, width=w, height=h, bg=bg, highlightthickness=0, bd=0)
        self._i0 = rr_img(w, h, sc(10), P["card2"], border=P["line"])
        self._i1 = rr_img(w, h, sc(10), P["card2"], border=P["accent"])
        self._bg = self.create_image(0, 0, image=self._i0, anchor="nw")
        self.text = tk.Text(self, bd=0, highlightthickness=0, relief="flat", bg=P["card2"], fg=P["text"],
                            insertbackground=P["accent"], selectbackground=P["accent"],
                            selectforeground=P["accent_text"], font=F, wrap="none", height=lines, undo=True)
        self.create_window(sc(12), sc(10), window=self.text, anchor="nw", width=w - sc(24),
                           height=h - sc(20))
        self.text.bind("<FocusIn>", lambda e: self.itemconfigure(self._bg, image=self._i1))
        self.text.bind("<FocusOut>", lambda e: self.itemconfigure(self._bg, image=self._i0))

    def get(self):
        return self.text.get("1.0", "end")


class Check(tk.Canvas):
    def __init__(self, parent, var, P, bg, cmd=None):
        s = sc(22)
        super().__init__(parent, width=s, height=s, bg=bg, highlightthickness=0, bd=0, cursor="hand2")
        self.var, self.P, self.cmd, self.s = var, P, cmd, s
        self._off = rr_img(s, s, sc(7), P["card2"], border=P["line"])
        self._on = rr_img(s, s, sc(7), P["accent"], P["accent2"])
        self.bind("<Button-1>", self.toggle)
        self.draw()

    def toggle(self, e=None):
        self.var.set(not self.var.get())
        self.draw()
        if self.cmd:
            self.cmd()

    def draw(self):
        self.delete("all")
        on = self.var.get()
        self.create_image(0, 0, image=self._on if on else self._off, anchor="nw")
        if on:
            s = self.s
            self.create_line(s * .27, s * .52, s * .43, s * .68, s * .74, s * .32,
                             fill=self.P["accent_text"], width=max(2, sc(2)), capstyle="round",
                             joinstyle="round")


class Seg(tk.Canvas):
    """Segmented control."""

    def __init__(self, parent, options, var, P, F, w, bg, cmd=None, h=36):
        w, h = sc(w), sc(h)
        super().__init__(parent, width=w, height=h, bg=bg, highlightthickness=0, bd=0, cursor="hand2")
        self.opts, self.var, self.P, self.F, self.cmd, self.w, self.h = options, var, P, F, cmd, w, h
        self.track = rr_img(w, h, sc(10), P["card2"])
        self.bind("<Button-1>", self.click)
        self.draw()

    def click(self, e):
        i = min(len(self.opts) - 1, int(e.x / (self.w / len(self.opts))))
        self.var.set(self.opts[i][0])
        self.draw()
        if self.cmd:
            self.cmd()

    def draw(self):
        self.delete("all")
        self.create_image(0, 0, image=self.track, anchor="nw")
        n = len(self.opts)
        sw = self.w / n
        for i, (val, label) in enumerate(self.opts):
            on = self.var.get() == val
            if on:
                x1 = int(i * sw) + sc(3)
                tw = int(sw) - sc(6)
                self.create_image(x1, sc(3), image=rr_img(tw, self.h - sc(6), sc(8), self.P["accent"],
                                                          self.P["accent2"]), anchor="nw")
            self.create_text(i * sw + sw / 2, self.h / 2, text=label, font=self.F,
                             fill=self.P["accent_text"] if on else self.P["muted"])


class Swatches(tk.Canvas):
    """Grid of colour tiles: a circle with its name underneath."""

    def __init__(self, parent, items, var, P, F, w, bg, cols=4):
        gap = sc(10)
        w = sc(w)
        self.tw = (w - gap * (cols - 1)) // cols
        self.th = sc(92)
        rows = (len(items) + cols - 1) // cols
        super().__init__(parent, width=w, height=rows * self.th + (rows - 1) * gap, bg=bg,
                         highlightthickness=0, bd=0, cursor="hand2")
        self.items, self.var, self.P, self.F, self.cols, self.gap = items, var, P, F, cols, gap
        self.bind("<Button-1>", self.click)
        self.draw()

    def pos(self, i):
        return (i % self.cols) * (self.tw + self.gap), (i // self.cols) * (self.th + self.gap)

    def click(self, e):
        for i, (key, _, _) in enumerate(self.items):
            x, y = self.pos(i)
            if x <= e.x <= x + self.tw and y <= e.y <= y + self.th:
                self.var.set(key)
                self.draw()
                return

    def set_color(self, key, color):
        self.items = [(k, n, color if k == key else c) for k, n, c in self.items]
        self.draw()

    def draw(self):
        self.delete("all")
        P = self.P
        for i, (key, name, color) in enumerate(self.items):
            x, y = self.pos(i)
            on = self.var.get() == key
            self.create_image(x, y, image=rr_img(self.tw, self.th, sc(14), P["card2"],
                                                 border=color if on else P["line"]), anchor="nw")
            cx, cy, r = x + self.tw / 2, y + sc(32), sc(18)
            self.create_image(int(cx - r), int(cy - r), image=rr_img(2 * r, 2 * r, r, color), anchor="nw")
            if on:
                s = sc(7)
                tc = "#06121a" if lum(color) > 0.62 else "#ffffff"
                self.create_line(cx - s, cy, cx - s * .25, cy + s * .75, cx + s, cy - s * .6, fill=tc,
                                 width=max(2, sc(2)), capstyle="round", joinstyle="round")
            self.create_text(x + self.tw / 2, y + sc(66), text=name, fill=P["text"] if on else P["muted"],
                             font=self.F, width=self.tw - sc(10), justify="center")


class Stepper(tk.Frame):
    def __init__(self, parent, var, lo, hi, P, F, bg, fmt=None, step=1):
        super().__init__(parent, bg=bg)
        self.var, self.lo, self.hi, self.step, self.fmt = var, lo, hi, step, fmt or str
        Btn(self, "-", lambda: self.bump(-self.step), P, F, w=36, h=34, bg=bg).pack(side="left")
        self.lbl = tk.Label(self, bg=bg, fg=P["text"], font=F, width=8)
        self.lbl.pack(side="left")
        Btn(self, "+", lambda: self.bump(self.step), P, F, w=36, h=34, bg=bg).pack(side="left")
        self.show()

    def bump(self, d):
        self.var.set(max(self.lo, min(self.hi, self.var.get() + d)))
        self.show()

    def show(self):
        self.lbl.config(text=self.fmt(self.var.get()))


TILE = {"video": ("mp4 mkv avi mov webm m4v", "accent2"), "archive": ("zip rar 7z iso gz tar xz", "warn"),
        "app": ("exe msi apk dmg", "danger"), "audio": ("mp3 flac wav m4a ogg", "ok")}


def tile_color(name):
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    for _, (exts, key) in TILE.items():
        if ext in exts.split():
            return key
    return "accent"


class Item:
    _n = 0

    def __init__(self, url, dest, ips, primary, mode, conns):
        Item._n += 1
        self.id = Item._n
        self.url, self.dest, self.ips, self.primary = url, dest, ips, primary   # ips: {ip: name}
        self.mode, self.conns = mode, conns
        self.kind = "torrent" if url.startswith("magnet:") else "http"
        self.eips = list(ips)       # adapters handed to the engine
        self.seq = False
        self.can_pause = self.kind == "torrent"
        self.resume = False
        self.pausing = False
        self.single = False
        self.name = os.path.basename(dest)
        self.state = "queued"       # queued running done error
        self.total = self.done = 0
        self.speeds = {ip: 0.0 for ip in ips}
        self.bytes = {ip: 0 for ip in ips}
        self.err = {}
        self.msg = ""
        self.proc = None
        self.t0 = 0
        self.ema = 0.0
        self.peak = 0.0             # fastest speed seen
        self.sbytes = 0.0           # bytes moved this session (for the average)
        self.act_s = 0.0            # seconds actually receiving data
        self.idle_s = 0.0           # seconds running/paused without data
        self.shown = 0.0            # eased progress fraction

    @property
    def speed(self):
        return sum(self.speeds.values())


class App:
    def __init__(self):
        global S
        try:
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass
        self.root = tk.Tk()
        self.root.withdraw()
        S = max(1.0, self.root.winfo_fpixels("1i") / 96.0)
        self.cfg = load_cfg()
        self.items = []
        self.adapters = []              # [(name, ip)]
        self.ifready = threading.Event()
        self._scan = None
        self.samples = collections.deque(maxlen=200)    # (t, {ip: bps})
        self.disp_total = 0.0
        self.ymax = 1e6
        self.scroll_t = self.scroll_c = 0.0
        self.relayout_job = None
        self.dlg = None
        self.last_cfg = 0.0
        self.last_stat = time.time()
        self.st_peak = self.st_bytes = self.st_act = self.st_idle = 0.0
        self.tick = 0
        self.hdt = 0.0
        self.last = time.time()
        self.last_sample = 0
        self.root.title(APP_NAME)
        try:
            self.root.iconphoto(True, tk.PhotoImage(data=ICON_B64))
        except Exception:
            pass
        self.root.minsize(sc(860), sc(600))
        self.root.geometry(f"{sc(1020)}x{sc(720)}")
        threading.Thread(target=self.scanner, daemon=True).start()
        self.build()
        self.root.protocol("WM_DELETE_WINDOW", self.quit)
        self.root.deiconify()
        dark_titlebar(self.root, self.P)
        self.loop()

    # ---------- background adapter scan ----------
    def scanner(self):
        while True:
            try:
                ad = [(n, ip) for n, ip in list_adapters()]
                load_ifindex()
                self._scan = ad
                self.ifready.set()
            except Exception:
                self.ifready.set()
            time.sleep(5)

    # ---------- fonts / palette ----------
    def fonts(self):
        fam = "Segoe UI"
        have = set(tkfont.families())
        for f in ("Segoe UI Variable Text", "Segoe UI", "Inter", "Helvetica Neue", "DejaVu Sans"):
            if f in have:
                fam = f
                break

        def mk(px, bold=False):
            return tkfont.Font(family=fam, size=-sc(px), weight="bold" if bold else "normal")
        self.F = dict(huge=mk(54, True), title=mk(20, True), h=mk(15, True), b=mk(13), bb=mk(13, True),
                      s=mk(12), sb=mk(12, True), xs=mk(11), tag=mk(10, True))

    def build(self):
        for w in self.root.winfo_children():
            w.destroy()
        self.P = P = palette(self.cfg)
        self.fonts()
        self.root.configure(bg=P["bg"])
        dark_titlebar(self.root, P)
        pad = sc(26)
        self.main = tk.Frame(self.root, bg=P["bg"])
        self.main.pack(fill="both", expand=True, padx=pad, pady=(sc(18), sc(14)))
        # header
        hd = tk.Frame(self.main, bg=P["bg"])
        hd.pack(fill="x")
        logo = tk.Canvas(hd, width=sc(42), height=sc(42), bg=P["bg"], highlightthickness=0)
        logo.create_image(0, 0, image=rr_img(sc(42), sc(42), sc(13), P["accent"], P["accent2"]), anchor="nw")
        merge_glyph(logo, sc(21), sc(21), sc(22), P["accent_text"], max(2, sc(2.4)))
        logo.pack(side="left")
        tx = tk.Frame(hd, bg=P["bg"])
        tx.pack(side="left", padx=(sc(12), 0))
        tk.Label(tx, text=APP_NAME, bg=P["bg"], fg=P["text"], font=self.F["title"]).pack(anchor="w")
        tk.Label(tx, text="Two connections. One fast download.", bg=P["bg"], fg=P["muted"], font=self.F["xs"]).pack(anchor="w")
        Btn(hd, "New download", self.new_download, P, self.F["bb"], kind="accent", h=40).pack(side="right")
        Btn(hd, "Settings", self.settings, P, self.F["b"], h=40).pack(side="right", padx=(0, sc(10)))
        self.pa_btn = Btn(hd, "Pause all", self.pause_all, P, self.F["b"], h=40, w=112)
        self.pa_btn.pack(side="right", padx=(0, sc(10)))
        self.pa_lbl = "Pause all"
        self.net_btn = Btn(hd, "Networks", self.network, P, self.F["b"], h=40, dot=P["ok"])
        self.net_btn.pack(side="right", padx=(0, sc(10)))
        # hero + list
        self.hero = tk.Canvas(self.main, height=sc(262), bg=P["bg"], highlightthickness=0, bd=0)
        self.hero.pack(fill="x", pady=(sc(18), 0))
        self.lc = tk.Canvas(self.main, bg=P["bg"], highlightthickness=0, bd=0)
        self.lc.pack(fill="both", expand=True, pady=(sc(8), 0))
        self.hero.bind("<Configure>", lambda e: self.schedule_hero())
        self.lc.bind("<Configure>", lambda e: self.schedule_layout())
        self.root.bind("<Configure>", self.on_cfg)
        self.root.bind_all("<MouseWheel>", self.wheel)
        self.root.bind_all("<Button-4>", lambda e: self.wheel(e, 120))
        self.root.bind_all("<Button-5>", lambda e: self.wheel(e, -120))
        self.root.bind("<Control-n>", lambda e: self.new_download())
        self.root.bind("<Control-v>", lambda e: self.paste_start())
        self.hero_layout()
        self.layout()

    def adapter_color(self, ip):
        ips = [ip_ for _, ip_ in self.adapters]
        k = ips.index(ip) if ip in ips else 0
        return self.P[SEG_KEYS[k % 4]]

    def adapter_name(self, ip):
        for n, i in self.adapters:
            if i == ip:
                return n
        return ip

    def selected(self):
        """Adapters the user wants to use: [(name, ip)]"""
        use = self.cfg.get("use")
        ad = [a for a in self.adapters if (a[0] in use if use is not None else not is_virtual(a[0]))]
        return ad or self.adapters

    def primary_ip(self):
        sel = self.selected()
        for n, ip in sel:
            if n == self.cfg.get("primary"):
                return ip
        return sel[0][1] if sel else None

    # ---------- hero ----------
    def hero_layout(self):
        c, P = self.hero, self.P
        c.delete("all")
        W = c.winfo_width()
        if W < 50:
            return
        H = sc(262)
        self.hW = W
        card(c, 0, 0, W, H, sc(20), P["card"], "bg")
        lw = sc(300)
        c.create_text(sc(26), sc(24), text="COMBINED SPEED", fill=P["muted"], font=self.F["tag"], anchor="nw")
        self.h_num = c.create_text(sc(24), sc(40), text="0.0", fill=P["text"], font=self.F["huge"], anchor="nw")
        self.h_unit = c.create_text(sc(26) + self.F["huge"].measure("0.0") + sc(8), sc(40) + sc(36),
                                    text=self.cfg["units"], fill=P["muted"], font=self.F["b"], anchor="sw")
        self.h_rows = {}
        c.create_line(lw, sc(22), lw, H - sc(22), fill=P["line"])
        self.gx1, self.gx2, self.gy1, self.gy2 = lw + sc(56), W - sc(26), sc(26), H - sc(34)
        for k in range(3):
            y = self.gy1 + (self.gy2 - self.gy1) * k / 2
            c.create_line(self.gx1, y, self.gx2, y, fill=P["line"], dash=(2, 4))
        self.g_lab = [c.create_text(self.gx1 - sc(10), self.gy1 + (self.gy2 - self.gy1) * k / 2, text="",
                                    fill=P["muted"], font=self.F["xs"], anchor="e") for k in range(3)]
        self.g_poly = {}
        self.g_line = {}
        self.g_idle = c.create_text((self.gx1 + self.gx2) / 2, (self.gy1 + self.gy2) / 2,
                                    text="Start a download to see both links working together",
                                    fill=P["muted"], font=self.F["s"])
        c.create_text(self.gx1, self.gy2 + sc(18), text="60 s ago", fill=P["muted"], font=self.F["xs"], anchor="w")
        c.create_text(self.gx2, self.gy2 + sc(18), text="now", fill=P["muted"], font=self.F["xs"], anchor="e")
        self.h_rows_y = sc(112)
        self.h_stat = {}
        cols = (sc(26), sc(160))
        for k, (key, lab) in enumerate((("peak", "PEAK"), ("avg", "AVERAGE"), ("act", "DOWNLOADING"), ("idle", "IDLE"))):
            x = cols[k % 2]
            yy = H - sc(88) + (k // 2) * sc(40)
            c.create_text(x, yy, text=lab, fill=P["muted"], font=self.F["tag"], anchor="nw")
            self.h_stat[key] = c.create_text(x, yy + sc(15), text="-", fill=P["text"], font=self.F["sb"], anchor="nw")
        self.h_ips_key = None
        self.hero_adapters()

    def hero_adapters(self):
        """The little per-adapter legend under the big number."""
        c, P = self.hero, self.P
        c.delete("legend")
        sel = self.selected()
        key = tuple(sel) + (self.primary_ip(),)
        self.h_ips_key = key
        self.h_rows = {}
        y = self.h_rows_y
        step = sc(26)
        for name, ip in sel[:4]:
            col = self.adapter_color(ip)
            c.create_oval(sc(26), y + sc(5), sc(26) + sc(10), y + sc(15), fill=col, width=0, tags="legend")
            lab = name + ("  (primary)" if ip == self.primary_ip() and len(sel) > 1 else "")
            c.create_text(sc(44), y + sc(10), text=clip(self.F["s"], lab, sc(150)), fill=P["text"],
                          font=self.F["s"], anchor="w", tags="legend")
            t = c.create_text(sc(270), y + sc(10), text="0.0", fill=P["muted"], font=self.F["sb"], anchor="e",
                              tags="legend")
            self.h_rows[ip] = t
            y += step
        if not sel:
            c.create_text(sc(26), y + sc(10), text="No network adapters found", fill=P["warn"],
                          font=self.F["s"], anchor="w", tags="legend")

    def hero_update(self, dt):
        c = self.hero
        if not hasattr(self, "h_num") or not c.winfo_width() > 50:
            return
        now = time.time()
        act = [it for it in self.items if it.state == "running"]
        by = {}
        for it in act:
            for ip, v in it.speeds.items():
                by[ip] = by.get(ip, 0) + v
        if now - self.last_sample >= .25:
            self.last_sample = now
            self.samples.append((now, by))
        tot = sum(by.values())
        self.disp_total += (tot - self.disp_total) * min(1, dt * 7)
        if abs(self.disp_total - tot) < 1000:
            self.disp_total = tot
        v, u = spd(self.disp_total, self.cfg["units"])
        txt = f"{v:.1f}"
        c.itemconfigure(self.h_num, text=txt)
        c.coords(self.h_unit, sc(26) + self.F["huge"].measure(txt) + sc(8), sc(40) + sc(36))
        c.itemconfigure(self.h_unit, text=u)
        if tuple(self.selected()) + (self.primary_ip(),) != self.h_ips_key:
            self.hero_adapters()
        for ip, t in self.h_rows.items():
            c.itemconfigure(t, text=fmt_speed(by.get(ip, 0), self.cfg["units"]))
        if self.tick % 6 == 0 and getattr(self, "h_stat", None):
            U = self.cfg["units"]
            avg = self.st_bytes / self.st_act if self.st_act > 0.5 else 0
            for key, val in (("peak", fmt_speed(self.st_peak, U) if self.st_peak else "-"),
                             ("avg", fmt_speed(avg, U) if avg else "-"),
                             ("act", fmt_dur(self.st_act)), ("idle", fmt_dur(self.st_idle))):
                c.itemconfigure(self.h_stat[key], text=val)
        # graph: stacked areas, time-based so it scrolls smoothly
        win = 60.0
        pts = [(t, d) for t, d in self.samples if now - t <= win + 1]
        ips = [ip for _, ip in self.selected()] + (["all"] if "all" in by else [])
        peak = max([sum(d.get(i, 0) for i in ips) for _, d in pts] + [1e6])
        self.ymax += (peak * 1.18 - self.ymax) * min(1, dt * 3)
        yv = self.ymax
        for k in range(3):
            val = yv * (1 - k / 2)
            c.itemconfigure(self.g_lab[k], text=f"{spd(val, self.cfg['units'])[0]:.0f}" if k < 2 else "0")
        x1, x2, y1, y2 = self.gx1, self.gx2, self.gy1, self.gy2
        c.itemconfigure(self.g_idle, state="hidden" if (act or len(pts) > 3 and peak > 1.1e6) else "normal")
        if not pts:
            for i in list(self.g_poly):
                c.itemconfigure(self.g_poly[i], state="hidden")
                c.itemconfigure(self.g_line[i], state="hidden")
            return
        xs = [x2 - (now - t) / win * (x2 - x1) for t, _ in pts]
        base = [y2] * len(pts)
        for ip in ips:
            col = self.adapter_color(ip)
            top = [b - (d.get(ip, 0) / yv) * (y2 - y1) for b, (_, d) in zip(base, pts)]
            fl = []
            for x, y in zip(xs, top):
                fl += [x, y]
            bl = []
            for x, y in zip(reversed(xs), reversed(base)):
                bl += [x, y]
            if ip not in self.g_poly:
                self.g_poly[ip] = c.create_polygon(0, 0, 0, 0, 0, 0, fill=mix(col, self.P["card"], .62), width=0, outline="")
                self.g_line[ip] = c.create_line(0, 0, 0, 0, fill=col, width=max(2, sc(2)), joinstyle="round",
                                                capstyle="round")
                c.tag_raise(self.g_idle)
            if len(pts) >= 2:
                c.coords(self.g_poly[ip], *(fl + bl))
                c.coords(self.g_line[ip], *fl)
                c.itemconfigure(self.g_poly[ip], state="normal", fill=mix(col, self.P["card"], .62))
                c.itemconfigure(self.g_line[ip], state="normal", fill=col)
            base = top

    # ---------- list ----------
    def on_cfg(self, e):
        if e.widget is self.root:
            self.last_cfg = time.time()      # window is being moved/resized: pause the heavy animation

    def schedule_hero(self):
        if getattr(self, "hero_job", None):
            self.root.after_cancel(self.hero_job)
        self.hero_job = self.root.after(120, self.hero_layout)

    def schedule_layout(self):
        if self.relayout_job:
            self.root.after_cancel(self.relayout_job)
        self.relayout_job = self.root.after(140, self.layout)

    def layout(self):
        self.relayout_job = None
        c, P = self.lc, self.P
        c.delete("all")
        self.rows = {}
        W = c.winfo_width()
        Hc = c.winfo_height()
        if W < 50:
            return
        self.lW = W
        if not self.items:
            cx, cy = W // 2, max(sc(120), Hc // 2 - sc(10))
            sz = sc(84)
            c.create_image(cx - sz // 2, cy - sc(90), image=rr_img(sz, sz, sc(26), P["accent"], P["accent2"]),
                           anchor="nw")
            merge_glyph(c, cx, cy - sc(90) + sz // 2, sc(44), P["accent_text"], max(3, sc(4)))
            c.create_text(cx, cy + sc(24), text="No downloads yet", fill=P["text"], font=self.F["h"])
            c.create_text(cx, cy + sc(50), text="Paste a link, pick your adapters and let both connections work.",
                          fill=P["muted"], font=self.F["s"])
            c.create_text(cx, cy + sc(70), text="Tip: press Ctrl+V anywhere to start from your clipboard.",
                          fill=P["muted"], font=self.F["xs"])
            c.configure(scrollregion=(0, 0, W, Hc))
            self.total_h = Hc
            return
        y = sc(2)
        run = sum(1 for i in self.items if i.state == "running")
        c.create_text(sc(4), y + sc(12), anchor="w", text="Downloads", fill=P["text"], font=self.F["h"])
        self.cnt = c.create_text(sc(4) + self.F["h"].measure("Downloads") + sc(10), y + sc(13), anchor="w",
                                 text=f"{len(self.items)} total  -  {run} active", fill=P["muted"], font=self.F["s"])
        t = c.create_text(W - sc(4), y + sc(12), anchor="e", text="Clear finished", fill=P["muted"], font=self.F["s"],
                          tags="clear")
        c.tag_bind("clear", "<Button-1>", lambda e: self.clear_done())
        c.tag_bind("clear", "<Enter>", lambda e: (c.itemconfigure(t, fill=P["accent"]), c.config(cursor="hand2")))
        c.tag_bind("clear", "<Leave>", lambda e: (c.itemconfigure(t, fill=P["muted"]), c.config(cursor="")))
        y += sc(34)
        for it in reversed(self.items):
            y = self.draw_row(it, y, W) + sc(12)
        self.total_h = y
        c.configure(scrollregion=(0, 0, W, max(Hc, y)))
        self.scroll_c = min(self.scroll_c, max(0, y - Hc))
        self.scroll_t = min(self.scroll_t, max(0, y - Hc))
        self.apply_scroll()

    def draw_row(self, it, y, W):
        c, P, F = self.lc, self.P, self.F
        H = sc(146)
        card(c, 0, y, W, y + H, sc(16), P["card"], f"r{it.id}")
        col = P[tile_color(it.name)]
        ts = sc(52)
        c.create_image(sc(18), y + sc(18), image=rr_img(ts, ts, sc(14), mix(col, P["card"], .78)), anchor="nw")
        ext = (it.name.rsplit(".", 1)[-1][:4].upper() if "." in it.name else "FILE")
        c.create_text(sc(18) + ts // 2, y + sc(18) + ts // 2, text=ext, fill=col, font=F["tag"])
        x0 = sc(86)
        bx = W - sc(100)
        R = {"y": y}
        R["name"] = c.create_text(x0, y + sc(18), anchor="nw", text=clip(F["bb"], it.name, W - x0 - sc(310)),
                                  fill=P["text"], font=F["bb"])
        R["sub"] = c.create_text(x0, y + sc(40), anchor="nw", text="", fill=P["muted"], font=F["s"])
        R["right"] = c.create_text(W - sc(154), y + sc(18), anchor="ne", text="", fill=P["text"], font=F["bb"])
        R["eta"] = c.create_text(W - sc(154), y + sc(40), anchor="ne", text="", fill=P["muted"], font=F["s"])
        # progress bar
        by, bh = y + sc(68), sc(8)
        bx1, bx2 = x0, W - sc(20)
        R["bar"] = (bx1, bx2, by, bh)
        c.create_rectangle(bx1, by, bx2, by + bh, fill=P["track"], width=0)
        R["segs"] = {ip: c.create_rectangle(bx1, by, bx1, by + bh, fill=self.adapter_color(ip), width=0)
                     for ip in it.ips}
        rr = bh // 2
        for pos, (xx, yy, a) in {"tl": (bx1, by, "nw"), "tr": (bx2, by, "ne"),
                                 "bl": (bx1, by + bh, "sw"), "br": (bx2, by + bh, "se")}.items():
            c.create_image(xx, yy, image=corner(rr, P["card"], pos, inverse=True), anchor=a)
        # per-adapter line
        ax, ay = x0, y + sc(90)
        R["ad"] = {}
        slot = sc(280)
        for k, (ip, name) in enumerate(it.ips.items()):
            col2 = self.adapter_color(ip)
            xx = ax + k * slot
            c.create_oval(xx, ay + sc(4), xx + sc(8), ay + sc(12), fill=col2, width=0)
            R["ad"][ip] = (c.create_text(xx + sc(14), ay + sc(8), anchor="w", text="", fill=P["muted"], font=F["s"]),
                           name)
        R["stats"] = c.create_text(x0, y + sc(121), anchor="w", text="", fill=P["muted"], font=F["s"])
        R["warn"] = c.create_text(bx2, ay + sc(8), anchor="e", text="", fill=P["warn"], font=F["s"])
        # buttons
        tag = f"b{it.id}"
        bs = sc(34)
        bxr = W - sc(18) - bs
        c.create_image(bxr, y + sc(16), image=rr_img(bs, bs, sc(10), P["card2"]), anchor="nw", tags=(tag, f"{tag}x"))
        R["btn_bg"] = c.find_withtag(f"{tag}x")[-1]
        cx, cy = bxr + bs / 2, y + sc(16) + bs / 2
        R["icon"] = []
        self.draw_icon(R, it, cx, cy)
        c.tag_bind(tag, "<Button-1>", lambda e, i=it: self.row_action(i))
        c.tag_bind(tag, "<Enter>", lambda e, r=R: (c.itemconfigure(r["btn_bg"], image=rr_img(bs, bs, sc(10), P["line"])),
                                                   c.config(cursor="hand2")))
        c.tag_bind(tag, "<Leave>", lambda e, r=R: (c.itemconfigure(r["btn_bg"], image=rr_img(bs, bs, sc(10), P["card2"])),
                                                   c.config(cursor="")))
        R["tag"], R["ico"] = tag, (cx, cy)
        ptag = f"p{it.id}"
        pbx = bxr - sc(8) - bs
        R["pbg"] = c.create_image(pbx, y + sc(16), image=rr_img(bs, bs, sc(10), P["card2"]), anchor="nw",
                                  tags=(ptag,), state="hidden")
        R["pc"] = (pbx + bs / 2, y + sc(16) + bs / 2)
        R["pic"], R["pstate"] = [], None
        c.tag_bind(ptag, "<Button-1>", lambda e, i=it: self.toggle_pause(i))
        c.tag_bind(ptag, "<Enter>", lambda e, r=R: (c.itemconfigure(r["pbg"], image=rr_img(bs, bs, sc(10), P["line"])),
                                                    c.config(cursor="hand2")))
        c.tag_bind(ptag, "<Leave>", lambda e, r=R: (c.itemconfigure(r["pbg"], image=rr_img(bs, bs, sc(10), P["card2"])),
                                                    c.config(cursor="")))
        self.rows[it.id] = R
        R["last"] = {}
        self.row_update(it, True)
        return y + H

    def draw_icon(self, R, it, cx, cy):
        c, P = self.lc, self.P
        for i in R["icon"]:
            c.delete(i)
        R["icon"] = []
        u = sc(7)
        tag = R.get("tag") or f"b{it.id}"
        kw = dict(fill=P["text"], width=max(2, sc(2)), capstyle="round", joinstyle="round", tags=(tag,))
        if it.state in ("queued", "running", "error", "paused"):
            R["icon"] = [c.create_line(cx - u, cy - u, cx + u, cy + u, **kw),
                         c.create_line(cx - u, cy + u, cx + u, cy - u, **kw)]
        else:   # done: folder
            R["icon"] = [c.create_line(cx - u, cy - u * .6, cx - u, cy + u * .8, cx + u, cy + u * .8, cx + u,
                                       cy - u * .3, cx + u * .1, cy - u * .3, cx - u * .2, cy - u * .6, cx - u, cy - u * .6, **kw)]
        R["icon_state"] = it.state

    def row_update(self, it, force=False):
        R = self.rows.get(it.id)
        if not R:
            return
        c, P, U = self.lc, self.P, self.cfg["units"]
        L = R["last"]

        def put(key, item, **kw):
            sig = tuple(kw.items())
            if force or L.get(key) != sig:
                L[key] = sig
                c.itemconfigure(item, **kw)
        if R.get("icon_state") != it.state:
            self.draw_icon(R, it, *R["ico"])
        want = ("pause" if it.state == "running" and it.can_pause else
                "play" if it.state in ("paused",) else None)
        if R["pstate"] != want:
            R["pstate"] = want
            for i in R["pic"]:
                c.delete(i)
            R["pic"] = []
            c.itemconfigure(R["pbg"], state="normal" if want else "hidden")
            cx, cy = R["pc"]
            u = sc(6)
            kw = dict(fill=P["text"], tags=(f"p{it.id}",))
            if want == "pause":
                R["pic"] = [c.create_rectangle(cx - u, cy - u, cx - u * .3, cy + u, width=0, **kw),
                            c.create_rectangle(cx + u * .3, cy - u, cx + u, cy + u, width=0, **kw)]
            elif want == "play":
                R["pic"] = [c.create_polygon(cx - u * .6, cy - u, cx + u, cy, cx - u * .6, cy + u, width=0, **kw)]
        frac = (it.done / it.total) if it.total else 0
        if it.state == "done":
            frac = 1
        it.shown += (frac - it.shown) * 0.25
        if abs(it.shown - frac) < 0.0005:
            it.shown = frac
        if it.state == "queued":
            sub, right, eta = ("Waiting for the network scan..." if not self.ifready.is_set() else "Queued"), "", ""
        elif it.state == "paused":
            sub, right, eta = (f"Paused  -  {human(it.done)} of {human(it.total)}" if it.total else "Paused"), "Paused", ""
        elif it.state == "running" and it.pausing:
            sub, right, eta = "Pausing...", "", ""
        elif it.state == "error":
            sub, right, eta = it.msg or "Failed", "Failed", ""
        elif it.state == "done":
            sub, right, eta = f"{human(it.total)}  -  finished", "Done", ""
        else:
            sub = (f"{human(it.done)} of {human(it.total)}" if it.total else
                   (f"{human(it.done)} downloaded" if it.done else "Connecting..."))
            if it.total:
                sub += f"   -   {frac * 100:.1f}%"
            right = fmt_speed(it.speed, U) if it.speed else ""
            left = (it.total - it.done) / it.ema if it.ema > 1000 and it.total else 0
            eta = fmt_eta(left) if left else ""
        put("sub", R["sub"], text=sub, fill=P["danger"] if it.state == "error" else P["muted"])
        put("right", R["right"], text=right, fill=P["ok"] if it.state == "done" else (
            P["danger"] if it.state == "error" else (P["warn"] if it.state == "paused" else P["text"])))
        put("eta", R["eta"], text=eta)
        bx1, bx2, by, bh = R["bar"]
        fw = (bx2 - bx1) * it.shown
        tot = sum(it.bytes.values()) or 1
        x = bx1
        for ip, sid in R["segs"].items():
            w = fw * it.bytes.get(ip, 0) / tot
            sig = (round(x, 1), round(x + w, 1))
            if L.get(("s", ip)) != sig or force:
                L[("s", ip)] = sig
                c.coords(sid, x, by, x + w, by + bh)
            x += w
        if it.act_s > 0.5 or it.idle_s > 0.5:
            avg = it.sbytes / it.act_s if it.act_s > 0.5 else 0
            st = (f"Peak {fmt_speed(it.peak, U)}   |   Avg {fmt_speed(avg, U)}   |   "
                  f"Downloading {fmt_dur(it.act_s)}   |   Idle {fmt_dur(it.idle_s)}")
        else:
            st = ""
        put("stats", R["stats"], text=st)
        warn = ""
        running = it.state == "running" and time.time() - it.t0 > 6
        for ip, (tid, name) in R["ad"].items():
            s = it.speeds.get(ip, 0)
            lab = name + ("  (primary)" if ip == it.primary and len(it.ips) > 1 else "")
            txt = f"{clip(self.F['s'], lab, sc(150))}   {fmt_speed(s, U)}" if it.state == "running" else lab
            put(("ad", ip), tid, text=txt, fill=P["text"] if s > 1000 else P["muted"])
            if running and it.bytes.get(ip, 0) < 1 and not warn:
                if it.err.get(ip):
                    warn = f"{name}: {it.err[ip]}"
                elif time.time() - it.t0 > 10 and it.mode != "backup" and len(it.ips) > 1:
                    warn = f"{name}: no data yet, still connecting..."
        if it.single and it.state == "running":
            warn = f"Server can't split this file - using {it.ips.get(it.primary, 'one adapter')} only"
        put("warn", R["warn"], text=clip(self.F["s"], warn, sc(420)) if warn else "")

    def row_action(self, it):
        if it.state == "done":
            try:
                if IS_WIN:
                    subprocess.Popen(["explorer", "/select,", os.path.normpath(it.dest)])
            except Exception:
                pass
        else:
            self.cancel(it)

    # ---------- engine control ----------
    def add(self, url, folder, sel_ips, primary_ip, mode, seq=False):
        if url.startswith("magnet:"):
            from urllib.parse import parse_qs
            nm = safe_name((parse_qs(urlsplit(url).query).get("dn") or ["Torrent"])[0])
            it = Item(url, os.path.join(folder, nm), {"all": "All adapters"}, "all", mode, self.cfg["conns"])
            it.eips = [ip for _, ip in sel_ips]
        else:
            name = unique_path(folder, name_from_url(url))
            it = Item(url, name, {ip: n for n, ip in sel_ips}, primary_ip, mode, self.cfg["conns"])
        it.seq = seq
        self.items.append(it)
        self.layout()
        return it

    @staticmethod
    def engine_cmd(flag, cfgj):
        if getattr(sys, "frozen", False):          # running as DualLink.exe
            return [sys.executable, flag, cfgj]
        return [sys.executable, os.path.abspath(__file__), flag, cfgj]

    def start(self, it):
        if it.kind == "http" and it.mode == "equal" and len(it.ips) > 1:
            # spread single-stream downloads over the adapters so both links get used
            use = {ip: 0 for ip in it.ips}
            for o in self.items:
                if o is not it and o.state == "running" and o.kind == "http" and o.primary in use:
                    use[o.primary] += 1
            it.primary = min(use, key=lambda k: (use[k], k != it.primary))
        lim = int(self.cfg["limit_mb"] * 1e6)
        if it.kind == "torrent":
            cfgj = json.dumps(dict(url=it.url, folder=os.path.dirname(it.dest), ips=it.eips, limit=lim,
                                   seq=it.seq))
            cmd = self.engine_cmd("--torrent", cfgj)
        else:
            cfgj = json.dumps(dict(url=it.url, dest=it.dest, ips=list(it.ips), conns=it.conns,
                                   primary=it.primary, mode=it.mode, limit=lim,
                                   auto=not it.resume, resume=it.resume))
            cmd = self.engine_cmd("--engine", cfgj)
        it.pausing = False
        try:
            os.makedirs(os.path.dirname(it.dest), exist_ok=True)
            it.proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                       stderr=subprocess.DEVNULL, text=True, bufsize=1,
                                       creationflags=(0x08000000 | 0x00004000) if IS_WIN else 0)  # no window + BELOW_NORMAL priority
        except Exception as e:
            it.state, it.msg = "error", str(e)[:80]
            return
        it.state, it.t0 = "running", time.time()
        threading.Thread(target=self.reader, args=(it,), daemon=True).start()

    def reader(self, it):
        try:
            for line in it.proc.stdout:
                try:
                    m = json.loads(line)
                except Exception:
                    continue
                if m["t"] == "p":
                    it.total, it.done = m["total"], m["done"]
                    for ip_, v_ in m["speeds"].items():     # smooth out bursty readings
                        old = it.speeds.get(ip_, 0.0)
                        it.speeds[ip_] = v_ if v_ == 0 and it.done >= it.total else old + (v_ - old) * 0.35
                    it.bytes.update(m["bytes"])
                    it.err = m["err"]
                elif m["t"] == "info":
                    it.total = m["total"]
                    if it.kind == "http":
                        it.can_pause = True
                        it.single = not bool(m.get("ranged", True))
                    if m.get("dest") and m["dest"] != it.dest:
                        it.dest, it.name = m["dest"], os.path.basename(m["dest"])
                        it.renamed = True
                elif m["t"] == "state":
                    it.state = "paused" if m["paused"] else "running"
                    if m["paused"]:
                        it.speeds = {ip: 0.0 for ip in it.ips}
                elif m["t"] == "end":
                    it.pausing = False
                    if m["ok"]:
                        it.state = "done"
                    elif m["msg"] == "paused" and it.state != "cancelled":
                        it.state = "paused"
                    elif it.state != "cancelled":
                        it.state, it.msg = "error", m["msg"]
        except Exception:
            pass
        if it.state in ("running",) or (it.state == "paused" and it.kind == "torrent" and False):
            it.state, it.msg = "error", "download engine stopped unexpectedly"
        it.speeds = {ip: 0.0 for ip in it.ips}

    def toggle_pause(self, it):
        try:
            if it.state == "running" and it.can_pause and not it.pausing:
                it.pausing = True
                it.proc.stdin.write("PAUSE\n")
                it.proc.stdin.flush()
                if it.kind == "torrent" or it.single:
                    it.state = "paused"
                    it.speeds = {ip: 0.0 for ip in it.ips}
                    it.pausing = False
            elif it.state == "paused":
                if it.kind == "torrent" or it.single:
                    it.proc.stdin.write("RESUME\n")
                    it.proc.stdin.flush()
                    it.state = "running"
                else:
                    it.resume, it.state = True, "queued"
        except Exception:
            pass

    def pause_all(self):
        run = [i for i in self.items if i.state == "running" and i.can_pause and not i.pausing]
        for i in (run or [i for i in self.items if i.state == "paused"]):
            self.toggle_pause(i)

    def cancel(self, it):
        if it.state == "paused" and it.kind == "http":
            for ext in (".part", ".dlstate"):
                try:
                    os.remove(it.dest + ext)
                except OSError:
                    pass
        if it.state in ("running", "paused") and it.proc and it.proc.poll() is None:
            it.state = "cancelled"
            try:
                it.proc.stdin.close()      # engine sees EOF, stops and deletes the .part file
            except Exception:
                pass
            threading.Timer(4, lambda: it.proc.poll() is None and it.proc.kill()).start()
        else:
            it.state = "cancelled"
        self.remove(it)

    def remove(self, it):
        if it in self.items:
            self.items.remove(it)
            self.layout()

    def clear_done(self):
        self.items = [i for i in self.items if i.state in ("queued", "running")]
        self.layout()

    def paste_start(self):
        if self.dlg:
            return
        self.new_download()

    # ---------- frame loop ----------
    def stats_tick(self, dt):
        """Peak / average speed and downloading-vs-idle timers, per download and overall."""
        tot = 0.0
        waiting = False
        for it in self.items:
            if it.state == "running":
                sp = it.speed
                if sp > 1000:
                    it.act_s += dt
                    it.sbytes += sp * dt
                    it.peak = max(it.peak, sp)
                else:
                    it.idle_s += dt
                tot += sp
                waiting = True
            elif it.state == "paused":
                it.idle_s += dt
        if tot > 1000:
            self.st_act += dt
            self.st_bytes += tot * dt
            self.st_peak = max(self.st_peak, tot)
        elif waiting:
            self.st_idle += dt

    def loop(self):
        now = time.time()
        dt = min(.1, now - self.last)
        self.last = now
        self.tick += 1
        self.stats_tick(min(2.0, now - self.last_stat))
        self.last_stat = now
        if now - self.last_cfg < 0.25:        # resizing / maximizing: do nothing heavy, stay snappy
            self.root.after(40, self.loop)
            return
        try:
            if self._scan is not None:
                ad, self._scan = self._scan, None
                if ad != self.adapters:
                    self.adapters = ad
                    self.net_dot()
            active = 0
            for it in self.items:
                if it.state == "running":
                    active += 1
                    sp = it.speed
                    it.ema = sp if it.ema == 0 else it.ema + (sp - it.ema) * min(1, dt * 1.2)
            for it in self.items:
                if it.state == "queued" and self.ifready.is_set() and active < self.cfg["max_active"]:
                    if it.seq and any(o is not it and o.seq and o.state == "running" for o in self.items):
                        continue
                    self.start(it)
                    active += 1
            finished = False
            for it in list(self.items):
                R = self.rows.get(it.id)
                if R and R.get("seen") != it.state:
                    R["seen"] = it.state
                    if it.state in ("done", "error", "running") and R.get("shown_once"):
                        finished = True
                    R["shown_once"] = True
                if getattr(it, "renamed", False):
                    it.renamed = False
                    self.layout()
                    break
                self.row_update(it)
            want = ("Pause all" if any(i.state == "running" and i.can_pause for i in self.items) or
                    not any(i.state == "paused" for i in self.items) else "Resume all")
            if want != self.pa_lbl:
                self.pa_lbl = want
                self.pa_btn.itemconfigure(self.pa_btn.txt, text=want)
            if self.items:
                run = sum(1 for i in self.items if i.state == "running")
                txt = f"{len(self.items)} total  -  {run} active"
                if getattr(self, "cnt_txt", None) != txt:
                    self.cnt_txt = txt
                    self.lc.itemconfigure(self.cnt, text=txt)
            self.hdt += dt
            if self.tick % 2 == 0:             # graph at ~15 fps is plenty
                self.hero_update(self.hdt)
                self.hdt = 0.0
            self.do_scroll()
            if finished:
                self.layout()
        except tk.TclError:
            return
        scrolling = abs(self.scroll_t - self.scroll_c) > .5
        busy = any(i.state in ("running", "queued") for i in self.items)
        spent = int((time.time() - now) * 1000)
        self.root.after(max(1, (16 if scrolling else 33 if busy else 120) - spent), self.loop)

    def net_dot(self):
        pass

    # ---------- smooth scrolling ----------
    def wheel(self, e, d=None):
        d = d if d is not None else e.delta
        w = self.root.winfo_containing(e.x_root, e.y_root)
        if w is not self.lc:
            return
        mx = max(0, self.total_h - self.lc.winfo_height())
        self.scroll_t = max(0, min(mx, self.scroll_t - d / 120 * sc(70)))

    def do_scroll(self):
        if abs(self.scroll_t - self.scroll_c) > .3:
            self.scroll_c += (self.scroll_t - self.scroll_c) * .22
            self.apply_scroll()

    def apply_scroll(self):
        tot = max(1, self.total_h)
        self.lc.yview_moveto(self.scroll_c / tot)

    def quit(self):
        for it in self.items:
            if it.proc and it.proc.poll() is None:
                try:
                    it.proc.kill()
                except Exception:
                    pass
        self.root.destroy()


    # ---------- dialogs ----------
    def dialog(self, title, sub, w):
        if self.dlg:
            try:
                self.dlg.destroy()
            except Exception:
                pass
        P = self.P
        d = tk.Toplevel(self.root)
        d.withdraw()
        d.title(title)
        d.configure(bg=P["card"])
        d.resizable(False, False)
        d.transient(self.root)
        self._dlg_w = sc(w)
        body = tk.Frame(d, bg=P["card"])
        body.pack(fill="both", expand=True, padx=sc(28), pady=sc(24))
        tk.Label(body, text=title, bg=P["card"], fg=P["text"], font=self.F["title"]).pack(anchor="w")
        if sub:
            tk.Label(body, text=sub, bg=P["card"], fg=P["muted"], font=self.F["s"], wraplength=sc(w - 60),
                     justify="left").pack(anchor="w", pady=(sc(2), 0))
        d.bind("<Escape>", lambda e: self.close_dlg())
        d.protocol("WM_DELETE_WINDOW", self.close_dlg)
        self.dlg = d
        return d, body

    def show_dlg(self, d):
        d.update_idletasks()
        w = self._dlg_w
        h = d.winfo_reqheight()
        x = self.root.winfo_x() + (self.root.winfo_width() - w) // 2
        y = self.root.winfo_y() + max(sc(40), (self.root.winfo_height() - h) // 3)
        d.geometry(f"{w}x{h}+{x}+{y}")
        dark_titlebar(d, self.P)
        d.deiconify()
        d.grab_set()
        d.focus_force()

    def close_dlg(self):
        if self.dlg:
            try:
                self.dlg.grab_release()
                self.dlg.destroy()
            except Exception:
                pass
        self.dlg = None

    def lab(self, body, text, top=16):
        tk.Label(body, text=text.upper(), bg=self.P["card"], fg=self.P["muted"], font=self.F["tag"]).pack(
            anchor="w", pady=(sc(top), sc(6)))

    def new_download(self):
        P, F = self.P, self.F
        d, body = self.dialog("New download", "Paste direct links or magnet links, one per line.", 560)
        cw = 560 - 56
        self.lab(body, "Link(s)")
        area = Area(body, P, F["b"], cw, P["card"], lines=3)
        area.pack(anchor="w")
        try:
            clip_txt = self.root.clipboard_get().strip()
            if clip_txt.lower().startswith(("http://", "https://", "magnet:")) and len(clip_txt) < 4000:
                area.text.insert("1.0", clip_txt)
        except Exception:
            pass
        area.text.focus_set()
        seq = tk.BooleanVar(value=bool(self.cfg.get("seq", False)))
        sr = tk.Frame(body, bg=P["card"])
        sr.pack(anchor="w", pady=(sc(10), 0))
        Check(sr, seq, P, P["card"]).pack(side="left")
        tk.Label(sr, text="Sequential: one at a time, in order (torrents: pieces in order)", bg=P["card"],
                 fg=P["text"], font=F["s"]).pack(side="left", padx=(sc(10), 0))
        self.lab(body, "Save to")
        row = tk.Frame(body, bg=P["card"])
        row.pack(anchor="w")
        folder = tk.StringVar(value=self.cfg["folder"])
        Field(row, folder, P, F["b"], cw - 110, P["card"]).pack(side="left")

        def browse():
            p = filedialog.askdirectory(initialdir=folder.get(), parent=d)
            if p:
                folder.set(p)
        Btn(row, "Browse", browse, P, F["b"], w=98, h=38, bg=P["card"]).pack(side="left", padx=(sc(12), 0))
        self.lab(body, "Adapters to use")
        box = tk.Frame(body, bg=P["card"])
        box.pack(anchor="w", fill="x")
        use = {}
        prim = tk.StringVar(value=self.cfg.get("primary") or "")
        default_use = self.cfg.get("use")
        rows_ = []

        def paint_primary():
            for name, b in rows_:
                b.itemconfigure("all", state="normal")
        if not self.adapters:
            tk.Label(box, text="No active network adapters found.", bg=P["card"], fg=P["warn"], font=F["s"]).pack(anchor="w")
        for name, ip in self.adapters:
            on = (name in default_use) if default_use is not None else not is_virtual(name)
            use[name] = tk.BooleanVar(value=on)
            r = tk.Frame(box, bg=P["card"])
            r.pack(fill="x", pady=sc(3))
            Check(r, use[name], P, P["card"]).pack(side="left")
            tk.Label(r, text=name, bg=P["card"], fg=P["text"], font=F["bb"]).pack(side="left", padx=(sc(10), sc(8)))
            tk.Label(r, text=ip, bg=P["card"], fg=P["muted"], font=F["s"]).pack(side="left")
            rows_.append((name, r))
        # primary picker
        if len(self.adapters) > 1:
            self.lab(body, "Primary adapter")
            names = [(n, clip(F["sb"], n, sc(150))) for n, _ in self.adapters][:3]
            if prim.get() not in [n for n, _ in names]:
                prim.set(names[0][0])
            Seg(body, names, prim, P, F["sb"], cw, P["card"]).pack(anchor="w")
            self.lab(body, "Other adapters")
            mode = tk.StringVar(value=self.cfg["mode"])
            hint = tk.Label(body, text=MODE_HELP[mode.get()], bg=P["card"], fg=P["muted"], font=F["s"],
                            wraplength=sc(cw), justify="left")
            Seg(body, MODES, mode, P, F["sb"], cw, P["card"],
                cmd=lambda: hint.config(text=MODE_HELP[mode.get()])).pack(anchor="w")
            hint.pack(anchor="w", pady=(sc(8), 0))
        else:
            mode = tk.StringVar(value="equal")
        err = tk.Label(body, text="", bg=P["card"], fg=P["danger"], font=F["s"])
        err.pack(anchor="w", pady=(sc(10), 0))
        bt = tk.Frame(body, bg=P["card"])
        bt.pack(fill="x", pady=(sc(8), 0))

        def go():
            links = [x.strip() for x in area.get().splitlines() if x.strip()]
            if not links or not all(x.lower().startswith(("http://", "https://", "magnet:")) for x in links):
                err.config(text="Enter links starting with http://, https:// or magnet:")
                return
            sel = [(n, ip) for n, ip in self.adapters if use[n].get()]
            if not sel:
                err.config(text="Pick at least one adapter.")
                return
            pn = prim.get()
            pip_ = next((ip for n, ip in sel if n == pn), sel[0][1])
            self.cfg.update(folder=folder.get(), use=[n for n, _ in sel], primary=pn or sel[0][0],
                            mode=mode.get(), seq=seq.get())
            save_cfg(self.cfg)
            self.close_dlg()
            for u in links:
                self.add(u, folder.get(), sel, pip_, mode.get(), seq.get())
            self.hero_adapters()
        Btn(bt, "Start download", go, P, F["bb"], kind="accent", h=42, bg=P["card"]).pack(side="right")
        Btn(bt, "Cancel", self.close_dlg, P, F["b"], h=42, bg=P["card"]).pack(side="right", padx=(0, sc(10)))
        d.bind("<Control-Return>", lambda e: go())
        self.show_dlg(d)

    def settings(self):
        P, F = self.P, self.F
        d, body = self.dialog("Settings", None, 540)
        cw = 540 - 56
        theme = tk.StringVar(value=self.cfg["theme"] if self.cfg["theme"] in THEMES else "dark")
        accent = tk.StringVar(value=self.cfg.get("accent", "teal"))
        custom = tk.StringVar(value=self.cfg.get("custom", "#ff6a3d"))
        units = tk.StringVar(value=self.cfg["units"])
        folder = tk.StringVar(value=self.cfg["folder"])
        conns = tk.IntVar(value=self.cfg["conns"])
        maxa = tk.IntVar(value=self.cfg["max_active"])
        lim = tk.IntVar(value=int(self.cfg["limit_mb"]))
        tab = tk.StringVar(value="gen")
        holder = tk.Frame(body, bg=P["card"])
        gen = tk.Frame(holder, bg=P["card"])
        look = tk.Frame(holder, bg=P["card"])

        def lab(parent, text, top=16):
            tk.Label(parent, text=text.upper(), bg=P["card"], fg=P["muted"], font=F["tag"]).pack(
                anchor="w", pady=(sc(top), sc(6)))

        # --- General
        lab(gen, "Speed units", 14)
        Seg(gen, [("MB/s", "MB/s"), ("Mbps", "Mbps")], units, P, F["sb"], cw, P["card"]).pack(anchor="w")
        lab(gen, "Default download folder")
        row = tk.Frame(gen, bg=P["card"])
        row.pack(anchor="w")
        Field(row, folder, P, F["b"], cw - 110, P["card"]).pack(side="left")

        def browse():
            p = filedialog.askdirectory(initialdir=folder.get(), parent=d)
            if p:
                folder.set(p)
        Btn(row, "Browse", browse, P, F["b"], w=98, h=38, bg=P["card"]).pack(side="left", padx=(sc(12), 0))
        for label, var, lo, hi, fmt in (("Connections per adapter", conns, 1, 32, None),
                                        ("Downloads at the same time", maxa, 1, 5, None),
                                        ("Speed limit (saves data)", lim, 0, 500,
                                         lambda v: "Off" if v == 0 else f"{v} MB/s")):
            r = tk.Frame(gen, bg=P["card"])
            r.pack(fill="x", pady=(sc(14), 0))
            tk.Label(r, text=label, bg=P["card"], fg=P["text"], font=F["b"]).pack(side="left")
            Stepper(r, var, lo, hi, P, F["bb"], P["card"], fmt, step=1 if lo or hi < 50 else 5).pack(side="right")

        # --- Personalization
        lab(look, "Theme", 14)
        Seg(look, THEME_NAMES, theme, P, F["sb"], cw, P["card"]).pack(anchor="w")
        lab(look, "Accent colour")
        items = [(k, v[0], v[1]) for k, v in ACCENTS.items()]
        items.append(("custom", "Custom", valid_hex(custom.get()) or "#ff6a3d"))
        sw = Swatches(look, items, accent, P, F["xs"], cw, P["card"], cols=4)
        sw.pack(anchor="w")
        lab(look, "Custom colour (hex, for example #ff6a3d)")
        Field(look, custom, P, F["b"], 200, P["card"]).pack(anchor="w")

        def typed(*_):
            h = valid_hex(custom.get())
            if h:
                accent.set("custom")
                sw.set_color("custom", h)
        custom.trace_add("write", typed)

        # --- tabs: same height for both so the window doesn't jump
        Seg(body, [("gen", "General"), ("look", "Personalization")], tab, P, F["sb"], cw, P["card"],
            cmd=lambda: show()).pack(anchor="w", pady=(sc(14), 0))
        holder.pack(fill="x")
        hmax = 0
        for f in (gen, look):
            f.pack(fill="x")
            d.update_idletasks()
            hmax = max(hmax, f.winfo_reqheight())
            f.pack_forget()
        holder.configure(height=hmax)
        holder.pack_propagate(False)

        def show():
            gen.pack_forget()
            look.pack_forget()
            (gen if tab.get() == "gen" else look).pack(fill="x")
        show()
        bt = tk.Frame(body, bg=P["card"])
        bt.pack(fill="x", pady=(sc(18), 0))

        def save():
            before = (self.cfg["theme"], self.cfg.get("accent"), self.cfg.get("custom"))
            h = valid_hex(custom.get())
            self.cfg.update(theme=theme.get(), accent=accent.get(), custom=h or self.cfg.get("custom", "#ff6a3d"),
                            units=units.get(), folder=folder.get(), conns=conns.get(),
                            max_active=maxa.get(), limit_mb=lim.get())
            if accent.get() == "custom" and not h:
                self.cfg["accent"] = "teal"
            save_cfg(self.cfg)
            self.close_dlg()
            for it in self.items:
                if it.state == "running" and it.proc:
                    try:
                        it.proc.stdin.write(f"LIMIT {int(lim.get() * 1e6)}\n")
                        it.proc.stdin.flush()
                    except Exception:
                        pass
            if before != (self.cfg["theme"], self.cfg["accent"], self.cfg["custom"]):
                self.build()
            else:
                self.hero_layout()
        Btn(bt, "Save", save, P, F["bb"], kind="accent", h=42, bg=P["card"]).pack(side="right")
        Btn(bt, "Cancel", self.close_dlg, P, F["b"], h=42, bg=P["card"]).pack(side="right", padx=(0, sc(10)))
        self.show_dlg(d)

    def network(self):
        P, F = self.P, self.F
        d, body = self.dialog("Networks", "Check that each adapter really reaches the internet on its own.", 580)
        cw = 580 - 56
        res = {}
        lines = {}
        if not self.adapters:
            tk.Label(body, text="No active network adapters found.", bg=P["card"], fg=P["warn"], font=F["b"]).pack(
                anchor="w", pady=(sc(16), 0))
        for name, ip in self.adapters:
            r = tk.Frame(body, bg=P["card2"])
            r.pack(fill="x", pady=(sc(10), 0))
            inner = tk.Frame(r, bg=P["card2"])
            inner.pack(fill="x", padx=sc(14), pady=sc(10))
            tk.Label(inner, text=name, bg=P["card2"], fg=P["text"], font=F["bb"]).grid(row=0, column=0, sticky="w")
            idx = IFINDEX.get(ip)
            route = f"forced via interface {idx}" if idx else ("routing: automatic" if not IS_WIN else "interface id not found")
            tk.Label(inner, text=f"{ip}   -   {route}", bg=P["card2"], fg=P["muted"], font=F["s"]).grid(
                row=1, column=0, sticky="w")
            v = tk.Label(inner, text="not tested", bg=P["card2"], fg=P["muted"], font=F["sb"])
            v.grid(row=0, column=1, rowspan=2, sticky="e")
            inner.grid_columnconfigure(1, weight=1)
            lines[ip] = v
        verdict = tk.Label(body, text="", bg=P["card"], fg=P["muted"], font=F["s"], wraplength=sc(cw), justify="left")
        verdict.pack(anchor="w", pady=(sc(14), 0))

        def work(ip):
            try:
                res[ip] = public_ip(ip)
            except Exception as e:
                res[ip] = "ERR " + short_err(e)

        def poll():
            if not self.dlg or self.dlg is not d:
                return
            done = True
            for ip, v in lines.items():
                if ip in res:
                    bad = res[ip].startswith("ERR")
                    v.config(text=res[ip][4:] if bad else f"public IP {res[ip]}", fg=P["danger"] if bad else P["ok"])
                else:
                    done = False
            if done and res:
                good = [x for x in res.values() if not x.startswith("ERR")]
                if len(good) < len(res):
                    verdict.config(text="At least one adapter cannot reach the internet by itself. "
                                        "Check that it is connected and has data.", fg=P["warn"])
                elif len(set(good)) == 1 and len(good) > 1:
                    verdict.config(text="Both adapters show the same public IP, so they share one internet "
                                        "connection. Speeds will not add up.", fg=P["warn"])
                else:
                    verdict.config(text="Independent links. Their speeds can add up.", fg=P["ok"])
                return
            d.after(300, poll)

        def test():
            res.clear()
            verdict.config(text="Testing...", fg=P["muted"])
            for ip, v in lines.items():
                v.config(text="testing...", fg=P["muted"])
                threading.Thread(target=work, args=(ip,), daemon=True).start()
            poll()
        bt = tk.Frame(body, bg=P["card"])
        bt.pack(fill="x", pady=(sc(18), 0))
        Btn(bt, "Test adapters", test, P, F["bb"], kind="accent", h=42, bg=P["card"]).pack(side="right")
        Btn(bt, "Close", self.close_dlg, P, F["b"], h=42, bg=P["card"]).pack(side="right", padx=(0, sc(10)))
        self.show_dlg(d)


def run_gui():
    App().root.mainloop()


if __name__ == "__main__":
    run_gui()
