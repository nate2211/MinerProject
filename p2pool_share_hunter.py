from __future__ import annotations

import base64
import ipaddress
import struct
import ctypes
import ctypes.util
import hashlib
import json
import os
import re
import select
import socket
import struct
import sys
import threading
import time
from collections import defaultdict, deque
from ctypes import POINTER, byref, c_uint32, c_uint64, c_ubyte, cast, memmove
from dataclasses import dataclass
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen
from typing import Any, Callable, Deque, Dict, Iterable, List, Optional, Set, Tuple

from monero_job import MoneroJob
from randomx_ctypes import RandomX


def _normalize_router_api_base_url(base_url: Optional[str], default_port: int = 8844) -> str:
    raw = str(base_url or '').strip()
    if not raw:
        return f'http://127.0.0.1:{int(default_port)}'
    if not re.match(r'^[A-Za-z][A-Za-z0-9+.-]*://', raw):
        raw = f'http://{raw}'
    m = re.match(r'^(?P<scheme>https?)://(?P<authority>[^/]+)', raw, re.IGNORECASE)
    if not m:
        return f'http://127.0.0.1:{int(default_port)}'
    scheme = str(m.group('scheme') or 'http').lower()
    authority = str(m.group('authority') or '').strip()
    host = authority
    port_digits = ''
    if authority.startswith('['):
        end = authority.find(']')
        if end > 0:
            host = authority[:end + 1]
            tail = authority[end + 1:]
            if tail.startswith(':'):
                port_digits = ''.join(ch for ch in tail[1:] if ch.isdigit())
    else:
        if authority.count(':') == 1:
            maybe_host, maybe_port = authority.rsplit(':', 1)
            if maybe_host:
                host = maybe_host.strip()
            port_digits = ''.join(ch for ch in maybe_port if ch.isdigit())
        elif authority.count(':') > 1 and not authority.startswith('['):
            host = authority.strip()
    host = str(host or '').strip() or '127.0.0.1'

    if not port_digits:
        port_digits = str(int(default_port))
    try:
        port_value = int(port_digits)
    except Exception:
        port_value = int(default_port)
    if port_value <= 0 or port_value > 65535:
        port_value = int(default_port)

    return f'{scheme}://{host}:{port_value}'


@dataclass
class CaptureDevice:
    name: str
    description: str = ""
    addresses: List[str] = None
    flags: int = 0

    def __post_init__(self) -> None:
        if self.addresses is None:
            self.addresses = []


class LibpcapError(RuntimeError):
    pass


class _TimeVal(ctypes.Structure):
    _fields_ = [("tv_sec", ctypes.c_long), ("tv_usec", ctypes.c_long)]


class _PcapPkthdr(ctypes.Structure):
    _fields_ = [("ts", _TimeVal), ("caplen", ctypes.c_uint32), ("len", ctypes.c_uint32)]


class _SockAddr(ctypes.Structure):
    _fields_ = [("sa_family", ctypes.c_ushort), ("sa_data", ctypes.c_ubyte * 14)]


class _PcapAddr(ctypes.Structure):
    pass


_PcapAddr._fields_ = [
    ("next", ctypes.POINTER(_PcapAddr)),
    ("addr", ctypes.POINTER(_SockAddr)),
    ("netmask", ctypes.POINTER(_SockAddr)),
    ("broadaddr", ctypes.POINTER(_SockAddr)),
    ("dstaddr", ctypes.POINTER(_SockAddr)),
]


class _PcapIf(ctypes.Structure):
    pass


_PcapIf._fields_ = [
    ("next", ctypes.POINTER(_PcapIf)),
    ("name", ctypes.c_char_p),
    ("description", ctypes.c_char_p),
    ("addresses", ctypes.POINTER(_PcapAddr)),
    ("flags", ctypes.c_uint32),
]


class _BpfInsn(ctypes.Structure):
    _fields_ = [("code", ctypes.c_ushort), ("jt", ctypes.c_ubyte), ("jf", ctypes.c_ubyte), ("k", ctypes.c_uint32)]


class _BpfProgram(ctypes.Structure):
    _fields_ = [("bf_len", ctypes.c_uint32), ("bf_insns", ctypes.POINTER(_BpfInsn))]


@dataclass
class _CaptureState:
    device_name: str = ""
    bpf_filter: str = ""
    running: bool = False


class LibpcapBackend:
    def __init__(self) -> None:
        self._lib = self._load_library()
        self._declare_functions()
        self._handle = ctypes.c_void_p()
        self._capture_thread: Optional[threading.Thread] = None
        self._stop_capture = threading.Event()
        self._capture_state = _CaptureState()
        self._lock = threading.RLock()
        self._packet_counter = 0
        self._callback: Optional[Callable[[Dict[str, Any]], None]] = None
        self._last_error: Optional[str] = None
        self._active_device_name: str = ""
        self._capture_generation = 0

    @property
    def last_error(self) -> Optional[str]:
        return self._last_error

    @staticmethod
    def _load_library() -> ctypes.CDLL:
        candidates: List[str] = []
        for name in ('wpcap', 'pcap', ctypes.util.find_library('pcap'), ctypes.util.find_library('wpcap')):
            if name and name not in candidates:
                candidates.append(name)
        errors: List[str] = []
        for name in candidates:
            try:
                return ctypes.CDLL(name)
            except OSError as exc:
                errors.append(f'{name}: {exc}')
        raise LibpcapError('Unable to load libpcap/Npcap. Install Npcap on Windows or libpcap on Linux/macOS. Errors: ' + '; '.join(errors))

    def _declare_functions(self) -> None:
        self._lib.pcap_findalldevs.argtypes = [ctypes.POINTER(ctypes.POINTER(_PcapIf)), ctypes.c_char_p]
        self._lib.pcap_findalldevs.restype = ctypes.c_int
        self._lib.pcap_freealldevs.argtypes = [ctypes.POINTER(_PcapIf)]
        self._lib.pcap_freealldevs.restype = None
        self._lib.pcap_open_live.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_char_p]
        self._lib.pcap_open_live.restype = ctypes.c_void_p
        self._lib.pcap_close.argtypes = [ctypes.c_void_p]
        self._lib.pcap_close.restype = None
        self._lib.pcap_next_ex.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.POINTER(_PcapPkthdr)), ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte))]
        self._lib.pcap_next_ex.restype = ctypes.c_int
        self._lib.pcap_sendpacket.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int]
        self._lib.pcap_sendpacket.restype = ctypes.c_int
        self._lib.pcap_geterr.argtypes = [ctypes.c_void_p]
        self._lib.pcap_geterr.restype = ctypes.c_char_p
        self._lib.pcap_compile.argtypes = [ctypes.c_void_p, ctypes.POINTER(_BpfProgram), ctypes.c_char_p, ctypes.c_int, ctypes.c_uint32]
        self._lib.pcap_compile.restype = ctypes.c_int
        self._lib.pcap_setfilter.argtypes = [ctypes.c_void_p, ctypes.POINTER(_BpfProgram)]
        self._lib.pcap_setfilter.restype = ctypes.c_int
        self._lib.pcap_freecode.argtypes = [ctypes.POINTER(_BpfProgram)]
        self._lib.pcap_freecode.restype = None
        if hasattr(self._lib, 'pcap_setnonblock'):
            self._lib.pcap_setnonblock.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_char_p]
            self._lib.pcap_setnonblock.restype = ctypes.c_int

    def _errbuf(self):
        return ctypes.create_string_buffer(512)

    def _handle_error(self, handle: Optional[ctypes.c_void_p] = None, fallback: str = 'libpcap call failed') -> None:
        message = fallback
        if handle:
            try:
                raw = self._lib.pcap_geterr(handle)
                if raw:
                    message = raw.decode(errors='replace')
            except Exception:
                pass
        self._last_error = message
        raise LibpcapError(message)

    def list_devices(self) -> List[CaptureDevice]:
        errbuf = self._errbuf()
        alldevs = ctypes.POINTER(_PcapIf)()
        rc = self._lib.pcap_findalldevs(ctypes.byref(alldevs), errbuf)
        if rc != 0:
            raise LibpcapError(errbuf.value.decode(errors='replace') or 'pcap_findalldevs failed')
        devices: List[CaptureDevice] = []
        try:
            current = alldevs
            while current:
                item = current.contents
                name = item.name.decode(errors='replace') if item.name else ''
                description = item.description.decode(errors='replace') if item.description else ''
                addresses: List[str] = []
                addr_ptr = item.addresses
                while addr_ptr:
                    try:
                        sockaddr = addr_ptr.contents.addr.contents
                        addresses.append(self._sockaddr_to_text(sockaddr))
                    except Exception:
                        pass
                    addr_ptr = addr_ptr.contents.next
                devices.append(CaptureDevice(name=name, description=description, addresses=addresses, flags=int(item.flags)))
                current = item.next
        finally:
            if alldevs:
                self._lib.pcap_freealldevs(alldevs)
        return devices

    @staticmethod
    def _sockaddr_to_text(sockaddr: _SockAddr) -> str:
        family = int(sockaddr.sa_family)
        if family == socket.AF_INET:
            raw = bytes(sockaddr.sa_data[2:6])
            return socket.inet_ntoa(raw)
        if family == getattr(socket, 'AF_INET6', 23):
            raw = bytes(sockaddr.sa_data)
            return raw.hex()
        return f'family={family}'

    def open_device(self, device_name: str, *, snaplen: int = 65535, promiscuous: bool = True, timeout_ms: int = 250, bpf_filter: str = '') -> None:
        with self._lock:
            self.close_device()
            errbuf = self._errbuf()
            handle = self._lib.pcap_open_live(str(device_name).encode(), int(snaplen), 1 if promiscuous else 0, int(timeout_ms), errbuf)
            if not handle:
                message = errbuf.value.decode(errors='replace') or f'Unable to open device {device_name}'
                self._last_error = message
                raise LibpcapError(message)
            self._handle = ctypes.c_void_p(handle)
            self._active_device_name = str(device_name)
            if hasattr(self._lib, 'pcap_setnonblock'):
                try:
                    nb_err = self._errbuf()
                    self._lib.pcap_setnonblock(self._handle, 0, nb_err)
                except Exception:
                    pass
            if bpf_filter.strip():
                self.set_filter(bpf_filter)

    def close_device(self) -> None:
        with self._lock:
            handle = self._handle
            if handle:
                try:
                    self._lib.pcap_close(handle)
                finally:
                    self._handle = ctypes.c_void_p()
                    self._active_device_name = ''

    def set_filter(self, bpf_filter: str) -> None:
        if not self._handle:
            raise LibpcapError('No active capture handle')
        program = _BpfProgram()
        rc = self._lib.pcap_compile(self._handle, ctypes.byref(program), str(bpf_filter).encode(), 1, 0xFFFFFFFF)
        if rc != 0:
            self._handle_error(self._handle, f'Unable to compile BPF filter: {bpf_filter}')
        try:
            rc = self._lib.pcap_setfilter(self._handle, ctypes.byref(program))
            if rc != 0:
                self._handle_error(self._handle, f'Unable to apply BPF filter: {bpf_filter}')
        finally:
            self._lib.pcap_freecode(ctypes.byref(program))

    def start_capture(self, device_name: str, callback: Callable[[Dict[str, Any]], None], *, bpf_filter: str = '', promiscuous: bool = True, snaplen: int = 65535, timeout_ms: int = 250) -> None:
        with self._lock:
            self.stop_capture()
            self.open_device(device_name, snaplen=snaplen, promiscuous=promiscuous, timeout_ms=timeout_ms, bpf_filter=bpf_filter)
            self._callback = callback
            self._stop_capture.clear()
            self._capture_generation += 1
            generation = self._capture_generation
            self._capture_state = _CaptureState(device_name=device_name, bpf_filter=bpf_filter, running=True)
            self._capture_thread = threading.Thread(target=self._capture_loop, args=(generation,), daemon=True, name='MinerInterface-PcapCapture')
            self._capture_thread.start()

    def stop_capture(self) -> None:
        with self._lock:
            self._stop_capture.set()
            self._capture_generation += 1
            thread = self._capture_thread
            self._capture_thread = None
            self._capture_state.running = False
            self._callback = None
        if thread and thread.is_alive() and thread is not threading.current_thread():
            thread.join(timeout=3.0)
        with self._lock:
            self.close_device()
            self._capture_state = _CaptureState()

    def _capture_loop(self, generation: int) -> None:
        header_ptr = ctypes.POINTER(_PcapPkthdr)()
        data_ptr = ctypes.POINTER(ctypes.c_ubyte)()
        while not self._stop_capture.is_set():
            with self._lock:
                handle = self._handle
                device_name = self._active_device_name
                callback = self._callback
                active_generation = self._capture_generation
            if generation != active_generation or not handle:
                break
            try:
                rc = self._lib.pcap_next_ex(handle, ctypes.byref(header_ptr), ctypes.byref(data_ptr))
                if rc == 0:
                    continue
                if rc < 0:
                    if rc == -2 or self._stop_capture.is_set() or generation != self._capture_generation:
                        break
                    self._handle_error(handle, 'pcap_next_ex failed')
                header = header_ptr.contents
                raw = ctypes.string_at(data_ptr, int(header.caplen))
                self._packet_counter += 1
                packet = self._decode_packet(raw, ts_sec=int(header.ts.tv_sec), ts_usec=int(header.ts.tv_usec), wire_len=int(header.len), cap_len=int(header.caplen))
                packet['capture_index'] = self._packet_counter
                packet['device_name'] = device_name
                if callback is not None and not self._stop_capture.is_set() and generation == self._capture_generation:
                    callback(packet)
            except Exception as exc:
                if self._stop_capture.is_set() or generation != self._capture_generation:
                    break
                self._last_error = f'capture_loop: {type(exc).__name__}: {exc}'
                error_payload = {'kind': 'capture_error', 'message': self._last_error, 'device_name': device_name, 'ts': time.time()}
                if callback is not None:
                    try:
                        callback(error_payload)
                    except Exception:
                        pass
                time.sleep(0.10)
        self._capture_state.running = False

    def send_packet(self, frame: bytes) -> Dict[str, Any]:
        if not self._handle:
            raise LibpcapError('No active device is open')
        if not isinstance(frame, (bytes, bytearray)):
            raise TypeError('frame must be bytes')
        arr = (ctypes.c_ubyte * len(frame)).from_buffer_copy(bytes(frame))
        rc = self._lib.pcap_sendpacket(self._handle, arr, len(frame))
        if rc != 0:
            self._handle_error(self._handle, 'pcap_sendpacket failed')
        return {'ok': True, 'device_name': self._active_device_name, 'length': len(frame), 'sent_at': time.time()}

    def send_packet_once(self, device_name: str, frame: bytes, *, promiscuous: bool = True) -> Dict[str, Any]:
        with self._lock:
            existing_handle = self._handle
            existing_name = self._active_device_name
            if existing_handle and existing_name == device_name:
                return self.send_packet(frame)
            errbuf = self._errbuf()
            handle = self._lib.pcap_open_live(str(device_name).encode(), 65535, 1 if promiscuous else 0, 250, errbuf)
            if not handle:
                message = errbuf.value.decode(errors='replace') or f'Unable to open device {device_name}'
                self._last_error = message
                raise LibpcapError(message)
            temp_handle = ctypes.c_void_p(handle)
            try:
                arr = (ctypes.c_ubyte * len(frame)).from_buffer_copy(bytes(frame))
                rc = self._lib.pcap_sendpacket(temp_handle, arr, len(frame))
                if rc != 0:
                    self._handle_error(temp_handle, 'pcap_sendpacket failed')
                return {'ok': True, 'device_name': device_name, 'length': len(frame), 'sent_at': time.time()}
            finally:
                self._lib.pcap_close(temp_handle)

    @property
    def capture_running(self) -> bool:
        return bool(self._capture_state.running)

    @property
    def active_device_name(self) -> str:
        return self._active_device_name

    def _decode_packet(self, raw: bytes, *, ts_sec: int, ts_usec: int, wire_len: int, cap_len: int) -> Dict[str, Any]:
        packet: Dict[str, Any] = {
            'kind': 'packet', 'ts': float(ts_sec) + (float(ts_usec) / 1_000_000.0), 'ts_sec': ts_sec, 'ts_usec': ts_usec,
            'wire_len': wire_len, 'cap_len': cap_len, 'captured_len': cap_len, 'raw_len': cap_len, 'raw_hex_preview': raw[:64].hex(),
            'raw_hex': raw.hex(), 'raw_base64': base64.b64encode(raw).decode('ascii'), 'summary': f'{cap_len} bytes',
            'topic': 'ethernet', 'l3': 'unknown', 'proto': 'unknown', 'src_mac': None, 'dst_mac': None, 'src_ip': None,
            'dst_ip': None, 'sport': None, 'dport': None, 'flags': None, 'has_raw': True, 'capture_quality': 'libpcap_raw',
        }
        if len(raw) < 14:
            return packet
        dst_mac = ':'.join(f'{b:02x}' for b in raw[0:6])
        src_mac = ':'.join(f'{b:02x}' for b in raw[6:12])
        eth_type = struct.unpack('!H', raw[12:14])[0]
        packet.update({'src_mac': src_mac, 'dst_mac': dst_mac, 'eth_type': f'0x{eth_type:04x}', 'source': 'libpcap', 'iface': self._active_device_name})
        if eth_type == 0x0800 and len(raw) >= 34:
            packet['l3'] = 'ipv4'
            ihl = (raw[14] & 0x0F) * 4
            if len(raw) < 14 + ihl:
                return packet
            proto = raw[23]
            src_ip = socket.inet_ntoa(raw[26:30])
            dst_ip = socket.inet_ntoa(raw[30:34])
            packet.update({'src_ip': src_ip, 'dst_ip': dst_ip})
            offset = 14 + ihl
            if proto == 6 and len(raw) >= offset + 20:
                sport, dport, seq, ack, off_flags = struct.unpack('!HHIIH', raw[offset: offset + 14])
                flags = off_flags & 0x01FF
                packet.update({'proto': 'tcp', 'topic': 'transport', 'sport': sport, 'dport': dport, 'seq': seq, 'ack': ack, 'flags': self._tcp_flags_text(flags), 'summary': f'TCP {src_ip}:{sport} -> {dst_ip}:{dport} {self._tcp_flags_text(flags)}'})
                self._apply_topic_from_ports(packet)
            elif proto == 17 and len(raw) >= offset + 8:
                sport, dport, udp_len, _ = struct.unpack('!HHHH', raw[offset: offset + 8])
                packet.update({'proto': 'udp', 'topic': 'transport', 'sport': sport, 'dport': dport, 'summary': f'UDP {src_ip}:{sport} -> {dst_ip}:{dport} len={udp_len}'})
                self._apply_topic_from_ports(packet)
            elif proto == 1 and len(raw) >= offset + 4:
                packet.update({'proto': 'icmp', 'topic': 'icmp', 'summary': f'ICMP {src_ip} -> {dst_ip}'})
            else:
                packet.update({'proto': str(proto), 'summary': f'IPv4 proto={proto} {src_ip} -> {dst_ip}'})
            return packet
        if eth_type == 0x0806 and len(raw) >= 42:
            packet.update({'topic': 'arp', 'l3': 'arp', 'proto': 'arp', 'src_ip': socket.inet_ntoa(raw[28:32]), 'dst_ip': socket.inet_ntoa(raw[38:42]), 'summary': f'ARP {socket.inet_ntoa(raw[28:32])} -> {socket.inet_ntoa(raw[38:42])}'})
        return packet

    @staticmethod
    def _tcp_flags_text(flags: int) -> str:
        names = []
        mapping = [(0x001, 'FIN'), (0x002, 'SYN'), (0x004, 'RST'), (0x008, 'PSH'), (0x010, 'ACK'), (0x020, 'URG'), (0x040, 'ECE'), (0x080, 'CWR')]
        for mask, name in mapping:
            if flags & mask:
                names.append(name)
        return ','.join(names) if names else 'NONE'

    @staticmethod
    def _apply_topic_from_ports(packet: Dict[str, Any]) -> None:
        dport = int(packet.get('dport') or 0)
        sport = int(packet.get('sport') or 0)
        topics = {53: 'dns', 67: 'dhcp', 68: 'dhcp', 80: 'http', 443: 'https', 3333: 'stratum', 37888: 'p2pool', 37889: 'p2pool', 18080: 'monero', 18081: 'monero', 18083: 'monero'}
        packet['topic'] = topics.get(dport) or topics.get(sport) or packet.get('topic') or 'transport'
        proto = packet.get('proto')
        src_ip = packet.get('src_ip')
        dst_ip = packet.get('dst_ip')
        if packet.get('sport') and packet.get('dport'):
            packet['summary'] = f"{str(proto).upper()} {src_ip}:{packet['sport']} -> {dst_ip}:{packet['dport']} [{packet['topic']}]"


@dataclass(frozen=True)
class P2PoolBestCandidate:
    nonce_u32: int
    value64: int
    result32: bytes

    @property
    def hash_hex(self) -> str:
        return self.result32.hex()


class _FastTail64Probe:
    __slots__ = ()

    @staticmethod
    def read_tail64(out_buf) -> int:
        return (
            int(out_buf[24])
            | (int(out_buf[25]) << 8)
            | (int(out_buf[26]) << 16)
            | (int(out_buf[27]) << 24)
            | (int(out_buf[28]) << 32)
            | (int(out_buf[29]) << 40)
            | (int(out_buf[30]) << 48)
            | (int(out_buf[31]) << 56)
        )


class _ChangeGate:
    __slots__ = ("_mu", "_last_ts", "_last_key")

    def __init__(self) -> None:
        self._mu = threading.Lock()
        self._last_ts = 0.0
        self._last_key: Tuple[Any, ...] = ()

    def should_emit(self, *, key: Tuple[Any, ...], min_interval_sec: float, force: bool = False) -> bool:
        now = time.time()
        with self._mu:
            changed = key != self._last_key
            cooled = (now - self._last_ts) >= float(min_interval_sec)
            if force or changed or cooled:
                self._last_key = key
                self._last_ts = now
                return True
            return False


class _RecentRateWindow:
    __slots__ = ("window_sec", "samples")

    def __init__(self, window_sec: float = 10.0) -> None:
        self.window_sec = max(1.0, float(window_sec))
        self.samples: Deque[Tuple[float, Tuple[int, ...]]] = deque(maxlen=256)

    def add(self, now: float, values: Tuple[int, ...]) -> None:
        self.samples.append((float(now), tuple(int(v) for v in values)))
        cutoff = float(now) - (self.window_sec * 2.0)
        while len(self.samples) > 2 and self.samples[0][0] < cutoff:
            self.samples.popleft()

    def diff_rate(self, now: float) -> Tuple[float, ...]:
        if len(self.samples) < 2:
            if not self.samples:
                return tuple()
            return tuple(0.0 for _ in self.samples[-1][1])

        newest_t, newest_vals = self.samples[-1]
        oldest_t, oldest_vals = self.samples[0]
        target_t = float(now) - self.window_sec
        for t, vals in self.samples:
            if t >= target_t:
                oldest_t, oldest_vals = t, vals
                break

        dt = max(0.001, newest_t - oldest_t)
        return tuple((float(nv - ov) / dt) for nv, ov in zip(newest_vals, oldest_vals))


class _SharedStatusState:
    __slots__ = ("gate", "min_interval_sec", "hash_bucket_size")

    def __init__(self, min_interval_sec: float = 12.0) -> None:
        self.gate = _ChangeGate()
        self.min_interval_sec = max(12.0, float(min_interval_sec))
        self.hash_bucket_size = 4096


class _UniqueNonceCandidatePool:
    """
    Keeps one best row per nonce.
    Lower value64 wins. On tie, lower nonce wins.
    """

    __slots__ = ("limit", "_rows")

    def __init__(self, limit: int) -> None:
        self.limit = max(1, int(limit))
        self._rows: Dict[int, Tuple[int, int, bytes]] = {}

    def __len__(self) -> int:
        return len(self._rows)

    def clear(self) -> None:
        self._rows.clear()

    def add(self, row: Tuple[int, int, bytes]) -> bool:
        nonce_u32, value64, result32 = row
        nonce_key = int(nonce_u32) & 0xFFFFFFFF
        prev = self._rows.get(nonce_key)

        if prev is not None:
            if (int(value64), int(nonce_u32)) >= (int(prev[1]), int(prev[0])):
                return False

        self._rows[nonce_key] = (int(nonce_u32), int(value64), bytes(result32))

        if len(self._rows) > self.limit:
            worst_nonce = None
            worst_score = None
            for nk, r in self._rows.items():
                score = (int(r[1]), int(r[0]))
                if worst_score is None or score > worst_score:
                    worst_score = score
                    worst_nonce = nk
            if worst_nonce is not None:
                self._rows.pop(worst_nonce, None)

        return True

    def extend(self, rows: Iterable[Tuple[int, int, bytes]]) -> int:
        added = 0
        for row in rows:
            if self.add(row):
                added += 1
        return added

    def rows_sorted(self, cap: Optional[int] = None) -> List[Tuple[int, int, bytes]]:
        out = sorted(self._rows.values(), key=lambda x: (int(x[1]), int(x[0])))
        if cap is not None:
            out = out[: max(0, int(cap))]
        return out


class _RecentTemplateNonceGuard:
    """
    Per job-template recent nonce guard.

    A nonce can only be admitted once for the same stable job template while it
    remains in the recent window. This prevents duplicate shares from multiple
    threads and repeated hash_job() calls for the same live job.
    """

    __slots__ = ("_mu", "_seen", "_order", "_max_entries")

    def __init__(self, max_entries: int = 1_000_000) -> None:
        self._mu = threading.Lock()
        self._seen: Set[Tuple[str, int]] = set()
        self._order: Deque[Tuple[str, int]] = deque()
        self._max_entries = max(8192, int(max_entries))

    def claim(self, job_key: str, nonce_u32: int) -> bool:
        key = (str(job_key), int(nonce_u32) & 0xFFFFFFFF)
        with self._mu:
            if key in self._seen:
                return False
            self._seen.add(key)
            self._order.append(key)
            while len(self._order) > self._max_entries:
                old = self._order.popleft()
                self._seen.discard(old)
            return True

    def clear(self) -> None:
        with self._mu:
            self._seen.clear()
            self._order.clear()


class _RecentTemplateSubmitGuard:
    """
    Per job-template submit guard.

    A candidate nonce can only be reserved for submit once for the same stable
    job template. This closes the last duplicate gap if the same candidate is
    observed by multiple lanes or if upstream code also inspects returned
    `found` rows after an internal submit callback was already used.
    """

    __slots__ = ("_mu", "_seen", "_order", "_max_entries")

    def __init__(self, max_entries: int = 1_000_000) -> None:
        self._mu = threading.Lock()
        self._seen: Set[Tuple[str, int]] = set()
        self._order: Deque[Tuple[str, int]] = deque()
        self._max_entries = max(8192, int(max_entries))

    def claim(self, job_key: str, nonce_u32: int) -> bool:
        key = (str(job_key), int(nonce_u32) & 0xFFFFFFFF)
        with self._mu:
            if key in self._seen:
                return False
            self._seen.add(key)
            self._order.append(key)
            while len(self._order) > self._max_entries:
                old = self._order.popleft()
                self._seen.discard(old)
            return True

    def forget(self, job_key: str, nonce_u32: int) -> None:
        key = (str(job_key), int(nonce_u32) & 0xFFFFFFFF)
        with self._mu:
            self._seen.discard(key)

    def contains(self, job_key: str, nonce_u32: int) -> bool:
        key = (str(job_key), int(nonce_u32) & 0xFFFFFFFF)
        with self._mu:
            return key in self._seen

    def clear(self) -> None:
        with self._mu:
            self._seen.clear()
            self._order.clear()


class _JobLeaseSession:
    """
    Shared nonce allocator for a live job template.

    Every hash_job() call for the same template leases a fresh, non-overlapping
    nonce span. That prevents overlap across concurrent callers.
    """

    __slots__ = ("job_key", "_mu", "_next_nonce", "_last_seen_ts")

    def __init__(self, job_key: str, start_nonce: int) -> None:
        self.job_key = str(job_key)
        self._mu = threading.Lock()
        self._next_nonce = int(start_nonce) & 0xFFFFFFFF
        self._last_seen_ts = time.time()

    def lease(self, total_nonces: int) -> int:
        total_nonces = max(1, int(total_nonces))
        with self._mu:
            start = self._next_nonce
            self._next_nonce = (self._next_nonce + total_nonces) & 0xFFFFFFFF
            self._last_seen_ts = time.time()
            return start

    def touch(self) -> None:
        with self._mu:
            self._last_seen_ts = time.time()

    def age_sec(self) -> float:
        with self._mu:
            return time.time() - self._last_seen_ts


class _JobLeaseManager:
    __slots__ = ("_mu", "_sessions", "_ttl_sec")

    def __init__(self, ttl_sec: float = 300.0) -> None:
        self._mu = threading.Lock()
        self._sessions: Dict[str, _JobLeaseSession] = {}
        self._ttl_sec = max(30.0, float(ttl_sec))

    def get_or_create(self, job_key: str, start_nonce: int) -> _JobLeaseSession:
        with self._mu:
            self._gc_locked()
            sess = self._sessions.get(job_key)
            if sess is None:
                sess = _JobLeaseSession(job_key=job_key, start_nonce=start_nonce)
                self._sessions[job_key] = sess
            else:
                sess.touch()
            return sess

    def _gc_locked(self) -> None:
        dead = [k for k, v in self._sessions.items() if v.age_sec() > self._ttl_sec]
        for k in dead:
            self._sessions.pop(k, None)



class _RC_Event(ctypes.Structure):
    _fields_ = [
        ("frame_id", ctypes.c_uint64),
        ("timestamp_ms", ctypes.c_uint64),
        ("event_type", ctypes.c_uint32),
        ("service", ctypes.c_uint32),
        ("direction", ctypes.c_uint32),
        ("command_family", ctypes.c_uint32),
        ("command", ctypes.c_uint32),
        ("return_code", ctypes.c_int32),
        ("flags", ctypes.c_uint32),
        ("protocol_version", ctypes.c_uint32),
        ("body_size", ctypes.c_uint64),
        ("expect_response", ctypes.c_uint8),
        ("validation_ok", ctypes.c_uint8),
        ("portable_storage_ok", ctypes.c_uint8),
        ("fragment_count", ctypes.c_uint16),
        ("semantic_mask", ctypes.c_uint32),
        ("decoded_current_height", ctypes.c_uint64),
        ("decoded_current_blockchain_height", ctypes.c_uint64),
        ("decoded_start_height", ctypes.c_uint64),
        ("decoded_total_height", ctypes.c_uint64),
        ("decoded_cumulative_difficulty_low64", ctypes.c_uint64),
        ("decoded_cumulative_difficulty_high64", ctypes.c_uint64),
        ("decoded_peer_id", ctypes.c_uint64),
        ("decoded_my_port", ctypes.c_uint32),
        ("decoded_rpc_port", ctypes.c_uint16),
        ("decoded_local_peerlist_count", ctypes.c_uint16),
        ("decoded_rpc_credits_per_hash", ctypes.c_uint32),
        ("decoded_support_flags", ctypes.c_uint32),
        ("decoded_pruning_seed", ctypes.c_uint32),
        ("decoded_top_version", ctypes.c_uint8),
        ("decoded_top_id_hex", ctypes.c_char * 65),
        ("decoded_status", ctypes.c_char * 64),
        ("stream_id", ctypes.c_char * 64),
        ("peer", ctypes.c_char * 128),
        ("note", ctypes.c_char * 192),
        ("semantic_summary", ctypes.c_char * 256),
    ]


class RemoteConnectionDll:
    RC_SERVICE_UNKNOWN = 0
    RC_SERVICE_MONERO_P2P = 1
    RC_SERVICE_P2POOL_P2P = 2

    RC_DIR_UNKNOWN = 0
    RC_DIR_INBOUND = 1
    RC_DIR_OUTBOUND = 2

    RC_EVENT_NONE = 0
    RC_EVENT_VALIDATED_FRAME = 1
    RC_EVENT_DUMMY_FRAME = 2
    RC_EVENT_INVALID_FRAME = 3

    _LOGGER_CB = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_char_p)

    def __init__(
        self,
        dll_path: Optional[str] = None,
        *,
        logger: Optional[Callable[[str], None]] = None,
    ) -> None:
        self.logger = logger or (lambda s: None)
        self._mu = threading.RLock()
        self._dll_path = self._resolve_dll_path(dll_path)
        self._dll = ctypes.CDLL(self._dll_path)
        self._handle = ctypes.c_void_p()
        self._logger_cb_ref: Optional[Any] = None
        self._configured = False
        self._closed = False
        self._configure_signatures()
        rc = int(self._dll.RC_Create(ctypes.byref(self._handle)))
        if rc != 0 or not self._handle.value:
            raise RuntimeError(f"RC_Create failed rc={rc} dll={self._dll_path}")
        self._configured = True
        self._install_logger()

    @staticmethod
    def _resolve_dll_path(dll_path: Optional[str]) -> str:
        candidates: List[Path] = []
        if dll_path:
            candidates.append(Path(dll_path))
        try:
            here = Path(__file__).resolve().parent
            candidates.append(here / "RemoteConnection.dll")
        except Exception:
            pass
        candidates.append(Path.cwd() / "RemoteConnection.dll")
        for cand in candidates:
            try:
                if cand.exists():
                    return str(cand.resolve())
            except Exception:
                continue
        raise FileNotFoundError("RemoteConnection.dll was not found in the script directory or current working directory")

    def _configure_signatures(self) -> None:
        self._dll.RC_Create.argtypes = [ctypes.POINTER(ctypes.c_void_p)]
        self._dll.RC_Create.restype = ctypes.c_int

        self._dll.RC_Destroy.argtypes = [ctypes.c_void_p]
        self._dll.RC_Destroy.restype = ctypes.c_int

        self._dll.RC_Reset.argtypes = [ctypes.c_void_p]
        self._dll.RC_Reset.restype = ctypes.c_int

        self._dll.RC_SetLogger.argtypes = [ctypes.c_void_p, self._LOGGER_CB, ctypes.c_void_p]
        self._dll.RC_SetLogger.restype = ctypes.c_int

        self._dll.RC_OpenStream.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint32]
        self._dll.RC_OpenStream.restype = ctypes.c_int

        self._dll.RC_CloseStream.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        self._dll.RC_CloseStream.restype = ctypes.c_int

        self._dll.RC_FeedTcpBytes.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_size_t,
            ctypes.c_uint64,
        ]
        self._dll.RC_FeedTcpBytes.restype = ctypes.c_int

        self._dll.RC_PollEvent.argtypes = [ctypes.c_void_p, ctypes.POINTER(_RC_Event)]
        self._dll.RC_PollEvent.restype = ctypes.c_int

        self._dll.RC_CopyFrameBody.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint64,
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_size_t),
        ]
        self._dll.RC_CopyFrameBody.restype = ctypes.c_int

        self._dll.RC_CopySemanticJson.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint64,
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_size_t),
        ]
        self._dll.RC_CopySemanticJson.restype = ctypes.c_int

        self._dll.RC_ReleaseFrame.argtypes = [ctypes.c_void_p, ctypes.c_uint64]
        self._dll.RC_ReleaseFrame.restype = ctypes.c_int

        self._dll.RC_GetLastError.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t]
        self._dll.RC_GetLastError.restype = ctypes.c_int

    def _install_logger(self) -> None:
        def _cb(_user_data, message_ptr):
            try:
                msg = ctypes.cast(message_ptr, ctypes.c_char_p).value.decode("utf-8", errors="ignore") if message_ptr else ""
            except Exception:
                msg = ""
            if msg:
                try:
                    self.logger(f"[RemoteConnection.dll] {msg}")
                except Exception:
                    pass

        self._logger_cb_ref = self._LOGGER_CB(_cb)
        try:
            self._dll.RC_SetLogger(self._handle, self._logger_cb_ref, None)
        except Exception:
            pass

    @staticmethod
    def _decode_c_string(buf: Any) -> str:
        try:
            return bytes(buf).split(b"\x00", 1)[0].decode("utf-8", errors="ignore")
        except Exception:
            return ""

    def get_last_error(self) -> str:
        if not self._handle:
            return "dll handle is closed"
        buf = ctypes.create_string_buffer(1024)
        try:
            self._dll.RC_GetLastError(self._handle, buf, ctypes.sizeof(buf))
        except Exception as e:
            return str(e)
        return buf.value.decode("utf-8", errors="ignore")

    def _rc_ok(self, rc: int, func_name: str) -> None:
        if int(rc) != 0:
            raise RuntimeError(f"{func_name} failed rc={rc} err={self.get_last_error()}")

    def reset(self) -> None:
        with self._mu:
            self._rc_ok(self._dll.RC_Reset(self._handle), "RC_Reset")

    def open_stream(self, stream_id: str, peer: str, service: int) -> None:
        with self._mu:
            self._rc_ok(
                self._dll.RC_OpenStream(
                    self._handle,
                    stream_id.encode("utf-8", errors="ignore"),
                    peer.encode("utf-8", errors="ignore"),
                    int(service),
                ),
                "RC_OpenStream",
            )

    def close_stream(self, stream_id: str) -> None:
        with self._mu:
            self._rc_ok(
                self._dll.RC_CloseStream(
                    self._handle,
                    stream_id.encode("utf-8", errors="ignore"),
                ),
                "RC_CloseStream",
            )

    def feed_tcp_bytes(
        self,
        stream_id: str,
        direction: int,
        data: bytes,
        timestamp_ms: Optional[int] = None,
    ) -> None:
        blob = bytes(data or b"")
        if not blob:
            return
        if timestamp_ms is None:
            timestamp_ms = int(time.time() * 1000.0)
        arr = (ctypes.c_uint8 * len(blob)).from_buffer_copy(blob)
        with self._mu:
            self._rc_ok(
                self._dll.RC_FeedTcpBytes(
                    self._handle,
                    stream_id.encode("utf-8", errors="ignore"),
                    int(direction),
                    arr,
                    len(blob),
                    int(timestamp_ms),
                ),
                "RC_FeedTcpBytes",
            )

    def copy_frame_body(self, frame_id: int, size_hint: int) -> bytes:
        cap = max(64, int(size_hint))
        buf = (ctypes.c_uint8 * cap)()
        written = ctypes.c_size_t(0)
        with self._mu:
            rc = int(self._dll.RC_CopyFrameBody(self._handle, int(frame_id), buf, cap, ctypes.byref(written)))
        if rc != 0:
            return b""
        return bytes(buf[: int(written.value)])

    def copy_semantic_json(self, frame_id: int) -> str:
        cap = 8192
        buf = ctypes.create_string_buffer(cap)
        written = ctypes.c_size_t(0)
        with self._mu:
            rc = int(self._dll.RC_CopySemanticJson(self._handle, int(frame_id), buf, cap, ctypes.byref(written)))
        if rc != 0:
            return ""
        return buf.value.decode("utf-8", errors="ignore")

    def release_frame(self, frame_id: int) -> None:
        with self._mu:
            try:
                self._dll.RC_ReleaseFrame(self._handle, int(frame_id))
            except Exception:
                pass

    def poll_events(self, limit: int = 256) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        with self._mu:
            for _ in range(max(1, int(limit))):
                ev = _RC_Event()
                rc = int(self._dll.RC_PollEvent(self._handle, ctypes.byref(ev)))
                if rc == 1:
                    break
                if rc != 0:
                    raise RuntimeError(f"RC_PollEvent failed rc={rc} err={self.get_last_error()}")
                event = {
                    "frame_id": int(ev.frame_id),
                    "timestamp_ms": int(ev.timestamp_ms),
                    "event_type": int(ev.event_type),
                    "service": int(ev.service),
                    "direction": int(ev.direction),
                    "command_family": int(ev.command_family),
                    "command": int(ev.command),
                    "return_code": int(ev.return_code),
                    "flags": int(ev.flags),
                    "protocol_version": int(ev.protocol_version),
                    "body_size": int(ev.body_size),
                    "expect_response": int(ev.expect_response),
                    "validation_ok": bool(ev.validation_ok),
                    "portable_storage_ok": bool(ev.portable_storage_ok),
                    "fragment_count": int(ev.fragment_count),
                    "semantic_mask": int(ev.semantic_mask),
                    "decoded_current_height": int(ev.decoded_current_height),
                    "decoded_current_blockchain_height": int(ev.decoded_current_blockchain_height),
                    "decoded_start_height": int(ev.decoded_start_height),
                    "decoded_total_height": int(ev.decoded_total_height),
                    "decoded_cumulative_difficulty_low64": int(ev.decoded_cumulative_difficulty_low64),
                    "decoded_cumulative_difficulty_high64": int(ev.decoded_cumulative_difficulty_high64),
                    "decoded_peer_id": int(ev.decoded_peer_id),
                    "decoded_my_port": int(ev.decoded_my_port),
                    "decoded_rpc_port": int(ev.decoded_rpc_port),
                    "decoded_local_peerlist_count": int(ev.decoded_local_peerlist_count),
                    "decoded_rpc_credits_per_hash": int(ev.decoded_rpc_credits_per_hash),
                    "decoded_support_flags": int(ev.decoded_support_flags),
                    "decoded_pruning_seed": int(ev.decoded_pruning_seed),
                    "decoded_top_version": int(ev.decoded_top_version),
                    "decoded_top_id_hex": self._decode_c_string(ev.decoded_top_id_hex),
                    "decoded_status": self._decode_c_string(ev.decoded_status),
                    "stream_id": self._decode_c_string(ev.stream_id),
                    "peer": self._decode_c_string(ev.peer),
                    "note": self._decode_c_string(ev.note),
                    "semantic_summary": self._decode_c_string(ev.semantic_summary),
                }
                if event["frame_id"]:
                    try:
                        event["semantic_json"] = self.copy_semantic_json(event["frame_id"])
                    except Exception:
                        event["semantic_json"] = ""
                    try:
                        event["body"] = self.copy_frame_body(event["frame_id"], event["body_size"])
                    except Exception:
                        event["body"] = b""
                else:
                    event["semantic_json"] = ""
                    event["body"] = b""
                out.append(event)
        for ev in out:
            if ev["frame_id"]:
                self.release_frame(ev["frame_id"])
        return out

    def close(self) -> None:
        with self._mu:
            if self._closed:
                return
            self._closed = True
            handle = self._handle
            self._handle = ctypes.c_void_p()
        if handle:
            try:
                self._dll.RC_Destroy(handle)
            except Exception:
                pass


class _TcpDirectionalReassembler:
    __slots__ = ("next_seq", "pending")

    def __init__(self) -> None:
        self.next_seq: Optional[int] = None
        self.pending: Dict[int, bytes] = {}

    def reset(self) -> None:
        self.next_seq = None
        self.pending.clear()

    def feed(self, seq: int, payload: bytes) -> List[bytes]:
        blob = bytes(payload or b"")
        if not blob:
            return []

        seq = int(seq) & 0xFFFFFFFF
        if self.next_seq is None:
            self.next_seq = seq

        if self.next_seq is not None and seq < self.next_seq:
            overlap = self.next_seq - seq
            if overlap >= len(blob):
                return []
            blob = blob[overlap:]
            seq = self.next_seq

        if self.next_seq is not None and seq > self.next_seq:
            prev = self.pending.get(seq)
            if prev is None or len(blob) > len(prev):
                self.pending[seq] = blob
            return []

        out: List[bytes] = []
        out.append(blob)
        self.next_seq = (seq + len(blob)) & 0xFFFFFFFF

        while True:
            nxt = self.pending.pop(self.next_seq, None)
            if nxt is None:
                break
            out.append(nxt)
            self.next_seq = (self.next_seq + len(nxt)) & 0xFFFFFFFF

        return out




@dataclass
class RouterPacket:
    packet_id: int
    source: str = ""
    topic: str = ""
    proto: str = ""
    iface: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    raw_len: int = 0
    raw_hex: str = ""
    raw_ascii: str = ""
    raw_base64: str = ""
    summary: str = ""
    raw_hexdump: str = ""
    raw_url: str = ""
    flags: str = ""
    direction: str = ""
    capture_quality: str = ""
    wire_len: int = 0
    captured_len: int = 0
    has_raw: bool = False

    DEFAULT_INJECT_IFACE = "Miner"

    @classmethod
    def from_api_payload(cls, payload: Dict[str, Any]) -> "RouterPacket":
        envelope = payload if isinstance(payload, dict) else {}
        result = envelope.get("result") if isinstance(envelope, dict) else None
        if isinstance(result, dict):
            data = dict(envelope)
            data.update(result)
        else:
            data = dict(envelope)
        if not isinstance(data, dict):
            raise ValueError("RouterPacket payload is not a dict")
        packet_id = int(data.get("packet_id") or data.get("id") or envelope.get("id") or 0)
        return cls(
            packet_id=packet_id,
            source=str(data.get("source") or envelope.get("source") or ""),
            topic=str(data.get("topic") or envelope.get("topic") or ""),
            proto=str(data.get("proto") or envelope.get("proto") or ""),
            iface=str(data.get("iface") or envelope.get("iface") or ""),
            src_ip=str(data.get("src_ip") or envelope.get("src_ip") or ""),
            dst_ip=str(data.get("dst_ip") or envelope.get("dst_ip") or ""),
            src_port=int(data.get("src_port") or data.get("sport") or envelope.get("src_port") or envelope.get("sport") or 0),
            dst_port=int(data.get("dst_port") or data.get("dport") or envelope.get("dst_port") or envelope.get("dport") or 0),
            raw_len=int(data.get("raw_len") or envelope.get("raw_len") or data.get("captured_len") or envelope.get("captured_len") or data.get("wire_len") or envelope.get("wire_len") or 0),
            raw_hex=str((data.get("raw_hex") or envelope.get("raw_hex") or data.get("raw_hex_preview") or envelope.get("raw_hex_preview") or (data.get("extra", {}).get("hex_preview") if isinstance(data.get("extra"), dict) else ""))),
            raw_ascii=str(data.get("raw_ascii") or envelope.get("raw_ascii") or ""),
            raw_base64=str(data.get("raw_base64") or envelope.get("raw_base64") or ""),
            summary=str(data.get("summary") or envelope.get("summary") or ""),
            raw_hexdump=str(data.get("raw_hexdump") or envelope.get("raw_hexdump") or ""),
            raw_url=str(data.get("raw_url") or envelope.get("raw_url") or ""),
            flags=str(data.get("flags") or envelope.get("flags") or ""),
            direction=str(data.get("direction") or envelope.get("direction") or ""),
            capture_quality=str(data.get("capture_quality") or envelope.get("capture_quality") or ""),
            wire_len=int(data.get("wire_len") or envelope.get("wire_len") or 0),
            captured_len=int(data.get("captured_len") or envelope.get("captured_len") or 0),
            has_raw=bool(data.get("has_raw") if "has_raw" in data else envelope.get("has_raw") if "has_raw" in envelope else False),
        )

    def to_bytes(self) -> bytes:
        if self.raw_hex:
            try:
                return bytes.fromhex(self.raw_hex)
            except Exception:
                pass
        if self.raw_base64:
            try:
                return base64.b64decode(self.raw_base64)
            except Exception:
                pass
        return b""

    def peer_key(self) -> str:
        if self.dst_ip and int(self.dst_port or 0) > 0:
            return f"{self.dst_ip}:{int(self.dst_port)}"
        if self.src_ip and int(self.src_port or 0) > 0:
            return f"{self.src_ip}:{int(self.src_port)}"
        return ""

    def service_guess(self) -> int:
        topic = str(self.topic or "").strip().lower()
        if topic == 'p2pool' or int(self.src_port or 0) in (37888, 37889, 37890) or int(self.dst_port or 0) in (37888, 37889, 37890):
            return RemoteConnectionDll.RC_SERVICE_P2POOL_P2P
        if topic == 'monero' or int(self.src_port or 0) in (18080, 18081, 18083) or int(self.dst_port or 0) in (18080, 18081, 18083):
            return RemoteConnectionDll.RC_SERVICE_MONERO_P2P
        return RemoteConnectionDll.RC_SERVICE_UNKNOWN

    def is_protocol_candidate(self) -> bool:
        blob = self.to_bytes()
        if not blob:
            return False
        if self.service_guess() != RemoteConnectionDll.RC_SERVICE_UNKNOWN:
            return True
        probe = (self.topic or "") + ' ' + (self.proto or '') + ' ' + (self.summary or '')
        probe = probe.lower()
        return any(x in probe for x in ('monero', 'p2pool', 'levin', 'stratum'))

    def to_event_dict(self) -> Dict[str, Any]:
        return {
            "block": "packet_raw_bytes",
            "result": {
                "packet_id": int(self.packet_id),
                "raw_len": int(self.raw_len or 0),
                "raw_hex": self.raw_hex,
                "raw_ascii": self.raw_ascii,
                "raw_hexdump": self.raw_hexdump,
                "raw_base64": self.raw_base64,
                "source": self.source,
                "topic": self.topic,
                "proto": self.proto,
                "iface": self.iface,
                "src_ip": self.src_ip,
                "dst_ip": self.dst_ip,
                "src_port": self.src_port,
                "dst_port": self.dst_port,
                "summary": self.summary,
                "raw_url": self.raw_url,
                "flags": self.flags,
                "direction": self.direction,
                "capture_quality": self.capture_quality,
                "wire_len": int(self.wire_len or 0),
                "captured_len": int(self.captured_len or 0),
                "has_raw": bool(self.has_raw),
            },
        }

    def to_inject_payload(
        self,
        *,
        iface: str = DEFAULT_INJECT_IFACE,
        delegate_from: Optional[str] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        iface_name = str(iface or self.iface or self.DEFAULT_INJECT_IFACE).strip() or self.DEFAULT_INJECT_IFACE
        payload: Dict[str, Any] = dict(self.to_event_dict().get('result') or {})
        payload['iface'] = iface_name
        payload['interface_name'] = iface_name
        payload['inbound_iface'] = iface_name
        payload['source'] = str(self.source or 'minerinterface:inject')
        payload['has_raw'] = True
        payload['capture_quality'] = str(self.capture_quality or ('miner_injected' if iface_name.lower() == 'miner' else 'synthetic_protocol'))
        payload['direction'] = str(self.direction or 'outbound')
        payload['topic'] = str(self.topic or '')
        payload['proto'] = str(self.proto or '')
        payload['wire_len'] = int(self.wire_len or self.raw_len or len(self.to_bytes()))
        payload['captured_len'] = int(self.captured_len or self.raw_len or len(self.to_bytes()))
        if delegate_from:
            payload['delegate_from'] = str(delegate_from)
        merged_extra: Dict[str, Any] = {}
        if isinstance(extra, dict):
            merged_extra.update(extra)
        merged_extra.setdefault('component', 'miner_interface')
        merged_extra.setdefault('inject_source', str(self.source or 'minerinterface:inject'))
        merged_extra.setdefault('service_guess', int(self.service_guess()))
        merged_extra.setdefault('peer_key', self.peer_key())
        merged_extra.setdefault('is_protocol_candidate', bool(self.is_protocol_candidate()))
        if merged_extra:
            payload['extra'] = merged_extra
        return payload

    def inject_via_router_api(
            self,
            *,
            base_url: str,
            iface: str = DEFAULT_INJECT_IFACE,
            delegate_from: Optional[str] = None,
            timeout_sec: float = 10.0,
            token: str = '',
            extra: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        raw_base = str(base_url or '').strip()
        raw_base = re.sub(r'(:\d+)[^\d/]+(?=$|/)', r'\1', raw_base)
        base = _normalize_router_api_base_url(raw_base).rstrip('/')

        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'User-Agent': 'p2pool-share-hunter/1.0',
        }
        token_s = str(token or '').strip()
        if token_s:
            headers['X-Router-Token'] = token_s
            headers['Authorization'] = f'Bearer {token_s}'

        primary_payload = self.to_inject_payload(
            iface=iface,
            delegate_from=delegate_from,
            extra=extra,
        )

        # server expects flat top-level fields
        payload_variants = [primary_payload]

        last_err: Optional[Exception] = None
        for path in ('/api/inject-packet',):
            for payload in payload_variants:
                try:
                    body = json.dumps(payload).encode('utf-8')
                    req = Request(base + path, data=body, headers=headers, method='POST')
                    with urlopen(req, timeout=max(20, int(timeout_sec))) as resp:
                        raw_resp = resp.read()

                    if not raw_resp:
                        return {'ok': True, 'path': path}

                    try:
                        decoded = json.loads(raw_resp.decode('utf-8', errors='ignore'))
                    except Exception:
                        decoded = {
                            'ok': True,
                            'path': path,
                            'raw': raw_resp.decode('utf-8', errors='ignore'),
                        }

                    if isinstance(decoded, dict):
                        decoded.setdefault('path', path)
                    return decoded

                except HTTPError as e:
                    try:
                        err_body = e.read().decode('utf-8', errors='ignore')
                    except Exception:
                        err_body = ''
                    raise RuntimeError(f'HTTP {e.code} on {path}: {err_body or e.reason}') from e
                except Exception as e:
                    last_err = e
                    continue

        if last_err is not None:
            raise last_err
        raise RuntimeError('router injection failed')
    @classmethod
    def from_capture_dict(cls, packet: Dict[str, Any], *, iface: str = DEFAULT_INJECT_IFACE, source: str = 'minerinterface:capture', capture_quality: str = 'miner_injected') -> 'RouterPacket':
        pkt = dict(packet or {})
        raw_hex = str(pkt.get('raw_hex') or pkt.get('raw_hex_preview') or '')
        raw_base64 = str(pkt.get('raw_base64') or '')
        if not raw_hex and raw_base64:
            try:
                raw_hex = base64.b64decode(raw_base64).hex()
            except Exception:
                raw_hex = ''
        raw_len = int(pkt.get('raw_len') or pkt.get('cap_len') or pkt.get('captured_len') or pkt.get('wire_len') or 0)
        return cls(
            packet_id=int(pkt.get('packet_id') or pkt.get('id') or 0),
            source=str(pkt.get('source') or source),
            topic=str(pkt.get('topic') or ''),
            proto=str(pkt.get('proto') or pkt.get('l4') or ''),
            iface=str(iface or pkt.get('iface') or cls.DEFAULT_INJECT_IFACE),
            src_ip=str(pkt.get('src_ip') or ''),
            dst_ip=str(pkt.get('dst_ip') or ''),
            src_port=int(pkt.get('src_port') or pkt.get('sport') or 0),
            dst_port=int(pkt.get('dst_port') or pkt.get('dport') or 0),
            raw_len=raw_len,
            raw_hex=raw_hex,
            raw_ascii=str(pkt.get('raw_ascii') or ''),
            raw_base64=raw_base64,
            summary=str(pkt.get('summary') or ''),
            raw_hexdump=str(pkt.get('raw_hexdump') or ''),
            raw_url=str(pkt.get('raw_url') or ''),
            flags=str(pkt.get('flags') or ''),
            direction=str(pkt.get('direction') or 'outbound'),
            capture_quality=str(pkt.get('capture_quality') or capture_quality),
            wire_len=int(pkt.get('wire_len') or raw_len),
            captured_len=int(pkt.get('captured_len') or pkt.get('cap_len') or raw_len),
            has_raw=bool(pkt.get('has_raw') if 'has_raw' in pkt else bool(raw_hex or raw_base64)),
        )

    @staticmethod
    def _tcp_flags_value(flags_text: str) -> int:
        probe = str(flags_text or '').upper()
        value = 0
        if 'F' in probe:
            value |= 0x01
        if 'S' in probe:
            value |= 0x02
        if 'R' in probe:
            value |= 0x04
        if 'P' in probe:
            value |= 0x08
        if 'A' in probe:
            value |= 0x10
        if 'U' in probe:
            value |= 0x20
        return value or 0x18

    @classmethod
    def _build_ipv4_tcp_packet(cls, *, src_ip: str, dst_ip: str, src_port: int, dst_port: int, payload: bytes, flags: str = 'PA') -> bytes:
        sport = max(1, int(src_port) & 0xFFFF)
        dport = max(1, int(dst_port) & 0xFFFF)
        blob = bytes(payload or b'')
        total_len = 20 + 20 + len(blob)
        ip_header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, total_len, int(time.time() * 1000.0) & 0xFFFF, 0, 64, 6, 0, socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
        ip_checksum = _inet_checksum(ip_header)
        ip_header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, total_len, int(time.time() * 1000.0) & 0xFFFF, 0, 64, 6, ip_checksum, socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
        seq = int(time.time() * 1000000.0) & 0xFFFFFFFF
        ack = 0
        offset_res_flags = (5 << 12) | cls._tcp_flags_value(flags)
        tcp_header = struct.pack('!HHIIHHHH', sport, dport, seq, ack, offset_res_flags, 0x2000, 0, 0)
        pseudo = socket.inet_aton(src_ip) + socket.inet_aton(dst_ip) + struct.pack('!BBH', 0, 6, len(tcp_header) + len(blob))
        tcp_checksum = _inet_checksum(pseudo + tcp_header + blob)
        tcp_header = struct.pack('!HHIIHHHH', sport, dport, seq, ack, offset_res_flags, 0x2000, tcp_checksum, 0)
        return ip_header + tcp_header + blob

    @classmethod
    def from_protocol_packet(
        cls,
        packet_obj: '_LevinProtocolPacketBase',
        remote_connection: 'RemoteConnection',
        *,
        local_ip: str,
        remote_ip: str,
        local_port: int,
        remote_port: int,
        iface: str = DEFAULT_INJECT_IFACE,
        source: str = 'minerinterface:protocol',
        capture_quality: str = 'synthetic_protocol',
    ) -> 'RouterPacket':
        frame = bytes(packet_obj.to_frame(remote_connection))
        raw = cls._build_ipv4_tcp_packet(src_ip=str(local_ip), dst_ip=str(remote_ip), src_port=int(local_port), dst_port=int(remote_port), payload=frame, flags='PA')
        return cls(
            packet_id=0,
            source=str(source),
            topic=str(getattr(packet_obj, 'packet_topic', 'transport') or 'transport'),
            proto=str(getattr(packet_obj, 'packet_proto', 'Levin') or 'Levin'),
            iface=str(iface or cls.DEFAULT_INJECT_IFACE),
            src_ip=str(local_ip),
            dst_ip=str(remote_ip),
            src_port=int(local_port),
            dst_port=int(remote_port),
            raw_len=len(raw),
            raw_hex=raw.hex(),
            raw_ascii='',
            raw_base64=base64.b64encode(raw).decode('ascii'),
            summary=f"IP / TCP {local_ip}:{int(local_port)} > {remote_ip}:{int(remote_port)} PA / {str(getattr(packet_obj, 'packet_proto', 'Levin'))}",
            raw_hexdump='',
            raw_url='',
            flags='PA',
            direction='outbound',
            capture_quality=str(capture_quality),
            wire_len=len(raw),
            captured_len=len(raw),
            has_raw=True,
        )


class RouterPacketStream:
    _SEEN_LIMIT = 4096

    def __init__(
        self,
        *,
        base_url: str,
        callback: Callable[[RouterPacket], None],
        logger: Optional[Callable[[str], None]] = None,
        timeout_sec: float = 2.0,
        poll_interval_sec: float = 0.75,
        list_limit: int = 128,
    ) -> None:
        self.base_url = str(base_url or "").rstrip("/")
        self.callback = callback
        self.logger = logger or (lambda s: None)
        self.timeout_sec = max(0.5, float(timeout_sec))
        self.poll_interval_sec = max(0.10, float(poll_interval_sec))
        self.list_limit = max(8, int(list_limit))
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._seen_tokens: Set[str] = set()
        self._seen_order: Deque[str] = deque()
        self._last_error: str = ""
        self._last_ok_base_url: str = ""
        self._candidate_urls: List[str] = []
        self._set_candidates(self.base_url)

    def _set_candidates(self, base_url: str) -> None:
        primary = _normalize_router_api_base_url(base_url).rstrip("/")

        candidates: List[str] = []
        for cand in (
            primary,
            "http://127.0.0.1:8844",
            "http://localhost:8844",
        ):
            cand = str(cand or "").rstrip("/")
            if cand and cand not in candidates:
                candidates.append(cand)

        self.base_url = primary
        self._candidate_urls = candidates

    def set_base_url(self, base_url: str) -> None:
        self._set_candidates(base_url)

    def _router_ingest_base(self) -> str:
        return _normalize_router_api_base_url(getattr(self.remote_connection, 'router_base_url', '') or 'http://127.0.0.1:8844').rstrip('/')

    def _pick_delegate_iface(self, packet: Optional[RouterPacket] = None) -> Optional[str]:
        candidates = []
        if packet is not None:
            candidates.extend([str(packet.iface or '').strip(), str(packet.source or '').strip()])
        with self._mu:
            last_dev = dict(self._last_device_packet or {})
        candidates.extend([str(last_dev.get('device_name') or '').strip(), str(self.device_name or '').strip(), 'WinDivertBridge'])
        for cand in candidates:
            if cand and cand.lower() not in {'miner', 'socket interface'} and not cand.startswith('http'):
                return cand
        return None

    def _best_local_ip_for_peer(self, peer_key: str) -> str:
        peer_key = str(peer_key or '').strip()
        with self._mu:
            hints = dict(self._peer_device_hints)
            last_dev = dict(self._last_device_packet or {})
        hint = hints.get(peer_key) or {}
        remote_host = str(peer_key).split(':', 1)[0] if ':' in peer_key else str(peer_key)
        for candidate in (hint, last_dev):
            src_ip = str(candidate.get('src_ip') or '')
            dst_ip = str(candidate.get('dst_ip') or '')
            if src_ip and dst_ip:
                if src_ip == remote_host and dst_ip and RemoteConnection._is_private_ip(dst_ip):
                    return dst_ip
                if dst_ip == remote_host and src_ip and RemoteConnection._is_private_ip(src_ip):
                    return src_ip
        return '192.168.0.10'

    def _best_local_port_for_peer(self, peer_key: str, remote_port: int) -> int:
        with self._mu:
            hint = dict(self._peer_device_hints.get(str(peer_key), {}) or {})
            last_dev = dict(self._last_device_packet or {})
        remote_host = str(peer_key).split(':', 1)[0] if ':' in peer_key else str(peer_key)
        for candidate in (hint, last_dev):
            src_ip = str(candidate.get('src_ip') or '')
            dst_ip = str(candidate.get('dst_ip') or '')
            sport = int(candidate.get('sport') or candidate.get('src_port') or 0)
            dport = int(candidate.get('dport') or candidate.get('dst_port') or 0)
            if dst_ip == remote_host and dport == int(remote_port) and sport > 0:
                return sport
            if src_ip == remote_host and sport == int(remote_port) and dport > 0:
                return dport
        return 40000 + (abs(hash(str(peer_key))) % 20000)

    def inject_router_packet(self, packet: RouterPacket, *, reason: str = 'miner_inject') -> bool:
        if packet is None or not packet.to_bytes():
            return False
        try:
            result = packet.inject_via_router_api(
                base_url=self._router_ingest_base(),
                iface=self.IFACE_NAME,
                delegate_from=self._pick_delegate_iface(packet),
                timeout_sec=max(0.5, float(self.remote_connection.router_timeout_sec)),
                extra={'reason': str(reason or 'miner_inject'), 'component': 'miner_interface'},
            )
            with self._mu:
                self._tx_packets += 1
                self._inject_success += 1
                self._tx_queue.append((packet.peer_key() or None, packet.to_bytes()[:128], reason))
            return bool(isinstance(result, dict) and result.get('ok', True))
        except Exception as e:
            with self._mu:
                self._last_error = str(e)
                self._inject_fail += 1
            return False

    def send_protocol_packet(self, packet_obj: '_LevinProtocolPacketBase') -> int:
        if packet_obj is None:
            return 0
        peer_key = str(getattr(packet_obj, 'peer_key', '') or '')
        host = str(peer_key).split(':', 1)[0]
        try:
            port = int(str(peer_key).rpartition(':')[2])
        except Exception:
            port = 0
        if not host or port <= 0:
            return 0
        local_ip = self._best_local_ip_for_peer(peer_key)
        local_port = self._best_local_port_for_peer(peer_key, port)
        synthetic = RouterPacket.from_protocol_packet(
            packet_obj,
            self.remote_connection,
            local_ip=local_ip,
            remote_ip=host,
            local_port=local_port,
            remote_port=port,
            iface=self.IFACE_NAME,
            source='minerinterface:protocol_packet',
            capture_quality='synthetic_protocol',
        )
        injected = self.inject_router_packet(synthetic, reason=str(getattr(packet_obj, 'reason', '') or getattr(packet_obj, 'command_name', '') or 'protocol_packet'))
        rc = self.queue_socket_payload(peer_key, packet_obj.to_frame(self.remote_connection), reason=str(getattr(packet_obj, 'reason', '') or 'protocol_packet'))
        return int(rc) + (1 if injected else 0)

    def send_monero_packet(self, packet_obj: MoneroPacket) -> int:
        return self.send_protocol_packet(packet_obj)

    def send_p2pool_packet(self, packet_obj: P2PoolPacket) -> int:
        return self.send_protocol_packet(packet_obj)


    def _device_rank(self, dev: CaptureDevice) -> Tuple[int, int, str]:
        name = str(getattr(dev, 'name', '') or '')
        desc = str(getattr(dev, 'description', '') or '')
        lower = f"{name} {desc}".lower()
        score = 0
        if 'loopback' in lower:
            score -= 100
        if 'npcap_loopback' in lower:
            score -= 100
        if '\\device\\npf_' in lower:
            score += 20
        if 'wi-fi' in lower or 'wifi' in lower or 'wireless' in lower:
            score += 14
        if 'ethernet' in lower:
            score += 12
        if 'hyper-v' in lower or 'vmswitch' in lower or 'virtualbox' in lower:
            score -= 6
        if 'bluetooth' in lower:
            score -= 10
        addrs = list(getattr(dev, 'addresses', []) or [])
        priv = 0
        for addr in addrs:
            try:
                ip = ipaddress.ip_address(str(addr).split('%', 1)[0])
            except Exception:
                continue
            if ip.version == 4 and (ip.is_private or ip.is_link_local):
                priv += 1
        score += min(10, priv * 2)
        return (score, len(addrs), lower)

    def _auto_select_device(self) -> str:
        try:
            if self._backend is None:
                self._backend = LibpcapBackend()
            devices = list(self._backend.list_devices() or [])
        except Exception as e:
            with self._mu:
                self._last_error = str(e)
            self._log(f'[MinerInterface] auto-device warning: {e}')
            return ''
        if not devices:
            self._log('[MinerInterface] auto-device warning: no capture devices found')
            return ''
        ranked = sorted(devices, key=self._device_rank, reverse=True)
        picked = ranked[0]
        name = str(getattr(picked, 'name', '') or '').strip()
        if name:
            self._log(f"[MinerInterface] 🔎 auto-selected device={name} desc={str(getattr(picked, 'description', '') or '<none>')}")
        return name

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._thread_main, name="RouterPacketStream", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        t = self._thread
        if t is not None:
            try:
                t.join(timeout=1.0)
            except Exception:
                pass

    def _json_get_from(self, base_url: str, path: str, params: Optional[Dict[str, Any]] = None) -> Any:
        query = ""
        if params:
            try:
                flat = {k: v for k, v in params.items() if v is not None}
                if flat:
                    query = "?" + urlencode(flat)
            except Exception:
                query = ""
        url = f"{str(base_url).rstrip('/')}{path}{query}"
        req = Request(url, headers={"Accept": "application/json", "User-Agent": "p2pool-share-hunter/1.0"})
        with urlopen(req, timeout=self.timeout_sec) as resp:
            raw = resp.read()
        if not raw:
            return {}
        return json.loads(raw.decode("utf-8", errors="ignore"))

    def _json_get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Any:
        last_exc: Optional[Exception] = None
        for base_url in list(self._candidate_urls or [self.base_url or "http://127.0.0.1:8844"]):
            try:
                payload = self._json_get_from(base_url, path, params)
                self._last_ok_base_url = base_url
                self._last_error = ""
                return payload
            except Exception as e:
                last_exc = e
                self._last_error = str(e)
                continue
        if last_exc is not None:
            raise last_exc
        return {}

    @staticmethod
    def _item_id(item: Dict[str, Any]) -> int:
        try:
            direct = int(item.get("packet_id") or item.get("id") or 0)
            if direct > 0:
                return direct
        except Exception:
            pass
        try:
            source = str(item.get("source") or "")
            m = re.search(r"/api/packets/raw/(\d+)", source)
            if m:
                return int(m.group(1))
        except Exception:
            pass
        return 0

    @staticmethod
    def _fingerprint_for_item(item: Dict[str, Any]) -> str:
        pid = 0
        try:
            pid = int(item.get("packet_id") or item.get("id") or 0)
        except Exception:
            pid = 0
        if pid > 0:
            return f"id:{pid}"
        parts = [
            str(item.get("source") or ""),
            str(item.get("raw_hex") or "")[:128],
            str(item.get("raw_base64") or "")[:128],
            str(item.get("topic") or ""),
            str(item.get("proto") or ""),
            str(item.get("summary") or ""),
            str(item.get("src_ip") or ""),
            str(item.get("dst_ip") or ""),
            str(item.get("src_port") or item.get("sport") or ""),
            str(item.get("dst_port") or item.get("dport") or ""),
        ]
        digest = hashlib.blake2b("|".join(parts).encode("utf-8", errors="ignore"), digest_size=16).hexdigest()
        return f"fp:{digest}"

    def _remember_token(self, token: str) -> bool:
        tok = str(token or "").strip()
        if not tok:
            return False
        if tok in self._seen_tokens:
            return False
        self._seen_tokens.add(tok)
        self._seen_order.append(tok)
        while len(self._seen_order) > self._SEEN_LIMIT:
            old = self._seen_order.popleft()
            self._seen_tokens.discard(old)
        return True

    @classmethod
    def _extract_packet_records(cls, payload: Any) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        seen_local: Set[int] = set()

        def _is_packet_like(d: Dict[str, Any]) -> bool:
            keys = set(d.keys())
            return bool(keys & {
                "packet_id", "id", "raw_hex", "raw_base64", "raw_len", "src_ip", "dst_ip",
                "src_port", "dst_port", "sport", "dport", "summary", "topic", "proto", "source"
            })

        def _walk(obj: Any, depth: int = 0) -> None:
            if depth > 6:
                return
            oid = id(obj)
            if oid in seen_local:
                return
            seen_local.add(oid)
            if isinstance(obj, dict):
                if _is_packet_like(obj):
                    out.append(obj)
                result = obj.get("result")
                if isinstance(result, dict) and _is_packet_like(result):
                    merged = dict(result)
                    for k in ("block", "source", "topic", "proto", "iface", "summary"):
                        if k not in merged and k in obj:
                            merged[k] = obj.get(k)
                    out.append(merged)
                for v in obj.values():
                    if isinstance(v, (dict, list, tuple)):
                        _walk(v, depth + 1)
            elif isinstance(obj, (list, tuple)):
                for v in obj:
                    if isinstance(v, (dict, list, tuple)):
                        _walk(v, depth + 1)

        _walk(payload, 0)
        return out

    @classmethod
    def _looks_interesting(cls, item: Dict[str, Any]) -> bool:
        if item.get("raw_hex") or item.get("raw_base64"):
            return True
        text = " ".join(
            str(item.get(k) or "")
            for k in ("topic", "proto", "summary", "source", "src_ip", "dst_ip", "src", "dst", "flags")
        ).lower()
        if any(x in text for x in ("monero", "p2pool", "levin", "stratum", "packet")):
            return True
        for key in ("src_port", "dst_port", "sport", "dport"):
            try:
                p = int(item.get(key) or 0)
            except Exception:
                p = 0
            if p in (18080, 37888, 37889, 37890, 3333, 8844):
                return True
        return bool(cls._item_id(item) > 0)

    @staticmethod
    def _merge_router_metadata(envelope: Dict[str, Any], packet: RouterPacket) -> RouterPacket:
        merged: Dict[str, Any] = dict(envelope or {})
        result = dict(packet.to_event_dict().get("result") or {})
        if packet.source and not result.get("source"):
            result["source"] = packet.source
        merged["result"] = result
        return RouterPacket.from_api_payload(merged)

    def _fetch_raw_packet_from(
        self,
        base_url: str,
        packet_id: int,
        *,
        raw_url: str = "",
        envelope: Optional[Dict[str, Any]] = None,
    ) -> Optional[RouterPacket]:
        last_exc: Optional[Exception] = None
        paths: List[str] = []
        raw_url_s = str(raw_url or "").strip()
        if raw_url_s:
            paths.append(raw_url_s)
        paths.extend((
            f"/api/packets/raw/{int(packet_id)}",
            f"/api/packets/{int(packet_id)}",
        ))
        seen_paths: Set[str] = set()
        envelope_pkt: Optional[RouterPacket] = None
        if envelope:
            try:
                envelope_pkt = RouterPacket.from_api_payload(envelope)
            except Exception:
                envelope_pkt = None
        for path in paths:
            if path in seen_paths:
                continue
            seen_paths.add(path)
            try:
                if path.startswith("http://") or path.startswith("https://"):
                    req = Request(path, headers={"Accept": "application/json", "User-Agent": "p2pool-share-hunter/1.0"})
                    with urlopen(req, timeout=self.timeout_sec) as resp:
                        raw = resp.read()
                    payload = json.loads(raw.decode("utf-8", errors="ignore")) if raw else {}
                else:
                    payload = self._json_get_from(base_url, path)
                pkt = RouterPacket.from_api_payload(payload)
                if envelope:
                    pkt = self._merge_router_metadata(envelope, pkt)
                if pkt.to_bytes():
                    return pkt
                if envelope_pkt is not None and envelope_pkt.to_bytes():
                    return envelope_pkt
                return pkt
            except Exception as e:
                last_exc = e
                continue
        if envelope_pkt is not None and envelope_pkt.to_bytes():
            return envelope_pkt
        if last_exc is not None:
            self._last_error = str(last_exc)
        return envelope_pkt

    def _dispatch_item(self, item: Dict[str, Any], base_url: str) -> bool:
        if not isinstance(item, dict):
            return False
        if not self._looks_interesting(item):
            return False

        direct_pkt: Optional[RouterPacket] = None
        try:
            direct_pkt = RouterPacket.from_api_payload(item)
        except Exception:
            direct_pkt = None

        if direct_pkt is not None and direct_pkt.to_bytes():
            token = f"id:{int(direct_pkt.packet_id)}" if int(direct_pkt.packet_id or 0) > 0 else self._fingerprint_for_item(item)
            if token and token in self._seen_tokens:
                return False
            try:
                self.callback(direct_pkt)
            except Exception:
                return False
            if token:
                self._remember_token(token)
            return True

        packet_id = self._item_id(item)
        if packet_id <= 0:
            return False
        token = f"id:{packet_id}"
        if token in self._seen_tokens:
            return False
        raw_url = str(item.get("raw_url") or "").strip()
        if not raw_url:
            source = str(item.get("source") or "").strip()
            if "/api/packets/raw/" in source:
                raw_url = source
        pkt = self._fetch_raw_packet_from(base_url, packet_id, raw_url=raw_url, envelope=item)
        if pkt is None or not pkt.to_bytes():
            if direct_pkt is None or not direct_pkt.to_bytes():
                return False
            pkt = direct_pkt
        try:
            self.callback(pkt)
        except Exception:
            return False
        self._remember_token(token)
        return True

    def _poll_endpoint_once(self, base_url: str, path: str, params: Optional[Dict[str, Any]] = None) -> int:
        payload = self._json_get_from(base_url, path, params)
        items = self._extract_packet_records(payload)
        if items:
            items.sort(key=lambda x: (self._item_id(x), self._fingerprint_for_item(x)))
        dispatched = 0
        for item in items:
            if self._dispatch_item(item, base_url):
                dispatched += 1
        return dispatched

    def _thread_main(self) -> None:
        while not self._stop.is_set():
            total_dispatched = 0
            last_exc: Optional[Exception] = None
            candidates = list(self._candidate_urls or [self.base_url or "http://127.0.0.1:8844"])
            if self._last_ok_base_url and self._last_ok_base_url in candidates:
                candidates.remove(self._last_ok_base_url)
                candidates.insert(0, self._last_ok_base_url)
            for base_url in candidates:
                for path, params in (
                    ("/api/packets/raw", {"limit": self.list_limit}),
                    ("/api/packets", {"limit": self.list_limit}),
                ):
                    try:
                        total_dispatched += self._poll_endpoint_once(base_url, path, params)
                        self._last_ok_base_url = base_url
                        self._last_error = ""
                    except (HTTPError, URLError, TimeoutError, OSError, json.JSONDecodeError) as e:
                        last_exc = e
                        self._last_error = str(e)
                        continue
                    except Exception as e:
                        last_exc = e
                        self._last_error = str(e)
                        continue
            if total_dispatched <= 0 and last_exc is not None:
                self._last_error = str(last_exc)
            self._stop.wait(self.poll_interval_sec)


def _inet_checksum(data: bytes) -> int:
    blob = bytes(data or b'')
    if len(blob) % 2:
        blob += b'\x00'
    total = 0
    for i in range(0, len(blob), 2):
        total += (blob[i] << 8) + blob[i + 1]
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF



@dataclass(frozen=True)
class _LevinProtocolPacketBase:
    peer_key: str
    command: int
    body: bytes = b''
    expect_response: bool = True
    is_request: bool = True
    is_response: bool = False
    return_code: int = 0
    reason: str = ''
    command_name: str = ''
    packet_topic: str = 'transport'
    packet_proto: str = 'Levin'
    service_kind: int = RemoteConnectionDll.RC_SERVICE_UNKNOWN
    priority: float = 1.0

    def to_frame(self, remote_connection: 'RemoteConnection') -> bytes:
        return remote_connection._build_levin_frame(
            int(self.command),
            body=bytes(self.body or b''),
            expect_response=bool(self.expect_response),
            is_request=bool(self.is_request),
            is_response=bool(self.is_response),
            return_code=int(self.return_code),
        )

    def summary(self) -> str:
        return f"{self.packet_topic}:{self.packet_proto}:{self.command_name or self.command}"


@dataclass(frozen=True)
class MoneroPacket(_LevinProtocolPacketBase):
    packet_topic: str = 'monero'
    service_kind: int = RemoteConnectionDll.RC_SERVICE_MONERO_P2P
    priority: float = 1.10

    @classmethod
    def handshake(cls, remote_connection: 'RemoteConnection', peer_key: str, *, reason: str = 'monero_handshake') -> 'MoneroPacket':
        return cls(
            peer_key=str(peer_key),
            command=1001,
            body=remote_connection._build_handshake_body(str(peer_key), RemoteConnectionDll.RC_SERVICE_MONERO_P2P),
            reason=str(reason),
            command_name='handshake',
            priority=1.25,
        )

    @classmethod
    def timed_sync(cls, remote_connection: 'RemoteConnection', peer_key: str, *, reason: str = 'monero_timed_sync') -> 'MoneroPacket':
        return cls(
            peer_key=str(peer_key),
            command=1002,
            body=remote_connection._build_timed_sync_body(),
            reason=str(reason),
            command_name='timed_sync',
            priority=1.18,
        )

    @classmethod
    def ping(cls, remote_connection: 'RemoteConnection', peer_key: str, *, reason: str = 'monero_ping') -> 'MoneroPacket':
        return cls(
            peer_key=str(peer_key),
            command=1003,
            body=b'',
            reason=str(reason),
            command_name='ping',
            priority=0.96,
        )

    @classmethod
    def support_flags(cls, remote_connection: 'RemoteConnection', peer_key: str, *, reason: str = 'monero_support_flags') -> 'MoneroPacket':
        return cls(
            peer_key=str(peer_key),
            command=1007,
            body=b'',
            reason=str(reason),
            command_name='support_flags',
            priority=1.02,
        )


@dataclass(frozen=True)
class P2PoolPacket(_LevinProtocolPacketBase):
    packet_topic: str = 'p2pool'
    service_kind: int = RemoteConnectionDll.RC_SERVICE_P2POOL_P2P
    priority: float = 1.18

    @classmethod
    def handshake(cls, remote_connection: 'RemoteConnection', peer_key: str, *, reason: str = 'p2pool_handshake') -> 'P2PoolPacket':
        return cls(
            peer_key=str(peer_key),
            command=1001,
            body=remote_connection._build_handshake_body(str(peer_key), RemoteConnectionDll.RC_SERVICE_P2POOL_P2P),
            reason=str(reason),
            command_name='handshake',
            priority=1.34,
        )

    @classmethod
    def timed_sync(cls, remote_connection: 'RemoteConnection', peer_key: str, *, reason: str = 'p2pool_timed_sync') -> 'P2PoolPacket':
        return cls(
            peer_key=str(peer_key),
            command=1002,
            body=remote_connection._build_timed_sync_body(),
            reason=str(reason),
            command_name='timed_sync',
            priority=1.28,
        )

    @classmethod
    def ping(cls, remote_connection: 'RemoteConnection', peer_key: str, *, reason: str = 'p2pool_ping') -> 'P2PoolPacket':
        return cls(
            peer_key=str(peer_key),
            command=1003,
            body=b'',
            reason=str(reason),
            command_name='ping',
            priority=0.98,
        )

    @classmethod
    def support_flags(cls, remote_connection: 'RemoteConnection', peer_key: str, *, reason: str = 'p2pool_support_flags') -> 'P2PoolPacket':
        return cls(
            peer_key=str(peer_key),
            command=1007,
            body=b'',
            reason=str(reason),
            command_name='support_flags',
            priority=1.08,
        )


class MinerInterface:
    IFACE_NAME = 'Miner'

    def __init__(
        self,
        *,
        remote_connection: 'RemoteConnection',
        logger: Optional[Callable[[str], None]] = None,
        device_name: str = '',
        bpf_filter: str = '',
        promiscuous: bool = True,
        snaplen: int = 65535,
        timeout_ms: int = 250,
        enable_capture: bool = True,
    ) -> None:
        self.remote_connection = remote_connection
        self.logger = logger or (lambda _s: None)
        self.device_name = str(device_name or '').strip()
        self.bpf_filter = str(bpf_filter or '').strip()
        self.promiscuous = bool(promiscuous)
        self.snaplen = max(256, int(snaplen))
        self.timeout_ms = max(1, int(timeout_ms))
        self.enable_capture = bool(enable_capture)
        self._backend: Optional[LibpcapBackend] = None
        self._started = False
        self._mu = threading.RLock()
        self._rx_packets = 0
        self._tx_packets = 0
        self._last_error = ''
        self._last_packet_ts = 0.0
        self._last_device_packet: Dict[str, Any] = {}
        self._peer_device_hints: Dict[str, Dict[str, Any]] = {}
        self._capture_generation = 0
        self._tx_queue: Deque[Tuple[Optional[str], bytes, str]] = deque(maxlen=1024)
        self._inject_success = 0
        self._inject_fail = 0
        self._inject_garbage = 0
        self._capture_high_value = 0
        self._capture_low_value = 0
        self._last_log_emit_ts = 0.0
        self._start_ts = 0.0
        self._capture_watchdog_stop = threading.Event()
        self._capture_watchdog_thread: Optional[threading.Thread] = None
        self._candidate_devices: List[str] = []
        self._candidate_device_descs: Dict[str, str] = {}
        self._candidate_index = -1
        self._capture_restart_count = 0
        self._force_router_for_all_capture = True
        self._last_capture_reason = ''
        self._feedback_suppress = 0

    def _log(self, msg: str) -> None:
        text = str(msg or '')
        if not text:
            return
        try:
            self.logger(text)
        except Exception:
            pass
        try:
            print(text, flush=True)
        except Exception:
            pass

    def _log_activity(self, msg: str, *, force: bool = False, min_interval_sec: float = 2.0) -> None:
        now = time.time()
        emit = bool(force)
        with self._mu:
            if force or (now - float(self._last_log_emit_ts or 0.0)) >= float(min_interval_sec):
                self._last_log_emit_ts = now
                emit = True
        if emit:
            self._log(msg)

    @property
    def rx_packets(self) -> int:
        with self._mu:
            return int(self._rx_packets)

    @property
    def tx_packets(self) -> int:
        with self._mu:
            return int(self._tx_packets)

    @property
    def last_error(self) -> str:
        with self._mu:
            return str(self._last_error or '')

    def set_device(self, device_name: str, *, bpf_filter: Optional[str] = None) -> None:
        with self._mu:
            self.device_name = str(device_name or '').strip()
            if bpf_filter is not None:
                self.bpf_filter = str(bpf_filter or '').strip()

    def list_devices(self) -> List[CaptureDevice]:
        try:
            if self._backend is None:
                self._backend = LibpcapBackend()
            return self._backend.list_devices()
        except Exception as e:
            with self._mu:
                self._last_error = str(e)
            return []

    def _effective_bpf_filter(self) -> str:
        raw = str(self.bpf_filter or '').strip()
        if raw:
            return raw
        return 'ip or ip6 or arp'

    def _device_rank(self, dev: CaptureDevice) -> Tuple[int, int, str]:
        name = str(getattr(dev, 'name', '') or '')
        desc = str(getattr(dev, 'description', '') or '')
        lower = f"{name} {desc}".lower()
        score = 0
        if 'loopback' in lower or 'npcap_loopback' in lower:
            score -= 100
        if '\\device\\npf_' in lower:
            score += 20
        if 'wi-fi' in lower or 'wifi' in lower or 'wireless' in lower:
            score += 14
        if 'ethernet' in lower:
            score += 12
        if 'hyper-v' in lower or 'vmswitch' in lower or 'virtualbox' in lower or 'loop' in lower:
            score -= 6
        if 'bluetooth' in lower:
            score -= 10
        if 'wintun' in lower or "protonvpn" in lower or 'openvpn' in lower:
            score -= 8
        addrs = list(getattr(dev, 'addresses', []) or [])
        priv = 0
        for addr in addrs:
            try:
                ip = ipaddress.ip_address(str(addr).split('%', 1)[0])
            except Exception:
                continue
            if ip.version == 4 and (ip.is_private or ip.is_link_local):
                priv += 1
        score += min(10, priv * 2)
        return (score, len(addrs), lower)


    def _refresh_capture_candidates_locked(self) -> List[str]:
        names: List[str] = []
        descs: Dict[str, str] = {}
        try:
            devices = list(self.list_devices() or [])
        except Exception:
            devices = []
        ranked = sorted(devices, key=self._device_rank, reverse=True)
        for dev in ranked:
            name = str(getattr(dev, 'name', '') or '').strip()
            if not name:
                continue
            if name not in names:
                names.append(name)
                descs[name] = str(getattr(dev, 'description', '') or '')
        if self.device_name and self.device_name not in names:
            names.insert(0, self.device_name)
            descs.setdefault(self.device_name, '')
        self._candidate_devices = names
        self._candidate_device_descs = descs
        return list(names)

    def _choose_capture_device_locked(self, *, rotate: bool = False) -> str:
        names = self._refresh_capture_candidates_locked()
        if not names:
            return str(self.device_name or '').strip()
        current = str(self.device_name or '').strip()
        if current and not rotate:
            return current
        if rotate:
            self._candidate_index = (int(self._candidate_index) + 1) % len(names)
        else:
            if current and current in names:
                self._candidate_index = names.index(current)
                return current
            self._candidate_index = 0
        return names[self._candidate_index]

    def _start_capture_locked(self, *, rotate: bool = False, reason: str = '') -> bool:
        if not self.enable_capture:
            self._log('[MinerInterface] capture disabled')
            return False
        target = self._choose_capture_device_locked(rotate=rotate)
        if not target:
            self._log('[MinerInterface] capture warning: no capture device available')
            return False
        self.device_name = target
        effective_filter = self._effective_bpf_filter()
        try:
            if self._backend is None:
                self._backend = LibpcapBackend()
            try:
                self._backend.stop_capture()
            except Exception:
                pass
            self._backend.start_capture(
                self.device_name,
                self._on_capture_packet,
                bpf_filter=effective_filter,
                promiscuous=self.promiscuous,
                snaplen=self.snaplen,
                timeout_ms=self.timeout_ms,
            )
            self._capture_restart_count += 1
            why = f' reason={reason}' if reason else ''
            desc = self._candidate_device_descs.get(self.device_name, '')
            self._log(f'[MinerInterface] 🎣 capture armed device={self.device_name} filter={effective_filter or "<none>"}{why} desc={desc or "<none>"}')
            return True
        except Exception as e:
            self._last_error = str(e)
            self._log(f'[MinerInterface] capture start warning on {self.device_name}: {e}')
            return False

    def _capture_watchdog_loop(self) -> None:
        while not self._capture_watchdog_stop.wait(4.0):
            try:
                with self._mu:
                    started = bool(self._started)
                    last_ts = float(self._last_packet_ts or 0.0)
                    start_ts = float(self._start_ts or 0.0)
                    backend = self._backend
                if not started or not self.enable_capture:
                    continue
                now = time.time()
                quiet_for = now - (last_ts or start_ts or now)
                running = bool(backend.capture_running) if backend is not None else False
                if not running:
                    with self._mu:
                        self._start_capture_locked(rotate=False, reason='watchdog_not_running')
                    continue
                if quiet_for >= 6.0:
                    with self._mu:
                        self._log(f'[MinerInterface] 🔄 quiet capture for {quiet_for:.1f}s; rotating device')
                        self._start_capture_locked(rotate=True, reason='watchdog_quiet')
            except Exception as e:
                self._log(f'[MinerInterface] watchdog warning: {type(e).__name__}: {e}')

    def _router_delegate_iface_locked(self, peer_key: str = '') -> Optional[str]:
        peer_key_s = str(peer_key or '').strip()
        hint = dict(self._peer_device_hints.get(peer_key_s) or {}) if peer_key_s else {}
        iface = str(hint.get('device_name') or hint.get('iface') or '').strip()
        if iface and iface.lower() != self.IFACE_NAME.lower():
            return iface
        last = dict(self._last_device_packet or {})
        iface = str(last.get('device_name') or last.get('iface') or '').strip()
        if iface and iface.lower() != self.IFACE_NAME.lower():
            return iface
        return self.device_name or None

    def _local_ingest_router_packet(self, packet: RouterPacket, *, reason: str = 'miner_local_ingest') -> bool:
        if packet is None or not packet.to_bytes():
            return False
        ok = False
        try:
            with self._mu:
                self._feedback_suppress += 1
            ok = bool(self.remote_connection.ingest_router_packet(packet))
            self._log_activity(
                f'[MinerInterface] 🧩 local-ingest reason={reason} peer={packet.peer_key() or "?"} bytes={len(packet.to_bytes())} ok={str(bool(ok)).lower()}',
                force=(not ok),
                min_interval_sec=0.35,
            )
        except Exception as e:
            with self._mu:
                self._last_error = str(e)
            self._log(f'[MinerInterface] local ingest warning: {type(e).__name__}: {e}')
            ok = False
        finally:
            with self._mu:
                self._feedback_suppress = max(0, int(self._feedback_suppress) - 1)
        return ok

    def _inject_router_packet(self, packet: RouterPacket, *, peer_key: str = '', reason: str = 'miner_inject') -> bool:
        if packet is None or not packet.to_bytes():
            return False

        raw_base_url = str(getattr(self.remote_connection, 'router_base_url', '') or '').strip()
        raw_base_url = re.sub(r'(:\d+)[^\d/]+(?=$|/)', r'\1', raw_base_url)
        base_url = _normalize_router_api_base_url(raw_base_url or 'http://127.0.0.1:8844')

        token = str(getattr(self.remote_connection, 'router_token', '') or '')
        peer_key_s = str(peer_key or packet.peer_key() or '').strip()

        with self._mu:
            delegate_from = self._router_delegate_iface_locked(peer_key_s)

        remote_ok = False
        local_ok = False
        try:
            packet.inject_via_router_api(
                base_url=base_url,
                iface=self.IFACE_NAME,
                delegate_from=delegate_from,
                timeout_sec=float(getattr(self.remote_connection, 'router_timeout_sec', 2.0) or 2.0),
                token=token,
                extra={'reason': str(reason or 'miner_inject'), 'peer_key': peer_key_s},
            )
            remote_ok = True
        except Exception as e:
            with self._mu:
                self._last_error = str(e)
            self._log(f'[MinerInterface] inject warning: {e}')
        try:
            local_ok = self._local_ingest_router_packet(packet, reason=str(reason or 'miner_local_ingest'))
        except Exception:
            local_ok = False
        plen = len(packet.to_bytes())
        with self._mu:
            if remote_ok:
                self._inject_success += 1
            else:
                self._inject_fail += 1
            if 'garbage' in str(reason or '').lower() or 'low_value' in str(reason or '').lower() or 'socket_' in str(reason or '').lower():
                self._inject_garbage += 1
        self._log_activity(
            f'[MinerInterface] ↪ injected reason={reason} peer={peer_key_s or "?"} bytes={plen} iface={self.IFACE_NAME} delegate={delegate_from or "<none>"} remote={str(bool(remote_ok)).lower()} local={str(bool(local_ok)).lower()}',
            force=(remote_ok or local_ok),
            min_interval_sec=0.20,
        )
        return bool(remote_ok or local_ok)

    def _router_packet_from_socket_payload(self, peer_key: str, payload: bytes, *, outbound: bool, reason: str) -> Optional[RouterPacket]:
        blob = bytes(payload or b'')
        if not blob:
            return None
        peer_key_s = str(peer_key or '').strip()
        host, _, port_text = peer_key_s.rpartition(':')
        try:
            remote_port = int(port_text)
        except Exception:
            remote_port = 0
        remote_ip = str(host or '')
        service_kind = int(self.remote_connection._peer_services.get(peer_key_s, RemoteConnectionDll.RC_SERVICE_UNKNOWN))
        local_ip = ''
        local_port = 0
        with self._mu:
            hint = dict(self._peer_device_hints.get(peer_key_s) or {})
            if outbound:
                local_ip = str(hint.get('src_ip') or '')
                local_port = int(hint.get('sport') or hint.get('src_port') or 0)
            else:
                local_ip = str(hint.get('dst_ip') or '')
                local_port = int(hint.get('dport') or hint.get('dst_port') or 0)
        if not local_ip:
            try:
                local_ip = str(getattr(self.remote_connection, '_best_local_ip_for_remote')(remote_ip, prefer_private=True) or '')
            except Exception:
                local_ip = ''
        if local_port <= 0:
            local_port = (56000 + (int(time.time() * 1000.0) % 5000))
        packet_obj: _LevinProtocolPacketBase
        if service_kind == RemoteConnectionDll.RC_SERVICE_P2POOL_P2P:
            packet_obj = P2PoolPacket(peer_key=peer_key_s, command=0, body=blob, reason=reason, command_name='raw_p2pool', priority=1.20)
        else:
            packet_obj = MoneroPacket(peer_key=peer_key_s, command=0, body=blob, reason=reason, command_name='raw_monero', priority=1.10)
        if not remote_ip or remote_port <= 0 or not local_ip:
            return None
        return RouterPacket.from_protocol_packet(
            packet_obj,
            self.remote_connection,
            local_ip=local_ip,
            remote_ip=remote_ip,
            local_port=int(local_port),
            remote_port=int(remote_port),
            iface=self.IFACE_NAME,
            source='minerinterface:socket',
            capture_quality='miner_injected',
        )

    def start(self) -> None:
        with self._mu:
            if self._started:
                self._log('[MinerInterface] already started')
                return
            self._started = True
            self._capture_generation += 1
            self._start_ts = time.time()
            self._capture_watchdog_stop.clear()
        self._log(f'[MinerInterface] 🚀 start requested device={self.device_name or "<auto>"} capture={str(bool(self.enable_capture)).lower()} filter={self._effective_bpf_filter() or "<none>"}')
        with self._mu:
            self._start_capture_locked(rotate=False, reason='startup')
        with self._mu:
            if self._capture_watchdog_thread is None or not self._capture_watchdog_thread.is_alive():
                self._capture_watchdog_thread = threading.Thread(target=self._capture_watchdog_loop, name='MinerInterfaceWatchdog', daemon=True)
                self._capture_watchdog_thread.start()

    def stop(self) -> None:
        backend = None
        thread = None
        with self._mu:
            self._started = False
            self._capture_watchdog_stop.set()
            backend = self._backend
            thread = self._capture_watchdog_thread
            self._capture_watchdog_thread = None
        if backend is not None:
            try:
                backend.stop_capture()
            except Exception:
                pass
        if thread is not None and thread.is_alive() and thread is not threading.current_thread():
            try:
                thread.join(timeout=2.0)
            except Exception:
                pass
        self._log('[MinerInterface] 🛑 stopped')

    def note_socket_rx(self, peer_key: str, data: bytes) -> None:
        blob = bytes(data or b'')
        if not blob:
            return
        with self._mu:
            if int(self._feedback_suppress) > 0:
                return
            self._rx_packets += 1
            self._last_packet_ts = time.time()
        self._log_activity(f'[MinerInterface] 📥 socket-rx peer={peer_key} bytes={len(blob)}', force=True, min_interval_sec=0.5)
        try:
            self.remote_connection._received_packets.append({
                'ts': time.time(), 'peer': str(peer_key), 'kind': 'minerinterface_socket_rx', 'direction': 'in', 'size': len(blob), 'preview': blob[:64].hex()
            })
        except Exception:
            pass
        try:
            pkt = self._router_packet_from_socket_payload(peer_key, blob, outbound=False, reason='socket_rx')
            if pkt is not None:
                self._inject_router_packet(pkt, peer_key=peer_key, reason='socket_rx')
        except Exception:
            pass

    def note_socket_tx(self, peer_key: str, data: bytes) -> None:
        blob = bytes(data or b'')
        if not blob:
            return
        with self._mu:
            if int(self._feedback_suppress) > 0:
                return
            self._tx_packets += 1
        self._log_activity(f'[MinerInterface] 📤 socket-tx peer={peer_key} bytes={len(blob)}', force=True, min_interval_sec=0.5)
        try:
            pkt = self._router_packet_from_socket_payload(peer_key, blob, outbound=True, reason='socket_tx')
            if pkt is not None:
                self._inject_router_packet(pkt, peer_key=peer_key, reason='socket_tx')
        except Exception:
            pass

    def _on_capture_packet(self, packet: Dict[str, Any]) -> None:
        if not isinstance(packet, dict):
            return
        if packet.get('kind') == 'capture_error':
            with self._mu:
                self._last_error = str(packet.get('message') or '')
            self._log(f"[MinerInterface] capture warning: {packet.get('message') or ''}")
            return
        now = time.time()
        with self._mu:
            self._rx_packets += 1
            self._last_packet_ts = now
            self._last_device_packet = dict(packet)
        try:
            src_ip = str(packet.get('src_ip') or '')
            dst_ip = str(packet.get('dst_ip') or '')
            sport = int(packet.get('sport') or 0)
            dport = int(packet.get('dport') or 0)
            topic = str(packet.get('topic') or '')
            proto = str(packet.get('proto') or packet.get('l4') or '')
            service_kind = RemoteConnectionDll.RC_SERVICE_UNKNOWN
            if topic == 'p2pool' or sport in self.remote_connection._P2POOL_PORTS or dport in self.remote_connection._P2POOL_PORTS:
                service_kind = RemoteConnectionDll.RC_SERVICE_P2POOL_P2P
            elif topic == 'monero' or sport in self.remote_connection._MONERO_PORTS or dport in self.remote_connection._MONERO_PORTS:
                service_kind = RemoteConnectionDll.RC_SERVICE_MONERO_P2P
            if src_ip and sport:
                self._peer_device_hints[f'{src_ip}:{sport}'] = dict(packet)
            if dst_ip and dport:
                self._peer_device_hints[f'{dst_ip}:{dport}'] = dict(packet)
            router_pkt = RouterPacket.from_capture_dict(packet, iface=self.IFACE_NAME, source='minerinterface:capture', capture_quality='miner_injected')
            pkt_meta = router_pkt.to_event_dict().get('result') or {}
            blob = router_pkt.to_bytes()
            high_value = self.remote_connection._is_high_value_transport_packet(pkt_meta, blob, threshold=0.40)
            with self._mu:
                if high_value:
                    self._capture_high_value += 1
                else:
                    self._capture_low_value += 1
            self.remote_connection.ingest_packet_raw_event({'result': pkt_meta})
            inject_reason = 'capture_rx' if high_value else 'capture_rx_low_value'
            injected = self._inject_router_packet(router_pkt, peer_key=router_pkt.peer_key(), reason=inject_reason)
            self._last_capture_reason = inject_reason
            plen = len(blob)
            self._log_activity(
                f"[MinerInterface] 🧲 capture idx={self.rx_packets} topic={topic or '?'} proto={proto or '?'} peer={router_pkt.peer_key() or '?'} bytes={plen} high_value={str(bool(high_value)).lower()} injected={str(bool(injected)).lower()}",
                force=(self.rx_packets <= 8),
                min_interval_sec=0.25,
            )
            payload = b''
            try:
                payload, _meta = self.remote_connection._payload_from_maybe_packet(blob)
            except Exception:
                payload = blob
            if payload and service_kind != RemoteConnectionDll.RC_SERVICE_UNKNOWN:
                peer_key = f'{dst_ip}:{dport}' if dport in (self.remote_connection._MONERO_PORTS | self.remote_connection._P2POOL_PORTS) else f'{src_ip}:{sport}'
                direction = self.remote_connection._direction_for_packet(src_ip, sport, dst_ip, dport)
                self.remote_connection.feed_stream_bytes(
                    stream_id=f'libpcap:{src_ip}:{sport}>{dst_ip}:{dport}',
                    peer=peer_key,
                    direction=direction,
                    data=payload,
                    service=service_kind,
                    timestamp_ms=int(now * 1000.0),
                )
        except Exception as e:
            with self._mu:
                self._last_error = str(e)
            self._log(f'[MinerInterface] capture handler warning: {type(e).__name__}: {e}')

    def send_frame(self, frame: bytes, *, peer_key: Optional[str] = None, reason: str = 'raw_frame') -> bool:
        blob = bytes(frame or b'')
        if not blob:
            return False
        backend = self._backend
        device_name = self.device_name
        if backend is None or not device_name:
            return False
        try:
            backend.send_packet(blob)
            with self._mu:
                self._tx_packets += 1
                self._tx_queue.append((peer_key, blob[:128], reason))
            return True
        except Exception as e:
            with self._mu:
                self._last_error = str(e)
            return False

    def queue_socket_payload(self, peer_key: str, payload: bytes, *, reason: str = 'minerinterface_socket_payload') -> int:
        blob = bytes(payload or b'')
        if not blob:
            return 0
        try:
            pkt = self._router_packet_from_socket_payload(peer_key, blob, outbound=True, reason=reason)
            if pkt is not None:
                self._inject_router_packet(pkt, peer_key=peer_key, reason=reason)
        except Exception:
            pass
        rc = self.remote_connection.send_payload(blob, host=str(peer_key).split(':')[0], port=int(str(peer_key).split(':')[1]))
        if rc > 0:
            with self._mu:
                self._tx_packets += 1
                self._tx_queue.append((peer_key, blob[:128], reason))
        return rc

    def send_monero_handshake(self, peer_key: str, *, service_kind: int = RemoteConnectionDll.RC_SERVICE_MONERO_P2P, reason: str = 'minerinterface_handshake') -> int:
        try:
            return self.send_monero_packet(MoneroPacket.handshake(self.remote_connection, peer_key, reason=reason))
        except Exception as e:
            with self._mu:
                self._last_error = str(e)
            return 0

    def send_p2pool_handshake(self, peer_key: str, *, reason: str = 'minerinterface_p2pool_handshake') -> int:
        try:
            return self.send_p2pool_packet(P2PoolPacket.handshake(self.remote_connection, peer_key, reason=reason))
        except Exception as e:
            with self._mu:
                self._last_error = str(e)
            return 0

    def send_ping(self, peer_key: str, *, service_kind: int = RemoteConnectionDll.RC_SERVICE_MONERO_P2P, reason: str = 'minerinterface_ping') -> int:
        try:
            if int(service_kind) == RemoteConnectionDll.RC_SERVICE_P2POOL_P2P:
                return self.send_p2pool_packet(P2PoolPacket.ping(self.remote_connection, peer_key, reason=reason))
            return self.send_monero_packet(MoneroPacket.ping(self.remote_connection, peer_key, reason=reason))
        except Exception as e:
            with self._mu:
                self._last_error = str(e)
            return 0

    def maybe_send_hot_hash_probe(self, peer_key: str, score: float) -> int:
        score = float(score)
        if score <= 0.0:
            return 0
        service_kind = int(self.remote_connection._peer_services.get(peer_key, RemoteConnectionDll.RC_SERVICE_P2POOL_P2P))
        sent = 0
        try:
            if service_kind == RemoteConnectionDll.RC_SERVICE_P2POOL_P2P:
                if score >= 6.0:
                    sent += self.send_p2pool_packet(P2PoolPacket.handshake(self.remote_connection, peer_key, reason='hot_hash_probe_p2pool_handshake'))
                    sent += self.send_p2pool_packet(P2PoolPacket.timed_sync(self.remote_connection, peer_key, reason='hot_hash_probe_p2pool_timed_sync'))
                    sent += self.send_p2pool_packet(P2PoolPacket.support_flags(self.remote_connection, peer_key, reason='hot_hash_probe_p2pool_support_flags'))
                    return sent
                if score >= 3.0:
                    sent += self.send_p2pool_packet(P2PoolPacket.timed_sync(self.remote_connection, peer_key, reason='hot_hash_probe_p2pool_timed_sync'))
                    sent += self.send_p2pool_packet(P2PoolPacket.support_flags(self.remote_connection, peer_key, reason='hot_hash_probe_p2pool_support_flags'))
                    return sent
                if score >= 1.50:
                    return self.send_p2pool_handshake(peer_key, reason='hot_hash_probe_p2pool_handshake')
                return self.send_ping(peer_key, service_kind=service_kind, reason='hot_hash_probe_p2pool_ping')
            if score >= 4.50:
                sent += self.send_monero_packet(MoneroPacket.handshake(self.remote_connection, peer_key, reason='hot_hash_probe_monero_handshake'))
                sent += self.send_monero_packet(MoneroPacket.timed_sync(self.remote_connection, peer_key, reason='hot_hash_probe_monero_timed_sync'))
                return sent
            if score >= 2.0:
                return self.send_monero_handshake(peer_key, service_kind=service_kind, reason='hot_hash_probe_monero_handshake')
            return self.send_ping(peer_key, service_kind=service_kind, reason='hot_hash_probe_monero_ping')
        except Exception as e:
            with self._mu:
                self._last_error = str(e)
            return sent

    def snapshot(self) -> Dict[str, Any]:
        with self._mu:
            return {
                'started': bool(self._started),
                'device_name': self.device_name,
                'capture_running': bool(self._backend.capture_running) if self._backend is not None else False,
                'rx_packets': int(self._rx_packets),
                'tx_packets': int(self._tx_packets),
                'last_error': str(self._last_error or ''),
                'last_packet_ts': float(self._last_packet_ts or 0.0),
                'last_device_packet': dict(self._last_device_packet),
                'known_peers': len(self._peer_device_hints),
                'inject_success': int(self._inject_success),
                'inject_fail': int(self._inject_fail),
                'inject_garbage': int(self._inject_garbage),
                'capture_high_value': int(self._capture_high_value),
                'capture_low_value': int(self._capture_low_value),
                'capture_restart_count': int(self._capture_restart_count),
                'last_capture_reason': str(self._last_capture_reason or ''),
            }


class RemoteConnection:
    _MAX_QUIET_SEC = 900.0
    _ACTIVE_PEER_LIMIT = 4
    _KEEPALIVE_INTERVAL_SEC = 45.0
    _PROBE_INTERVAL_SEC = 25.0
    _SUPPORT_FLAGS_INTERVAL_SEC = 90.0
    _TIMED_SYNC_INTERVAL_SEC = 30.0
    _HANDSHAKE_RETRY_SEC = 12.0
    _BOOTSTRAP_IDLE_RETRY_SEC = 6.0
    _CONNECT_PROBE_BURST_SEC = 2.0
    _NATIVE_FRESH_SEC = 30.0
    _RX_PACKET_LIMIT = 4096
    _SEND_DRAIN_LIMIT = 64
    _STATUS_LOG_INTERVAL_SEC = 20.0
    _MAX_RECV_BYTES = 262144

    _MONERO_PORTS = {18080}
    _P2POOL_PORTS = {37888, 37889, 37890}
    _LEVIN_SIGNATURE = 0x0101010101012101
    _LEVIN_HEADER_SIZE = 33
    _LEVIN_FLAG_REQUEST = 0x00000001
    _LEVIN_FLAG_RESPONSE = 0x00000002
    _LEVIN_FLAG_BEGIN = 0x00000004
    _LEVIN_FLAG_END = 0x00000008

    _PORTABLE_STORAGE_SIGNATURE = b""
    _PORTABLE_STORAGE_VERSION = 1
    _PS_TYPE_INT64 = 1
    _PS_TYPE_INT32 = 2
    _PS_TYPE_INT16 = 3
    _PS_TYPE_INT8 = 4
    _PS_TYPE_UINT64 = 5
    _PS_TYPE_UINT32 = 6
    _PS_TYPE_UINT16 = 7
    _PS_TYPE_UINT8 = 8
    _PS_TYPE_DOUBLE = 9
    _PS_TYPE_STRING = 10
    _PS_TYPE_BOOL = 11
    _PS_TYPE_OBJECT = 12
    _PS_TYPE_ARRAY = 13
    _PS_FLAG_ARRAY = 0x80

    _MAINNET_NETWORK_ID = bytes((
        0x12, 0x30, 0xF1, 0x71, 0x61, 0x04, 0x41, 0x61,
        0x17, 0x31, 0x00, 0x82, 0x16, 0xA1, 0xA1, 0x10,
    ))

    def __init__(
        self,
        *,
        peers: List[Tuple[str, int]],
        logger: Optional[Callable[[str], None]] = None,
        connect_timeout_sec: float = 2.0,
        recv_timeout_sec: float = 1.0,
        reconnect_delay_sec: float = 10.0,
        log_cooldown_sec: float = 60.0,
        peer_rx_log_cooldown_sec: float = 20.0,
        hint_log_cooldown_sec: float = 45.0,
        hot_rx_window_sec: float = 30.0,
        router_base_url: Optional[str] = None,
        router_timeout_sec: float = 2.0,
        router_poll_interval_sec: float = 0.75,
        router_list_limit: int = 128,
        pcap_device_name: str = '',
        pcap_bpf_filter: str = '',
        pcap_promiscuous: bool = True,
        pcap_snaplen: int = 65535,
        pcap_timeout_ms: int = 250,
        use_miner_interface: bool = True,
    ) -> None:
        self.peers = [(str(host), int(port)) for host, port in peers if str(host).strip() and int(port) > 0]
        self.logger = logger or (lambda s: None)
        self.connect_timeout_sec = max(0.25, float(connect_timeout_sec))
        self.recv_timeout_sec = max(0.10, float(recv_timeout_sec))
        self.reconnect_delay_sec = max(1.0, float(reconnect_delay_sec))
        self.log_cooldown_sec = max(5.0, float(log_cooldown_sec))
        self.peer_rx_log_cooldown_sec = max(5.0, float(peer_rx_log_cooldown_sec))
        self.hint_log_cooldown_sec = max(5.0, float(hint_log_cooldown_sec))
        self.hot_rx_window_sec = max(5.0, float(hot_rx_window_sec))
        self.router_timeout_sec = max(0.5, float(router_timeout_sec))
        self.router_poll_interval_sec = max(0.10, float(router_poll_interval_sec))
        self.router_list_limit = max(8, int(router_list_limit))
        self.router_base_url = _normalize_router_api_base_url(router_base_url or "http://127.0.0.1:8844").rstrip("/")
        self.pcap_device_name = str(pcap_device_name or '').strip()
        self.pcap_bpf_filter = str(pcap_bpf_filter or '').strip()
        self.pcap_promiscuous = bool(pcap_promiscuous)
        self.pcap_snaplen = max(256, int(pcap_snaplen))
        self.pcap_timeout_ms = max(1, int(pcap_timeout_ms))
        self.use_miner_interface = bool(use_miner_interface)

        self._stop = threading.Event()
        self._started = False
        self._combined_mode = False
        self._mu = threading.RLock()
        self._slots = threading.BoundedSemaphore(self._ACTIVE_PEER_LIMIT)
        self._threads: List[threading.Thread] = []
        self._rate_window = _RecentRateWindow(window_sec=10.0)
        self._last_hint_log_ts = 0.0
        self._last_status_log_ts = 0.0

        self._connect_events_total = 0
        self._disconnect_events_total = 0
        self._fail_events_total = 0
        self._epoch = 0

        self._total_rx_packets = 0
        self._total_rx_bytes = 0
        self._total_tx_packets = 0
        self._total_tx_bytes = 0
        self._socket_rx_packets = 0
        self._socket_rx_bytes = 0
        self._router_rx_packets = 0
        self._router_rx_bytes = 0
        self._raw_packet_rx_packets = 0
        self._raw_packet_rx_bytes = 0
        self._dll_rx_frames = 0

        self._packet_topic: Optional[str] = None
        self._best_protocol_guess: Optional[str] = None
        self._service_guess: Optional[str] = None
        self._tcp_flags_compact: str = ""
        self._payload_len: int = 0
        self._levin_present = False
        self._sidechain_height: Optional[int] = None
        self._mainchain_height: Optional[int] = None
        self._difficulty: Optional[int] = None
        self._peer_count_hint: Optional[int] = None
        self._last_packet_observation_ts = 0.0
        self._last_native_observation_ts = 0.0
        self._last_validated_frame_ts = 0.0
        self._validated_frame_count = 0
        self._invalid_frame_count = 0
        self._router_packets_total = 0
        self._router_raw_packets_total = 0
        self._router_last_packet_id = 0
        self._router_last_poll_ts = 0.0

        self._last_command: Optional[int] = None
        self._last_command_name: Optional[str] = None
        self._last_return_code: Optional[int] = None
        self._last_status: Optional[str] = None
        self._last_top_id_hex: Optional[str] = None
        self._last_top_version: Optional[int] = None
        self._last_pruning_seed: Optional[int] = None
        self._last_rpc_port_hint: Optional[int] = None
        self._last_my_port: Optional[int] = None
        self._last_local_peerlist_count: Optional[int] = None
        self._last_cumulative_difficulty_top64: Optional[int] = None
        self._last_peer_id: Optional[int] = None
        self._last_support_flags: Optional[int] = None
        self._last_rpc_method: Optional[str] = None
        self._last_rpc_job_id: Optional[str] = None
        self._last_semantic_json: str = ""
        self._semantic_frame_count = 0
        self._real_data_frame_count = 0
        self._last_real_data_ts = 0.0
        self._last_semantic_source: str = ""
        self._packet_observation_count = 0
        self._packet_transport_confidence = 0.0
        self._last_packet_service_hint: Optional[str] = None
        self._last_packet_transport_kind: Optional[str] = None
        self._last_packet_payload_preview_hex: str = ""
        self._last_packet_entropy: Optional[float] = None
        self._last_packet_payload_len: int = 0
        self._last_syn_with_payload = False
        self._last_tcp_mss: Optional[int] = None
        self._last_tcp_window_scale: Optional[int] = None
        self._last_tcp_sack_permitted = False
        self._last_tcp_timestamp = False
        self._p2pool_transport_packet_count = 0
        self._monero_transport_packet_count = 0
        self._syn_with_payload_count = 0

        self._received_packets: Deque[Dict[str, Any]] = deque(maxlen=self._RX_PACKET_LIMIT)
        self._send_queues: Dict[str, Deque[bytes]] = defaultdict(deque)
        self._flow_reassemblers: Dict[str, _TcpDirectionalReassembler] = {}
        self._opened_streams: Set[str] = set()
        self._socket_map: Dict[str, socket.socket] = {}
        self._peer_services: Dict[str, int] = {}
        self._peer_stream_ids: Dict[str, Dict[str, str]] = {}
        self._stream_peer_map: Dict[str, str] = {}
        self._dll_stream_mode: Dict[str, str] = {}
        self._dll_skipped_non_levin = 0
        self._peer_last_probe_ts: Dict[str, float] = {}
        self._peer_last_support_probe_ts: Dict[str, float] = {}
        self._peer_last_probe_cmd: Dict[str, int] = {}
        self._peer_last_handshake_ts: Dict[str, float] = {}
        self._peer_last_timed_sync_ts: Dict[str, float] = {}
        self._peer_bootstrap_stage: Dict[str, str] = {}
        self._peer_recv_buffers: Dict[str, bytearray] = {}
        self._peer_last_inbound_frame_ts: Dict[str, float] = {}
        self._peer_last_inbound_command: Dict[str, int] = {}
        self._peer_inbound_frame_count: Dict[str, int] = {}
        self._local_peer_id = int.from_bytes(os.urandom(8), "little") | 1

        self._dll = RemoteConnectionDll(logger=self._log)
        self.miner_interface: Optional[MinerInterface] = MinerInterface(
            remote_connection=self,
            logger=self._log,
            device_name=self.pcap_device_name,
            bpf_filter=self.pcap_bpf_filter,
            promiscuous=self.pcap_promiscuous,
            snaplen=self.pcap_snaplen,
            timeout_ms=self.pcap_timeout_ms,
            enable_capture=self.use_miner_interface,
        ) if self.use_miner_interface else None
        self._router_stream = RouterPacketStream(
            base_url=self.router_base_url or "http://127.0.0.1:8844",
            callback=self.ingest_router_packet,
            logger=self._log,
            timeout_sec=self.router_timeout_sec,
            poll_interval_sec=self.router_poll_interval_sec,
            list_limit=self.router_list_limit,
        )

        now = time.time()
        self._peer_state: Dict[str, Dict[str, Any]] = {}
        for host, port in self.peers:
            key = f"{host}:{port}"
            self._peer_state[key] = {
                "host": host,
                "port": port,
                "connected": False,
                "latency_ms": None,
                "last_connect_ts": 0.0,
                "last_rx_ts": 0.0,
                "last_tx_ts": 0.0,
                "last_activity_ts": 0.0,
                "last_attempt_ts": 0.0,
                "rx_bytes": 0,
                "rx_packets": 0,
                "tx_bytes": 0,
                "tx_packets": 0,
                "last_error": "",
                "last_preview": "",
                "last_tx_preview": "",
                "recv_chunks": 0,
                "validated_frames": 0,
                "invalid_frames": 0,
                "created_ts": now,
                "last_probe_ts": 0.0,
                "last_support_probe_ts": 0.0,
                "last_probe_cmd": 0,
                "last_handshake_ts": 0.0,
                "last_timed_sync_ts": 0.0,
                "bootstrap_stage": "idle",
            }
        self._rate_window.add(now, (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))

    def set_combined_mode(self, enabled: bool) -> None:
        self._combined_mode = bool(enabled)

    def _log(self, message: str) -> None:
        try:
            self.logger(message)
        except Exception:
            pass

    def set_router_api_base_url(self, host_or_url: str, port: int = 8844) -> None:
        value = str(host_or_url or "").strip()
        if not value:
            return
        base_url = _normalize_router_api_base_url(value, default_port=int(port)).rstrip("/")
        with self._mu:
            self.router_base_url = base_url
            self._router_stream.set_base_url(base_url)

    def set_miner_interface_device(self, device_name: str, bpf_filter: str = '') -> None:
        with self._mu:
            self.pcap_device_name = str(device_name or '').strip()
            if bpf_filter:
                self.pcap_bpf_filter = str(bpf_filter or '').strip()
            if self.miner_interface is not None:
                self.miner_interface.set_device(self.pcap_device_name, bpf_filter=self.pcap_bpf_filter)

    def send_hot_hash_loop_packet(self, payload: bytes, *, peer_key: Optional[str] = None, score: float = 0.0, reason: str = 'hot_hash_loop_tx') -> int:
        blob = bytes(payload or b'')
        if not blob:
            return 0
        sent = 0
        if peer_key:
            try:
                host, port_s = str(peer_key).rsplit(':', 1)
                sent = self.send_payload(blob, host=host, port=int(port_s))
            except Exception:
                sent = 0
        else:
            sent = self.send_payload(blob)
        if sent <= 0 and self.miner_interface is not None and peer_key:
            self.miner_interface.maybe_send_hot_hash_probe(peer_key, score)
        return int(sent)

    def _service_for_router_hints(
        self,
        *,
        service_hint: Optional[str] = None,
        topic: Optional[str] = None,
        proto: Optional[str] = None,
        source: str = "",
        src_port: int = 0,
        dst_port: int = 0,
    ) -> Tuple[int, Optional[str], Optional[str]]:
        service_kind, service_guess, topic_guess = self._service_for_ports(int(src_port), int(dst_port))
        if service_kind != RemoteConnectionDll.RC_SERVICE_UNKNOWN:
            return service_kind, service_guess, topic_guess

        blob = " ".join(
            x.strip().lower()
            for x in (
                str(service_hint or ""),
                str(topic or ""),
                str(proto or ""),
                str(source or ""),
            )
            if str(x or "").strip()
        )
        if any(tok in blob for tok in ("p2pool", "sidechain")):
            return (RemoteConnectionDll.RC_SERVICE_P2POOL_P2P, "p2pool_p2p", "p2pool")
        if any(tok in blob for tok in ("monero", "mainchain", "levin")):
            if "p2pool" in blob:
                return (RemoteConnectionDll.RC_SERVICE_P2POOL_P2P, "p2pool_p2p", "p2pool")
            return (RemoteConnectionDll.RC_SERVICE_MONERO_P2P, "monero_p2p", "monero")
        return (RemoteConnectionDll.RC_SERVICE_UNKNOWN, None, None)

    def ingest_payload_bytes(
        self,
        raw_bytes: bytes,
        source: str = "",
        service_hint: Optional[str] = None,
        topic: Optional[str] = None,
        proto: Optional[str] = None,
        peer_hint: str = "",
        src_port: int = 0,
        dst_port: int = 0,
    ) -> bool:
        blob = bytes(raw_bytes or b"")
        if not blob:
            return False

        payload_blob, packet_meta = self._payload_from_maybe_packet(blob)
        effective_payload = bytes(payload_blob or b"")
        if not effective_payload:
            effective_payload = blob

        src_port_eff = int(packet_meta.get("src_port") or src_port or 0)
        dst_port_eff = int(packet_meta.get("dst_port") or dst_port or 0)

        now = time.time()
        service_kind, service_guess, topic_guess = self._service_for_router_hints(
            service_hint=service_hint,
            topic=topic,
            proto=proto,
            source=source,
            src_port=src_port_eff,
            dst_port=dst_port_eff,
        )
        peer_key = str(peer_hint or "").strip()
        if not peer_key:
            if packet_meta.get("was_packet"):
                direction = self._direction_for_packet(
                    str(packet_meta.get("src_ip") or ""),
                    src_port_eff,
                    str(packet_meta.get("dst_ip") or ""),
                    dst_port_eff,
                )
                peer_ip = str(packet_meta.get("dst_ip") if direction == RemoteConnectionDll.RC_DIR_OUTBOUND else packet_meta.get("src_ip") or "").strip()
                peer_port = int(dst_port_eff if direction == RemoteConnectionDll.RC_DIR_OUTBOUND else src_port_eff or 0)
                if peer_ip and peer_port > 0:
                    peer_key = f"{peer_ip}:{peer_port}"
            if not peer_key:
                if service_guess:
                    peer_key = f"router:{service_guess}:8844"
                else:
                    peer_key = "router:payload:8844"

        with self._mu:
            st = self._ensure_peer_state_locked(peer_key)
            st["connected"] = True
            st["last_rx_ts"] = now
            st["last_activity_ts"] = now
            st["rx_bytes"] += len(blob)
            st["rx_packets"] += 1
            st["recv_chunks"] = int(st.get("recv_chunks") or 0) + 1
            st["last_preview"] = self._preview_text(effective_payload)
            st["bootstrap_stage"] = "router_payload" if "router" in peer_key else "payload_rx"
            self._total_rx_packets += 1
            self._total_rx_bytes += len(blob)
            self._payload_len = len(effective_payload)
            self._last_packet_observation_ts = now
            self._last_native_observation_ts = now
            if service_guess:
                self._service_guess = service_guess
            if topic_guess:
                self._packet_topic = topic_guess
            if proto and str(proto).strip():
                self._best_protocol_guess = str(proto).strip()
            elif self._payload_contains_decode_markers(effective_payload):
                self._best_protocol_guess = "Levin"
                self._levin_present = True

            if service_kind != RemoteConnectionDll.RC_SERVICE_UNKNOWN:
                try:
                    self._stream_ids_for_peer_locked(peer_key, int(service_kind))
                except Exception:
                    pass
                try:
                    self._feed_dll_locked(
                        peer_key,
                        RemoteConnectionDll.RC_DIR_INBOUND,
                        effective_payload,
                        timestamp_ms=int(now * 1000.0),
                        service_kind=int(service_kind),
                    )
                except Exception:
                    pass

            self._received_packets.append({
                "ts": now,
                "peer": peer_key,
                "kind": "payload_chunk",
                "direction": "in",
                "size": len(effective_payload),
                "wire_size": len(blob),
                "preview": st["last_preview"],
                "service_guess": service_guess,
                "source": str(source or ""),
                "src_port": src_port_eff,
                "dst_port": dst_port_eff,
                "wrapped_packet": bool(packet_meta.get("was_packet")),
            })

            if self._is_probably_text(effective_payload):
                try:
                    decoded_text = effective_payload.decode("utf-8", errors="ignore")
                    self._extract_text_observations_locked(decoded_text)
                    self._extract_structured_payload_locked(decoded_text, service=int(service_kind), source="payload_text")
                except Exception:
                    pass

            try:
                self._consume_payload_evidence_locked(
                    peer_key,
                    effective_payload,
                    now,
                    int(service_kind),
                    source="router_payload" if "router" in str(source or "").lower() else "payload_text",
                )
            except Exception:
                pass
            self._poll_dll_events_locked(now)
            self._rate_sample_locked(now)
            self._emit_status_log_locked(now)
        return True

    @staticmethod
    def _preview_text(data: bytes, limit: int = 96) -> str:
        if not data:
            return ""
        try:
            text = data[:limit].decode("utf-8", errors="ignore")
        except Exception:
            text = ""
        text = text.replace("\r", " ").replace("\n", " ").strip()
        if len(data) > limit and text:
            text += " …"
        return text

    @staticmethod
    def _is_probably_text(data: bytes) -> bool:
        if not data:
            return False
        sample = data[:128]
        printable = 0
        for b in sample:
            if b in (9, 10, 13) or 32 <= b <= 126:
                printable += 1
        return printable >= max(8, int(len(sample) * 0.75))

    @staticmethod
    def _tcp_flags_to_compact(flags: int) -> str:
        mapping = [
            (0x01, "F"),
            (0x02, "S"),
            (0x04, "R"),
            (0x08, "P"),
            (0x10, "A"),
            (0x20, "U"),
            (0x40, "E"),
            (0x80, "C"),
        ]
        out = "".join(ch for bit, ch in mapping if flags & bit)
        return out or "-"

    @staticmethod
    def _command_name_for(command: int) -> Optional[str]:
        mapping = {
            1001: "handshake",
            1002: "timed_sync",
            1003: "ping",
            1004: "stat_info",
            1005: "network_state",
            1006: "peer_id",
            1007: "support_flags",
            2001: "new_block",
            2002: "new_transactions",
            2003: "request_get_objects",
            2004: "response_get_objects",
            2006: "request_chain",
            2007: "response_chain_entry",
            2008: "new_fluffy_block",
            2009: "request_fluffy_missing_tx",
            2010: "get_txpool_complement",
        }
        try:
            return mapping.get(int(command))
        except Exception:
            return None

    @staticmethod
    def _is_private_ip(ip: str) -> bool:
        try:
            return ip.startswith("10.") or ip.startswith("192.168.") or (ip.startswith("172.") and 16 <= int(ip.split(".")[1]) <= 31)
        except Exception:
            return False

    def _service_for_port(self, port: int) -> Tuple[int, Optional[str], Optional[str]]:
        port = int(port)
        if port in self._P2POOL_PORTS:
            return (RemoteConnectionDll.RC_SERVICE_P2POOL_P2P, "p2pool_p2p", "p2pool")
        if port in self._MONERO_PORTS:
            return (RemoteConnectionDll.RC_SERVICE_MONERO_P2P, "monero_p2p", "monero")
        return (RemoteConnectionDll.RC_SERVICE_UNKNOWN, None, None)

    def _service_for_ports(self, src_port: int, dst_port: int) -> Tuple[int, Optional[str], Optional[str]]:
        ports = {int(src_port), int(dst_port)}
        if ports & self._P2POOL_PORTS:
            return (RemoteConnectionDll.RC_SERVICE_P2POOL_P2P, "p2pool_p2p", "p2pool")
        if ports & self._MONERO_PORTS:
            return (RemoteConnectionDll.RC_SERVICE_MONERO_P2P, "monero_p2p", "monero")
        return (RemoteConnectionDll.RC_SERVICE_UNKNOWN, None, None)

    def _packet_value_score(self, packet: Dict[str, Any], raw_bytes: bytes = b'') -> float:
        pkt = dict(packet or {})
        blob = bytes(raw_bytes or b'')
        payload = b''
        meta: Dict[str, Any] = {}
        if blob:
            try:
                payload, meta = self._payload_from_maybe_packet(blob)
            except Exception:
                payload, meta = blob, {}
        elif pkt.get('payload'):
            payload = bytes(pkt.get('payload') or b'')
        score = 0.0
        proto = str(pkt.get('proto') or pkt.get('l4') or '').strip().lower()
        topic = str(pkt.get('topic') or '').strip().lower()
        sport = int(pkt.get('src_port') or pkt.get('sport') or 0)
        dport = int(pkt.get('dst_port') or pkt.get('dport') or 0)
        service_kind, _sg, _tg = self._service_for_ports(sport, dport)
        iface = str(pkt.get('iface') or '').strip().lower()
        capture_quality = str(pkt.get('capture_quality') or '').strip().lower()
        summary = str(pkt.get('summary') or '').strip().lower()
        if service_kind != RemoteConnectionDll.RC_SERVICE_UNKNOWN:
            score += 0.56
        if iface == 'miner':
            score += 0.22
        if capture_quality in {'synthetic_protocol', 'miner_injected'}:
            score += 0.24
        if topic in {'p2pool', 'monero'}:
            score += 0.28
        if proto in {'tcp', 'levin'}:
            score += 0.10
        if topic in {'ssdp', 'mdns', 'llmnr', 'dns', 'dhcp', 'arp', 'igmp', 'http'}:
            score -= 0.34
        if 'loopback' in iface or '127.0.0.1' in summary:
            score -= 0.25
        plen = int(len(payload or b''))
        raw_len = int(len(blob or b''))
        if self._payload_contains_decode_markers(payload):
            score += 0.62
        elif plen >= 1024:
            score += 0.28
        elif plen >= 256:
            score += 0.18
        elif plen >= 96:
            score += 0.11
        elif plen > 0:
            score += 0.04
        if raw_len >= 1400:
            score += 0.10
        flags_compact = str(meta.get('flags_compact') or pkt.get('flags') or '').upper()
        if meta.get('syn_with_payload'):
            score += 0.16
        elif flags_compact in {'ACK', 'A'} and plen <= 0:
            score -= 0.20
        if pkt.get('src_ip') and str(pkt.get('src_ip')).startswith('127.'):
            score -= 0.18
        if pkt.get('dst_ip') and str(pkt.get('dst_ip')).startswith('127.'):
            score -= 0.18
        if plen > 0:
            try:
                ent = float(self._shannon_entropy(payload))
            except Exception:
                ent = 0.0
            if ent >= 3.45:
                score += 0.05
        return max(0.0, min(1.70, float(score)))

    def _is_high_value_transport_packet(self, packet: Dict[str, Any], raw_bytes: bytes = b'', *, threshold: float = 0.44) -> bool:
        return self._packet_value_score(packet, raw_bytes) >= float(threshold)

    def _looks_like_levin_frame(self, data: bytes) -> bool:
        blob = bytes(data or b"")
        if len(blob) < 8:
            return False
        try:
            sig = struct.unpack_from("<Q", blob, 0)[0]
        except Exception:
            return False
        if sig != self._LEVIN_SIGNATURE:
            return False
        if len(blob) >= self._LEVIN_HEADER_SIZE:
            try:
                version = struct.unpack_from("<I", blob, 29)[0]
                if version != 1:
                    return False
            except Exception:
                return False
        return True

    def _portable_storage_offsets(self, data: bytes) -> List[int]:
        blob = bytes(data or b"")
        if len(blob) < 9:
            return []
        offsets: List[int] = []
        start = 0
        while True:
            idx = blob.find(self._PORTABLE_STORAGE_SIGNATURE, start)
            if idx < 0:
                break
            if idx + 8 < len(blob) and blob[idx + 8] == self._PORTABLE_STORAGE_VERSION:
                offsets.append(int(idx))
            start = idx + 1
        return offsets

    def _payload_contains_decode_markers(self, data: bytes) -> bool:
        blob = bytes(data or b"")
        if not blob:
            return False
        if self._looks_like_levin_frame(blob):
            return True
        if self._portable_storage_offsets(blob):
            return True
        markers = (
            b"local_peerlist_new",
            b"payload_data",
            b"current_height",
            b"current_blockchain_height",
            b"cumulative_difficulty",
            b"top_id",
            b"top_version",
            b"pruning_seed",
            b"rpc_port",
        )
        return any(m in blob for m in markers)

    def _dll_candidate_payload(self, data: bytes, service_kind: int) -> bool:
        blob = bytes(data or b'')
        if not blob:
            return False
        payload, meta = self._payload_from_maybe_packet(blob)
        effective = bytes(payload or blob)
        if self._payload_contains_decode_markers(effective):
            return True
        score = self._packet_value_score(meta, effective)
        if int(service_kind) in (RemoteConnectionDll.RC_SERVICE_MONERO_P2P, RemoteConnectionDll.RC_SERVICE_P2POOL_P2P):
            if len(effective) >= 8:
                return True
            if score >= 0.56:
                return True
            if meta.get('syn_with_payload') and len(effective) >= 24 and score >= 0.36:
                return True
            if len(effective) >= 64:
                return True
        return False

    @staticmethod
    def _payload_from_maybe_packet(raw_bytes: bytes) -> Tuple[bytes, Dict[str, Any]]:
        blob = bytes(raw_bytes or b"")
        meta: Dict[str, Any] = {"raw_len": len(blob), "was_packet": False}
        try:
            pkt = RemoteConnection._parse_packet_summary(blob)
        except Exception:
            pkt = None
        if pkt is not None:
            payload = bytes(pkt.get("payload") or b"")
            meta.update(pkt)
            meta["was_packet"] = True
            return payload, meta
        return blob, meta

    def _ensure_peer_state_locked(self, peer_key: str) -> Dict[str, Any]:
        st = self._peer_state.get(peer_key)
        if st is None:
            host, _, port_text = peer_key.rpartition(":")
            try:
                port = int(port_text)
            except Exception:
                port = 0
            st = {
                "host": host,
                "port": port,
                "connected": False,
                "latency_ms": None,
                "last_connect_ts": 0.0,
                "last_rx_ts": 0.0,
                "last_tx_ts": 0.0,
                "last_activity_ts": 0.0,
                "last_attempt_ts": 0.0,
                "rx_bytes": 0,
                "rx_packets": 0,
                "tx_bytes": 0,
                "tx_packets": 0,
                "last_error": "",
                "last_preview": "",
                "last_tx_preview": "",
                "recv_chunks": 0,
                "validated_frames": 0,
                "invalid_frames": 0,
                "created_ts": time.time(),
                "last_probe_ts": 0.0,
                "last_support_probe_ts": 0.0,
                "last_probe_cmd": 0,
                "last_handshake_ts": 0.0,
                "last_timed_sync_ts": 0.0,
                "bootstrap_stage": "idle",
            }
            self._peer_state[peer_key] = st
        return st

    @staticmethod
    def _shannon_entropy(data: bytes) -> float:
        blob = bytes(data or b"")
        if not blob:
            return 0.0
        counts = {}
        for b in blob:
            counts[b] = counts.get(b, 0) + 1
        total = float(len(blob))
        import math
        ent = 0.0
        for c in counts.values():
            p = float(c) / total
            ent -= p * math.log(p, 2)
        return ent

    @staticmethod
    def _decode_tcp_options(options: bytes) -> Dict[str, Any]:
        blob = bytes(options or b"")
        out: Dict[str, Any] = {
            "mss": None,
            "window_scale": None,
            "sack_permitted": False,
            "timestamp": None,
            "options": [],
        }
        i = 0
        while i < len(blob):
            kind = int(blob[i])
            if kind == 0:
                out["options"].append({"kind": 0, "name": "eol"})
                break
            if kind == 1:
                out["options"].append({"kind": 1, "name": "nop"})
                i += 1
                continue
            if i + 1 >= len(blob):
                break
            ln = int(blob[i + 1])
            if ln < 2 or (i + ln) > len(blob):
                break
            body = blob[i + 2:i + ln]
            item: Dict[str, Any] = {"kind": kind, "len": ln, "raw_hex": body.hex()}
            if kind == 2 and len(body) == 2:
                item["name"] = "mss"
                item["value"] = struct.unpack("!H", body)[0]
                out["mss"] = item["value"]
            elif kind == 3 and len(body) == 1:
                item["name"] = "window_scale"
                item["value"] = int(body[0])
                out["window_scale"] = item["value"]
            elif kind == 4 and len(body) == 0:
                item["name"] = "sack_permitted"
                item["value"] = True
                out["sack_permitted"] = True
            elif kind == 8 and len(body) == 8:
                tsval, tsecr = struct.unpack("!II", body)
                item["name"] = "timestamp"
                item["tsval"] = int(tsval)
                item["tsecr"] = int(tsecr)
                out["timestamp"] = {"tsval": int(tsval), "tsecr": int(tsecr)}
            else:
                item["name"] = f"opt_{kind}"
            out["options"].append(item)
            i += ln
        return out

    def _apply_packet_evidence_locked(self, packet_info: Dict[str, Any], *, service_guess: Optional[str], topic: Optional[str], source: str = "") -> None:
        payload = bytes(packet_info.get("payload") or b"")
        flags = str(packet_info.get("flags_compact") or "")
        payload_len = int(packet_info.get("payload_len") or 0)
        syn = "S" in flags and "A" not in flags
        syn_with_payload = bool(syn and payload_len > 0)
        packet_entropy = self._shannon_entropy(payload) if payload_len > 0 else 0.0
        tcp_opts = packet_info.get("tcp_options_decoded") or {}
        mss = tcp_opts.get("mss")
        wscale = tcp_opts.get("window_scale")
        sack_perm = bool(tcp_opts.get("sack_permitted"))
        ts_present = bool(tcp_opts.get("timestamp"))

        self._packet_observation_count += 1
        self._last_packet_payload_len = payload_len
        self._last_packet_payload_preview_hex = payload[:48].hex()
        self._last_packet_entropy = float(packet_entropy) if payload_len > 0 else None
        self._last_syn_with_payload = syn_with_payload
        self._last_tcp_mss = int(mss) if mss is not None else None
        self._last_tcp_window_scale = int(wscale) if wscale is not None else None
        self._last_tcp_sack_permitted = sack_perm
        self._last_tcp_timestamp = ts_present
        if service_guess:
            self._last_packet_service_hint = str(service_guess)
        if topic and not self._packet_topic:
            self._packet_topic = str(topic)

        packet_transport_kind = None
        conf = 0.0
        if service_guess == "p2pool_p2p":
            self._p2pool_transport_packet_count += 1
            if syn_with_payload:
                packet_transport_kind = "p2pool_syn_with_data"
                conf = 0.34
            elif syn:
                packet_transport_kind = "p2pool_syn"
                conf = 0.20
            elif payload_len > 0:
                packet_transport_kind = "p2pool_tcp_payload"
                conf = 0.28
            else:
                packet_transport_kind = "p2pool_tcp_control"
                conf = 0.16
        elif service_guess == "monero_p2p":
            self._monero_transport_packet_count += 1
            if syn_with_payload:
                packet_transport_kind = "monero_syn_with_data"
                conf = 0.38
            elif syn:
                packet_transport_kind = "monero_syn"
                conf = 0.22
            elif payload_len > 0:
                packet_transport_kind = "monero_tcp_payload"
                conf = 0.30
            else:
                packet_transport_kind = "monero_tcp_control"
                conf = 0.18

        if syn_with_payload:
            self._syn_with_payload_count += 1
            conf += 0.05
        if payload_len > 0 and self._looks_like_levin_frame(payload):
            self._best_protocol_guess = "Levin"
            self._levin_present = True
            conf = max(conf, 0.55)
            if packet_transport_kind:
                packet_transport_kind += "_levin"
        elif packet_transport_kind and not self._best_protocol_guess:
            self._best_protocol_guess = packet_transport_kind

        self._packet_transport_confidence = max(0.0, min(1.0, float(conf)))
        if packet_transport_kind:
            self._last_packet_transport_kind = packet_transport_kind

    def _extract_text_observations_locked(self, text: str) -> None:
        if not text:
            return
        low = text.lower()
        if "p2pool" in low:
            self._packet_topic = "p2pool"
            self._service_guess = "p2pool_p2p"
        elif "monero" in low:
            self._packet_topic = "monero"
            self._service_guess = "monero_p2p"
        if "levin" in low:
            self._levin_present = True
            self._best_protocol_guess = "Levin"

    def _apply_decoded_fields_locked(self, decoded: Dict[str, Any], *, service: Optional[int] = None, source: str = "") -> None:
        if not isinstance(decoded, dict):
            return

        source_l = str(source or "").lower()
        authoritative = source_l in {
            "dll_levin_event_inbound",
            "semantic_json_inbound",
            "dll_body_json_inbound",
            "router_semantic_json",
            "socket_semantic_json",
            "socket_levin_inbound",
            "socket_levin_body",
            "raw_packet_payload_portable_storage",
            "payload_text_portable_storage",
            "router_payload_portable_storage",
            "raw_packet_payload",
            "router_payload",
        }
        semantic_like = authoritative or ("levin" in source_l) or ("semantic" in source_l)

        def _as_int(*keys: str) -> Optional[int]:
            for k in keys:
                if k not in decoded:
                    continue
                try:
                    v = decoded.get(k)
                    if v is None or v == "":
                        continue
                    return int(v)
                except Exception:
                    continue
            return None

        def _as_str(*keys: str) -> Optional[str]:
            for k in keys:
                if k not in decoded:
                    continue
                v = decoded.get(k)
                if v is None:
                    continue
                s = str(v).strip()
                if s:
                    return s
            return None

        height_main = _as_int("current_blockchain_height", "height", "blockchain_height")
        height_side = _as_int("current_height", "sidechain_height")
        total_height = _as_int("total_height")
        difficulty = _as_int("decoded_cumulative_difficulty_low64", "cumulative_difficulty_low64", "cumulative_difficulty", "difficulty")
        difficulty_top64 = _as_int("decoded_cumulative_difficulty_high64", "cumulative_difficulty_top64")
        peer_count = _as_int("decoded_local_peerlist_count", "local_peerlist_count", "peer_count", "connected_peers")
        peer_id = _as_int("decoded_peer_id", "peer_id")
        support_flags = _as_int("decoded_support_flags", "support_flags")
        pruning_seed = _as_int("decoded_pruning_seed", "pruning_seed")
        top_version = _as_int("decoded_top_version", "top_version")
        rpc_port = _as_int("decoded_rpc_port", "rpc_port")
        my_port = _as_int("decoded_my_port", "my_port", "p2p_port", "port")
        status = _as_str("status", "decoded_status")
        top_id = _as_str("decoded_top_id_hex", "top_id_hex", "top_id")
        method = _as_str("method")
        job_id = _as_str("job_id")

        authoritative_fields_seen = False
        authoritative_value_updated = False

        if authoritative:
            if service == RemoteConnectionDll.RC_SERVICE_MONERO_P2P:
                if height_main is None:
                    height_main = height_side
                if height_main is not None and height_main > 0:
                    authoritative_fields_seen = True
                    if self._mainchain_height != int(height_main):
                        self._mainchain_height = int(height_main)
                        authoritative_value_updated = True
            elif service == RemoteConnectionDll.RC_SERVICE_P2POOL_P2P:
                if height_side is None:
                    height_side = height_main
                if height_side is not None and height_side > 0:
                    authoritative_fields_seen = True
                    if self._sidechain_height != int(height_side):
                        self._sidechain_height = int(height_side)
                        authoritative_value_updated = True
            else:
                if height_main is not None and height_main > 0:
                    authoritative_fields_seen = True
                    if self._mainchain_height != int(height_main):
                        self._mainchain_height = int(height_main)
                        authoritative_value_updated = True
                elif height_side is not None and height_side > 0:
                    authoritative_fields_seen = True
                    if self._sidechain_height != int(height_side):
                        self._sidechain_height = int(height_side)
                        authoritative_value_updated = True

            if total_height is not None and total_height > 0:
                authoritative_fields_seen = True
                if self._mainchain_height is None:
                    self._mainchain_height = int(total_height)
                    authoritative_value_updated = True
            if difficulty is not None and difficulty > 0:
                authoritative_fields_seen = True
                if self._difficulty != int(difficulty):
                    self._difficulty = int(difficulty)
                    authoritative_value_updated = True
            if peer_count is not None and peer_count > 0:
                authoritative_fields_seen = True
                if self._peer_count_hint != int(peer_count):
                    self._peer_count_hint = int(peer_count)
                    authoritative_value_updated = True
            if peer_id is not None and peer_id > 0:
                authoritative_fields_seen = True
                if self._last_peer_id != int(peer_id):
                    self._last_peer_id = int(peer_id)
                    authoritative_value_updated = True
            if support_flags is not None and support_flags >= 0:
                authoritative_fields_seen = True
                if self._last_support_flags != int(support_flags):
                    self._last_support_flags = int(support_flags)
                    authoritative_value_updated = True
            if difficulty_top64 is not None and difficulty_top64 >= 0:
                authoritative_fields_seen = True
                if self._last_cumulative_difficulty_top64 != int(difficulty_top64):
                    self._last_cumulative_difficulty_top64 = int(difficulty_top64)
                    authoritative_value_updated = True
            if pruning_seed is not None and pruning_seed >= 0:
                authoritative_fields_seen = True
                if self._last_pruning_seed != int(pruning_seed):
                    self._last_pruning_seed = int(pruning_seed)
                    authoritative_value_updated = True
            if top_version is not None and top_version >= 0:
                authoritative_fields_seen = True
                if self._last_top_version != int(top_version):
                    self._last_top_version = int(top_version)
                    authoritative_value_updated = True
            if rpc_port is not None and rpc_port > 0:
                authoritative_fields_seen = True
                if self._last_rpc_port_hint != int(rpc_port):
                    self._last_rpc_port_hint = int(rpc_port)
                    authoritative_value_updated = True
            if my_port is not None and my_port > 0:
                authoritative_fields_seen = True
                if self._last_my_port != int(my_port):
                    self._last_my_port = int(my_port)
                    authoritative_value_updated = True
            if peer_count is not None and peer_count >= 0:
                self._last_local_peerlist_count = int(peer_count)
            if top_id:
                authoritative_fields_seen = True
                if self._last_top_id_hex != top_id:
                    self._last_top_id_hex = top_id
                    authoritative_value_updated = True

            if authoritative_fields_seen:
                self._semantic_frame_count += 1
                self._last_real_data_ts = time.time()
                self._last_semantic_source = source or "semantic"
                if authoritative_value_updated:
                    self._real_data_frame_count += 1

        if status:
            self._last_status = status
        if method:
            self._last_rpc_method = method
        if job_id:
            self._last_rpc_job_id = job_id

        if decoded:
            try:
                self._last_semantic_json = json.dumps(decoded, sort_keys=True)[:4096]
            except Exception:
                pass

        if semantic_like:
            self._levin_present = True
            if self._best_protocol_guess != "Levin":
                self._best_protocol_guess = "Levin"

    def _extract_structured_payload_locked(self, payload: bytes | str, *, service: Optional[int] = None, source: str = "") -> None:
        if payload is None:
            return
        text = payload if isinstance(payload, str) else bytes(payload).decode("utf-8", errors="ignore")
        text = str(text or "").strip()
        if not text:
            return

        try:
            obj = json.loads(text)
        except Exception:
            obj = None
        if isinstance(obj, dict):
            flat: Dict[str, Any] = {}
            flat.update(obj)
            params = obj.get("params")
            if isinstance(params, dict):
                flat.update(params)
            result = obj.get("result")
            if isinstance(result, dict):
                flat.update(result)
            self._apply_decoded_fields_locked(flat, service=service, source=source or "json")
            return

        decoded: Dict[str, Any] = {}
        patterns = {
            "current_height": r"(?:current_height|sidechain_height)\s*[:=]\s*(\d+)",
            "current_blockchain_height": r"(?:current_blockchain_height|mainchain_height|height)\s*[:=]\s*(\d+)",
            "difficulty": r"(?:difficulty|cumulative_difficulty(?:_low64)?)\s*[:=]\s*(\d+)",
            "peer_count": r"(?:peer_count|connected_peers|local_peerlist_count)\s*[:=]\s*(\d+)",
            "peer_id": r"(?:peer_id)\s*[:=]\s*(\d+)",
            "support_flags": r"(?:support_flags)\s*[:=]\s*(\d+)",
            "job_id": r"(?:job_id)\s*[:=]\s*([A-Za-z0-9_-]+)",
            "method": r"(?:method)\s*[:=]\s*([A-Za-z0-9_.-]+)",
            "status": r"(?:status)\s*[:=]\s*([A-Za-z0-9_.:-]+)",
            "top_id_hex": r"(?:top_id|top_id_hex)\s*[:=]\s*([0-9a-fA-F]{16,64})",
        }
        low = text.lower()
        for k, pat in patterns.items():
            m = re.search(pat, text, flags=re.IGNORECASE)
            if not m:
                continue
            decoded[k] = m.group(1)
        if decoded:
            self._apply_decoded_fields_locked(decoded, service=service, source=source or "text")
        if "levin" in low:
            self._levin_present = True
            self._best_protocol_guess = "Levin"

    def _consume_payload_evidence_locked(
        self,
        peer_key: str,
        payload: bytes,
        now: float,
        service_kind: int,
        *,
        source: str,
    ) -> int:
        blob = bytes(payload or b"")
        if not blob:
            return 0

        parsed = 0
        try:
            parsed += int(self._consume_socket_stream_locked(peer_key, blob, now, int(service_kind)) or 0)
        except Exception:
            parsed += 0

        levin_sig = struct.pack("<Q", int(self._LEVIN_SIGNATURE))
        if parsed <= 0:
            try:
                sig_idx = blob.find(levin_sig)
            except Exception:
                sig_idx = -1
            if sig_idx > 0:
                try:
                    parsed += int(self._consume_socket_stream_locked(peer_key, blob[sig_idx:], now, int(service_kind)) or 0)
                except Exception:
                    parsed += 0

        if parsed <= 0:
            ps_offsets: List[int] = []
            if blob.startswith(self._PORTABLE_STORAGE_SIGNATURE):
                ps_offsets.append(0)
            try:
                idx = blob.find(self._PORTABLE_STORAGE_SIGNATURE, 1)
            except Exception:
                idx = -1
            if idx > 0:
                ps_offsets.append(int(idx))
            for ps_idx in ps_offsets:
                cand = blob[ps_idx:]
                if len(cand) < 9 or cand[8] != self._PORTABLE_STORAGE_VERSION:
                    continue
                try:
                    decoded_obj = self._ps_unpack_root(cand)
                    flat = self._flatten_decoded_object(decoded_obj)
                    flat.update({
                        "body_size": int(len(cand)),
                        "payload_len": int(len(blob)),
                    })
                    self._apply_decoded_fields_locked(flat, service=int(service_kind), source=f"{source}_portable_storage")
                    parsed += 1
                    break
                except Exception:
                    continue

        if self._is_probably_text(blob):
            try:
                decoded_text = blob.decode("utf-8", errors="ignore")
                self._extract_text_observations_locked(decoded_text)
                self._extract_structured_payload_locked(decoded_text, service=int(service_kind), source=source)
            except Exception:
                pass
        elif parsed <= 0:
            # Even when the blob is not text, allow the regex/json extractor to inspect any
            # printable islands once the transport heuristics say this is Monero/P2Pool traffic.
            try:
                self._extract_structured_payload_locked(blob, service=int(service_kind), source=source)
            except Exception:
                pass

        return int(parsed)

    @staticmethod
    def _parse_packet_summary(raw_bytes: bytes) -> Optional[Dict[str, Any]]:
        blob = bytes(raw_bytes or b"")
        if len(blob) < 20:
            return None

        offset = 0
        ether_type = None
        if len(blob) >= 14:
            ether_type = struct.unpack_from("!H", blob, 12)[0]
            if ether_type in (0x0800, 0x86DD, 0x8100, 0x88A8):
                offset = 14
                vlan_hops = 0
                while ether_type in (0x8100, 0x88A8) and len(blob) >= offset + 4 and vlan_hops < 2:
                    ether_type = struct.unpack_from("!H", blob, offset + 2)[0]
                    offset += 4
                    vlan_hops += 1
                if ether_type != 0x0800:
                    return None

        if len(blob) < offset + 20:
            return None

        first = blob[offset]
        version = first >> 4
        ihl = (first & 0x0F) * 4
        if version != 4 or ihl < 20 or len(blob) < offset + ihl:
            return None

        total_len = struct.unpack_from("!H", blob, offset + 2)[0]
        flags_frag = struct.unpack_from("!H", blob, offset + 6)[0]
        frag_offset = flags_frag & 0x1FFF
        more_frags = bool(flags_frag & 0x2000)
        protocol = blob[offset + 9]
        if protocol != 6 or frag_offset != 0 or more_frags:
            return None

        src_ip = ".".join(str(b) for b in blob[offset + 12: offset + 16])
        dst_ip = ".".join(str(b) for b in blob[offset + 16: offset + 20])

        tcp_off = offset + ihl
        if len(blob) < tcp_off + 20:
            return None

        src_port, dst_port = struct.unpack_from("!HH", blob, tcp_off)
        seq = struct.unpack_from("!I", blob, tcp_off + 4)[0]
        ack = struct.unpack_from("!I", blob, tcp_off + 8)[0]
        data_offset_words = (blob[tcp_off + 12] >> 4) & 0x0F
        tcp_header_len = max(20, data_offset_words * 4)
        if len(blob) < tcp_off + tcp_header_len:
            return None

        flags = blob[tcp_off + 13]
        payload_start = tcp_off + tcp_header_len
        ip_end = min(len(blob), offset + total_len if total_len >= ihl else len(blob))
        if payload_start > ip_end:
            payload_start = ip_end
        payload = blob[payload_start:ip_end]
        tcp_options = blob[tcp_off + 20: tcp_off + tcp_header_len] if tcp_header_len > 20 else b""
        tcp_options_decoded = RemoteConnection._decode_tcp_options(tcp_options)
        syn = bool(flags & 0x02) and not bool(flags & 0x10)

        return {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": int(src_port),
            "dst_port": int(dst_port),
            "seq": int(seq),
            "ack": int(ack),
            "flags": int(flags),
            "flags_compact": RemoteConnection._tcp_flags_to_compact(int(flags)),
            "payload": bytes(payload),
            "payload_len": len(payload),
            "raw_len": len(blob),
            "ip_header_len": int(ihl),
            "ip_total_len": int(total_len),
            "tcp_header_len": int(tcp_header_len),
            "tcp_options": bytes(tcp_options),
            "tcp_options_decoded": tcp_options_decoded,
            "syn_with_payload": bool(syn and len(payload) > 0),
        }

    def _rate_sample_locked(self, now: float) -> None:
        self._rate_window.add(
            now,
            (
                int(self._total_rx_packets),
                int(self._total_rx_bytes),
                int(self._total_tx_packets),
                int(self._total_tx_bytes),
                int(self._connect_events_total),
                int(self._disconnect_events_total),
                int(self._fail_events_total),
                int(self._socket_rx_packets),
                int(self._socket_rx_bytes),
                int(self._router_rx_packets),
                int(self._router_rx_bytes),
                int(self._raw_packet_rx_packets),
                int(self._raw_packet_rx_bytes),
                int(self._dll_rx_frames),
            ),
        )

    def _stream_ids_for_peer_locked(self, peer_key: str, service_kind: int) -> Dict[str, str]:
        ids = self._peer_stream_ids.get(peer_key)
        if ids is not None:
            return ids
        ids = {"out": f"tcp:{peer_key}:out", "in": f"tcp:{peer_key}:in"}
        for stream_id in ids.values():
            if stream_id in self._opened_streams:
                continue
            self._dll.open_stream(stream_id, peer_key, int(service_kind))
            self._opened_streams.add(stream_id)
            self._stream_peer_map[stream_id] = peer_key
        self._peer_stream_ids[peer_key] = ids
        self._peer_services[peer_key] = int(service_kind)
        return ids

    def _should_feed_dll_locked(self, stream_id: str, peer_key: str, service_kind: int, data: bytes) -> bool:
        blob = bytes(data or b"")
        if not blob:
            return False

        mode = self._dll_stream_mode.get(stream_id)
        if mode == "levin":
            return True

        allow = self._dll_candidate_payload(blob, int(service_kind))
        if allow:
            eff, _meta = self._payload_from_maybe_packet(blob)
            eff = bytes(eff or blob)
            self._dll_stream_mode[stream_id] = "levin" if self._payload_contains_decode_markers(eff) else "candidate"
            return True

        if int(service_kind) in (RemoteConnectionDll.RC_SERVICE_MONERO_P2P, RemoteConnectionDll.RC_SERVICE_P2POOL_P2P):
            eff, _meta = self._payload_from_maybe_packet(blob)
            eff = bytes(eff or blob)
            if len(eff) >= 8:
                self._dll_stream_mode[stream_id] = "candidate"
                return True

        # Never permanently lock a stream into a raw/control state. Router and
        # socket paths often see header-only TCP first and payload-bearing
        # Monero/P2Pool data later on the same stream.
        self._dll_stream_mode[stream_id] = "candidate" if mode == "candidate" else "control"
        self._dll_skipped_non_levin += 1
        return False

    def _feed_dll_locked(self, peer_key: str, direction: int, data: bytes, *, timestamp_ms: Optional[int] = None, service_kind: Optional[int] = None) -> None:
        blob = bytes(data or b"")
        if not blob:
            return
        if timestamp_ms is None:
            timestamp_ms = int(time.time() * 1000.0)
        if service_kind is None:
            try:
                port = int(peer_key.rpartition(":")[2])
            except Exception:
                port = 0
            service_kind = self._peer_services.get(peer_key, self._service_for_port(port)[0])
        ids = self._stream_ids_for_peer_locked(peer_key, int(service_kind))
        stream_id = ids["out" if int(direction) == RemoteConnectionDll.RC_DIR_OUTBOUND else "in"]
        if self._should_feed_dll_locked(stream_id, peer_key, int(service_kind), blob):
            self._dll.feed_tcp_bytes(stream_id, int(direction), blob, timestamp_ms=timestamp_ms)


    @classmethod
    def _ps_unpack_varint(cls, blob: bytes, offset: int) -> Tuple[int, int]:
        if offset >= len(blob):
            raise ValueError("portable-storage varint truncated")
        first = blob[offset]
        tag = first & 0x03
        size = 1 << tag
        end = offset + size
        if end > len(blob):
            raise ValueError("portable-storage varint overflow")
        raw = int.from_bytes(blob[offset:end], "little", signed=False)
        return int(raw >> 2), end

    @classmethod
    def _ps_unpack_string(cls, blob: bytes, offset: int) -> Tuple[bytes, int]:
        ln, offset = cls._ps_unpack_varint(blob, offset)
        end = offset + int(ln)
        if end > len(blob):
            raise ValueError("portable-storage string truncated")
        return bytes(blob[offset:end]), end

    @classmethod
    def _ps_unpack_scalar(cls, base_type: int, blob: bytes, offset: int) -> Tuple[Any, int]:
        if base_type == cls._PS_TYPE_INT64:
            end = offset + 8
            if end > len(blob):
                raise ValueError("portable-storage int64 truncated")
            return int.from_bytes(blob[offset:end], "little", signed=True), end
        if base_type == cls._PS_TYPE_INT32:
            end = offset + 4
            if end > len(blob):
                raise ValueError("portable-storage int32 truncated")
            return int.from_bytes(blob[offset:end], "little", signed=True), end
        if base_type == cls._PS_TYPE_INT16:
            end = offset + 2
            if end > len(blob):
                raise ValueError("portable-storage int16 truncated")
            return int.from_bytes(blob[offset:end], "little", signed=True), end
        if base_type == cls._PS_TYPE_INT8:
            end = offset + 1
            if end > len(blob):
                raise ValueError("portable-storage int8 truncated")
            return int.from_bytes(blob[offset:end], "little", signed=True), end
        if base_type == cls._PS_TYPE_UINT64:
            end = offset + 8
            if end > len(blob):
                raise ValueError("portable-storage uint64 truncated")
            return int.from_bytes(blob[offset:end], "little", signed=False), end
        if base_type == cls._PS_TYPE_UINT32:
            end = offset + 4
            if end > len(blob):
                raise ValueError("portable-storage uint32 truncated")
            return int.from_bytes(blob[offset:end], "little", signed=False), end
        if base_type == cls._PS_TYPE_UINT16:
            end = offset + 2
            if end > len(blob):
                raise ValueError("portable-storage uint16 truncated")
            return int.from_bytes(blob[offset:end], "little", signed=False), end
        if base_type == cls._PS_TYPE_UINT8:
            end = offset + 1
            if end > len(blob):
                raise ValueError("portable-storage uint8 truncated")
            return int.from_bytes(blob[offset:end], "little", signed=False), end
        if base_type == cls._PS_TYPE_DOUBLE:
            end = offset + 8
            if end > len(blob):
                raise ValueError("portable-storage double truncated")
            return struct.unpack_from("<d", blob, offset)[0], end
        if base_type == cls._PS_TYPE_STRING:
            return cls._ps_unpack_string(blob, offset)
        if base_type == cls._PS_TYPE_BOOL:
            end = offset + 1
            if end > len(blob):
                raise ValueError("portable-storage bool truncated")
            return bool(blob[offset]), end
        if base_type == cls._PS_TYPE_OBJECT:
            return cls._ps_unpack_section(blob, offset)
        if base_type == cls._PS_TYPE_ARRAY:
            # Rarely used in Monero. Best-effort decode as an empty list if no typed structure is known.
            count, offset = cls._ps_unpack_varint(blob, offset)
            return [None] * int(count), offset
        raise ValueError(f"unsupported portable-storage type: {base_type}")

    @classmethod
    def _ps_unpack_section(cls, blob: bytes, offset: int) -> Tuple[Dict[str, Any], int]:
        count, offset = cls._ps_unpack_varint(blob, offset)
        out: Dict[str, Any] = {}
        for _ in range(int(count)):
            if offset >= len(blob):
                raise ValueError("portable-storage section truncated before key length")
            key_len = blob[offset]
            offset += 1
            key_end = offset + int(key_len)
            if key_end > len(blob):
                raise ValueError("portable-storage section key truncated")
            key = blob[offset:key_end].decode("utf-8", errors="ignore")
            offset = key_end
            if offset >= len(blob):
                raise ValueError("portable-storage section truncated before type")
            type_code = blob[offset]
            offset += 1
            is_array = bool(type_code & cls._PS_FLAG_ARRAY)
            base_type = int(type_code & 0x7F)
            if is_array:
                arr_count, offset = cls._ps_unpack_varint(blob, offset)
                arr: List[Any] = []
                for _ in range(int(arr_count)):
                    value, offset = cls._ps_unpack_scalar(base_type, blob, offset)
                    arr.append(value)
                out[key] = arr
            else:
                value, offset = cls._ps_unpack_scalar(base_type, blob, offset)
                out[key] = value
        return out, offset

    @classmethod
    def _ps_unpack_root(cls, blob: bytes) -> Dict[str, Any]:
        raw = bytes(blob or b"")
        if len(raw) < 9:
            raise ValueError("portable-storage root too short")
        if raw[:8] != cls._PORTABLE_STORAGE_SIGNATURE:
            raise ValueError("portable-storage bad signature")
        if raw[8] != cls._PORTABLE_STORAGE_VERSION:
            raise ValueError(f"portable-storage bad version: {raw[8]}")
        obj, offset = cls._ps_unpack_section(raw, 9)
        return obj

    @staticmethod
    def _normalize_decoded_value(value: Any) -> Any:
        if isinstance(value, dict):
            return {str(k): RemoteConnection._normalize_decoded_value(v) for k, v in value.items()}
        if isinstance(value, list):
            return [RemoteConnection._normalize_decoded_value(v) for v in value]
        if isinstance(value, (bytes, bytearray)):
            blob = bytes(value)
            if not blob:
                return ""
            printable = sum(1 for b in blob if b in (9, 10, 13) or 32 <= b <= 126)
            if printable >= max(4, int(len(blob) * 0.85)):
                try:
                    return blob.decode("utf-8", errors="ignore")
                except Exception:
                    pass
            return blob.hex()
        return value

    def _flatten_decoded_object(self, obj: Dict[str, Any]) -> Dict[str, Any]:
        flat: Dict[str, Any] = {}
        if not isinstance(obj, dict):
            return flat
        for k, v in obj.items():
            key = str(k)
            if key in {"node_data", "payload_data"} and isinstance(v, dict):
                flat.update(self._flatten_decoded_object(v))
                continue
            if key == "local_peerlist_new" and isinstance(v, list):
                flat["local_peerlist_count"] = len(v)
                continue
            value = self._normalize_decoded_value(v)
            if key == "top_id" and isinstance(value, str):
                flat["top_id_hex"] = value
            flat[key] = value
        return flat

    def _consume_socket_stream_locked(self, peer_key: str, data: bytes, now: float, service_kind: int) -> int:
        blob = bytes(data or b"")
        if not blob:
            return 0
        buf = self._peer_recv_buffers.setdefault(peer_key, bytearray())
        buf.extend(blob)
        parsed = 0
        sig = struct.pack("<Q", int(self._LEVIN_SIGNATURE))

        while True:
            if len(buf) < self._LEVIN_HEADER_SIZE:
                break

            if bytes(buf[:8]) != sig:
                idx = bytes(buf).find(sig, 1)
                if idx < 0:
                    # Keep a small tail in case the next recv completes the signature.
                    if len(buf) > 64:
                        del buf[:-64]
                    break
                if idx > 0:
                    del buf[:idx]
                continue

            try:
                body_size = struct.unpack_from("<Q", buf, 8)[0]
                expect_response = int(buf[16])
                command = struct.unpack_from("<I", buf, 17)[0]
                return_code = struct.unpack_from("<i", buf, 21)[0]
                flags = struct.unpack_from("<I", buf, 25)[0]
                version = struct.unpack_from("<I", buf, 29)[0]
            except Exception:
                break

            if body_size < 0 or body_size > 16 * 1024 * 1024:
                # Bad frame size; resync past the signature.
                del buf[:8]
                continue

            frame_len = self._LEVIN_HEADER_SIZE + int(body_size)
            if len(buf) < frame_len:
                break

            frame = bytes(buf[:frame_len])
            body = bytes(buf[self._LEVIN_HEADER_SIZE:frame_len])
            del buf[:frame_len]
            parsed += 1

            st = self._ensure_peer_state_locked(peer_key)
            st["validated_frames"] = int(st.get("validated_frames") or 0) + 1
            st["bootstrap_stage"] = "live_rx_frame"
            self._peer_bootstrap_stage[peer_key] = "live_rx_frame"
            self._peer_last_inbound_frame_ts[peer_key] = now
            self._peer_last_inbound_command[peer_key] = int(command)
            self._peer_inbound_frame_count[peer_key] = int(self._peer_inbound_frame_count.get(peer_key) or 0) + 1
            self._validated_frame_count += 1
            self._dll_rx_frames += 1
            self._last_validated_frame_ts = now
            self._levin_present = True
            self._best_protocol_guess = "Levin"
            self._last_command = int(command)
            self._last_command_name = self._command_name_for(self._last_command)
            self._last_return_code = int(return_code)
            if int(service_kind) == RemoteConnectionDll.RC_SERVICE_MONERO_P2P:
                self._service_guess = "monero_p2p"
                self._packet_topic = "monero"
            elif int(service_kind) == RemoteConnectionDll.RC_SERVICE_P2POOL_P2P:
                self._service_guess = "p2pool_p2p"
                self._packet_topic = "p2pool"

            decoded_obj: Optional[Dict[str, Any]] = None
            if body.startswith(self._PORTABLE_STORAGE_SIGNATURE) and len(body) >= 9 and body[8] == self._PORTABLE_STORAGE_VERSION:
                try:
                    decoded_obj = self._ps_unpack_root(body)
                except Exception:
                    decoded_obj = None

            if decoded_obj is not None:
                flat = self._flatten_decoded_object(decoded_obj)
                flat.update({
                    "command": int(command),
                    "return_code": int(return_code),
                    "protocol_version": int(version),
                    "expect_response": int(expect_response),
                    "flags": int(flags),
                    "body_size": int(body_size),
                })
                self._apply_decoded_fields_locked(flat, service=int(service_kind), source="socket_levin_inbound")
                try:
                    semantic_json = json.dumps(flat, sort_keys=True)[:4096]
                except Exception:
                    semantic_json = ""
            else:
                semantic_json = ""
                if body and self._is_probably_text(body):
                    self._extract_structured_payload_locked(body, service=int(service_kind), source="socket_levin_body")

            self._received_packets.append({
                "ts": now,
                "peer": peer_key,
                "kind": "socket_levin_frame",
                "direction": "in",
                "command": int(command),
                "return_code": int(return_code),
                "flags": int(flags),
                "protocol_version": int(version),
                "body_size": int(body_size),
                "frame_size": int(frame_len),
                "semantic_json": semantic_json,
                "body_preview_hex": body[:96].hex(),
            })

        return parsed

    @classmethod
    def _levin_flags(
        cls,
        *,
        is_request: bool = False,
        is_response: bool = False,
        begin: bool = False,
        end: bool = False,
    ) -> int:
        flags = 0
        if is_request:
            flags |= cls._LEVIN_FLAG_REQUEST
        if is_response:
            flags |= cls._LEVIN_FLAG_RESPONSE
        if begin:
            flags |= cls._LEVIN_FLAG_BEGIN
        if end:
            flags |= cls._LEVIN_FLAG_END
        return int(flags)

    @classmethod
    def _ps_pack_varint(cls, value: int) -> bytes:
        n = max(0, int(value))
        if n < (1 << 6):
            return bytes([(n << 2) | 0])
        if n < (1 << 14):
            return ((n << 2) | 1).to_bytes(2, "little")
        if n < (1 << 30):
            return ((n << 2) | 2).to_bytes(4, "little")
        if n < (1 << 62):
            return ((n << 2) | 3).to_bytes(8, "little")
        raise ValueError(f"portable-storage varint too large: {n}")

    @classmethod
    def _ps_pack_string(cls, data: bytes) -> bytes:
        blob = bytes(data or b"")
        return cls._ps_pack_varint(len(blob)) + blob

    @classmethod
    def _ps_pack_section(cls, entries: Dict[str, Any]) -> bytes:
        out = bytearray()
        items = list((entries or {}).items())
        out.extend(cls._ps_pack_varint(len(items)))
        for name, value in items:
            key = str(name).encode("utf-8", errors="ignore")
            if len(key) > 255:
                raise ValueError(f"portable-storage key too long: {name!r}")
            out.append(len(key))
            out.extend(key)
            type_code, payload = cls._ps_pack_value(value)
            out.append(type_code)
            out.extend(payload)
        return bytes(out)

    @classmethod
    def _ps_pack_value(cls, value: Any) -> Tuple[int, bytes]:
        if isinstance(value, dict):
            return (cls._PS_TYPE_OBJECT, cls._ps_pack_section(value))
        if isinstance(value, (bytes, bytearray)):
            return (cls._PS_TYPE_STRING, cls._ps_pack_string(bytes(value)))
        if isinstance(value, str):
            return (cls._PS_TYPE_STRING, cls._ps_pack_string(value.encode("utf-8", errors="ignore")))
        if isinstance(value, bool):
            return (cls._PS_TYPE_BOOL, b"" if value else b"\x00")
        if isinstance(value, int):
            if value < 0:
                if -(1 << 31) <= value < (1 << 31):
                    return (cls._PS_TYPE_INT32, int(value).to_bytes(4, "little", signed=True))
                return (cls._PS_TYPE_INT64, int(value).to_bytes(8, "little", signed=True))
            if value <= 0xFF:
                return (cls._PS_TYPE_UINT8, int(value).to_bytes(1, "little", signed=False))
            if value <= 0xFFFF:
                return (cls._PS_TYPE_UINT16, int(value).to_bytes(2, "little", signed=False))
            if value <= 0xFFFFFFFF:
                return (cls._PS_TYPE_UINT32, int(value).to_bytes(4, "little", signed=False))
            return (cls._PS_TYPE_UINT64, int(value).to_bytes(8, "little", signed=False))
        raise TypeError(f"unsupported portable-storage value: {type(value)!r}")

    @classmethod
    def _ps_pack_root(cls, entries: Dict[str, Any]) -> bytes:
        return cls._PORTABLE_STORAGE_SIGNATURE + bytes((cls._PORTABLE_STORAGE_VERSION,)) + cls._ps_pack_section(entries)

    def _build_basic_node_data(self, *, port: int = 0, rpc_port: int = 0, support_flags: int = 1) -> Dict[str, Any]:
        return {
            "network_id": bytes(self._MAINNET_NETWORK_ID),
            "my_port": int(port) & 0xFFFFFFFF,
            "rpc_port": int(rpc_port) & 0xFFFF,
            "rpc_credits_per_hash": 0,
            "peer_id": int(self._local_peer_id) & 0xFFFFFFFFFFFFFFFF,
            "support_flags": int(support_flags) & 0xFFFFFFFF,
        }

    def _build_core_sync_data(self, *, current_height: Optional[int] = None) -> Dict[str, Any]:
        height = int(current_height if current_height is not None else (self._mainchain_height or self._sidechain_height or 1))
        if height <= 0:
            height = 1
        top_version = int((self._sidechain_height or self._mainchain_height or 1) and 1)
        top_id_hex = str(self._last_top_id_hex or "").strip().lower()
        try:
            top_id = bytes.fromhex(top_id_hex) if len(top_id_hex) == 64 else (b"\x00" * 32)
        except Exception:
            top_id = b"\x00" * 32
        difficulty = int(self._difficulty or 1)
        if difficulty <= 0:
            difficulty = 1
        return {
            "current_height": int(height) & 0xFFFFFFFFFFFFFFFF,
            "cumulative_difficulty": int(difficulty & 0xFFFFFFFFFFFFFFFF),
            "cumulative_difficulty_top64": int((difficulty >> 64) & 0xFFFFFFFFFFFFFFFF),
            "top_id": top_id,
            "top_version": int(top_version) & 0xFF,
            "pruning_seed": 0,
        }

    def _build_handshake_body(self, peer_key: str, service_kind: int) -> bytes:
        self._ensure_peer_state_locked(peer_key)
        # Outbound probe sockets should not advertise the remote peer's port as our own inbound port.
        # For observational connections we keep this at 0, which is valid for peers that do not accept inbound.
        support_flags = 1
        return self._ps_pack_root({
            "node_data": self._build_basic_node_data(port=0, rpc_port=0, support_flags=support_flags),
            "payload_data": self._build_core_sync_data(),
        })

    def _build_timed_sync_body(self) -> bytes:
        return self._ps_pack_root({
            "payload_data": self._build_core_sync_data(),
        })

    @classmethod
    def _build_levin_frame(
        cls,
        command: int,
        body: bytes = b"",
        *,
        expect_response: bool = False,
        is_request: bool = True,
        is_response: bool = False,
        return_code: int = 0,
    ) -> bytes:
        blob = bytes(body or b"")
        flags = cls._levin_flags(
            is_request=bool(is_request),
            is_response=bool(is_response),
            begin=False,
            end=False,
        )
        return struct.pack(
            "<QQBIiII",
            int(cls._LEVIN_SIGNATURE),
            int(len(blob)),
            1 if expect_response else 0,
            int(command),
            int(return_code),
            int(flags),
            1,
        ) + blob

    def _protocol_packet_for_command_locked(
        self,
        peer_key: str,
        command: int,
        *,
        reason: str = '',
        body: bytes = b'',
        service_kind: Optional[int] = None,
    ) -> _LevinProtocolPacketBase:
        try:
            sk = int(service_kind) if service_kind is not None else int(self._peer_services.get(peer_key) or 0)
        except Exception:
            sk = 0
        if sk == RemoteConnectionDll.RC_SERVICE_UNKNOWN:
            try:
                port = int(str(peer_key).rpartition(':')[2])
            except Exception:
                port = 0
            sk = self._service_for_port(port)[0]
            if sk == RemoteConnectionDll.RC_SERVICE_UNKNOWN and port in self._P2POOL_PORTS:
                sk = RemoteConnectionDll.RC_SERVICE_P2POOL_P2P
        if sk == RemoteConnectionDll.RC_SERVICE_P2POOL_P2P:
            if int(command) == 1001:
                return P2PoolPacket.handshake(self, peer_key, reason=reason or 'p2pool_handshake')
            if int(command) == 1002:
                return P2PoolPacket.timed_sync(self, peer_key, reason=reason or 'p2pool_timed_sync')
            if int(command) == 1003:
                return P2PoolPacket.ping(self, peer_key, reason=reason or 'p2pool_ping')
            if int(command) == 1007:
                return P2PoolPacket.support_flags(self, peer_key, reason=reason or 'p2pool_support_flags')
            return P2PoolPacket(peer_key=str(peer_key), command=int(command), body=bytes(body or b''), reason=str(reason or ''), command_name=self._command_name_for(int(command)) or str(int(command)))
        if int(command) == 1001:
            return MoneroPacket.handshake(self, peer_key, reason=reason or 'monero_handshake')
        if int(command) == 1002:
            return MoneroPacket.timed_sync(self, peer_key, reason=reason or 'monero_timed_sync')
        if int(command) == 1003:
            return MoneroPacket.ping(self, peer_key, reason=reason or 'monero_ping')
        if int(command) == 1007:
            return MoneroPacket.support_flags(self, peer_key, reason=reason or 'monero_support_flags')
        return MoneroPacket(peer_key=str(peer_key), command=int(command), body=bytes(body or b''), reason=str(reason or ''), command_name=self._command_name_for(int(command)) or str(int(command)))

    def _queue_levin_request_locked(
        self,
        peer_key: str,
        command: int,
        *,
        reason: str = "",
        body: bytes = b"",
        service_kind: Optional[int] = None,
    ) -> int:
        cmd = int(command)
        packet_obj = self._protocol_packet_for_command_locked(
            peer_key,
            cmd,
            reason=str(reason or ''),
            body=bytes(body or b''),
            service_kind=service_kind,
        )
        if body:
            packet_obj = type(packet_obj)(
                peer_key=packet_obj.peer_key,
                command=packet_obj.command,
                body=bytes(body or b''),
                expect_response=packet_obj.expect_response,
                is_request=packet_obj.is_request,
                is_response=packet_obj.is_response,
                return_code=packet_obj.return_code,
                reason=packet_obj.reason,
                command_name=packet_obj.command_name,
                packet_topic=packet_obj.packet_topic,
                packet_proto=packet_obj.packet_proto,
                service_kind=packet_obj.service_kind,
                priority=packet_obj.priority,
            )
        frame = packet_obj.to_frame(self)
        q = self._send_queues.setdefault(peer_key, deque())
        q.append(frame)
        now = time.time()
        st = self._ensure_peer_state_locked(peer_key)
        st["last_probe_ts"] = now
        st["last_probe_cmd"] = int(command)
        self._peer_last_probe_ts[peer_key] = now
        self._peer_last_probe_cmd[peer_key] = int(command)
        if int(command) == 1001:
            st["last_handshake_ts"] = now
            st["bootstrap_stage"] = "handshake_sent"
            self._peer_last_handshake_ts[peer_key] = now
            self._peer_bootstrap_stage[peer_key] = "handshake_sent"
        elif int(command) == 1002:
            st["last_timed_sync_ts"] = now
            if str(st.get("bootstrap_stage") or "") == "idle":
                st["bootstrap_stage"] = "timed_sync_sent"
                self._peer_bootstrap_stage[peer_key] = "timed_sync_sent"
            self._peer_last_timed_sync_ts[peer_key] = now
        elif int(command) == 1007:
            st["last_support_probe_ts"] = now
            self._peer_last_support_probe_ts[peer_key] = now
        self._received_packets.append({
            "ts": now,
            "peer": peer_key,
            "kind": "queued_probe",
            "command": int(command),
            "reason": str(reason or ""),
            "size": len(frame),
            "packet_kind": type(packet_obj).__name__,
            "packet_topic": packet_obj.packet_topic,
            "packet_summary": packet_obj.summary(),
            "priority": float(packet_obj.priority),
        })
        return len(frame)

    def _queue_initial_probes_locked(self, peer_key: str, service_kind: int) -> int:
        if int(service_kind) == RemoteConnectionDll.RC_SERVICE_UNKNOWN:
            return 0
        # Start with a single handshake instead of a burst. Several peers will silently drop
        # a fresh outbound connection if we flood multiple admin requests before the first reply.
        queued = 0
        queued += self._queue_levin_request_locked(peer_key, 1001, reason="connect_handshake", service_kind=int(service_kind))
        return queued

    def _maybe_queue_keepalive_probes_locked(
        self,
        peer_key: str,
        service_kind: int,
        now: float,
        *,
        force: bool = False,
    ) -> int:
        if int(service_kind) == RemoteConnectionDll.RC_SERVICE_UNKNOWN:
            return 0

        st = self._ensure_peer_state_locked(peer_key)
        last_probe_ts = float(st.get("last_probe_ts") or self._peer_last_probe_ts.get(peer_key) or 0.0)
        last_support_probe_ts = float(st.get("last_support_probe_ts") or self._peer_last_support_probe_ts.get(peer_key) or 0.0)
        last_handshake_ts = float(st.get("last_handshake_ts") or self._peer_last_handshake_ts.get(peer_key) or 0.0)
        last_timed_sync_ts = float(st.get("last_timed_sync_ts") or self._peer_last_timed_sync_ts.get(peer_key) or 0.0)
        last_rx_ts = float(st.get("last_rx_ts") or 0.0)
        stage = str(st.get("bootstrap_stage") or self._peer_bootstrap_stage.get(peer_key) or "idle")

        queued = 0
        needs_bootstrap = (last_rx_ts <= 0.0) or ((now - last_rx_ts) >= self._BOOTSTRAP_IDLE_RETRY_SEC)

        if force:
            queued += self._queue_levin_request_locked(peer_key, 1001, reason="forced_handshake", service_kind=int(service_kind))
            queued += self._queue_levin_request_locked(peer_key, 1002, reason="forced_timed_sync", service_kind=int(service_kind))
            if int(service_kind) == RemoteConnectionDll.RC_SERVICE_P2POOL_P2P:
                queued += self._queue_levin_request_locked(peer_key, 1007, reason="forced_support_flags", service_kind=int(service_kind))
            else:
                queued += self._queue_levin_request_locked(peer_key, 1003, reason="forced_ping", service_kind=int(service_kind))
            return queued

        if needs_bootstrap:
            if (now - last_handshake_ts) >= self._HANDSHAKE_RETRY_SEC:
                queued += self._queue_levin_request_locked(peer_key, 1001, reason="bootstrap_handshake", service_kind=int(service_kind))
                return queued

            # After a handshake has been on the wire for a short moment, follow with timed sync.
            if last_handshake_ts > 0.0 and (now - last_handshake_ts) >= 0.55 and (now - last_timed_sync_ts) >= self._TIMED_SYNC_INTERVAL_SEC:
                queued += self._queue_levin_request_locked(peer_key, 1002, reason="bootstrap_timed_sync", service_kind=int(service_kind))

            if int(service_kind) == RemoteConnectionDll.RC_SERVICE_P2POOL_P2P:
                if last_handshake_ts > 0.0 and (now - last_handshake_ts) >= 1.10 and (now - last_support_probe_ts) >= self._SUPPORT_FLAGS_INTERVAL_SEC:
                    queued += self._queue_levin_request_locked(peer_key, 1007, reason="bootstrap_support_flags", service_kind=int(service_kind))
                if last_handshake_ts > 0.0 and (now - last_handshake_ts) >= 1.40 and (now - last_probe_ts) >= self._PROBE_INTERVAL_SEC:
                    queued += self._queue_levin_request_locked(peer_key, 1003, reason="bootstrap_ping", service_kind=int(service_kind))
            else:
                if last_handshake_ts > 0.0 and (now - last_handshake_ts) >= 1.25 and (now - last_probe_ts) >= self._PROBE_INTERVAL_SEC:
                    queued += self._queue_levin_request_locked(peer_key, 1003, reason="bootstrap_ping", service_kind=int(service_kind))
                if last_handshake_ts > 0.0 and (now - last_handshake_ts) >= 2.00 and (now - last_support_probe_ts) >= self._SUPPORT_FLAGS_INTERVAL_SEC:
                    queued += self._queue_levin_request_locked(peer_key, 1007, reason="bootstrap_support_flags", service_kind=int(service_kind))
            return queued

        if (now - last_timed_sync_ts) >= self._TIMED_SYNC_INTERVAL_SEC:
            queued += self._queue_levin_request_locked(peer_key, 1002, reason="keepalive_timed_sync", service_kind=int(service_kind))
        if (now - last_probe_ts) >= self._PROBE_INTERVAL_SEC or (last_rx_ts > 0.0 and (now - last_rx_ts) >= self._KEEPALIVE_INTERVAL_SEC):
            queued += self._queue_levin_request_locked(peer_key, 1003, reason="keepalive_ping", service_kind=int(service_kind))
        if (now - last_support_probe_ts) >= self._SUPPORT_FLAGS_INTERVAL_SEC:
            queued += self._queue_levin_request_locked(peer_key, 1007, reason="keepalive_support_flags", service_kind=int(service_kind))
        return queued

    def _note_connect_locked(self, peer_key: str, latency_ms: Optional[float]) -> None:
        st = self._ensure_peer_state_locked(peer_key)
        now = time.time()
        st["connected"] = True
        st["latency_ms"] = latency_ms
        st["last_connect_ts"] = now
        st["last_activity_ts"] = now
        st["last_error"] = ""
        st["last_probe_ts"] = 0.0
        st["last_support_probe_ts"] = 0.0
        st["last_probe_cmd"] = 0
        st["last_handshake_ts"] = 0.0
        st["last_timed_sync_ts"] = 0.0
        st["bootstrap_stage"] = "idle"
        self._peer_last_probe_ts[peer_key] = 0.0
        self._peer_last_support_probe_ts[peer_key] = 0.0
        self._peer_last_probe_cmd[peer_key] = 0
        self._peer_last_handshake_ts[peer_key] = 0.0
        self._peer_last_timed_sync_ts[peer_key] = 0.0
        self._peer_bootstrap_stage[peer_key] = "idle"
        self._connect_events_total += 1
        self._epoch += 1
    def _note_disconnect_locked(self, peer_key: str, error_text: str = "") -> None:
        st = self._ensure_peer_state_locked(peer_key)
        was_connected = bool(st.get("connected"))
        st["connected"] = False
        st["last_activity_ts"] = time.time()
        if error_text:
            st["last_error"] = str(error_text)
        self._peer_last_probe_ts.pop(peer_key, None)
        self._peer_last_support_probe_ts.pop(peer_key, None)
        self._peer_last_probe_cmd.pop(peer_key, None)
        self._peer_last_handshake_ts.pop(peer_key, None)
        self._peer_last_timed_sync_ts.pop(peer_key, None)
        self._peer_bootstrap_stage.pop(peer_key, None)
        if was_connected:
            self._disconnect_events_total += 1
        else:
            self._fail_events_total += 1
        self._epoch += 1

    def _drain_send_queue_locked(self, peer_key: str, sock: socket.socket) -> int:
        sent_count = 0
        q = self._send_queues.get(peer_key)
        if not q:
            return 0
        while q and sent_count < self._SEND_DRAIN_LIMIT and not self._stop.is_set():
            payload = q.popleft()
            try:
                sock.sendall(payload)
            except Exception:
                q.appendleft(payload)
                raise
            now = time.time()
            st = self._ensure_peer_state_locked(peer_key)
            st["last_tx_ts"] = now
            st["last_activity_ts"] = now
            st["tx_bytes"] += len(payload)
            st["tx_packets"] += 1
            self._total_tx_packets += 1
            self._total_tx_bytes += len(payload)
            st["last_tx_preview"] = self._preview_text(payload)
            self._payload_len = len(payload)
            self._last_packet_observation_ts = now
            self._last_native_observation_ts = now
            self._feed_dll_locked(peer_key, RemoteConnectionDll.RC_DIR_OUTBOUND, payload, timestamp_ms=int(now * 1000.0))
            if self._is_probably_text(payload):
                self._extract_structured_payload_locked(payload, service=self._peer_services.get(peer_key), source="peer_tx_text")
            if self.miner_interface is not None:
                try:
                    self.miner_interface.note_socket_tx(peer_key, payload)
                except Exception:
                    pass
            sent_count += 1
        return sent_count

    def _process_incoming_bytes_locked(self, peer_key: str, data: bytes, now: float) -> None:
        st = self._ensure_peer_state_locked(peer_key)
        st["connected"] = True
        st["last_rx_ts"] = now
        st["last_activity_ts"] = now
        data_len = len(data)
        st["rx_bytes"] += data_len
        st["rx_packets"] += 1
        self._total_rx_packets += 1
        self._total_rx_bytes += data_len
        self._socket_rx_packets += 1
        self._socket_rx_bytes += data_len
        st["recv_chunks"] = int(st.get("recv_chunks") or 0) + 1
        st["bootstrap_stage"] = "live_rx"
        self._peer_bootstrap_stage[peer_key] = "live_rx"
        st["last_preview"] = self._preview_text(data)
        self._payload_len = len(data)
        self._last_packet_observation_ts = now
        self._last_native_observation_ts = now
        service_kind, service_guess, topic = self._service_for_port(int(st.get("port") or 0))
        if service_guess:
            self._service_guess = service_guess
        if topic:
            self._packet_topic = topic
        if service_kind != RemoteConnectionDll.RC_SERVICE_UNKNOWN:
            self._feed_dll_locked(peer_key, RemoteConnectionDll.RC_DIR_INBOUND, data, timestamp_ms=int(now * 1000.0), service_kind=service_kind)
        self._received_packets.append({
            "ts": now,
            "peer": peer_key,
            "kind": "socket_chunk",
            "direction": "in",
            "size": len(data),
            "preview": st["last_preview"],
            "service_guess": service_guess,
        })
        if self.miner_interface is not None:
            try:
                self.miner_interface.note_socket_rx(peer_key, data)
            except Exception:
                pass
        try:
            self._consume_payload_evidence_locked(peer_key, data, now, int(service_kind), source="socket_rx")
        except Exception as e:
            st["last_error"] = f"socket payload parse warning: {e}"

    def _poll_dll_events_locked(self, now: float) -> None:
        try:
            events = self._dll.poll_events(limit=256)
        except Exception as e:
            self._fail_events_total += 1
            self._last_status = str(e)
            return

        for ev in events:
            peer_key = ev.get("peer") or self._stream_peer_map.get(str(ev.get("stream_id") or ""), "") or "unknown:0"
            st = self._ensure_peer_state_locked(peer_key)
            st["last_activity_ts"] = now
            if ev.get("direction") == RemoteConnectionDll.RC_DIR_INBOUND:
                st["last_rx_ts"] = now
            elif ev.get("direction") == RemoteConnectionDll.RC_DIR_OUTBOUND:
                st["last_tx_ts"] = now

            event_type = int(ev.get("event_type") or 0)
            if event_type == RemoteConnectionDll.RC_EVENT_VALIDATED_FRAME:
                st["validated_frames"] = int(st.get("validated_frames") or 0) + 1
                self._validated_frame_count += 1
                if int(ev.get("direction") or 0) == RemoteConnectionDll.RC_DIR_INBOUND:
                    self._dll_rx_frames += 1
                self._last_validated_frame_ts = now
                self._levin_present = True
                self._best_protocol_guess = "Levin"
                service = int(ev.get("service") or 0)
                self._last_command = int(ev.get("command") or 0)
                self._last_command_name = self._command_name_for(self._last_command)
                self._last_return_code = int(ev.get("return_code") or 0)
                if service == RemoteConnectionDll.RC_SERVICE_MONERO_P2P:
                    self._service_guess = "monero_p2p"
                    self._packet_topic = "monero"
                elif service == RemoteConnectionDll.RC_SERVICE_P2POOL_P2P:
                    self._service_guess = "p2pool_p2p"
                    self._packet_topic = "p2pool"
                direction = int(ev.get("direction") or 0)
                src_name = "dll_levin_event_inbound" if direction == RemoteConnectionDll.RC_DIR_INBOUND else "dll_levin_event_outbound"
                self._apply_decoded_fields_locked(ev, service=service, source=src_name)
            elif event_type == RemoteConnectionDll.RC_EVENT_INVALID_FRAME:
                st["invalid_frames"] = int(st.get("invalid_frames") or 0) + 1
                self._invalid_frame_count += 1

            semantic_json = ev.get("semantic_json") or ""
            if semantic_json:
                try:
                    decoded = json.loads(semantic_json)
                    direction = int(ev.get("direction") or 0)
                    src_name = "semantic_json_inbound" if direction == RemoteConnectionDll.RC_DIR_INBOUND else "semantic_json_outbound"
                    self._apply_decoded_fields_locked(decoded, service=int(ev.get("service") or 0), source=src_name)
                except Exception:
                    pass

            body = ev.get("body") or b""
            if body:
                try:
                    if int(ev.get("direction") or 0) == RemoteConnectionDll.RC_DIR_INBOUND:
                        self._consume_payload_evidence_locked(
                            peer_key,
                            bytes(body),
                            now,
                            int(ev.get("service") or 0),
                            source="dll_body",
                        )
                    elif self._is_probably_text(body):
                        self._extract_structured_payload_locked(body, service=int(ev.get("service") or 0), source="dll_body")
                except Exception:
                    pass

            self._received_packets.append({
                "ts": now,
                "peer": peer_key,
                "kind": "dll_event",
                "event_type": event_type,
                "command": ev.get("command"),
                "service": ev.get("service"),
                "direction": ev.get("direction"),
                "body_size": ev.get("body_size"),
                "note": ev.get("note"),
                "semantic_summary": ev.get("semantic_summary"),
                "semantic_json": semantic_json,
            })

        if events:
            self._epoch += 1

    def _open_socket(self, host: str, port: int) -> socket.socket:
        sock = socket.create_connection((host, port), timeout=self.connect_timeout_sec)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        except Exception:
            pass
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except Exception:
            pass
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024 * 1024)
        except Exception:
            pass
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1024 * 1024)
        except Exception:
            pass
        sock.settimeout(self.recv_timeout_sec)
        return sock

    def _peer_loop(self, host: str, port: int) -> None:
        peer_key = f"{host}:{port}"
        service_kind, service_guess, topic = self._service_for_port(port)
        poll_timeout = max(0.05, min(float(self.recv_timeout_sec), 0.25))
        while not self._stop.is_set():
            acquired = self._slots.acquire(timeout=1.0)
            if not acquired:
                continue
            sock: Optional[socket.socket] = None
            try:
                with self._mu:
                    st = self._ensure_peer_state_locked(peer_key)
                    st["last_attempt_ts"] = time.time()

                t0 = time.time()
                sock = self._open_socket(host, port)
                latency_ms = (time.time() - t0) * 1000.0
                now = time.time()

                with self._mu:
                    self._socket_map[peer_key] = sock
                    self._note_connect_locked(peer_key, latency_ms)
                    if service_guess:
                        self._service_guess = service_guess
                    if topic:
                        self._packet_topic = topic
                    self._stream_ids_for_peer_locked(peer_key, int(service_kind))
                    self._queue_initial_probes_locked(peer_key, int(service_kind))
                    self._rate_sample_locked(now)
                    self._emit_status_log_locked(now)

                while not self._stop.is_set():
                    now = time.time()
                    with self._mu:
                        self._maybe_queue_keepalive_probes_locked(peer_key, int(service_kind), now)

                    want_write = False
                    with self._mu:
                        q = self._send_queues.get(peer_key)
                        want_write = bool(q)

                    try:
                        rlist, wlist, xlist = select.select([sock], [sock] if want_write else [], [sock], poll_timeout)
                    except (ValueError, OSError) as e:
                        raise ConnectionError(f"select failed: {e}")

                    if xlist:
                        raise ConnectionError("socket exception")

                    if wlist:
                        with self._mu:
                            self._drain_send_queue_locked(peer_key, sock)

                    if rlist:
                        data = sock.recv(self._MAX_RECV_BYTES)
                        if not data:
                            raise ConnectionError("remote closed connection")
                        now = time.time()
                        with self._mu:
                            self._process_incoming_bytes_locked(peer_key, data, now)
                            self._poll_dll_events_locked(now)
                            self._rate_sample_locked(now)
                            self._emit_status_log_locked(now)
                        continue

                    now = time.time()
                    with self._mu:
                        self._poll_dll_events_locked(now)
                        self._rate_sample_locked(now)
                        self._emit_status_log_locked(now)

            except Exception as e:
                now = time.time()
                with self._mu:
                    self._note_disconnect_locked(peer_key, str(e))
                    self._socket_map.pop(peer_key, None)
                    self._rate_sample_locked(now)
                    self._emit_status_log_locked(now, force=True)
            finally:
                try:
                    if sock is not None:
                        sock.shutdown(socket.SHUT_RDWR)
                except Exception:
                    pass
                try:
                    if sock is not None:
                        sock.close()
                except Exception:
                    pass
                with self._mu:
                    self._socket_map.pop(peer_key, None)
                self._slots.release()
            if not self._stop.is_set():
                self._stop.wait(self.reconnect_delay_sec)
    def _emit_status_log_locked(self, now: float, force: bool = False) -> None:
        if self._combined_mode:
            return
        if not force and (now - self._last_status_log_ts) < self._STATUS_LOG_INTERVAL_SEC:
            return
        self._last_status_log_ts = now
        snap = self.snapshot()
        self._log(
            f"[RemoteConnection] status peers={snap['connected_peers']}/{snap['peer_count']} "
            f"sockets={snap.get('socket_count', 0)} router_packets={snap.get('router_packets_total', 0)} "
            f"router_raw={snap.get('router_raw_packets_total', 0)} rx_pps={snap['rx_pps']:.2f} tx_pps={snap['tx_pps']:.2f} "
            f"validated={snap.get('validated_frame_count', 0)} semantic={snap.get('semantic_frame_count', 0)} real={snap.get('real_data_frame_count', 0)} "
            f"real_fresh={snap.get('real_data_fresh', False)} conf={snap.get('decode_confidence', 0.0):.2f} source={snap.get('last_semantic_source')} "
            f"sc={snap['sidechain_height']} mc={snap['mainchain_height']} diff={snap['difficulty']} "
            f"cmd={snap.get('last_command_name')} job_id={snap.get('last_rpc_job_id')}"
        )

    def start(self) -> None:
        with self._mu:
            if self._started:
                return
            self._started = True
            self._stop.clear()
            self._threads = []
            self._epoch += 1
            for host, port in self.peers:
                t = threading.Thread(target=self._peer_loop, args=(host, port), name=f"RemoteConnection-{host}-{port}", daemon=True)
                self._threads.append(t)
                t.start()
            self._router_stream.set_base_url(self.router_base_url or "http://127.0.0.1:8844")
        self._router_stream.start()
        self._log(f"[RemoteConnection] 🚀 started peers={len(self.peers)} router_api={self.router_base_url} miner_interface={str(self.miner_interface is not None).lower()} device={self.pcap_device_name or '<auto>'}")
        if self.miner_interface is not None:
            try:
                self.miner_interface.start()
            except Exception as e:
                self._log(f"[RemoteConnection] miner_interface start warning: {e}")
        with self._mu:
            self._emit_status_log_locked(time.time(), force=True)

    def stop(self) -> None:
        self._stop.set()
        self._router_stream.stop()
        if self.miner_interface is not None:
            try:
                self.miner_interface.stop()
            except Exception:
                pass
        with self._mu:
            sockets = list(self._socket_map.values())
            self._socket_map.clear()
            self._peer_last_probe_ts.clear()
            self._peer_last_support_probe_ts.clear()
            self._peer_last_probe_cmd.clear()
            self._peer_last_handshake_ts.clear()
            self._peer_last_timed_sync_ts.clear()
            self._peer_bootstrap_stage.clear()
            self._peer_recv_buffers.clear()
            self._peer_last_inbound_frame_ts.clear()
            self._peer_last_inbound_command.clear()
            self._peer_inbound_frame_count.clear()
            self._started = False
            self._epoch += 1
        for sock in sockets:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                sock.close()
            except Exception:
                pass

    def close(self) -> None:
        self.stop()
        with self._mu:
            threads = list(self._threads)
        for t in threads:
            try:
                t.join(timeout=1.0)
            except Exception:
                pass
        try:
            self._dll.close()
        except Exception:
            pass

    def get_epoch(self) -> int:
        with self._mu:
            return int(self._epoch)

    def ingest_routerclient_analysis(self, analysis: Dict[str, Any]) -> None:
        cur = analysis
        for _ in range(3):
            nxt = cur.get("result") if isinstance(cur, dict) else None
            if isinstance(nxt, dict):
                cur = nxt
            else:
                break
        if not isinstance(cur, dict):
            return
        now = time.time()
        with self._mu:
            l4 = cur.get("l4") or {}
            payload = cur.get("payload") or {}
            app = cur.get("application") or {}
            service_guess = l4.get("service_guess") or cur.get("service_guess")
            packet_topic = cur.get("packet_topic") or analysis.get("packet_topic")
            best_proto = cur.get("best_protocol_guess") or analysis.get("best_protocol_guess")
            flags_compact = str(l4.get("flags_compact") or "")
            payload_len = int(payload.get("length") or analysis.get("payload_length") or 0)
            levin_present = bool(((app.get("levin") or {}).get("present")) or analysis.get("levin_present"))

            if service_guess:
                self._service_guess = str(service_guess)
            if packet_topic:
                self._packet_topic = str(packet_topic)
            if best_proto:
                self._best_protocol_guess = str(best_proto)
            if flags_compact:
                self._tcp_flags_compact = flags_compact
            if payload_len:
                self._payload_len = payload_len
            if levin_present:
                self._levin_present = True

            text = "\n".join(str(x) for x in (cur.get("packet_summary"), cur.get("network_story"), cur.get("payload_hex_preview"), payload.get("ascii_preview"), payload.get("hexdump")) if x)
            self._extract_text_observations_locked(text)
            self._extract_structured_payload_locked(text, source="routerclient_analysis")
            self._last_packet_observation_ts = now
            self._last_native_observation_ts = now
            self._epoch += 1

    def _direction_for_packet(self, src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> int:
        peer_set = {f"{h}:{p}" for h, p in self.peers}
        if f"{dst_ip}:{dst_port}" in peer_set:
            return RemoteConnectionDll.RC_DIR_OUTBOUND
        if f"{src_ip}:{src_port}" in peer_set:
            return RemoteConnectionDll.RC_DIR_INBOUND
        if dst_port in self._MONERO_PORTS or dst_port in self._P2POOL_PORTS:
            return RemoteConnectionDll.RC_DIR_OUTBOUND
        if src_port in self._MONERO_PORTS or src_port in self._P2POOL_PORTS:
            return RemoteConnectionDll.RC_DIR_INBOUND
        src_priv = self._is_private_ip(src_ip)
        dst_priv = self._is_private_ip(dst_ip)
        if src_priv and not dst_priv:
            return RemoteConnectionDll.RC_DIR_OUTBOUND
        if dst_priv and not src_priv:
            return RemoteConnectionDll.RC_DIR_INBOUND
        return RemoteConnectionDll.RC_DIR_OUTBOUND

    def send_payload(self, payload: bytes, *, host: Optional[str] = None, port: Optional[int] = None) -> int:
        if payload is None:
            return 0
        blob = bytes(payload)
        if not blob:
            return 0
        sent_to = 0
        with self._mu:
            if host is not None and port is not None:
                key = f"{host}:{int(port)}"
                q = self._send_queues.setdefault(key, deque())
                q.append(blob)
                sent_to = 1
            else:
                for key in list(self._peer_state.keys()):
                    q = self._send_queues.setdefault(key, deque())
                    q.append(blob)
                    sent_to += 1
        return sent_to

    def send_protocol_packet(self, packet_obj: _LevinProtocolPacketBase) -> int:
        if packet_obj is None:
            return 0
        peer_key = str(packet_obj.peer_key)
        host = str(peer_key).split(':', 1)[0]
        try:
            port = int(str(peer_key).rpartition(':')[2])
        except Exception:
            port = 0
        if port <= 0:
            return 0
        frame = packet_obj.to_frame(self)
        sent = 0
        try:
            self.feed_stream_bytes(
                stream_id=f'protocol:{peer_key}:{int(getattr(packet_obj, "command", 0))}',
                peer=peer_key,
                direction=RemoteConnectionDll.RC_DIR_OUTBOUND,
                data=frame,
                service=int(getattr(packet_obj, 'service_kind', RemoteConnectionDll.RC_SERVICE_UNKNOWN)),
                timestamp_ms=int(time.time() * 1000.0),
            )
        except Exception:
            pass
        if self.miner_interface is not None:
            try:
                sent += int(self.miner_interface.send_protocol_packet(packet_obj) > 0)
            except Exception:
                pass
        sent += self.send_payload(frame, host=host, port=port)
        return int(sent)

    def send_monero_packet(self, packet_obj: MoneroPacket) -> int:
        return self.send_protocol_packet(packet_obj)

    def send_p2pool_packet(self, packet_obj: P2PoolPacket) -> int:
        return self.send_protocol_packet(packet_obj)

    def send_line(self, text: str, *, host: Optional[str] = None, port: Optional[int] = None) -> int:
        if text is None:
            return 0
        return self.send_payload(str(text).encode("utf-8", errors="ignore") + b"\n", host=host, port=port)

    def pop_received_packets(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        with self._mu:
            cap = len(self._received_packets) if limit is None else max(0, int(limit))
            while self._received_packets and len(out) < cap:
                out.append(self._received_packets.popleft())
        return out

    def feed_stream_bytes(
        self,
        stream_id: str,
        peer: str,
        direction: int,
        data: bytes,
        *,
        service: int = RemoteConnectionDll.RC_SERVICE_UNKNOWN,
        timestamp_ms: Optional[int] = None,
    ) -> int:
        blob = bytes(data or b"")
        if not blob:
            return 0
        if timestamp_ms is None:
            timestamp_ms = int(time.time() * 1000.0)
        peer_key = str(peer)
        with self._mu:
            stream_key = f"{stream_id}:out" if int(direction) == RemoteConnectionDll.RC_DIR_OUTBOUND else f"{stream_id}:in"
            if stream_key not in self._opened_streams:
                self._dll.open_stream(stream_key, peer_key, int(service))
                self._opened_streams.add(stream_key)
                self._stream_peer_map[stream_key] = peer_key
                self._peer_services[peer_key] = int(service)
                self._connect_events_total += 1
            if self._should_feed_dll_locked(stream_key, peer_key, int(service), blob):
                self._dll.feed_tcp_bytes(stream_key, int(direction), blob, timestamp_ms=timestamp_ms)
            now = time.time()
            st = self._ensure_peer_state_locked(peer_key)
            st["connected"] = True
            if int(direction) == RemoteConnectionDll.RC_DIR_INBOUND:
                st["last_rx_ts"] = now
                st["rx_packets"] += 1
                st["rx_bytes"] += len(blob)
                st["last_preview"] = self._preview_text(blob)
                st["bootstrap_stage"] = "feed_stream_rx"
                self._peer_bootstrap_stage[peer_key] = "feed_stream_rx"
                self._total_rx_packets += 1
                self._total_rx_bytes += len(blob)
                self._socket_rx_packets += 1
                self._socket_rx_bytes += len(blob)
            else:
                st["last_tx_ts"] = now
                st["tx_packets"] += 1
                st["tx_bytes"] += len(blob)
                st["last_tx_preview"] = self._preview_text(blob)
                self._total_tx_packets += 1
                self._total_tx_bytes += len(blob)
            st["last_activity_ts"] = now
            self._payload_len = len(blob)
            self._last_packet_observation_ts = now
            self._last_native_observation_ts = now
            if int(direction) == RemoteConnectionDll.RC_DIR_INBOUND:
                self._consume_payload_evidence_locked(peer_key, blob, now, int(service), source="feed_stream_bytes")
            elif self._is_probably_text(blob):
                self._extract_text_observations_locked(blob.decode("utf-8", errors="ignore"))
                self._extract_structured_payload_locked(blob, service=int(service), source="feed_stream_bytes_out")
            self._rate_sample_locked(now)
            self._poll_dll_events_locked(now)
            if self.miner_interface is not None:
                try:
                    if int(direction) == RemoteConnectionDll.RC_DIR_INBOUND:
                        self.miner_interface.note_socket_rx(peer_key, blob)
                    else:
                        self.miner_interface.note_socket_tx(peer_key, blob)
                except Exception:
                    pass
        return len(blob)

    def ingest_packet_bytes(self, raw_bytes: bytes, source: str = "") -> bool:
        packet_info = self._parse_packet_summary(raw_bytes)
        if packet_info is None:
            return False
        now = time.time()
        direction = self._direction_for_packet(packet_info["src_ip"], packet_info["src_port"], packet_info["dst_ip"], packet_info["dst_port"])
        service_kind, service_guess, topic = self._service_for_ports(packet_info["src_port"], packet_info["dst_port"])
        peer_ip = packet_info["dst_ip"] if direction == RemoteConnectionDll.RC_DIR_OUTBOUND else packet_info["src_ip"]
        peer_port = packet_info["dst_port"] if direction == RemoteConnectionDll.RC_DIR_OUTBOUND else packet_info["src_port"]
        peer_key = f"{peer_ip}:{peer_port}"
        stream_id = f"{packet_info['src_ip']}:{packet_info['src_port']}>{packet_info['dst_ip']}:{packet_info['dst_port']}"
        with self._mu:
            st = self._ensure_peer_state_locked(peer_key)
            st["connected"] = True
            st["last_rx_ts"] = now
            st["last_activity_ts"] = now
            pkt_len = int(packet_info.get("raw_len") or 0)
            st["rx_bytes"] += pkt_len
            st["rx_packets"] += 1
            self._total_rx_packets += 1
            self._total_rx_bytes += pkt_len
            self._raw_packet_rx_packets += 1
            self._raw_packet_rx_bytes += pkt_len
            st["recv_chunks"] = int(st.get("recv_chunks") or 0) + 1
            st["last_preview"] = self._preview_text(packet_info.get("payload", b""))
            self._payload_len = int(packet_info.get("payload_len") or 0)
            self._tcp_flags_compact = str(packet_info.get("flags_compact") or "")
            if service_guess:
                self._service_guess = service_guess
            if topic:
                self._packet_topic = topic
            self._last_packet_observation_ts = now
            self._last_native_observation_ts = now
            self._apply_packet_evidence_locked(packet_info, service_guess=service_guess, topic=topic, source=source)
            self._received_packets.append({
                "ts": now,
                "peer": peer_key,
                "kind": "packet",
                "src_ip": packet_info["src_ip"],
                "dst_ip": packet_info["dst_ip"],
                "src_port": packet_info["src_port"],
                "dst_port": packet_info["dst_port"],
                "flags": packet_info["flags_compact"],
                "payload_len": packet_info["payload_len"],
                "preview": st["last_preview"],
                "service_guess": service_guess,
                "source": source,
                "syn_with_payload": bool(packet_info.get("syn_with_payload")),
                "tcp_header_len": int(packet_info.get("tcp_header_len") or 0),
                "ip_total_len": int(packet_info.get("ip_total_len") or 0),
                "tcp_mss": packet_info.get("tcp_options_decoded", {}).get("mss"),
            })
            payload = packet_info["payload"]
            if payload:
                reasm_key = f"{stream_id}:{'out' if direction == RemoteConnectionDll.RC_DIR_OUTBOUND else 'in'}"
                reasm = self._flow_reassemblers.setdefault(reasm_key, _TcpDirectionalReassembler())
                out_stream_id = f"{stream_id}:out" if int(direction) == RemoteConnectionDll.RC_DIR_OUTBOUND else f"{stream_id}:in"
                if out_stream_id not in self._opened_streams:
                    self._dll.open_stream(out_stream_id, peer_key, int(service_kind))
                    self._opened_streams.add(out_stream_id)
                    self._stream_peer_map[out_stream_id] = peer_key
                    self._peer_services[peer_key] = int(service_kind)
                    self._connect_events_total += 1
                for chunk in reasm.feed(packet_info["seq"], payload):
                    if self._should_feed_dll_locked(out_stream_id, peer_key, int(service_kind), chunk):
                        self._dll.feed_tcp_bytes(out_stream_id, int(direction), chunk, timestamp_ms=int(now * 1000.0))
                    self._consume_payload_evidence_locked(
                        peer_key,
                        chunk,
                        now,
                        int(service_kind),
                        source="raw_packet_payload",
                    )
            self._poll_dll_events_locked(now)
            self._rate_sample_locked(now)
            self._epoch += 1
        return True

    def ingest_packet_raw_event(self, event: Dict[str, Any]) -> bool:
        result = event.get("result") if isinstance(event, dict) else None
        if isinstance(result, dict):
            event = result
        blob = b""
        raw_hex = event.get("raw_hex") if isinstance(event, dict) else None
        if raw_hex:
            try:
                blob = bytes.fromhex(str(raw_hex))
            except Exception:
                blob = b""
        if not blob:
            raw_base64 = event.get("raw_base64") if isinstance(event, dict) else None
            if raw_base64:
                try:
                    blob = base64.b64decode(str(raw_base64))
                except Exception:
                    blob = b""
        if not blob:
            return False
        source = str(event.get("source") or "") if isinstance(event, dict) else ""
        topic = str(event.get("topic") or "") if isinstance(event, dict) else ""
        proto = str(event.get("proto") or "") if isinstance(event, dict) else ""
        try:
            src_port = int(event.get("src_port") or event.get("sport") or 0) if isinstance(event, dict) else 0
        except Exception:
            src_port = 0
        try:
            dst_port = int(event.get("dst_port") or event.get("dport") or 0) if isinstance(event, dict) else 0
        except Exception:
            dst_port = 0
        payload, pkt_meta = self._payload_from_maybe_packet(blob)
        ok = False
        try:
            ok = self.ingest_packet_bytes(blob, source=source)
        except Exception:
            ok = False
        if not ok:
            try:
                ok = self.ingest_payload_bytes(
                    payload or blob,
                    source=source,
                    service_hint=topic or proto,
                    topic=topic,
                    proto=proto,
                    src_port=src_port,
                    dst_port=dst_port,
                )
            except Exception:
                ok = False
        service_kind, _sg, _tg = self._service_for_ports(src_port, dst_port)
        if payload and service_kind != RemoteConnectionDll.RC_SERVICE_UNKNOWN:
            try:
                src_ip = str(event.get('src_ip') or pkt_meta.get('src_ip') or '')
                dst_ip = str(event.get('dst_ip') or pkt_meta.get('dst_ip') or '')
                peer_ip = dst_ip if dst_port in (self._MONERO_PORTS | self._P2POOL_PORTS) else src_ip
                peer_port = dst_port if dst_port in (self._MONERO_PORTS | self._P2POOL_PORTS) else src_port
                peer_key = f'{peer_ip}:{int(peer_port)}' if peer_ip and int(peer_port) > 0 else f'raw:{service_kind}'
                direction = self._direction_for_packet(src_ip, src_port, dst_ip, dst_port) if src_ip and dst_ip else RemoteConnectionDll.RC_DIR_INBOUND
                self.feed_stream_bytes(
                    stream_id=f'rawevent:{src_ip}:{src_port}>{dst_ip}:{dst_port}',
                    peer=peer_key,
                    direction=direction,
                    data=payload,
                    service=service_kind,
                    timestamp_ms=int(time.time() * 1000.0),
                )
            except Exception:
                pass
        return ok

    def ingest_router_packet(self, packet: RouterPacket) -> bool:
        if packet is None:
            return False
        blob = packet.to_bytes()
        if not blob:
            return False
        source = packet.source or (f"miner://{packet.peer_key()}" if str(packet.iface or '').strip().lower() == 'miner' else f"/api/packets/raw/{packet.packet_id}")
        value_score = self._packet_value_score(packet.to_event_dict().get('result') or {}, blob)
        pkt_meta = packet.to_event_dict().get('result') or {}
        high_value = self._is_high_value_transport_packet(pkt_meta, blob, threshold=0.42)
        if str(packet.iface or '').strip().lower() == 'miner' and packet.is_protocol_candidate():
            high_value = True
            value_score = max(float(value_score), 0.92)
        payload, parsed_meta = self._payload_from_maybe_packet(blob)
        ok = False
        if high_value:
            try:
                ok = self.ingest_packet_bytes(blob, source=source)
            except Exception:
                ok = False
        if high_value and not ok:
            peer_hint = ""
            if packet.dst_ip and packet.dst_port:
                peer_hint = f"{packet.dst_ip}:{int(packet.dst_port)}"
            elif packet.src_ip and packet.src_port:
                peer_hint = f"{packet.src_ip}:{int(packet.src_port)}"
            try:
                ok = self.ingest_payload_bytes(
                    payload or blob,
                    source=source,
                    service_hint=str(packet.topic or packet.proto or ""),
                    topic=str(packet.topic or ""),
                    proto=str(packet.proto or ""),
                    peer_hint=peer_hint,
                    src_port=int(packet.src_port or parsed_meta.get('src_port') or 0),
                    dst_port=int(packet.dst_port or parsed_meta.get('dst_port') or 0),
                )
            except Exception:
                ok = False
        service_kind = int(packet.service_guess())
        if payload and service_kind != RemoteConnectionDll.RC_SERVICE_UNKNOWN:
            try:
                src_ip = str(packet.src_ip or parsed_meta.get('src_ip') or '')
                dst_ip = str(packet.dst_ip or parsed_meta.get('dst_ip') or '')
                src_port = int(packet.src_port or parsed_meta.get('src_port') or 0)
                dst_port = int(packet.dst_port or parsed_meta.get('dst_port') or 0)
                peer_ip = dst_ip if dst_port in (self._MONERO_PORTS | self._P2POOL_PORTS) else src_ip
                peer_port = dst_port if dst_port in (self._MONERO_PORTS | self._P2POOL_PORTS) else src_port
                peer_key = f'{peer_ip}:{int(peer_port)}' if peer_ip and int(peer_port) > 0 else (packet.peer_key() or f'router:{service_kind}')
                direction = self._direction_for_packet(src_ip, src_port, dst_ip, dst_port) if src_ip and dst_ip else (RemoteConnectionDll.RC_DIR_OUTBOUND if str(packet.direction or '').lower().startswith('out') else RemoteConnectionDll.RC_DIR_INBOUND)
                self.feed_stream_bytes(
                    stream_id=f'router:{packet.packet_id}:{src_ip}:{src_port}>{dst_ip}:{dst_port}',
                    peer=peer_key,
                    direction=direction,
                    data=payload,
                    service=service_kind,
                    timestamp_ms=int(time.time() * 1000.0),
                )
            except Exception:
                pass
        with self._mu:
            self._router_packets_total += 1
            self._router_rx_packets += 1
            self._router_rx_bytes += len(blob)
            self._router_last_poll_ts = time.time()
            self._router_last_packet_id = max(self._router_last_packet_id, int(packet.packet_id or 0))
            if high_value:
                self._packet_transport_confidence = max(float(self._packet_transport_confidence), min(1.0, float(value_score)))
            if ok:
                self._router_raw_packets_total += 1
                if packet.topic:
                    self._packet_topic = packet.topic
                    if str(packet.topic).lower() == "p2pool":
                        self._service_guess = "p2pool_p2p"
                    elif str(packet.topic).lower() == "monero":
                        self._service_guess = "monero_p2p"
                proto_l = str(packet.proto or "").strip().lower()
                if proto_l in {"levin", "monero_p2p", "p2pool_p2p"}:
                    self._best_protocol_guess = proto_l
                self._rate_sample_locked(time.time())
        return ok

    def snapshot(self) -> Dict[str, Any]:
        now = time.time()
        with self._mu:
            diff = self._rate_window.diff_rate(now)
            (
                rx_pps,
                rx_bps,
                tx_pps,
                tx_bps,
                connect_eps,
                disconnect_eps,
                fail_eps,
                socket_rx_pps,
                socket_rx_bps,
                router_rx_pps,
                router_rx_bps,
                raw_packet_rx_pps,
                raw_packet_rx_bps,
                dll_rx_fps,
            ) = ((list(diff) + [0.0] * 14)[:14])
            rx_pps = max(float(rx_pps), float(socket_rx_pps) + float(router_rx_pps) + float(raw_packet_rx_pps), float(dll_rx_fps))
            peers = [dict(v) for v in self._peer_state.values()]
            connected = sum(1 for p in peers if (now - float(p.get("last_activity_ts") or 0.0)) <= self._MAX_QUIET_SEC)
            hot = sum(1 for p in peers if (now - float(p.get("last_rx_ts") or 0.0)) <= self.hot_rx_window_sec)
            latencies = [float(p["latency_ms"]) for p in peers if p.get("latency_ms") is not None]
            best_latency_ms = min(latencies) if latencies else None
            avg_latency_ms = (sum(latencies) / len(latencies)) if latencies else None
            real_data_age_sec = (now - self._last_real_data_ts) if self._last_real_data_ts > 0 else None
            real_data_fresh = (real_data_age_sec is not None and real_data_age_sec <= self._NATIVE_FRESH_SEC)
            router_fresh = (now - self._router_last_poll_ts) <= (self.router_poll_interval_sec * 4.0) if self._router_last_poll_ts > 0 else False
            validated_frame_count = int(self._validated_frame_count)
            invalid_frame_count = int(self._invalid_frame_count)
            semantic_frame_count = int(self._semantic_frame_count)
            real_data_frame_count = int(self._real_data_frame_count)
            socket_count = len(self._socket_map)

            has_chain_height = (self._mainchain_height is not None) or (self._sidechain_height is not None)
            has_difficulty = self._difficulty is not None
            has_peer_state = (self._peer_count_hint is not None) or (self._last_peer_id is not None) or (self._last_support_flags is not None)
            has_protocol = bool(self._last_command_name or self._last_command or self._best_protocol_guess or self._levin_present)
            has_status_text = bool(self._last_status)
            has_top_id = bool(self._last_top_id_hex)

            decode_components = 0.0
            if real_data_fresh:
                decode_components += 0.30
            if has_chain_height:
                decode_components += 0.22
            if has_difficulty:
                decode_components += 0.18
            if has_protocol:
                decode_components += 0.12
            if has_peer_state:
                decode_components += 0.08
            if has_status_text:
                decode_components += 0.05
            if has_top_id:
                decode_components += 0.05
            decode_confidence = min(1.0, decode_components)

            valid_total = max(1, validated_frame_count + invalid_frame_count)
            frame_valid_ratio = float(validated_frame_count) / float(valid_total)
            real_data_ratio = float(real_data_frame_count) / float(max(1, semantic_frame_count))
            semantic_density = float(semantic_frame_count) / float(max(1, validated_frame_count))

            return {
                "peer_count": len(peers),
                "connected_peers": connected,
                "hot_peers": hot,
                "best_latency_ms": best_latency_ms,
                "avg_latency_ms": avg_latency_ms,
                "rx_pps": float(rx_pps),
                "rx_bps": float(rx_bps),
                "tx_pps": float(tx_pps),
                "tx_bps": float(tx_bps),
                "connect_eps": float(connect_eps),
                "disconnect_eps": float(disconnect_eps),
                "fail_eps": float(fail_eps),
                "socket_rx_pps": float(socket_rx_pps),
                "socket_rx_bps": float(socket_rx_bps),
                "router_rx_pps": float(router_rx_pps),
                "router_rx_bps": float(router_rx_bps),
                "raw_packet_rx_pps": float(raw_packet_rx_pps),
                "raw_packet_rx_bps": float(raw_packet_rx_bps),
                "dll_rx_fps": float(dll_rx_fps),
                "sidechain_height": self._sidechain_height,
                "mainchain_height": self._mainchain_height,
                "difficulty": self._difficulty,
                "peer_count_hint": self._peer_count_hint,
                "network_epoch": int(self._epoch),
                "packet_topic": self._packet_topic,
                "best_protocol_guess": self._best_protocol_guess,
                "service_guess": self._service_guess,
                "tcp_flags_compact": self._tcp_flags_compact,
                "payload_len": self._payload_len,
                "levin_present": self._levin_present,
                "native_fresh": (now - self._last_native_observation_ts) <= self._NATIVE_FRESH_SEC if self._last_native_observation_ts > 0 else False,
                "packet_fresh": (now - self._last_packet_observation_ts) <= self._NATIVE_FRESH_SEC if self._last_packet_observation_ts > 0 else False,
                "real_data_fresh": real_data_fresh,
                "real_data_age_sec": real_data_age_sec,
                "decode_confidence": decode_confidence,
                "has_chain_height": has_chain_height,
                "has_difficulty": has_difficulty,
                "has_peer_state": has_peer_state,
                "has_protocol": has_protocol,
                "has_status_text": has_status_text,
                "has_top_id": has_top_id,
                "frame_valid_ratio": frame_valid_ratio,
                "real_data_ratio": real_data_ratio,
                "semantic_density": semantic_density,
                "queued_packets": sum(len(q) for q in self._send_queues.values()),
                "buffered_packets": len(self._received_packets),
                "validated_frame_count": validated_frame_count,
                "invalid_frame_count": invalid_frame_count,
                "semantic_frame_count": semantic_frame_count,
                "real_data_frame_count": real_data_frame_count,
                "last_real_data_ts": float(self._last_real_data_ts),
                "last_semantic_source": self._last_semantic_source,
                "socket_count": socket_count,
                "dll_skipped_non_levin": int(self._dll_skipped_non_levin),
                "router_packets_total": int(self._router_packets_total),
                "router_base_url": self.router_base_url,
                "router_raw_packets_total": int(self._router_raw_packets_total),
                "router_last_packet_id": int(self._router_last_packet_id),
                "router_fresh": router_fresh,
                "last_command": self._last_command,
                "last_command_name": self._last_command_name,
                "last_return_code": self._last_return_code,
                "last_status": self._last_status,
                "last_top_id_hex": self._last_top_id_hex,
                "last_top_version": self._last_top_version,
                "last_pruning_seed": self._last_pruning_seed,
                "last_rpc_port_hint": self._last_rpc_port_hint,
                "last_my_port": self._last_my_port,
                "last_local_peerlist_count": self._last_local_peerlist_count,
                "last_cumulative_difficulty_top64": self._last_cumulative_difficulty_top64,
                "last_peer_id": self._last_peer_id,
                "last_support_flags": self._last_support_flags,
                "last_rpc_method": self._last_rpc_method,
                "last_rpc_job_id": self._last_rpc_job_id,
                "last_semantic_json": self._last_semantic_json,
                "dll_ready": bool(
                    ((now - self._last_validated_frame_ts) <= self._NATIVE_FRESH_SEC if self._last_validated_frame_ts > 0 else False)
                    or (self._last_semantic_source.startswith("dll"))
                ),
                "packet_observation_count": int(self._packet_observation_count),
                "packet_transport_confidence": float(self._packet_transport_confidence),
                "last_packet_service_hint": self._last_packet_service_hint,
                "last_packet_transport_kind": self._last_packet_transport_kind,
                "last_packet_payload_preview_hex": self._last_packet_payload_preview_hex,
                "last_packet_entropy": self._last_packet_entropy,
                "last_packet_payload_len": int(self._last_packet_payload_len),
                "last_syn_with_payload": bool(self._last_syn_with_payload),
                "last_tcp_mss": self._last_tcp_mss,
                "last_tcp_window_scale": self._last_tcp_window_scale,
                "last_tcp_sack_permitted": bool(self._last_tcp_sack_permitted),
                "last_tcp_timestamp": bool(self._last_tcp_timestamp),
                "p2pool_transport_packet_count": int(self._p2pool_transport_packet_count),
                "monero_transport_packet_count": int(self._monero_transport_packet_count),
                "syn_with_payload_count": int(self._syn_with_payload_count),
                "peers": peers,
                "native_stats": {
                    "syn_pps": float(self._syn_with_payload_count),
                    "ack_pps": 0.0,
                    "payload_pps": max(0.0, float(rx_pps)),
                    "socket_rx_pps": max(0.0, float(socket_rx_pps)),
                    "router_rx_pps": max(0.0, float(router_rx_pps)),
                    "raw_packet_rx_pps": max(0.0, float(raw_packet_rx_pps)),
                    "dll_rx_fps": max(0.0, float(dll_rx_fps)),
                    "levin_pps": max(0.0, float(dll_rx_fps)) if self._levin_present else 0.0,
                },
            }

    def get_hint(self) -> Dict[str, Any]:
        snap = self.snapshot()

        decode_confidence = float(snap.get("decode_confidence", 0.0) or 0.0)
        frame_valid_ratio = float(snap.get("frame_valid_ratio", 0.0) or 0.0)
        real_data_ratio = float(snap.get("real_data_ratio", 0.0) or 0.0)
        semantic_density = float(snap.get("semantic_density", 0.0) or 0.0)
        real_data_fresh = bool(snap.get("real_data_fresh"))
        dll_ready = bool(snap.get("dll_ready"))
        has_chain_height = bool(snap.get("has_chain_height"))
        has_difficulty = bool(snap.get("has_difficulty"))
        has_peer_state = bool(snap.get("has_peer_state"))
        has_protocol = bool(snap.get("has_protocol"))
        has_status_text = bool(snap.get("has_status_text"))
        has_top_id = bool(snap.get("has_top_id"))

        packet_transport_confidence = float(snap.get("packet_transport_confidence", 0.0) or 0.0)
        packet_observation_count = int(snap.get("packet_observation_count", 0) or 0)
        last_syn_with_payload = bool(snap.get("last_syn_with_payload"))
        last_packet_transport_kind = str(snap.get("last_packet_transport_kind") or "")
        last_packet_service_hint = str(snap.get("last_packet_service_hint") or "")
        last_packet_payload_len = int(snap.get("last_packet_payload_len", 0) or 0)

        semantic_score = 0.0
        semantic_score += decode_confidence * 0.58
        semantic_score += min(1.0, frame_valid_ratio) * 0.10
        semantic_score += min(1.0, real_data_ratio) * 0.12
        semantic_score += min(1.0, semantic_density) * 0.08
        if real_data_fresh:
            semantic_score += 0.10
        if has_chain_height:
            semantic_score += 0.08
        if has_difficulty:
            semantic_score += 0.06
        if has_protocol:
            semantic_score += 0.05
        if has_peer_state:
            semantic_score += 0.03
        if has_status_text:
            semantic_score += 0.02
        if has_top_id:
            semantic_score += 0.02
        semantic_score = min(1.0, semantic_score)

        packet_score = 0.0
        packet_score += min(0.40, packet_transport_confidence * 0.55)
        if packet_observation_count > 0:
            packet_score += 0.05
        if bool(snap.get("packet_fresh")):
            packet_score += 0.05
        if last_syn_with_payload:
            packet_score += 0.07
        if last_packet_payload_len > 0:
            packet_score += 0.05
        if last_packet_transport_kind:
            packet_score += 0.05
        if last_packet_service_hint in {"p2pool_p2p", "monero_p2p"}:
            packet_score += 0.04
        packet_score = min(0.35, packet_score)

        transport_score = 0.0
        if int(snap.get("socket_count", 0)) > 0:
            transport_score += 0.04
        if bool(snap.get("router_fresh")):
            transport_score += 0.04
        if int(snap.get("connected_peers", 0)) > 0:
            transport_score += 0.03
        if int(snap.get("hot_peers", 0)) > 0:
            transport_score += 0.03
        if float(snap.get("rx_pps", 0.0) or 0.0) > 0.0:
            transport_score += 0.02
        transport_score = min(0.14, transport_score)

        evidence_score = max(semantic_score, min(1.0, semantic_score + packet_score * 0.70))
        pressure = min(1.0, semantic_score + packet_score + transport_score)
        if semantic_score < 0.18:
            pressure = min(pressure, 0.34 if packet_score > 0.0 else 0.24)
        elif semantic_score < 0.35:
            pressure = min(pressure, 0.50)

        if dll_ready and real_data_fresh and has_chain_height and has_difficulty:
            live_poll = 8
            stale_poll = 4
            chunk_scale = 0.58
            hint_mode = "dll_decoded_chain_and_diff"
        elif real_data_fresh and has_chain_height and has_difficulty:
            live_poll = 16
            stale_poll = 8
            chunk_scale = 0.72
            hint_mode = "decoded_chain_and_diff"
        elif real_data_fresh and (has_chain_height or has_difficulty or has_protocol):
            live_poll = 24
            stale_poll = 12
            chunk_scale = 0.80
            hint_mode = "decoded_live"
        elif packet_score >= 0.20 and last_syn_with_payload:
            live_poll = 40
            stale_poll = 20
            chunk_scale = 0.90
            hint_mode = "packet_syn_with_data"
        elif packet_score >= 0.12:
            live_poll = 56
            stale_poll = 28
            chunk_scale = 0.98
            hint_mode = "packet_transport_only"
        elif int(snap.get("validated_frame_count", 0)) > 0:
            live_poll = 64
            stale_poll = 32
            chunk_scale = 1.00
            hint_mode = "validated_transport"
        else:
            live_poll = 128
            stale_poll = 64
            chunk_scale = 1.18
            hint_mode = "transport_only"

        authoritative_fields = []
        if has_chain_height:
            authoritative_fields.append("height")
        if has_difficulty:
            authoritative_fields.append("difficulty")
        if has_peer_state:
            authoritative_fields.append("peer_state")
        if has_protocol:
            authoritative_fields.append("protocol")
        if has_status_text:
            authoritative_fields.append("status")
        if has_top_id:
            authoritative_fields.append("top_id")

        return {
            "pressure": float(pressure),
            "evidence_score": float(evidence_score),
            "semantic_score": float(semantic_score),
            "packet_score": float(packet_score),
            "transport_score": float(transport_score),
            "hint_mode": hint_mode,
            "authoritative_fields": authoritative_fields,
            "suggested_live_poll": int(live_poll),
            "suggested_stale_poll": int(stale_poll),
            "suggested_chunk_scale": float(chunk_scale),
            "connected_peers": int(snap.get("connected_peers", 0)),
            "hot_peers": int(snap.get("hot_peers", 0)),
            "rx_pps": float(snap.get("rx_pps", 0.0) or 0.0),
            "socket_rx_pps": float(snap.get("socket_rx_pps", 0.0) or 0.0),
            "router_rx_pps": float(snap.get("router_rx_pps", 0.0) or 0.0),
            "raw_packet_rx_pps": float(snap.get("raw_packet_rx_pps", 0.0) or 0.0),
            "dll_rx_fps": float(snap.get("dll_rx_fps", 0.0) or 0.0),
            "best_latency_ms": snap.get("best_latency_ms"),
            "avg_latency_ms": snap.get("avg_latency_ms"),
            "sidechain_height": snap.get("sidechain_height"),
            "mainchain_height": snap.get("mainchain_height"),
            "difficulty": snap.get("difficulty"),
            "peer_count_hint": snap.get("peer_count_hint"),
            "network_epoch": int(snap.get("network_epoch", 0)),
            "packet_topic": snap.get("packet_topic"),
            "best_protocol_guess": snap.get("best_protocol_guess"),
            "service_guess": snap.get("service_guess"),
            "levin_present": bool(snap.get("levin_present")),
            "real_data_fresh": bool(real_data_fresh),
            "real_data_age_sec": snap.get("real_data_age_sec"),
            "decode_confidence": float(decode_confidence),
            "frame_valid_ratio": float(frame_valid_ratio),
            "real_data_ratio": float(real_data_ratio),
            "semantic_density": float(semantic_density),
            "packet_transport_confidence": float(packet_transport_confidence),
            "last_packet_transport_kind": last_packet_transport_kind or None,
            "last_packet_service_hint": last_packet_service_hint or None,
            "last_syn_with_payload": bool(last_syn_with_payload),
            "last_packet_payload_len": int(last_packet_payload_len),
            "last_tcp_mss": snap.get("last_tcp_mss"),
            "last_tcp_window_scale": snap.get("last_tcp_window_scale"),
            "last_tcp_sack_permitted": bool(snap.get("last_tcp_sack_permitted")),
            "last_tcp_timestamp": bool(snap.get("last_tcp_timestamp")),
            "last_packet_entropy": snap.get("last_packet_entropy"),
            "last_command": snap.get("last_command"),
            "last_command_name": snap.get("last_command_name"),
            "last_status": snap.get("last_status"),
            "last_top_id_hex": snap.get("last_top_id_hex"),
            "last_top_version": snap.get("last_top_version"),
            "last_pruning_seed": snap.get("last_pruning_seed"),
            "last_rpc_port_hint": snap.get("last_rpc_port_hint"),
            "last_my_port": snap.get("last_my_port"),
            "last_local_peerlist_count": snap.get("last_local_peerlist_count"),
            "last_cumulative_difficulty_top64": snap.get("last_cumulative_difficulty_top64"),
            "last_peer_id": snap.get("last_peer_id"),
            "last_support_flags": snap.get("last_support_flags"),
            "last_rpc_method": snap.get("last_rpc_method"),
            "last_rpc_job_id": snap.get("last_rpc_job_id"),
            "last_semantic_source": snap.get("last_semantic_source"),
            "dll_ready": bool(dll_ready),
        }



class PythonUsageController:
    """
    Conservative PythonUsage gate for the P2Pool hot loop.

    Goals:
      - keep the public P2PoolShareHunterWorker signatures unchanged
      - only allow one safe worker to use python_usage at a time
      - keep chunk sizes very small to avoid memory pressure
      - permanently stand down on access-violation style failures
      - fall back to the direct path immediately on any unsafe condition
    """

    def __init__(
        self,
        *,
        threads: int,
        logger: Optional[Callable[[str], None]],
        python_usage: Optional[Any],
        startup_grace_sec: float = 8.0,
        max_threads: int = 4,
        owner_worker: int = 0,
        min_direct_hashes_before_usage: int = 256,
        chunk_hashes: int = 8,
    ) -> None:
        self.threads = max(1, int(threads))
        self.logger = logger or (lambda s: None)
        self.python_usage = python_usage

        self._mu = threading.RLock()
        self._usage_lock = threading.Lock()
        self._started_at = time.perf_counter()
        self._startup_grace_until = self._started_at + max(0.0, float(startup_grace_sec))

        self._max_threads = max(1, int(max_threads))
        self._owner_worker = max(0, int(owner_worker))
        self._min_direct_hashes_before_usage = max(1, int(min_direct_hashes_before_usage))
        self._chunk_hashes = max(1, min(64, int(chunk_hashes)))

        self._enabled = python_usage is not None
        self._permanently_disabled = False
        self._disabled_until = 0.0
        self._av_count = 0
        self._active_worker: Optional[int] = None
        self._active_invocations = 0
        self._direct_hashes: Dict[int, int] = {}
        self._next_retry_at: Dict[int, float] = {}
        self._stats = {
            "usage_attempts": 0,
            "usage_ok": 0,
            "usage_fail": 0,
            "usage_av": 0,
            "direct_notes": 0,
            "pressure_bypass": 0,
        }

    def _log(self, msg: str) -> None:
        try:
            self.logger(msg)
        except Exception:
            pass

    @staticmethod
    def _now() -> float:
        return time.perf_counter()

    @staticmethod
    def _err_text(e: BaseException) -> str:
        return f"{type(e).__name__}: {e}"

    @staticmethod
    def _looks_like_access_violation_text(msg: str) -> bool:
        m = str(msg).lower()
        return (
            "access violation" in m
            or "0xc0000005" in m
            or "exception reading 0x0000000000000000" in m
            or "raised structured exception" in m
            or "memoryerror" in m
            or "bad allocation" in m
        )

    def _cooldown_seconds(self, failures: int, *, base: float = 2.0, cap: float = 120.0) -> float:
        failures = max(1, int(failures))
        return min(cap, base * (2.0 ** min(failures - 1, 5)))

    def _av_cooldown_seconds(self, av_count: int, *, base: float = 30.0, cap: float = 900.0) -> float:
        av_count = max(1, int(av_count))
        return min(cap, base * (2.0 ** min(av_count - 1, 4)))

    def note_direct_hashes(self, worker_index: int, count: int = 1) -> None:
        wi = int(worker_index)
        n = max(0, int(count))
        if n <= 0:
            return
        with self._mu:
            self._direct_hashes[wi] = int(self._direct_hashes.get(wi, 0)) + n
            self._stats["direct_notes"] += n

    def request_stop(self) -> None:
        with self._mu:
            self._active_worker = None
            self._active_invocations = 0

    def close(self) -> None:
        self.request_stop()
        pu = self.python_usage
        if pu is not None:
            stopper = getattr(pu, "stop_worker", None)
            if callable(stopper):
                try:
                    stopper()
                except Exception:
                    pass

    def is_enabled(self) -> bool:
        with self._mu:
            return bool(self._enabled and not self._permanently_disabled and self.python_usage is not None)

    def suggested_chunk_hashes(self, remaining: int) -> int:
        return max(1, min(int(remaining), self._chunk_hashes))

    def _feature_available_locked(self, worker_index: int) -> bool:
        now = self._now()
        if not self._enabled or self.python_usage is None:
            return False
        if self._permanently_disabled:
            return False
        if now < self._startup_grace_until:
            return False
        if now < float(self._disabled_until):
            return False
        if self.threads > self._max_threads:
            self._stats["pressure_bypass"] += 1
            return False
        wi = int(worker_index)
        if wi != self._owner_worker:
            return False
        if self._active_worker is not None and self._active_worker != wi:
            self._stats["pressure_bypass"] += 1
            return False
        if self._active_invocations > 0:
            self._stats["pressure_bypass"] += 1
            return False
        if now < float(self._next_retry_at.get(wi, 0.0)):
            return False
        if int(self._direct_hashes.get(wi, 0)) < self._min_direct_hashes_before_usage:
            return False
        return True

    def should_run(self, worker_index: int) -> bool:
        with self._mu:
            return self._feature_available_locked(worker_index)

    def invoke_chunk(self, worker_index: int, func: Callable[..., Any], *args: Any, **kwargs: Any) -> Tuple[bool, Any]:
        wi = int(worker_index)
        with self._mu:
            if not self._feature_available_locked(wi):
                return False, None
            self._active_worker = wi
            self._active_invocations += 1
            self._stats["usage_attempts"] += 1

        try:
            with self._usage_lock:
                pu = self.python_usage
                if pu is None:
                    raise RuntimeError("python_usage unavailable")

                caller = getattr(pu, "call", None)
                if callable(caller):
                    result = caller(func, *args, **kwargs)
                else:
                    setter = getattr(pu, "set_function", None)
                    runner = getattr(pu, "run_once", None)
                    getter = getattr(pu, "get_last_python_result", None)
                    if not callable(setter) or not callable(runner):
                        raise RuntimeError("python_usage is missing call/run_once support")
                    setter(func, *args, **kwargs)
                    int(runner())
                    err_getter = getattr(pu, "get_last_error", None)
                    if callable(err_getter):
                        err = err_getter()
                        if err is not None:
                            raise err
                    result = getter() if callable(getter) else None

            with self._mu:
                self._stats["usage_ok"] += 1
                self._next_retry_at[wi] = 0.0
            return True, result

        except BaseException as e:
            msg = self._err_text(e)
            with self._mu:
                self._stats["usage_fail"] += 1
                if self._looks_like_access_violation_text(msg):
                    self._av_count += 1
                    self._stats["usage_av"] += 1
                    self._permanently_disabled = True
                    self._disabled_until = max(self._disabled_until, self._now() + self._av_cooldown_seconds(self._av_count))
                    self._log(
                        f"[P2PoolHunter][PythonUsage] ⚠️ permanently disabled after access-violation style error "
                        f"worker={wi} av_count={self._av_count} reason={msg}"
                    )
                else:
                    failures = int(self._stats["usage_fail"])
                    self._next_retry_at[wi] = max(
                        float(self._next_retry_at.get(wi, 0.0)),
                        self._now() + self._cooldown_seconds(failures, base=3.0),
                    )
                    self._log(
                        f"[P2PoolHunter][PythonUsage] ↩️ fallback to direct worker={wi} reason={msg}"
                    )
            return False, None

        finally:
            with self._mu:
                if self._active_invocations > 0:
                    self._active_invocations -= 1
                if self._active_worker == wi:
                    self._active_worker = None

    def snapshot(self) -> Dict[str, Any]:
        with self._mu:
            return {
                "enabled": self._enabled,
                "permanently_disabled": self._permanently_disabled,
                "disabled_until": float(self._disabled_until),
                "av_count": int(self._av_count),
                "active_worker": self._active_worker,
                "active_invocations": int(self._active_invocations),
                "max_threads": int(self._max_threads),
                "owner_worker": int(self._owner_worker),
                "chunk_hashes": int(self._chunk_hashes),
                "min_direct_hashes_before_usage": int(self._min_direct_hashes_before_usage),
                "stats": dict(self._stats),
            }

@dataclass
class _WorkerLane:
    worker_index: int
    vm: Any = None
    blob_buf: Any = None
    nonce_ptr: Any = None
    out_buf: Any = None
    value64_view: Any = None
    last_seed: bytes = b""
    last_blob: bytes = b""

    assigned_job: Optional[MoneroJob] = None
    assigned_job_key: str = ""
    assigned_generation: int = 0
    assigned_start_nonce: int = 0
    assigned_count: int = 0
    assigned_stride: int = 1
    assigned_result_cap: int = 0
    assigned_best_cap: int = 0
    assigned_near_cutoff: int = 0
    assigned_poll_interval: int = 64
    assigned_stale_poll_interval: int = 32
    assigned_is_current: Optional[Callable[[], bool]] = None
    assigned_stop_flag: Any = None
    assigned_submit_candidate: Optional[Callable[[int, int, bytes], None]] = None
    assigned_job_urgency: float = 0.0
    assigned_submit_immediately: bool = False
    assigned_hash_chunk_cap: int = 0

    hashes_done: int = 0
    stale_aborts: int = 0
    chain_hits: int = 0
    submitted_hits: int = 0
    streak_groups: int = 0
    max_streak_len: int = 0
    found: Optional[List[Tuple[int, int, bytes]]] = None
    best: Optional[List[Tuple[int, int, bytes]]] = None
    error: Optional[str] = None
    busy: bool = False

    start_event: Optional[threading.Event] = None
    done_event: Optional[threading.Event] = None
    stop_event: Any = None
    probe: Any = None

class P2PoolShareHunterWorker:
    """
    Full rewrite focused on fixing duplicate shares by fixing duplicate search.

    Main rules:
      - every live job template gets a shared nonce lease session
      - every hash_job() call leases a disjoint nonce span
      - per-lane search is interleaved and non-overlapping
      - valid shares must claim their nonce immediately per job template
      - burst/found/submit pools are nonce-unique
      - submit_candidate is protected by a second per-template submit guard
      - if submit_candidate is used, already-submitted rows are hidden from `found`
    """

    def __init__(
        self,
        *,
        threads: int,
        logger: Optional[Callable[[str], None]],
        randomx: RandomX,
        batch_size: int = 2048,
        keep_best: int = 8,
        near_miss_ratio: float = 1.75,
        log_cooldown_sec: float = 120.0,
        poll_interval: int = 64,
        stale_poll_interval: int = 32,
        warmup_once_per_job: bool = True,
        remote_connection: Optional[RemoteConnection] = None,
        stratum_host: str = "127.0.0.1",
    ) -> None:
        self.threads = max(1, int(threads))
        self.logger = logger or (lambda s: None)
        self.randomx = randomx

        self.batch_size = max(1, int(batch_size))
        self.keep_best = max(1, int(keep_best))
        self.near_miss_ratio = max(1.0, float(near_miss_ratio))
        self.log_cooldown_sec = max(1.0, float(log_cooldown_sec))
        self.poll_interval = max(1, int(poll_interval))
        self.stale_poll_interval = max(1, int(stale_poll_interval))
        self.warmup_once_per_job = bool(warmup_once_per_job)

        self._min_unique_flush = 2
        self._max_unique_flush = max(8, min(64, self.keep_best * 8))
        self._post_hit_harvest_floor = 512
        self._post_hit_harvest_multiplier = 8
        self._pending_submit_limit = max(128, self.keep_best * 64)
        self._chain_gap_limit = 64

        self.remote_connection = remote_connection
        self.stratum_host = str(stratum_host or "127.0.0.1").strip() or "127.0.0.1"

        self._stop = threading.Event()
        self._closed = threading.Event()

        self._states_mu = threading.Lock()
        self._states: List[_WorkerLane] = []
        self._threads_runtime: List[threading.Thread] = []

        self._job_timing_mu = threading.Lock()
        self._job_change_times: Deque[float] = deque(maxlen=64)
        self._job_history: Deque[Tuple[float, str, int]] = deque(maxlen=64)
        self._last_job_signature: Tuple[str, int] = ("", -1)
        self._last_job_change_ts = 0.0
        self._recent_reject_times: Deque[float] = deque(maxlen=64)
        self._recent_accept_times: Deque[float] = deque(maxlen=64)

        self._perf_mu = threading.Lock()
        self._worker_hashes_total: List[int] = [0] * self.threads
        self._worker_hashes_window: List[int] = [0] * self.threads
        self._worker_hits_total: List[int] = [0] * self.threads
        self._worker_stale_total: List[int] = [0] * self.threads
        self._worker_streak_total: List[int] = [0] * self.threads

        self._shared_status = _SharedStatusState(min_interval_sec=12.0)
        self._template_nonce_guard = _RecentTemplateNonceGuard(max_entries=1_000_000)
        self._template_submit_guard = _RecentTemplateSubmitGuard(max_entries=1_000_000)
        self._job_sessions = _JobLeaseManager(ttl_sec=300.0)

        self._dispatch_lock = threading.Lock()
        self._lane_call_locks = [threading.Lock() for _ in range(self.threads)]

        self.python_usage_controller: Optional[PythonUsageController] = self._build_default_python_usage_controller()

        if self.remote_connection is not None:
            try:
                setter = getattr(self.remote_connection, "set_router_api_base_url", None)
                if callable(setter):
                    setter(self.stratum_host, 8844)
            except Exception:
                pass
            try:
                self.remote_connection.set_combined_mode(True)
                self.remote_connection.start()
            except Exception as e:
                self.logger(f"[P2PoolHunter] remote_connection start warning: {e}")

        self._bootstrap_workers()

    @staticmethod
    def _stable_job_template_key(job: MoneroJob) -> str:
        """
        Stable key for the logical job template.
        Nonce bytes are zeroed so new nonce values do not create a different key.
        """
        try:
            nonce_off = int(job.nonce_offset)
        except Exception:
            nonce_off = 0

        blob = bytearray(bytes(job.blob))
        for i in range(nonce_off, min(nonce_off + 4, len(blob))):
            blob[i] = 0

        h = hashlib.blake2b(digest_size=20)
        h.update(bytes(job.seed_hash))
        h.update(bytes(blob))
        h.update(int(job.target64).to_bytes(8, "little", signed=False))
        return h.hexdigest()

    @staticmethod
    def _quality_ratio(value64: int, target64: int) -> float:
        v = int(value64) & 0xFFFFFFFFFFFFFFFF
        t = int(target64) & 0xFFFFFFFFFFFFFFFF
        if v <= 0:
            return float("inf")
        if t <= 0:
            return 0.0
        return float(t / v)

    @staticmethod
    def _share_difficulty_from_value(value64: int) -> float:
        v = int(value64) & 0xFFFFFFFFFFFFFFFF
        if v <= 0:
            return float("inf")
        return float((1 << 64) / v)

    def _maybe_emit_hot_hash_transport(self, job: MoneroJob, value64: int) -> None:
        rc = self.remote_connection
        if rc is None:
            return
        try:
            snap = rc.snapshot()
            peers = snap.get('peer_states') or {}
            peer_key = None
            for k, st in peers.items():
                if st.get('connected'):
                    peer_key = k
                    break
            if not peer_key:
                return
            score = self._share_difficulty_from_value(value64) / max(1.0, float(job.target64 or 1))
            rc.send_hot_hash_loop_packet(b'', peer_key=peer_key, score=score, reason='hot_hash_loop_probe')
        except Exception:
            pass

    def _normalize_worker_idx(self, worker_idx: Optional[int]) -> Optional[int]:
        if worker_idx is None:
            return None
        try:
            wi = int(worker_idx)
        except Exception:
            return None
        if 0 <= wi < self.threads:
            return wi
        return None

    def _worker_tag(self, worker_idx: Optional[int]) -> str:
        wi = self._normalize_worker_idx(worker_idx)
        return "[P2PoolHunter]" if wi is None else f"[P2PoolHunter/W{wi}]"

    def _build_default_python_usage_controller(self) -> Optional[PythonUsageController]:
        try:
            existing = getattr(self.randomx, "python_usage_controller", None)
            if isinstance(existing, PythonUsageController):
                return existing
        except Exception:
            pass

        try:
            python_usage = getattr(self.randomx, "python_usage", None)
        except Exception:
            python_usage = None

        if python_usage is None:
            return None

        try:
            return PythonUsageController(
                threads=self.threads,
                logger=self.logger,
                python_usage=python_usage,
            )
        except Exception as e:
            self.logger(f"[P2PoolHunter][PythonUsage] init warning: {e}")
            return None

    def set_python_usage_controller(self, controller: Optional[PythonUsageController]) -> None:
        self.python_usage_controller = controller

    def install_python_usage_controller(self, python_usage: Optional[Any], **kwargs: Any) -> Optional[PythonUsageController]:
        if python_usage is None:
            self.python_usage_controller = None
            return None
        controller = PythonUsageController(
            threads=self.threads,
            logger=self.logger,
            python_usage=python_usage,
            **kwargs,
        )
        self.python_usage_controller = controller
        return controller


    def _stopped_hash_result(self, worker_idx: Optional[int], *, errors: Optional[List[str]] = None) -> Dict[str, Any]:
        return {
            "hashes_done": 0,
            "found": [],
            "best": [],
            "stale_aborts": 0,
            "chain_hits": 0,
            "submitted_hits": 0,
            "streak_groups": 0,
            "max_streak_len": 0,
            "worker_idx": self._normalize_worker_idx(worker_idx),
            "remote_hint": None,
            "job_timing": None,
            "rx_pps": None,
            "socket_rx_pps": None,
            "router_rx_pps": None,
            "raw_packet_rx_pps": None,
            "dll_rx_fps": None,
            "elapsed_sec": 0.0,
            "errors": list(errors or []),
        }

    def _live_lane_count(self) -> int:
        with self._states_mu:
            return min(self.threads, len(self._states), len(self._lane_call_locks))

    def _safe_lane_state(self, idx: int) -> Optional[_WorkerLane]:
        if idx < 0:
            return None
        with self._states_mu:
            if idx >= len(self._states):
                return None
            return self._states[idx]

    def _note_job_dispatch(self, job: MoneroJob, generation: int) -> Dict[str, Any]:
        now = time.time()
        sig = (str(getattr(job, "job_id", "") or ""), int(generation))
        with self._job_timing_mu:
            if sig != self._last_job_signature:
                if self._job_history:
                    prev_ts = float(self._job_history[-1][0])
                    gap = max(0.0, now - prev_ts)
                    self._job_change_times.append(gap)
                self._job_history.append((now, sig[0], sig[1]))
                self._last_job_signature = sig
                self._last_job_change_ts = now
            current_age_sec = max(0.0, now - float(self._last_job_change_ts or now))
            intervals = list(self._job_change_times)

        avg_interval_sec = (sum(intervals) / len(intervals)) if intervals else None
        min_interval_sec = min(intervals) if intervals else None

        urgency = 0.0
        if avg_interval_sec is not None:
            if avg_interval_sec <= 0.50:
                urgency = max(urgency, 1.0)
            elif avg_interval_sec <= 1.00:
                urgency = max(urgency, 0.90)
            elif avg_interval_sec <= 1.50:
                urgency = max(urgency, 0.78)
            elif avg_interval_sec <= 2.50:
                urgency = max(urgency, 0.55)
            elif avg_interval_sec <= 4.00:
                urgency = max(urgency, 0.30)

        if current_age_sec <= 0.20:
            urgency = max(urgency, 1.0)
        elif current_age_sec <= 0.50:
            urgency = max(urgency, 0.85)
        elif current_age_sec <= 1.00:
            urgency = max(urgency, 0.65)
        elif current_age_sec <= 2.00:
            urgency = max(urgency, 0.40)

        return {
            "job_id": sig[0],
            "generation": sig[1],
            "avg_interval_sec": avg_interval_sec,
            "min_interval_sec": min_interval_sec,
            "current_age_sec": current_age_sec,
            "urgency": float(max(0.0, min(1.0, urgency))),
        }

    def _apply_job_urgency(
        self,
        *,
        batch_n: int,
        live_poll: int,
        stale_poll: int,
        urgency: float,
        lane_count: int,
    ) -> Dict[str, Any]:
        lane_count = max(1, int(lane_count))
        batch_n = max(1, int(batch_n))
        live_poll = max(1, int(live_poll))
        stale_poll = max(1, int(stale_poll))
        urgency = max(0.0, min(1.0, float(urgency)))

        if urgency >= 0.90:
            batch_cap = max(lane_count * 8, 64)
            hash_chunk_cap = 4
            submit_immediately = True
            live_cap = 1
            stale_cap = 1
        elif urgency >= 0.75:
            batch_cap = max(lane_count * 12, 96)
            hash_chunk_cap = 6
            submit_immediately = True
            live_cap = 1
            stale_cap = 1
        elif urgency >= 0.55:
            batch_cap = max(lane_count * 16, 128)
            hash_chunk_cap = 8
            submit_immediately = False
            live_cap = 2
            stale_cap = 1
        elif urgency >= 0.35:
            batch_cap = max(lane_count * 24, 192)
            hash_chunk_cap = 12
            submit_immediately = False
            live_cap = 4
            stale_cap = 2
        else:
            batch_cap = batch_n
            hash_chunk_cap = 24
            submit_immediately = False
            live_cap = live_poll
            stale_cap = stale_poll

        return {
            "batch_n": max(1, min(batch_n, int(batch_cap))),
            "live_poll": max(1, min(live_poll, int(live_cap))),
            "stale_poll": max(1, min(stale_poll, int(stale_cap))),
            "hash_chunk_cap": max(1, int(hash_chunk_cap)),
            "submit_immediately": bool(submit_immediately),
            "urgency": urgency,
        }

    def _wait_lane_done(self, st: _WorkerLane, *, timeout_sec: float = 0.05) -> bool:
        timeout_sec = max(0.01, float(timeout_sec))
        while True:
            if st.done_event.wait(timeout=timeout_sec):
                return True
            if not st.busy:
                return bool(st.done_event.wait(timeout=0.01))
            if self._stop.is_set() or self._closed.is_set():
                return False

    def _bootstrap_workers(self) -> None:
        with self._states_mu:
            if self._states:
                return

            for i in range(self.threads):
                st = _WorkerLane(
                    worker_index=i,
                    out_buf=(c_ubyte * 32)(),
                    start_event=threading.Event(),
                    done_event=threading.Event(),
                    stop_event=self._stop,
                    probe=_FastTail64Probe(),
                )
                st.value64_view = c_uint64.from_buffer(st.out_buf, 24)
                st.found = []
                st.best = []

                t = threading.Thread(
                    target=self._thread_main,
                    args=(st,),
                    name=f"P2PoolHunter-{i}",
                    daemon=True,
                )
                self._states.append(st)
                self._threads_runtime.append(t)
                t.start()

        self.logger(
            f"[P2PoolHunter] initialized threads={self.threads} batch_size={self.batch_size} keep_best={self.keep_best}"
        )

    def stop(self) -> None:
        self._stop.set()

        if self.python_usage_controller is not None:
            try:
                self.python_usage_controller.request_stop()
            except Exception:
                pass

        if self.remote_connection is not None:
            try:
                self.remote_connection.stop()
            except Exception:
                pass

        for st in self._states:
            try:
                st.assigned_stop_flag = self._stop
            except Exception:
                pass
            try:
                st.start_event.set()
            except Exception:
                pass

    def close(self) -> None:
        if self._closed.is_set():
            return

        self._closed.set()
        self.stop()

        for t in self._threads_runtime:
            try:
                t.join(timeout=1.0)
            except Exception:
                pass

        with self._states_mu:
            states = list(self._states)
            self._states.clear()

        for st in states:
            try:
                if st.vm is not None:
                    self.randomx.destroy_vm(st.vm)
            except Exception:
                pass

        if self.python_usage_controller is not None:
            try:
                self.python_usage_controller.close()
            except Exception:
                pass

        if self.remote_connection is not None:
            try:
                self.remote_connection.close()
            except Exception:
                pass

    def pop_worker_hash_windows(self) -> List[int]:
        with self._perf_mu:
            out = list(self._worker_hashes_window)
            for i in range(len(self._worker_hashes_window)):
                self._worker_hashes_window[i] = 0
            return out

    def snapshot_worker_perf(self) -> List[Dict[str, Any]]:
        with self._perf_mu:
            return [
                {
                    "worker_idx": i,
                    "hashes_total": int(self._worker_hashes_total[i]),
                    "hits_total": int(self._worker_hits_total[i]),
                    "stale_aborts_total": int(self._worker_stale_total[i]),
                    "streak_groups_total": int(self._worker_streak_total[i]),
                }
                for i in range(self.threads)
            ]

    def _note_worker_perf(
        self,
        *,
        worker_idx: Optional[int],
        hashes_done: int,
        hits_found: int,
        stale_aborts: int,
        streak_groups: int,
    ) -> None:
        wi = self._normalize_worker_idx(worker_idx)
        if wi is None:
            return

        with self._perf_mu:
            if wi >= len(self._worker_hashes_total):
                return
            self._worker_hashes_total[wi] += int(hashes_done)
            self._worker_hashes_window[wi] += int(hashes_done)
            self._worker_hits_total[wi] += int(hits_found)
            self._worker_stale_total[wi] += int(stale_aborts)
            self._worker_streak_total[wi] += int(streak_groups)

    def _ensure_lane_vm(self, st: _WorkerLane, job: MoneroJob) -> None:
        seed_changed = (st.last_seed != bytes(job.seed_hash))
        blob_changed = (st.last_blob != bytes(job.blob))

        if seed_changed:
            self.randomx.ensure_seed(job.seed_hash)
            if st.vm is not None:
                try:
                    self.randomx.destroy_vm(st.vm)
                except Exception:
                    pass
                st.vm = None
            st.vm = self.randomx.create_vm()
            st.last_seed = bytes(job.seed_hash)
            st.last_blob = b""

        if st.blob_buf is None or len(st.blob_buf) != len(job.blob):
            st.blob_buf = (c_ubyte * len(job.blob))()
            blob_changed = True

        if blob_changed:
            memmove(st.blob_buf, job.blob, len(job.blob))
            st.last_blob = bytes(job.blob)

        st.nonce_ptr = cast(byref(st.blob_buf, int(job.nonce_offset)), POINTER(c_uint32))

    def _thread_main(self, st: _WorkerLane) -> None:
        while not self._stop.is_set():
            st.start_event.wait(0.1)
            if self._stop.is_set():
                break
            if not st.start_event.is_set():
                continue

            st.start_event.clear()
            st.done_event.clear()
            st.busy = True

            try:
                self._run_lane(st)
            except Exception as e:
                st.error = f"{type(e).__name__}: {e}"
            finally:
                st.busy = False
                st.done_event.set()

    def _flush_candidates(
        self,
        *,
        job_key: str,
        rows: Iterable[Tuple[int, int, bytes]],
        submit_candidate: Callable[[int, int, bytes], None],
    ) -> int:
        submitted = 0
        seen_nonce: Set[int] = set()

        for nonce_u32, value64, result32 in sorted(rows, key=lambda x: (int(x[1]), int(x[0]))):
            nonce_key = int(nonce_u32) & 0xFFFFFFFF
            if nonce_key in seen_nonce:
                continue
            seen_nonce.add(nonce_key)

            if not self._template_submit_guard.claim(job_key, nonce_key):
                continue

            try:
                submit_candidate(int(nonce_u32), int(value64), bytes(result32))
                submitted += 1
            except Exception:
                self._template_submit_guard.forget(job_key, nonce_key)
                continue

        return submitted

    def _should_emit_status(
        self,
        *,
        worker_idx: Optional[int],
        job_id: str,
        hashes_done: int,
        chain_hits: int,
        stale_aborts: int,
        remote_snapshot: Optional[Dict[str, Any]],
        network_hint: Optional[Dict[str, Any]],
        force: bool = False,
    ) -> bool:
        key = (
            str(job_id),
            int(hashes_done) // self._shared_status.hash_bucket_size,
            int(chain_hits),
            int(stale_aborts),
            None if remote_snapshot is None else int(remote_snapshot.get("network_epoch", -1)),
            None if network_hint is None else int(float(network_hint.get("pressure", 0.0)) * 10.0),
            self._normalize_worker_idx(worker_idx),
        )
        return self._shared_status.gate.should_emit(
            key=key,
            min_interval_sec=self._shared_status.min_interval_sec,
            force=bool(force and chain_hits > 0),
        )

    def _emit_consolidated_status(
        self,
        *,
        worker_idx: Optional[int],
        job: MoneroJob,
        hashes_done: int,
        chain_hits: int,
        stale_aborts: int,
        submitted_hits: int,
        remote_snapshot: Optional[Dict[str, Any]],
        network_hint: Optional[Dict[str, Any]],
        force: bool = False,
    ) -> None:
        if not self._should_emit_status(
            worker_idx=worker_idx,
            job_id=str(job.job_id or "unknown"),
            hashes_done=hashes_done,
            chain_hits=chain_hits,
            stale_aborts=stale_aborts,
            remote_snapshot=remote_snapshot,
            network_hint=network_hint,
            force=force,
        ):
            return

        worker_tag = self._worker_tag(worker_idx)
        if remote_snapshot is None:
            self.logger(
                f"{worker_tag} status job={job.job_id} hashes_done={hashes_done} hits={chain_hits} "
                f"submitted={submitted_hits} stale_aborts={stale_aborts} remote=none"
            )
            return

        pressure = None if network_hint is None else float(network_hint.get("pressure", 0.0))
        self.logger(
            f"{worker_tag} status job={job.job_id} hashes_done={hashes_done} hits={chain_hits} "
            f"submitted={submitted_hits} stale_aborts={stale_aborts} "
            f"conn={int(remote_snapshot.get('connected_peers', 0))}/{int(remote_snapshot.get('peer_count', 0))} "
            f"hot={int(remote_snapshot.get('hot_peers', 0))} "
            f"router_packets={int(remote_snapshot.get('router_packets_total', 0))} "
            f"router_raw={int(remote_snapshot.get('router_raw_packets_total', 0))} "
            f"rx_pps={float(remote_snapshot.get('rx_pps', 0.0)):.2f} "
            f"socket_rx_pps={float(remote_snapshot.get('socket_rx_pps', 0.0)):.2f} "
            f"router_rx_pps={float(remote_snapshot.get('router_rx_pps', 0.0)):.2f} "
            f"raw_packet_rx_pps={float(remote_snapshot.get('raw_packet_rx_pps', 0.0)):.2f} "
            f"dll_rx_fps={float(remote_snapshot.get('dll_rx_fps', 0.0)):.2f} "
            f"tx_pps={float(remote_snapshot.get('tx_pps', 0.0)):.2f} "
            f"sc={remote_snapshot.get('sidechain_height')} "
            f"mc={remote_snapshot.get('mainchain_height')} "
            f"diff={remote_snapshot.get('difficulty')} "
            f"topic={remote_snapshot.get('packet_topic')} "
            f"proto={remote_snapshot.get('best_protocol_guess')} "
            f"dll_ready={bool(remote_snapshot.get('dll_ready'))} "
            f"cmd={remote_snapshot.get('last_command_name') or remote_snapshot.get('last_command')} "
            f"top={str(remote_snapshot.get('last_top_id_hex') or '')[:16] or None} "
            f"tv={remote_snapshot.get('last_top_version')} "
            f"rpcp={remote_snapshot.get('last_rpc_port_hint')} "
            f"pc={remote_snapshot.get('peer_count_hint') or remote_snapshot.get('last_local_peerlist_count')} "
            f"conf={float(remote_snapshot.get('decode_confidence', 0.0)):.2f} "
            f"pressure={pressure}"
        )

    def _distribute_count(self, count: int) -> List[int]:
        threads = min(self.threads, max(1, int(count)))
        per_thread = int(count) // threads
        remainder = int(count) % threads
        out: List[int] = []
        for i in range(threads):
            out.append(per_thread + (1 if i < remainder else 0))
        return out

    def _run_lane(self, st: _WorkerLane) -> None:
        st.error = None
        st.hashes_done = 0
        st.stale_aborts = 0
        st.chain_hits = 0
        st.submitted_hits = 0
        st.streak_groups = 0
        st.max_streak_len = 0
        st.found = []
        st.best = []

        job = st.assigned_job
        if job is None or st.assigned_count <= 0:
            return

        self._ensure_lane_vm(st, job)
        if st.vm is None or st.blob_buf is None or st.nonce_ptr is None:
            raise RuntimeError("lane state is not initialized")

        hash_into = self.randomx.hash_into
        nonce_ptr = st.nonce_ptr
        out_buf = st.out_buf
        value64_view = st.value64_view
        read_tail64 = st.probe.read_tail64
        use_view = sys.byteorder == "little"

        target64 = int(job.target64) & 0xFFFFFFFFFFFFFFFF
        near_cutoff = int(st.assigned_near_cutoff) & 0xFFFFFFFFFFFFFFFF
        result_cap = max(1, int(st.assigned_result_cap))
        best_cap = max(1, int(st.assigned_best_cap))
        nonce_u32 = int(st.assigned_start_nonce) & 0xFFFFFFFF
        remaining = int(st.assigned_count)
        stride = max(1, int(st.assigned_stride))
        poll_interval = max(1, int(st.assigned_poll_interval))
        stale_poll_interval = max(1, int(st.assigned_stale_poll_interval))
        external_stop_is_set = getattr(st.assigned_stop_flag, "is_set", None)
        is_current = st.assigned_is_current
        submit_candidate = st.assigned_submit_candidate
        job_key = str(st.assigned_job_key or "")
        submit_immediately = bool(st.assigned_submit_immediately)
        hash_chunk_cap = max(1, int(st.assigned_hash_chunk_cap or 24))

        found_pool = _UniqueNonceCandidatePool(limit=max(64, result_cap * 16))
        best_pool = _UniqueNonceCandidatePool(limit=max(64, best_cap * 16))
        pending_submit_pool = _UniqueNonceCandidatePool(limit=max(self._pending_submit_limit, result_cap * 16))

        burst_pool = _UniqueNonceCandidatePool(limit=max(32, result_cap * 8))
        last_burst_nonce: Optional[int] = None
        local_step_counter = 0
        streak_len = 0
        harvest_budget_left = 0
        stale_triggered = False
        batch_submit_target = max(self._min_unique_flush, min(self._max_unique_flush, max(2, result_cap * 2)))
        if submit_immediately:
            batch_submit_target = 1

        def _reset_burst() -> None:
            nonlocal burst_pool, last_burst_nonce, streak_len
            burst_pool = _UniqueNonceCandidatePool(limit=max(32, result_cap * 8))
            last_burst_nonce = None
            streak_len = 0

        def _arm_harvest_budget() -> None:
            nonlocal harvest_budget_left
            if submit_immediately:
                harvest_budget_left = 0
                return
            harvest_budget_left = max(
                self._post_hit_harvest_floor,
                min(16384, int(max(1, remaining) * self._post_hit_harvest_multiplier)),
            )

        def _commit_burst() -> int:
            committed = 0
            if len(burst_pool) <= 0:
                return 0

            for row in burst_pool.rows_sorted():
                if found_pool.add(row):
                    pending_submit_pool.add(row)
                    committed += 1
            return committed

        def _flush_pending(force: bool = False) -> int:
            nonlocal harvest_budget_left
            if submit_candidate is None or len(pending_submit_pool) <= 0:
                return 0

            pending_n = len(pending_submit_pool)
            should_flush = False

            if force:
                should_flush = True
            elif pending_n >= batch_submit_target:
                should_flush = True
            elif pending_n >= self._min_unique_flush and harvest_budget_left <= 0:
                should_flush = True
            elif pending_n >= (pending_submit_pool.limit - 1):
                should_flush = True

            if not should_flush:
                return 0

            rows = pending_submit_pool.rows_sorted()
            pending_submit_pool.clear()
            harvest_budget_left = 0
            return int(self._flush_candidates(job_key=job_key, rows=rows, submit_candidate=submit_candidate))

        def _consume_hash_result(row_nonce_u32: int, row_value64: int, row_result32: bytes) -> None:
            nonlocal last_burst_nonce, streak_len
            row = (int(row_nonce_u32), int(row_value64), bytes(row_result32))

            if row_value64 < target64:
                st.chain_hits += 1
                nonce_key = int(row_nonce_u32) & 0xFFFFFFFF

                if last_burst_nonce is None:
                    st.streak_groups += 1
                    streak_len = 1
                else:
                    gap = ((nonce_key - last_burst_nonce) & 0xFFFFFFFF)
                    if gap <= self._chain_gap_limit:
                        streak_len += 1
                    else:
                        if len(burst_pool) > 0:
                            committed_now = _commit_burst()
                            if committed_now > 0:
                                _arm_harvest_budget()
                            _reset_burst()
                        st.streak_groups += 1
                        streak_len = 1

                st.max_streak_len = max(st.max_streak_len, streak_len)

                if self._template_nonce_guard.claim(job_key, nonce_key):
                    burst_pool.add(row)
                    last_burst_nonce = nonce_key
                    if len(burst_pool) == 1:
                        _arm_harvest_budget()
                    if submit_immediately and len(burst_pool) > 0:
                        committed_now = _commit_burst()
                        if committed_now > 0:
                            st.submitted_hits += _flush_pending(force=True)
                        _reset_burst()

            elif row_value64 < near_cutoff:
                best_pool.add(row)

            if len(burst_pool) > 0 and harvest_budget_left <= 0:
                committed_now = _commit_burst()
                if committed_now > 0:
                    st.submitted_hits += _flush_pending(force=False)
                _reset_burst()

            if len(pending_submit_pool) > 0:
                st.submitted_hits += _flush_pending(force=False)

        def _run_usage_hash_chunk(chunk_n: int) -> Dict[str, Any]:
            local_rows: List[Tuple[int, int, bytes]] = []
            local_nonce = int(nonce_u32) & 0xFFFFFFFF
            local_remaining = int(remaining)
            local_steps = int(local_step_counter)
            local_stale_abort = False

            for _ in range(max(1, int(chunk_n))):
                if local_remaining <= 0:
                    break
                if self._stop.is_set() or (external_stop_is_set is not None and external_stop_is_set()):
                    break

                if is_current is not None and (local_steps % stale_poll_interval == 0):
                    try:
                        if not bool(is_current()):
                            local_stale_abort = True
                            break
                    except Exception:
                        pass

                if is_current is not None and (local_steps % poll_interval == 0):
                    try:
                        if not bool(is_current()):
                            local_stale_abort = True
                            break
                    except Exception:
                        pass

                nonce_ptr[0] = local_nonce
                hash_into(st.vm, st.blob_buf, out_buf)
                value64 = int(value64_view.value) if use_view else int(read_tail64(out_buf))
                local_rows.append((int(local_nonce), int(value64), bytes(out_buf)))

                local_steps += 1
                local_nonce = (local_nonce + stride) & 0xFFFFFFFF
                local_remaining -= 1

            return {
                "rows": local_rows,
                "nonce_after": int(local_nonce) & 0xFFFFFFFF,
                "remaining_after": int(local_remaining),
                "steps_after": int(local_steps),
                "stale_abort": bool(local_stale_abort),
            }

        while remaining > 0:
            if self._stop.is_set() or (external_stop_is_set is not None and external_stop_is_set()):
                break

            used_usage = False
            usage_controller = self.python_usage_controller
            if usage_controller is not None and usage_controller.should_run(st.worker_index):
                chunk_n = min(max(1, int(hash_chunk_cap)), max(1, int(usage_controller.suggested_chunk_hashes(remaining))))
                used_usage, usage_result = usage_controller.invoke_chunk(
                    st.worker_index,
                    _run_usage_hash_chunk,
                    chunk_n,
                )
                if used_usage and isinstance(usage_result, dict):
                    rows = list(usage_result.get("rows") or [])
                    for row_nonce_u32, row_value64, row_result32 in rows:
                        st.hashes_done += 1
                        if harvest_budget_left > 0:
                            harvest_budget_left -= 1
                        _consume_hash_result(int(row_nonce_u32), int(row_value64), bytes(row_result32))

                    nonce_u32 = int(usage_result.get("nonce_after", nonce_u32)) & 0xFFFFFFFF
                    remaining = max(0, int(usage_result.get("remaining_after", remaining)))
                    local_step_counter = max(local_step_counter, int(usage_result.get("steps_after", local_step_counter)))

                    if rows:
                        try:
                            usage_controller.note_direct_hashes(st.worker_index, 0)
                        except Exception:
                            pass

                    if bool(usage_result.get("stale_abort", False)):
                        st.stale_aborts += 1
                        stale_triggered = True
                        break

                    continue

            if is_current is not None and (local_step_counter % stale_poll_interval == 0):
                try:
                    if not bool(is_current()):
                        st.stale_aborts += 1
                        stale_triggered = True
                        break
                except Exception:
                    pass

            if is_current is not None and (local_step_counter % poll_interval == 0):
                try:
                    if not bool(is_current()):
                        st.stale_aborts += 1
                        stale_triggered = True
                        break
                except Exception:
                    pass

            nonce_ptr[0] = nonce_u32
            hash_into(st.vm, st.blob_buf, out_buf)

            st.hashes_done += 1
            local_step_counter += 1

            if self.python_usage_controller is not None:
                try:
                    self.python_usage_controller.note_direct_hashes(st.worker_index, 1)
                except Exception:
                    pass

            if harvest_budget_left > 0:
                harvest_budget_left -= 1

            value64 = int(value64_view.value) if use_view else int(read_tail64(out_buf))
            result32 = bytes(out_buf)
            _consume_hash_result(int(nonce_u32), int(value64), result32)

            nonce_u32 = (nonce_u32 + stride) & 0xFFFFFFFF
            remaining -= 1

        if len(burst_pool) > 0:
            _commit_burst()
            _reset_burst()

        if len(pending_submit_pool) > 0:
            st.submitted_hits += _flush_pending(force=True)

        st.found = found_pool.rows_sorted(result_cap)
        st.best = best_pool.rows_sorted(best_cap)

        if stale_triggered and submit_candidate is not None and st.submitted_hits > 0:
            pass

    def hash_job(
        self,
        *,
        job: MoneroJob,
        generation: int,
        start_nonce: int,
        count: Optional[int] = None,
        max_results: Optional[int] = None,
        stop_flag: Any = None,
        poll_interval: Optional[int] = None,
        stale_poll_interval: Optional[int] = None,
        is_current: Optional[Callable[[], bool]] = None,
        submit_candidate: Optional[Callable[[int, int, bytes], None]] = None,
        worker_idx: Optional[int] = None,
    ) -> Dict[str, Any]:
        if self._stop.is_set() or self._closed.is_set():
            return self._stopped_hash_result(worker_idx, errors=["stopped"])

        t0 = time.perf_counter()
        batch_n = max(1, int(count if count is not None else self.batch_size))
        result_cap = max(1, int(max_results if max_results is not None else self.keep_best))
        best_cap = max(1, int(self.keep_best))
        live_poll = max(1, int(self.poll_interval if poll_interval is None else poll_interval))
        stale_poll = max(1, int(self.stale_poll_interval if stale_poll_interval is None else stale_poll_interval))

        network_hint: Optional[Dict[str, Any]] = None
        remote_snapshot: Optional[Dict[str, Any]] = None
        if self.remote_connection is not None:
            try:
                network_hint = self.remote_connection.get_hint()
                remote_snapshot = self.remote_connection.snapshot()
                live_poll = min(live_poll, max(1, int(network_hint.get("suggested_live_poll", live_poll))))
                stale_poll = min(stale_poll, max(1, int(network_hint.get("suggested_stale_poll", stale_poll))))
                chunk_scale = float(network_hint.get("suggested_chunk_scale", 1.0))
                chunk_scale = max(0.25, min(2.00, chunk_scale))
                batch_n = max(1, int(round(float(batch_n) * chunk_scale)))
            except Exception as e:
                self.logger(f"[P2PoolHunter] remote hint warning: {e}")

        lane_count = max(1, self._live_lane_count())
        job_timing = self._note_job_dispatch(job, generation)
        job_adjust = self._apply_job_urgency(
            batch_n=batch_n,
            live_poll=live_poll,
            stale_poll=stale_poll,
            urgency=float(job_timing.get("urgency", 0.0) or 0.0),
            lane_count=lane_count,
        )
        batch_n = int(job_adjust["batch_n"])
        live_poll = int(job_adjust["live_poll"])
        stale_poll = int(job_adjust["stale_poll"])
        hash_chunk_cap = int(job_adjust["hash_chunk_cap"])
        submit_immediately = bool(job_adjust["submit_immediately"])
        job_urgency = float(job_adjust["urgency"])

        target64 = int(job.target64) & 0xFFFFFFFFFFFFFFFF
        if target64 <= 0:
            raise RuntimeError("job target is empty or invalid")

        near_cutoff = min(
            0xFFFFFFFFFFFFFFFF,
            max(target64 + 1, int(float(target64) * float(self.near_miss_ratio))),
        )

        job_key = self._stable_job_template_key(job)
        session = self._job_sessions.get_or_create(job_key=job_key, start_nonce=int(start_nonce))
        lease_start = session.lease(batch_n)

        active: List[_WorkerLane] = []
        normalized_worker_idx = self._normalize_worker_idx(worker_idx)

        if normalized_worker_idx is not None:
            if normalized_worker_idx >= len(self._lane_call_locks):
                return self._stopped_hash_result(worker_idx, errors=["worker lanes unavailable"])
            lane_lock = self._lane_call_locks[normalized_worker_idx]
            lane_lock.acquire()
            try:
                st = self._safe_lane_state(normalized_worker_idx)
                if st is None:
                    return self._stopped_hash_result(worker_idx, errors=["worker lane missing"])
                st.assigned_job = job
                st.assigned_job_key = job_key
                st.assigned_generation = int(generation)
                st.assigned_start_nonce = int(lease_start) & 0xFFFFFFFF
                st.assigned_count = int(batch_n)
                st.assigned_stride = 1
                st.assigned_result_cap = max(result_cap, 16)
                st.assigned_best_cap = max(best_cap, 16)
                st.assigned_near_cutoff = near_cutoff
                st.assigned_poll_interval = live_poll
                st.assigned_stale_poll_interval = stale_poll
                st.assigned_is_current = is_current
                st.assigned_stop_flag = stop_flag
                st.assigned_submit_candidate = submit_candidate
                st.assigned_job_urgency = job_urgency
                st.assigned_submit_immediately = submit_immediately
                st.assigned_hash_chunk_cap = hash_chunk_cap
                st.hashes_done = 0
                st.stale_aborts = 0
                st.chain_hits = 0
                st.submitted_hits = 0
                st.streak_groups = 0
                st.max_streak_len = 0
                st.found = []
                st.best = []
                st.error = None
                st.done_event.clear()

                st.start_event.set()
                self._wait_lane_done(st)

                if self._stop.is_set() and not st.done_event.is_set():
                    errors = [f"worker[{st.worker_index}] stopped"]
                    found_items = []
                    best_items = []
                    hashes_done = int(st.hashes_done)
                    stale_aborts = int(st.stale_aborts)
                    chain_hits = int(st.chain_hits)
                    submitted_hits = int(st.submitted_hits)
                    streak_groups = int(st.streak_groups)
                    max_streak_len = int(st.max_streak_len)
                else:
                    hashes_done = int(st.hashes_done)
                    stale_aborts = int(st.stale_aborts)
                    chain_hits = int(st.chain_hits)
                    submitted_hits = int(st.submitted_hits)
                    streak_groups = int(st.streak_groups)
                    max_streak_len = int(st.max_streak_len)
                    errors = [f"worker[{st.worker_index}] {st.error}"] if st.error else []
                    found_items = list(st.found or [])
                    best_items = list(st.best or [])
            finally:
                lane_lock.release()

        else:
            with self._dispatch_lock:
                available_lanes = self._live_lane_count()
                if available_lanes <= 0:
                    return self._stopped_hash_result(worker_idx, errors=["no live worker lanes"])
                splits = self._distribute_count(batch_n)[:available_lanes]
                active_threads = len(splits)
                used_lane_indices = [i for i, take in enumerate(splits) if take > 0 and i < available_lanes]

                for idx in used_lane_indices:
                    self._lane_call_locks[idx].acquire()

                try:
                    for i, take in enumerate(splits):
                        if take <= 0:
                            continue

                        st = self._states[i]
                        st.assigned_job = job
                        st.assigned_job_key = job_key
                        st.assigned_generation = int(generation)
                        st.assigned_start_nonce = (int(lease_start) + i) & 0xFFFFFFFF
                        st.assigned_count = int(take)
                        st.assigned_stride = max(1, active_threads)
                        st.assigned_result_cap = max(result_cap, 16)
                        st.assigned_best_cap = max(best_cap, 16)
                        st.assigned_near_cutoff = near_cutoff
                        st.assigned_poll_interval = live_poll
                        st.assigned_stale_poll_interval = stale_poll
                        st.assigned_is_current = is_current
                        st.assigned_stop_flag = stop_flag
                        st.assigned_submit_candidate = submit_candidate
                        st.assigned_job_urgency = job_urgency
                        st.assigned_submit_immediately = submit_immediately
                        st.assigned_hash_chunk_cap = hash_chunk_cap
                        st.hashes_done = 0
                        st.stale_aborts = 0
                        st.chain_hits = 0
                        st.submitted_hits = 0
                        st.streak_groups = 0
                        st.max_streak_len = 0
                        st.found = []
                        st.best = []
                        st.error = None
                        st.done_event.clear()
                        active.append(st)

                    for st in active:
                        st.start_event.set()
                    for st in active:
                        self._wait_lane_done(st)

                    hashes_done = 0
                    stale_aborts = 0
                    chain_hits = 0
                    submitted_hits = 0
                    streak_groups = 0
                    max_streak_len = 0
                    errors: List[str] = []
                    found_items: List[Tuple[int, int, bytes]] = []
                    best_items: List[Tuple[int, int, bytes]] = []

                    if self._stop.is_set():
                        errors.append("stopped")

                    for st in active:
                        hashes_done += int(st.hashes_done)
                        stale_aborts += int(st.stale_aborts)
                        chain_hits += int(st.chain_hits)
                        submitted_hits += int(st.submitted_hits)
                        streak_groups += int(st.streak_groups)
                        max_streak_len = max(max_streak_len, int(st.max_streak_len))
                        if st.found:
                            found_items.extend(st.found)
                        if st.best:
                            best_items.extend(st.best)
                        if st.error:
                            errors.append(f"worker[{st.worker_index}] {st.error}")
                finally:
                    for idx in reversed(used_lane_indices):
                        self._lane_call_locks[idx].release()

        found_pool = _UniqueNonceCandidatePool(limit=max(64, result_cap * 16))
        best_pool = _UniqueNonceCandidatePool(limit=max(64, best_cap * 16))
        found_pool.extend(found_items)
        best_pool.extend(best_items)

        dedup_found = found_pool.rows_sorted(result_cap)
        dedup_best = best_pool.rows_sorted(best_cap)

        submitted_found = [
            row for row in dedup_found
            if self._template_submit_guard.contains(job_key, int(row[0]) & 0xFFFFFFFF)
        ]
        if submit_candidate is not None:
            dedup_found = [
                row for row in dedup_found
                if not self._template_submit_guard.contains(job_key, int(row[0]) & 0xFFFFFFFF)
            ]

        self._note_worker_perf(
            worker_idx=worker_idx,
            hashes_done=hashes_done,
            hits_found=chain_hits,
            stale_aborts=stale_aborts,
            streak_groups=streak_groups,
        )

        if self.remote_connection is not None:
            try:
                network_hint = self.remote_connection.get_hint()
                remote_snapshot = self.remote_connection.snapshot()
            except Exception as e:
                self.logger(f"[P2PoolHunter] remote snapshot refresh warning: {e}")

        self._emit_consolidated_status(
            worker_idx=worker_idx,
            job=job,
            hashes_done=hashes_done,
            chain_hits=chain_hits,
            stale_aborts=stale_aborts,
            submitted_hits=submitted_hits,
            remote_snapshot=remote_snapshot,
            network_hint=network_hint,
            force=bool(chain_hits > 0),
        )

        found_rows = [
            {
                "nonce_u32": int(nonce_u32),
                "value64": int(value64),
                "quality_ratio": self._quality_ratio(value64, target64),
                "share_difficulty": self._share_difficulty_from_value(value64),
                "hash_hex": bytes(result32).hex(),
            }
            for nonce_u32, value64, result32 in dedup_found
        ]
        best_rows = [
            {
                "nonce_u32": int(nonce_u32),
                "value64": int(value64),
                "quality_ratio": self._quality_ratio(value64, target64),
                "share_difficulty": self._share_difficulty_from_value(value64),
                "hash_hex": bytes(result32).hex(),
            }
            for nonce_u32, value64, result32 in dedup_best
        ]

        return {
            "job_id": job.job_id,
            "generation": int(generation),
            "hashes_done": int(hashes_done),
            "found": found_rows,
            "best": best_rows,
            "stale_aborts": int(stale_aborts),
            "chain_hits": int(chain_hits),
            "submitted_hits": int(submitted_hits),
            "streak_groups": int(streak_groups),
            "max_streak_len": int(max_streak_len),
            "worker_idx": normalized_worker_idx,
            "remote_hint": network_hint,
            "job_timing": job_timing,
            "rx_pps": None if remote_snapshot is None else float(remote_snapshot.get("rx_pps", 0.0) or 0.0),
            "socket_rx_pps": None if remote_snapshot is None else float(remote_snapshot.get("socket_rx_pps", 0.0) or 0.0),
            "router_rx_pps": None if remote_snapshot is None else float(remote_snapshot.get("router_rx_pps", 0.0) or 0.0),
            "raw_packet_rx_pps": None if remote_snapshot is None else float(remote_snapshot.get("raw_packet_rx_pps", 0.0) or 0.0),
            "dll_rx_fps": None if remote_snapshot is None else float(remote_snapshot.get("dll_rx_fps", 0.0) or 0.0),
            "dll_ready": None if remote_snapshot is None else bool(remote_snapshot.get("dll_ready")),
            "sidechain_height": None if remote_snapshot is None else remote_snapshot.get("sidechain_height"),
            "mainchain_height": None if remote_snapshot is None else remote_snapshot.get("mainchain_height"),
            "difficulty": None if remote_snapshot is None else remote_snapshot.get("difficulty"),
            "last_top_id_hex": None if remote_snapshot is None else remote_snapshot.get("last_top_id_hex"),
            "last_top_version": None if remote_snapshot is None else remote_snapshot.get("last_top_version"),
            "last_rpc_port_hint": None if remote_snapshot is None else remote_snapshot.get("last_rpc_port_hint"),
            "peer_count_hint": None if remote_snapshot is None else remote_snapshot.get("peer_count_hint"),
            "elapsed_sec": max(0.0, time.perf_counter() - t0),
            "errors": errors,
        }
