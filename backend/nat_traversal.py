"""
NAT Traversal — STUN Public Endpoint Discovery & UDP Hole Punching
====================================================================
Minimal RFC 5389 STUN Binding Request client + UDP hole-punching over a
single reusable local socket. The Relay Server is used only as an
out-of-band signaling channel to exchange each peer's STUN-discovered
public (ip, port) — it never sees the resulting P2P traffic, which flows
directly between peers once the NAT mapping is open on both sides.

This works for the common case (both peers behind independent, non-symmetric
NATs / typical home routers). It will NOT succeed against symmetric NATs on
both ends, or restrictive corporate firewalls — in that case callers should
keep falling back to the Relay Server, which they already do.
"""
import asyncio
import logging
import secrets
import socket
import struct
import time
from typing import Callable, Optional, Tuple

logger = logging.getLogger("NATTraversal")

STUN_SERVERS = [
    ("stun.l.google.com", 19302),
    ("stun1.l.google.com", 19302),
    ("stun.cloudflare.com", 3478),
]

_STUN_MAGIC_COOKIE = 0x2112A442
_BINDING_REQUEST = 0x0001
_BINDING_SUCCESS = 0x0101
_XOR_MAPPED_ADDRESS = 0x0020
_MAPPED_ADDRESS = 0x0001


# ─── RFC 5389 message (de)serialisation ───────────────────────────────────────
def _build_binding_request(txn_id: bytes) -> bytes:
    return struct.pack(">HHI12s", _BINDING_REQUEST, 0, _STUN_MAGIC_COOKIE, txn_id)


def _parse_binding_response(data: bytes, txn_id: bytes) -> Optional[Tuple[str, int]]:
    if len(data) < 20:
        return None
    msg_type, msg_len, cookie, resp_txn_id = struct.unpack(">HHI12s", data[:20])
    if msg_type != _BINDING_SUCCESS or resp_txn_id != txn_id:
        return None

    body = data[20:20 + msg_len]
    offset = 0
    while offset + 4 <= len(body):
        attr_type, attr_len = struct.unpack(">HH", body[offset:offset + 4])
        attr_val = body[offset + 4: offset + 4 + attr_len]

        if attr_type == _XOR_MAPPED_ADDRESS and len(attr_val) >= 8 and attr_val[1] == 0x01:
            xport = struct.unpack(">H", attr_val[2:4])[0] ^ (_STUN_MAGIC_COOKIE >> 16)
            cookie_bytes = _STUN_MAGIC_COOKIE.to_bytes(4, "big")
            xaddr_bytes = bytes(b ^ c for b, c in zip(attr_val[4:8], cookie_bytes))
            return ".".join(str(b) for b in xaddr_bytes), xport

        if attr_type == _MAPPED_ADDRESS and len(attr_val) >= 8 and attr_val[1] == 0x01:
            port = struct.unpack(">H", attr_val[2:4])[0]
            return ".".join(str(b) for b in attr_val[4:8]), port

        offset += 4 + attr_len + ((4 - attr_len % 4) % 4)  # attrs are 4-byte padded
    return None


# ─── Shared UDP endpoint: used for STUN, hole punching AND app traffic ────────
class P2PUDPProtocol(asyncio.DatagramProtocol):
    def __init__(self):
        self.transport: Optional[asyncio.DatagramTransport] = None
        self._stun_waiters: dict[bytes, "asyncio.Future"] = {}
        self.on_data: Optional[Callable[[bytes, Tuple[str, int]], None]] = None

    def connection_made(self, transport: asyncio.DatagramTransport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr: Tuple[str, int]):
        # STUN responses start with a binding-success message type; try to match
        # a pending transaction first, otherwise hand off to the app callback
        # (punch packets and real sealed packets both land here).
        if len(data) >= 20:
            txn_id = data[8:20]
            fut = self._stun_waiters.get(txn_id)
            if fut and not fut.done():
                parsed = _parse_binding_response(data, txn_id)
                if parsed:
                    fut.set_result(parsed)
                    return

        if self.on_data:
            try:
                self.on_data(data, addr)
            except Exception as e:
                logger.warning(f"[P2P] on_data handler raised: {e}")

    def error_received(self, exc):
        logger.warning(f"[P2P] UDP socket error: {exc}")


class P2PSocket:
    """
    One shared, long-lived UDP socket for the whole app: used to discover our
    own public endpoint via STUN, to punch holes to any number of contacts,
    and to send/receive actual message datagrams once a hole is open.
    """

    def __init__(self):
        self._transport: Optional[asyncio.DatagramTransport] = None
        self._protocol: Optional[P2PUDPProtocol] = None
        self.local_port: Optional[int] = None
        self.public_endpoint: Optional[Tuple[str, int]] = None

    async def start(self, local_port: int = 0):
        if self._transport:
            return
        loop = asyncio.get_event_loop()
        self._transport, self._protocol = await loop.create_datagram_endpoint(
            P2PUDPProtocol, local_addr=("0.0.0.0", local_port)
        )
        self.local_port = self._transport.get_extra_info("sockname")[1]
        logger.info(f"[P2P] UDP socket bound on local port {self.local_port}")

    def set_data_handler(self, callback: Callable[[bytes, Tuple[str, int]], None]):
        self._protocol.on_data = callback

    def send(self, ip: str, port: int, payload: bytes):
        if self._transport:
            self._transport.sendto(payload, (ip, port))

    async def discover_public_endpoint(self, timeout: float = 2.5) -> Optional[Tuple[str, int]]:
        """Sends a STUN Binding Request over OUR bound socket so the resulting
        NAT mapping can be reused for hole punching immediately afterwards."""
        loop = asyncio.get_event_loop()
        for stun_host, stun_port in STUN_SERVERS:
            txn_id = secrets.token_bytes(12)
            fut = loop.create_future()
            self._protocol._stun_waiters[txn_id] = fut
            try:
                addr_info = await loop.getaddrinfo(stun_host, stun_port, type=socket.SOCK_DGRAM)
                dest = addr_info[0][4]
                self._transport.sendto(_build_binding_request(txn_id), dest)
                result = await asyncio.wait_for(fut, timeout=timeout)
                self.public_endpoint = result
                logger.info(f"[STUN] Public endpoint: {result[0]}:{result[1]} (via {stun_host})")
                return result
            except Exception as e:
                logger.warning(f"[STUN] {stun_host} did not respond: {e}")
            finally:
                self._protocol._stun_waiters.pop(txn_id, None)

        logger.error("[STUN] All STUN servers failed — offline, or UDP blocked by firewall")
        return None

    async def punch(
        self,
        peer_ip: str,
        peer_port: int,
        attempts: int = 15,
        interval: float = 0.25,
        timeout: float = 6.0,
    ) -> bool:
        """
        Sends periodic small "punch" datagrams to the peer's advertised public
        endpoint (opening our NAT's outbound mapping for that peer), while the
        peer does the same towards us at the same time. Returns True as soon
        as ANY datagram is received back from that peer's IP, confirming a
        bidirectional path is open.
        """
        loop = asyncio.get_event_loop()
        confirmed = loop.create_future()
        prev_handler = self._protocol.on_data

        def _watch_for_peer(data: bytes, addr: Tuple[str, int]):
            if addr[0] == peer_ip and not confirmed.done():
                confirmed.set_result(True)
            if prev_handler:
                prev_handler(data, addr)

        self._protocol.on_data = _watch_for_peer
        punch_payload = b'{"type":"punch"}'

        async def _sender():
            for _ in range(attempts):
                self.send(peer_ip, peer_port, punch_payload)
                await asyncio.sleep(interval)

        sender_task = asyncio.create_task(_sender())
        try:
            await asyncio.wait_for(confirmed, timeout=timeout)
            logger.info(f"[P2P] Hole punch to {peer_ip}:{peer_port} succeeded")
            return True
        except asyncio.TimeoutError:
            logger.warning(f"[P2P] Hole punch to {peer_ip}:{peer_port} timed out (likely symmetric NAT)")
            return False
        finally:
            sender_task.cancel()
            self._protocol.on_data = prev_handler

    async def close(self):
        if self._transport:
            self._transport.close()
            self._transport = None
