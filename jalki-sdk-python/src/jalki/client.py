"""
jälki wire client.

Handles:
- Unix socket connection to /run/jalki/jalki.sock
- Frame encoding/decoding (length-prefixed binary)
- MessagePack serialization
- Request/response multiplexing
- Automatic reconnect with exponential backoff
- Keepalive via PING/PONG
"""

from __future__ import annotations

import asyncio
import logging
import struct
from typing import Any, AsyncIterator, Optional

import msgpack

from jalki.protocol import (
    FRAME_HEADER_LEN,
    FRAME_MAX_LEN,
    KEEPALIVE_INTERVAL_SECS,
    KEEPALIVE_TIMEOUT_SECS,
    RECONNECT_BASE_MS,
    RECONNECT_MAX_MS,
    REQUEST_TIMEOUT_SECS,
    Flags,
    Method,
    MsgType,
)

logger = logging.getLogger("jalki.client")

SOCKET_PATH = "/run/jalki/jalki.sock"


class JalkiClient:
    """Connection to the jälki daemon over Unix socket."""

    def __init__(self, socket_path: str = SOCKET_PATH) -> None:
        self._socket_path = socket_path
        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None
        self._request_id: int = 0
        self._pending: dict[int, asyncio.Future[Any]] = {}
        self._streams: dict[str, asyncio.Queue[Any]] = {}
        self._connected = False
        self._lock = asyncio.Lock()
        self._reader_task: Optional[asyncio.Task[None]] = None
        self._keepalive_task: Optional[asyncio.Task[None]] = None

    async def connect(self) -> None:
        """Connect to the daemon Unix socket."""
        self._reader, self._writer = await asyncio.open_unix_connection(
            self._socket_path
        )
        self._connected = True
        self._reader_task = asyncio.create_task(self._reader_loop())
        self._keepalive_task = asyncio.create_task(self._keepalive_loop())
        logger.debug("connected to %s", self._socket_path)

    async def close(self) -> None:
        """Close the connection."""
        self._connected = False
        if self._reader_task is not None:
            self._reader_task.cancel()
        if self._keepalive_task is not None:
            self._keepalive_task.cancel()
        if self._writer is not None:
            self._writer.close()
            try:
                await self._writer.wait_closed()
            except Exception:
                pass
        self._reader = None
        self._writer = None

    async def call(self, method: Method, params: Any) -> Any:
        """Send request, await response. Raises on error or timeout."""
        if not self._connected:
            raise ConnectionError("not connected to daemon")

        async with self._lock:
            self._request_id += 1
            req_id = self._request_id

        future: asyncio.Future[Any] = asyncio.get_event_loop().create_future()
        self._pending[req_id] = future

        payload = msgpack.packb([req_id, method.value, params], use_bin_type=True)
        frame = self._encode_frame(MsgType.REQUEST, 0, payload)

        try:
            assert self._writer is not None
            self._writer.write(frame)
            await self._writer.drain()
            result = await asyncio.wait_for(future, timeout=REQUEST_TIMEOUT_SECS)
        finally:
            self._pending.pop(req_id, None)

        return result

    async def subscribe(self, params: Any) -> AsyncIterator[Any]:
        """Send subscribe request, yield STREAM_EVENTs until STREAM_END."""
        result = await self.call(Method.SUBSCRIBE, params)

        probe_id = result.get("probe_id", "unknown") if isinstance(result, dict) else "unknown"
        queue: asyncio.Queue[Any] = asyncio.Queue(maxsize=4096)
        self._streams[probe_id] = queue

        try:
            while True:
                item = await queue.get()
                if item is None:
                    break
                yield item
        finally:
            self._streams.pop(probe_id, None)

    async def _fetch_full(self, event_id: str) -> dict[str, Any]:
        """Fetch full FALSE Protocol Occurrence for an event by id."""
        return await self.call(Method.STATUS, {"event_id": event_id})

    def _encode_frame(self, msg_type: MsgType, flags: int, payload: bytes) -> bytes:
        """Encode a frame: [len:u32 BE][type:u8][flags:u8][payload]."""
        frame_len = 2 + len(payload)  # type + flags + payload
        return struct.pack(">I", frame_len) + bytes([msg_type.value, flags]) + payload

    async def _decode_frame(self) -> tuple[MsgType, int, Any]:
        """Read and decode next frame from socket."""
        assert self._reader is not None

        header = await self._reader.readexactly(4)
        frame_len = struct.unpack(">I", header)[0]

        if frame_len > FRAME_MAX_LEN:
            raise ValueError(f"frame too large: {frame_len}")

        data = await self._reader.readexactly(frame_len)
        msg_type = MsgType(data[0])
        flags = data[1]
        payload = msgpack.unpackb(data[2:], raw=False) if len(data) > 2 else None

        return msg_type, flags, payload

    async def _reader_loop(self) -> None:
        """Background task: read frames, dispatch to pending requests and streams."""
        try:
            while self._connected:
                msg_type, flags, payload = await self._decode_frame()

                if msg_type == MsgType.RESPONSE:
                    if isinstance(payload, list) and len(payload) >= 3:
                        req_id = payload[0]
                        ok = payload[1]
                        result = payload[2]
                        future = self._pending.get(req_id)
                        if future is not None and not future.done():
                            if ok:
                                future.set_result(result)
                            else:
                                future.set_exception(
                                    RuntimeError(f"daemon error: {result}")
                                )

                elif msg_type == MsgType.STREAM_EVENT:
                    # Dispatch to all active streams.
                    for queue in self._streams.values():
                        try:
                            queue.put_nowait(payload)
                        except asyncio.QueueFull:
                            logger.warning("stream queue full, dropping event")

                elif msg_type == MsgType.STREAM_END:
                    for queue in self._streams.values():
                        try:
                            queue.put_nowait(None)
                        except asyncio.QueueFull:
                            pass

                elif msg_type == MsgType.PONG:
                    logger.debug("pong received")

                elif msg_type == MsgType.ERROR:
                    if isinstance(payload, list) and len(payload) >= 2:
                        logger.error("daemon error: %s: %s", payload[0], payload[1])

        except asyncio.CancelledError:
            pass
        except (ConnectionResetError, asyncio.IncompleteReadError):
            logger.warning("connection lost")
            self._connected = False
        except Exception as e:
            logger.error("reader loop error: %s", e)
            self._connected = False

    async def _keepalive_loop(self) -> None:
        """Background task: PING every 30s."""
        try:
            while self._connected:
                await asyncio.sleep(KEEPALIVE_INTERVAL_SECS)
                if self._writer is not None and self._connected:
                    payload = msgpack.packb([], use_bin_type=True)
                    frame = self._encode_frame(MsgType.PING, 0, payload)
                    try:
                        self._writer.write(frame)
                        await self._writer.drain()
                    except Exception:
                        logger.warning("keepalive failed")
        except asyncio.CancelledError:
            pass

    async def _reconnect(self) -> None:
        """Reconnect with exponential backoff."""
        delay_ms = RECONNECT_BASE_MS
        while True:
            try:
                await self.close()
                await self.connect()
                logger.info("reconnected to %s", self._socket_path)
                return
            except Exception as e:
                logger.debug("reconnect failed: %s, retry in %dms", e, delay_ms)
                await asyncio.sleep(delay_ms / 1000)
                delay_ms = min(delay_ms * 2, RECONNECT_MAX_MS)
