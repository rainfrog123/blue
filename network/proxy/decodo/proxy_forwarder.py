#!/usr/bin/env python3
"""
Local HTTP proxy that forwards to an upstream Decodo sticky session.

Builds upstream from cred.json (no hardcoded secrets). HTTP CONNECT only
to Decodo HTTPS gateways — for SOCKS upstream use a dedicated SOCKS forwarder.

Usage:
    python proxy_forwarder.py --country gb --session apple
    python proxy_forwarder.py --upstream 'https://user-…:pass@gb.decodo.com:37143'
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import logging
import sys
from typing import Optional
from urllib.parse import unquote, urlparse

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)


class ProxyForwarder:
    """Async local HTTP proxy → upstream HTTP(S) CONNECT proxy."""

    def __init__(
        self,
        listen_host: str,
        listen_port: int,
        upstream_host: str,
        upstream_port: int,
        upstream_user: str,
        upstream_pass: str,
    ):
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.upstream_host = upstream_host
        self.upstream_port = upstream_port
        self.upstream_auth = base64.b64encode(
            f"{upstream_user}:{upstream_pass}".encode()
        ).decode()

    async def handle_client(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
    ) -> None:
        peer = client_writer.get_extra_info("peername")
        log.info("New connection from %s", peer)
        upstream_writer: Optional[asyncio.StreamWriter] = None

        try:
            request_line = await asyncio.wait_for(client_reader.readline(), timeout=30.0)
            if not request_line:
                return

            request_str = request_line.decode("utf-8", errors="ignore").strip()
            parts = request_str.split()
            if len(parts) < 3:
                log.warning("Invalid request: %s", request_str)
                return

            method, target, version = parts[0], parts[1], parts[2]
            log.info("Request: %s %s", method, target[:80])

            headers: list[bytes] = []
            while True:
                header_line = await asyncio.wait_for(
                    client_reader.readline(), timeout=30.0
                )
                if header_line in (b"\r\n", b"\n", b""):
                    break
                headers.append(header_line)

            upstream_reader, upstream_writer = await asyncio.wait_for(
                asyncio.open_connection(self.upstream_host, self.upstream_port),
                timeout=30.0,
            )

            if method == "CONNECT":
                await self._handle_connect(
                    client_reader,
                    client_writer,
                    upstream_reader,
                    upstream_writer,
                    target,
                    version,
                )
            else:
                await self._handle_http(
                    client_reader,
                    client_writer,
                    upstream_reader,
                    upstream_writer,
                    method,
                    target,
                    version,
                    headers,
                )
        except asyncio.TimeoutError:
            log.warning("Timeout handling %s", peer)
        except ConnectionResetError:
            log.debug("Connection reset by %s", peer)
        except Exception as exc:  # noqa: BLE001
            log.error("Error handling %s: %s", peer, exc)
        finally:
            client_writer.close()
            try:
                await client_writer.wait_closed()
            except Exception:
                pass
            if upstream_writer is not None:
                upstream_writer.close()

    async def _handle_connect(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        upstream_reader: asyncio.StreamReader,
        upstream_writer: asyncio.StreamWriter,
        target: str,
        version: str,
    ) -> None:
        connect_request = (
            f"CONNECT {target} {version}\r\n"
            f"Host: {target}\r\n"
            f"Proxy-Authorization: Basic {self.upstream_auth}\r\n"
            f"\r\n"
        )
        upstream_writer.write(connect_request.encode())
        await upstream_writer.drain()

        response_line = await asyncio.wait_for(upstream_reader.readline(), timeout=30.0)
        while True:
            header_line = await asyncio.wait_for(upstream_reader.readline(), timeout=30.0)
            if header_line in (b"\r\n", b"\n", b""):
                break

        response_str = response_line.decode("utf-8", errors="ignore").strip()
        if "200" in response_str:
            client_writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await client_writer.drain()
            await self._relay(
                client_reader, client_writer, upstream_reader, upstream_writer
            )
        else:
            log.warning("Upstream rejected CONNECT: %s", response_str)
            client_writer.write(response_line)
            await client_writer.drain()

    async def _handle_http(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        upstream_reader: asyncio.StreamReader,
        upstream_writer: asyncio.StreamWriter,
        method: str,
        target: str,
        version: str,
        headers: list[bytes],
    ) -> None:
        upstream_writer.write(f"{method} {target} {version}\r\n".encode())
        upstream_writer.write(
            f"Proxy-Authorization: Basic {self.upstream_auth}\r\n".encode()
        )
        content_length = 0
        for header in headers:
            text = header.decode("utf-8", errors="ignore")
            lower = text.lower()
            if lower.startswith("proxy-authorization:"):
                continue
            if lower.startswith("content-length:"):
                content_length = int(text.split(":", 1)[1].strip())
            upstream_writer.write(header)
        upstream_writer.write(b"\r\n")
        await upstream_writer.drain()

        if content_length > 0:
            body = await client_reader.readexactly(content_length)
            upstream_writer.write(body)
            await upstream_writer.drain()

        await self._relay_response(client_writer, upstream_reader)

    async def _relay_response(
        self,
        client_writer: asyncio.StreamWriter,
        upstream_reader: asyncio.StreamReader,
    ) -> None:
        while True:
            data = await upstream_reader.read(8192)
            if not data:
                break
            client_writer.write(data)
            await client_writer.drain()

    async def _relay(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        upstream_reader: asyncio.StreamReader,
        upstream_writer: asyncio.StreamWriter,
    ) -> None:
        async def forward(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            try:
                while True:
                    data = await reader.read(8192)
                    if not data:
                        break
                    writer.write(data)
                    await writer.drain()
            except Exception:
                pass
            finally:
                try:
                    writer.close()
                except Exception:
                    pass

        await asyncio.gather(
            forward(client_reader, upstream_writer),
            forward(upstream_reader, client_writer),
        )

    async def start(self) -> None:
        server = await asyncio.start_server(
            self.handle_client, self.listen_host, self.listen_port
        )
        addr = server.sockets[0].getsockname()
        log.info("Listening on %s:%s", addr[0], addr[1])
        log.info("Upstream %s:%s", self.upstream_host, self.upstream_port)
        async with server:
            await server.serve_forever()


def _parse_upstream(url: str) -> dict:
    if "://" not in url:
        url = "http://" + url
    parsed = urlparse(url)
    if not parsed.hostname or not parsed.port:
        raise SystemExit(f"upstream URL needs host and port: {url}")
    return {
        "host": parsed.hostname,
        "port": parsed.port,
        "username": unquote(parsed.username or ""),
        "password": unquote(parsed.password or ""),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Local forwarder → Decodo HTTPS proxy")
    parser.add_argument("-p", "--port", type=int, default=5566)
    parser.add_argument("-H", "--host", default="0.0.0.0")
    parser.add_argument("--upstream", help="Full upstream proxy URL")
    parser.add_argument("-c", "--country", default="gb")
    parser.add_argument("-s", "--session", help="Sticky session id")
    parser.add_argument("-d", "--duration", type=int, default=60)
    args = parser.parse_args()

    if args.upstream:
        upstream = _parse_upstream(args.upstream)
    else:
        # Local forwarder speaks HTTP CONNECT to Decodo's HTTPS gateway.
        from decodo import build_proxy_url

        built = build_proxy_url(
            country=args.country,
            session=args.session,
            session_duration=args.duration,
            protocol="https",
        )
        upstream = _parse_upstream(built)
        log.info("Built upstream from creds: %s:%s", upstream["host"], upstream["port"])

    forwarder = ProxyForwarder(
        listen_host=args.host,
        listen_port=args.port,
        upstream_host=upstream["host"],
        upstream_port=upstream["port"],
        upstream_user=upstream["username"],
        upstream_pass=upstream["password"],
    )
    try:
        asyncio.run(forwarder.start())
    except KeyboardInterrupt:
        log.info("Shutting down...")
        sys.exit(0)


if __name__ == "__main__":
    main()
