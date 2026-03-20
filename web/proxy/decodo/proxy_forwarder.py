#!/usr/bin/env python3
"""
Local proxy forwarder that redirects traffic to an upstream Decodo proxy.

Usage:
    python proxy_forwarder.py [--port 5566]

Anyone connecting to this VPS's public IP:5566 will be routed through the upstream proxy.
"""

import argparse
import asyncio
import base64
import logging
import ssl
import sys
from urllib.parse import urlparse

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)

# Default upstream proxy configuration
DEFAULT_UPSTREAM = {
    "host": "gb.decodo.com",
    "port": 37143,
    "username": "user-sp19qgy7m9-country-gb-session-365d58c1dfbd-sessionduration-60",
    "password": "+26iSboeQ0wUyx4qEw",
}


class ProxyForwarder:
    """Async proxy server that forwards to an upstream proxy."""

    def __init__(
        self,
        listen_host: str = "0.0.0.0",
        listen_port: int = 5566,
        upstream_host: str = DEFAULT_UPSTREAM["host"],
        upstream_port: int = DEFAULT_UPSTREAM["port"],
        upstream_user: str = DEFAULT_UPSTREAM["username"],
        upstream_pass: str = DEFAULT_UPSTREAM["password"],
    ):
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.upstream_host = upstream_host
        self.upstream_port = upstream_port
        self.upstream_auth = base64.b64encode(
            f"{upstream_user}:{upstream_pass}".encode()
        ).decode()

    async def handle_client(
        self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter
    ):
        """Handle incoming client connection."""
        client_addr = client_writer.get_extra_info("peername")
        log.info(f"New connection from {client_addr}")

        try:
            # Read the initial request line
            request_line = await asyncio.wait_for(
                client_reader.readline(), timeout=30.0
            )
            if not request_line:
                return

            request_str = request_line.decode("utf-8", errors="ignore").strip()
            parts = request_str.split()
            if len(parts) < 3:
                log.warning(f"Invalid request: {request_str}")
                return

            method, target, version = parts[0], parts[1], parts[2]
            log.info(f"Request: {method} {target[:80]}...")

            # Read headers
            headers = []
            while True:
                header_line = await asyncio.wait_for(
                    client_reader.readline(), timeout=30.0
                )
                if header_line in (b"\r\n", b"\n", b""):
                    break
                headers.append(header_line)

            # Connect to upstream proxy
            upstream_reader, upstream_writer = await asyncio.wait_for(
                asyncio.open_connection(self.upstream_host, self.upstream_port),
                timeout=30.0,
            )

            if method == "CONNECT":
                # HTTPS tunnel via CONNECT
                await self._handle_connect(
                    client_reader,
                    client_writer,
                    upstream_reader,
                    upstream_writer,
                    target,
                    version,
                )
            else:
                # Regular HTTP proxy request
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
            log.warning(f"Timeout handling {client_addr}")
        except ConnectionResetError:
            log.debug(f"Connection reset by {client_addr}")
        except Exception as e:
            log.error(f"Error handling {client_addr}: {e}")
        finally:
            client_writer.close()
            try:
                await client_writer.wait_closed()
            except Exception:
                pass

    async def _handle_connect(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        upstream_reader: asyncio.StreamReader,
        upstream_writer: asyncio.StreamWriter,
        target: str,
        version: str,
    ):
        """Handle CONNECT method for HTTPS tunneling."""
        # Send CONNECT to upstream with auth
        connect_request = (
            f"CONNECT {target} {version}\r\n"
            f"Host: {target}\r\n"
            f"Proxy-Authorization: Basic {self.upstream_auth}\r\n"
            f"\r\n"
        )
        upstream_writer.write(connect_request.encode())
        await upstream_writer.drain()

        # Read upstream response
        response_line = await asyncio.wait_for(
            upstream_reader.readline(), timeout=30.0
        )

        # Read response headers
        while True:
            header_line = await asyncio.wait_for(
                upstream_reader.readline(), timeout=30.0
            )
            if header_line in (b"\r\n", b"\n", b""):
                break

        # Check if upstream accepted
        response_str = response_line.decode("utf-8", errors="ignore").strip()
        if "200" in response_str:
            # Send success to client
            client_writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await client_writer.drain()

            # Start bidirectional relay
            await self._relay(
                client_reader, client_writer, upstream_reader, upstream_writer
            )
        else:
            log.warning(f"Upstream rejected CONNECT: {response_str}")
            client_writer.write(response_line)
            await client_writer.drain()

        upstream_writer.close()

    async def _handle_http(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        upstream_reader: asyncio.StreamReader,
        upstream_writer: asyncio.StreamWriter,
        method: str,
        target: str,
        version: str,
        headers: list,
    ):
        """Handle regular HTTP proxy request."""
        # Build request to upstream
        request = f"{method} {target} {version}\r\n"
        upstream_writer.write(request.encode())

        # Add proxy auth header
        upstream_writer.write(f"Proxy-Authorization: Basic {self.upstream_auth}\r\n".encode())

        # Forward original headers (except existing proxy-auth)
        for header in headers:
            header_lower = header.decode("utf-8", errors="ignore").lower()
            if not header_lower.startswith("proxy-authorization:"):
                upstream_writer.write(header)

        upstream_writer.write(b"\r\n")
        await upstream_writer.drain()

        # Check for request body (Content-Length or chunked)
        content_length = 0
        for header in headers:
            header_str = header.decode("utf-8", errors="ignore").lower()
            if header_str.startswith("content-length:"):
                content_length = int(header_str.split(":")[1].strip())

        if content_length > 0:
            body = await client_reader.read(content_length)
            upstream_writer.write(body)
            await upstream_writer.drain()

        # Relay response back to client
        await self._relay_response(client_writer, upstream_reader)

        upstream_writer.close()

    async def _relay_response(
        self,
        client_writer: asyncio.StreamWriter,
        upstream_reader: asyncio.StreamReader,
    ):
        """Relay HTTP response from upstream to client."""
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
    ):
        """Bidirectional relay for CONNECT tunnels."""

        async def forward(reader, writer, name):
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
            forward(client_reader, upstream_writer, "client->upstream"),
            forward(upstream_reader, client_writer, "upstream->client"),
        )

    async def start(self):
        """Start the proxy server."""
        server = await asyncio.start_server(
            self.handle_client,
            self.listen_host,
            self.listen_port,
        )

        addr = server.sockets[0].getsockname()
        log.info(f"Proxy forwarder listening on {addr[0]}:{addr[1]}")
        log.info(f"Forwarding to upstream: {self.upstream_host}:{self.upstream_port}")
        log.info(f"Use this proxy: http://<your-vps-ip>:{self.listen_port}")

        async with server:
            await server.serve_forever()


def parse_proxy_url(url: str) -> dict:
    """Parse a proxy URL into components."""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    
    parsed = urlparse(url)
    return {
        "host": parsed.hostname,
        "port": parsed.port or 43905,
        "username": parsed.username or "",
        "password": parsed.password or "",
    }


def main():
    parser = argparse.ArgumentParser(
        description="Local proxy forwarder to upstream Decodo proxy"
    )
    parser.add_argument(
        "-p", "--port",
        type=int,
        default=5566,
        help="Local port to listen on (default: 5566)",
    )
    parser.add_argument(
        "-H", "--host",
        default="0.0.0.0",
        help="Host to bind to (default: 0.0.0.0)",
    )
    parser.add_argument(
        "--upstream",
        type=str,
        help="Upstream proxy URL (default: built-in Decodo config)",
    )
    args = parser.parse_args()

    # Parse upstream if provided
    if args.upstream:
        upstream = parse_proxy_url(args.upstream)
    else:
        upstream = DEFAULT_UPSTREAM

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


if __name__ == "__main__":
    main()
