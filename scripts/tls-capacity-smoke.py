"""Keep idle CONNECT tunnels open, then check that a new request can still run."""
import asyncio
import sys


async def main():
    proxy_port, held_count = map(int, sys.argv[1:3])
    held = []

    async def origin(reader, writer):
        try:
            if await reader.read(1):
                writer.write(b"ok")
                await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    async with await asyncio.start_server(origin, "127.0.0.1", 0) as server:
        port = server.sockets[0].getsockname()[1]

        async def tunnel():
            reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)
            writer.write(f"CONNECT 127.0.0.1:{port} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n".encode())
            await writer.drain()
            try:
                response = await reader.readuntil(b"\r\n\r\n")
                assert b" 200 " in response, response.splitlines()[0]
                return reader, writer
            except BaseException:
                writer.close()
                await writer.wait_closed()
                raise

        try:
            for _ in range(held_count):
                held.append(await asyncio.wait_for(tunnel(), 5))
            reader, writer = await asyncio.wait_for(tunnel(), 3)
            try:
                writer.write(b"x")
                await writer.drain()
                assert await asyncio.wait_for(reader.readexactly(2), 3) == b"ok"
                print(f"new request passed while {held_count} idle tunnels remained open")
            finally:
                writer.close()
                await writer.wait_closed()
        finally:
            for _, writer in held:
                writer.close()
            await asyncio.gather(*(writer.wait_closed() for _, writer in held), return_exceptions=True)


asyncio.run(main())
