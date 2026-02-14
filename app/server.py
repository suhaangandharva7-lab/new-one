from __future__ import annotations

import argparse
import asyncio
import json
from collections import defaultdict, deque

users: set[str] = set()
queues: dict[str, deque[dict]] = defaultdict(deque)


async def send_json(writer: asyncio.StreamWriter, obj: dict) -> None:
    writer.write((json.dumps(obj) + "\n").encode("utf-8"))
    await writer.drain()


async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    peer = writer.get_extra_info("peername")
    try:
        while True:
            line = await reader.readline()
            if not line:
                break
            msg = json.loads(line.decode("utf-8"))
            mtype = msg.get("type")

            if mtype == "register":
                users.add(msg["user"])
                await send_json(writer, {"ok": True, "type": "register_ack"})

            elif mtype == "who":
                await send_json(writer, {"ok": True, "users": sorted(users)})

            elif mtype == "send":
                to = msg["to"]
                payload = msg["payload"]
                queues[to].append(payload)
                await send_json(writer, {"ok": True, "type": "send_ack"})

            elif mtype == "poll":
                user = msg["user"]
                items = []
                while queues[user]:
                    items.append(queues[user].popleft())
                await send_json(writer, {"ok": True, "messages": items})

            else:
                await send_json(writer, {"ok": False, "error": f"unknown type: {mtype}"})
    except Exception as exc:
        await send_json(writer, {"ok": False, "error": str(exc)})
    finally:
        writer.close()
        await writer.wait_closed()
        print(f"client disconnected: {peer}")


async def run_server(host: str, port: int) -> None:
    server = await asyncio.start_server(handle_client, host, port)
    addr = ", ".join(str(sock.getsockname()) for sock in server.sockets or [])
    print(f"relay listening on {addr}")
    async with server:
        await server.serve_forever()


def main() -> None:
    parser = argparse.ArgumentParser(description="Ciphertext relay server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9000)
    args = parser.parse_args()

    asyncio.run(run_server(args.host, args.port))


if __name__ == "__main__":
    main()
