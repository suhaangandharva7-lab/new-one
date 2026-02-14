from __future__ import annotations

import argparse
import asyncio
import json

from .crypto import Identity, decrypt_from_sender, encrypt_for_recipient


async def send_json(writer: asyncio.StreamWriter, obj: dict) -> None:
    writer.write((json.dumps(obj) + "\n").encode("utf-8"))
    await writer.drain()


async def recv_json(reader: asyncio.StreamReader) -> dict:
    line = await reader.readline()
    if not line:
        raise ConnectionError("server closed connection")
    return json.loads(line.decode("utf-8"))


class ChatClient:
    def __init__(self, host: str, port: int, user: str, shared_secret: str) -> None:
        self.host = host
        self.port = port
        self.identity = Identity.create(user, shared_secret)

    async def connect(self) -> None:
        self.reader, self.writer = await asyncio.open_connection(self.host, self.port)
        await send_json(self.writer, {"type": "register", "user": self.identity.name})
        ack = await recv_json(self.reader)
        if not ack.get("ok"):
            raise RuntimeError(f"register failed: {ack}")

    async def send_message(self, target: str, message: str) -> None:
        aad = {"from": self.identity.name, "to": target, "v": 1}
        envelope = encrypt_for_recipient(self.identity, message, aad)
        payload = {"from": self.identity.name, "to": target, "aad": aad, "envelope": envelope}
        await send_json(self.writer, {"type": "send", "to": target, "payload": payload})
        resp = await recv_json(self.reader)
        if not resp.get("ok"):
            raise RuntimeError(resp.get("error", "send failed"))

    async def poll(self) -> None:
        await send_json(self.writer, {"type": "poll", "user": self.identity.name})
        resp = await recv_json(self.reader)
        if not resp.get("ok"):
            raise RuntimeError(resp.get("error", "poll failed"))

        for item in resp.get("messages", []):
            sender = item["from"]
            aad = item["aad"]
            env = item["envelope"]
            try:
                plaintext = decrypt_from_sender(self.identity, env, aad)
                print(f"[secure] {sender}: {plaintext}")
            except Exception as exc:
                print(f"[tampered/wrong-key] {sender}: unable to decrypt ({exc})")

    async def who(self) -> None:
        await send_json(self.writer, {"type": "who"})
        resp = await recv_json(self.reader)
        if resp.get("ok"):
            print("users:", ", ".join(resp.get("users", [])))

    async def repl(self) -> None:
        print(f"connected as {self.identity.name}")
        print("commands: /send <user> <msg>, /poll, /who, /quit")
        while True:
            raw = await asyncio.to_thread(input, "> ")
            if raw.strip() == "/quit":
                break
            if raw.strip() == "/poll":
                await self.poll()
                continue
            if raw.strip() == "/who":
                await self.who()
                continue
            if raw.startswith("/send "):
                try:
                    _, target, message = raw.split(" ", 2)
                except ValueError:
                    print("usage: /send <user> <msg>")
                    continue
                await self.send_message(target, message)
                print("sent")
                continue
            print("unknown command")


def main() -> None:
    parser = argparse.ArgumentParser(description="E2EE chat client")
    parser.add_argument("--server-host", default="127.0.0.1")
    parser.add_argument("--server-port", type=int, default=9000)
    parser.add_argument("--user", required=True)
    parser.add_argument("--shared-secret", required=True, help="Out-of-band shared passphrase")
    args = parser.parse_args()

    async def _run() -> None:
        client = ChatClient(args.server_host, args.server_port, args.user, args.shared_secret)
        await client.connect()
        try:
            await client.repl()
        finally:
            client.writer.close()
            await client.writer.wait_closed()

    asyncio.run(_run())


if __name__ == "__main__":
    main()
