# Maximally Encrypted Chat App

This project is a reference encrypted chat prototype with end-to-end encryption semantics:

- Relay server only routes ciphertext.
- Clients encrypt locally and decrypt locally.
- Per-message random salt and nonce.
- `scrypt` KDF + Encrypt-then-MAC construction using HMAC-SHA512.

> This uses only Python standard library primitives so it works in constrained environments.

## Quick start

Run server:

```bash
python -m app.server --host 127.0.0.1 --port 9000
```

Run Alice in one terminal:

```bash
python -m app.client --server-host 127.0.0.1 --server-port 9000 --user alice --shared-secret "top-secret-room-key"
```

Run Bob in another terminal (same shared secret):

```bash
python -m app.client --server-host 127.0.0.1 --server-port 9000 --user bob --shared-secret "top-secret-room-key"
```

Inside a client:

- `/send bob hello there`
- `/poll`
- `/who`
- `/quit`

## Security notes

- The server cannot read message plaintext.
- Integrity is protected using HMAC; tampering is rejected.
- This is a demo/prototype and not a full production ratcheting protocol.
- Shared-secret distribution must happen out-of-band.
