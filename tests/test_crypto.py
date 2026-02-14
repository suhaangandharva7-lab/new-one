from app.crypto import Identity, decrypt_from_sender, encrypt_for_recipient


def test_encrypt_decrypt_roundtrip() -> None:
    alice = Identity.create("alice", "shared-super-secret")
    bob = Identity.create("bob", "shared-super-secret")
    aad = {"from": "alice", "to": "bob", "v": 1}

    env = encrypt_for_recipient(alice, "hello bob", aad)
    pt = decrypt_from_sender(bob, env, aad)

    assert pt == "hello bob"


def test_wrong_key_detected() -> None:
    alice = Identity.create("alice", "shared-super-secret")
    bob = Identity.create("bob", "different-secret")
    aad = {"from": "alice", "to": "bob", "v": 1}

    env = encrypt_for_recipient(alice, "hello bob", aad)

    failed = False
    try:
        decrypt_from_sender(bob, env, aad)
    except Exception:
        failed = True
    assert failed
