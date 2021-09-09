import os
import secp256k1

class PrivateKey(object):
    def __init__(self, rawkey) -> None:
        assert isinstance(rawkey, bytes)
        assert len(rawkey) == 32
        self.rawkey = rawkey
        self.key = secp256k1.PrivateKey(privkey=rawkey, raw=True)

    def to_bytes(self):
        return self.rawkey

    def to_hex(self):
        return self.to_bytes().hex()

    def public_key(self):
        return PublicKey(self.key.pubkey.serialize())

    def ecdh(self, pubkey):
        return pubkey.key.ecdh(self.rawkey)

    @staticmethod
    def new_ephemeral():
        return PrivateKey(os.urandom(32))

    @staticmethod
    def from_hex(hex_str):
        assert len(hex_str) == 64
        return PrivateKey(bytes.fromhex(hex_str))


class PublicKey(object):
    def __init__(self, innerkey):
        assert isinstance(innerkey, bytes), "not bytes"
        assert innerkey[0] in [2, 3], "not prefixed (1)"
        assert len(innerkey) == 33, "not prefixed (2)"
        innerkey = secp256k1.PublicKey(pubkey=innerkey, raw=True)
        self.key = innerkey

    def to_bytes(self, compressed=True) -> bytes:
        return self.key.serialize(compressed=compressed)

    def to_hex(self):
        return self.to_bytes().hex()

    def __str__(self):
        return "PublicKey[0x{}]".format(self.to_bytes().hex())
