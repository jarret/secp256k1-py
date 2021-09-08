import os
import coincurve

class PrivateKey(object):
    def __init__(self, rawkey) -> None:
        if not isinstance(rawkey, bytes):
            raise TypeError(f"rawkey must be bytes, {type(rawkey)} received")
        elif len(rawkey) != 32:
            raise ValueError(
                f"rawkey must be 32-byte long. {len(rawkey)} received")

        self.rawkey = rawkey
        self.key = coincurve.PrivateKey(rawkey)

    def to_bytes(self):
        return self.rawkey

    def to_hex(self):
        return self.to_bytes().hex()

    def public_key(self):
        return PublicKey(self.key.public_key)

    def ecdh(self, pubkey):
        k = coincurve.PrivateKey(secret=self.to_bytes())
        rk = coincurve.PublicKey(data=pubkey.to_bytes())
        return k.ecdh(rk.public_key)

    @staticmethod
    def new_ephemeral():
        return PrivateKey(os.urandom(32))

    @staticmethod
    def from_hex(hex_str):
        assert len(hex_str) == 64
        return PrivateKey(bytes.fromhex(hex_str))


class PublicKey(object):
    def __init__(self, innerkey):
        # We accept either 33-bytes raw keys, or an EC PublicKey as returned
        # by coincurve
        if isinstance(innerkey, bytes):
            if innerkey[0] in [2, 3] and len(innerkey) == 33:
                innerkey = coincurve.PublicKey(innerkey)
            else:
                raise ValueError("Byte keys must be 33-byte long starting "
                                 "from either 02 or 03")
        elif not isinstance(innerkey, coincurve.keys.PublicKey):
            raise ValueError("Key must either be bytes or "
                             "coincurve.keys.PublicKey")
        self.key = innerkey

    def to_bytes(self) -> bytes:
        return self.key.format(compressed=True)

    def to_hex(self):
        return self.to_bytes().hex()

    def __str__(self):
        return "PublicKey[0x{}]".format(self.to_bytes().hex())
