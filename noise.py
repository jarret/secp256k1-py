from cryptography.exceptions import InvalidTag
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from hashlib import sha256
import os
import coincurve
import struct

#############################################################################
# much borrowed from:
#   https://github.com/ElementsProject/lightning/blob/master/contrib/pyln-proto/pyln/proto/wire.py
#############################################################################

class Secret(object):
    def __init__(self, data: bytes) -> None:
        assert(len(data) == 32)
        self.data = data

    def to_bytes(self) -> bytes:
        return self.data

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Secret) and self.data == other.data

    def __str__(self):
        return "Secret[0x{}]".format(self.data.hex())


class PrivateKey(object):
    def __init__(self, rawkey) -> None:
        if not isinstance(rawkey, bytes):
            raise TypeError(f"rawkey must be bytes, {type(rawkey)} received")
        elif len(rawkey) != 32:
            raise ValueError(f"rawkey must be 32-byte long. {len(rawkey)} received")

        self.rawkey = rawkey
        self.key = coincurve.PrivateKey(rawkey)

    def serializeCompressed(self):
        return self.key.secret

    def public_key(self):
        return PublicKey(self.key.public_key)


class PublicKey(object):
    def __init__(self, innerkey):
        # We accept either 33-bytes raw keys, or an EC PublicKey as returned
        # by coincurve
        if isinstance(innerkey, bytes):
            if innerkey[0] in [2, 3] and len(innerkey) == 33:
                innerkey = coincurve.PublicKey(innerkey)
            else:
                raise ValueError(
                    "Byte keys must be 33-byte long starting from either 02 or 03"
                )

        elif not isinstance(innerkey, coincurve.keys.PublicKey):
            raise ValueError(
                "Key must either be bytes or coincurve.keys.PublicKey"
            )
        self.key = innerkey

    def serializeCompressed(self):
        return self.key.format(compressed=True)

    def to_bytes(self) -> bytes:
        return self.serializeCompressed()

    def __str__(self):
        return "PublicKey[0x{}]".format(
            self.serializeCompressed().hex()
        )

#############################################################################

def hkdf(ikm, salt=b"", info=b""):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=salt,
        info=info,
        backend=default_backend())

    return hkdf.derive(ikm)

def hkdf_two_keys(ikm, salt):
    t = hkdf(ikm, salt)
    return t[:32], t[32:]

def ecdh(k, rk):
    k = coincurve.PrivateKey(secret=k.rawkey)
    rk = coincurve.PublicKey(data=rk.serializeCompressed())
    a = k.ecdh(rk.public_key)
    return Secret(a)

def encryptWithAD(k, n, ad, plaintext):
    chacha = ChaCha20Poly1305(k)
    return chacha.encrypt(n, plaintext, ad)

def decryptWithAD(k, n, ad, ciphertext):
    chacha = ChaCha20Poly1305(k)
    return chacha.decrypt(n, ciphertext, ad)

def nonce(n):
    """Transforms a numeric nonce into a byte formatted one

    Nonce n encoded as 32 zero bits, followed by a little-endian 64-bit
    value. Note: this follows the Noise Protocol convention, rather than
    our normal endian.
    """
    return b'\x00' * 4 + struct.pack("<Q", n)

class Sha256Mixer(object):
    def __init__(self, base):
        self.hash = sha256(base).digest()

    def update(self, data):
        h = sha256(self.hash)
        h.update(data)
        self.hash = h.digest()
        return self.hash

    def digest(self):
        return self.hash

    def __str__(self):
        return "Sha256Mixer[0x{}]".format(self.hash.hex())

#############################################################################

class Bolt8Handshake():
    def __init__(self, remote_pubkey, local_privkey, is_initiator):
        self.chaining_key = None
        self.handshake_hash = None
        self.local_privkey = local_privkey
        self.local_pubkey = local_privkey.public_key()
        self.remote_pubkey = remote_pubkey
        self.is_initiator = is_initiator
        self.init_handshake()
        self.rn, self.sn = 0, 0


    def init_handshake(self):
        h = sha256(b'Noise_XK_secp256k1_ChaChaPoly_SHA256').digest()
        self.chaining_key = h
        h = sha256(h + b'lightning').digest()

        if self.is_initiator:
            responder_pubkey = self.remote_pubkey
        else:
            responder_pubkey = self.local_pubkey
        h = sha256(h + responder_pubkey.serializeCompressed()).digest()

        self.handshake = {
            'h': h,
            'e': PrivateKey(os.urandom(32)),
        }

    def act_one_initiator(self):
        h = Sha256Mixer(b'')
        h.hash = self.handshake['h']
        h.update(self.handshake['e'].public_key().serializeCompressed())
        es = ecdh(self.handshake['e'], self.remote_pubkey)
        t = hkdf(salt=self.chaining_key, ikm=es.data, info=b'')
        assert(len(t) == 64)
        self.chaining_key, temp_k1 = t[:32], t[32:]
        c = encryptWithAD(temp_k1, nonce(0), h.digest(), b'')
        self.handshake['h'] = h.update(c)
        pk = self.handshake['e'].public_key().serializeCompressed()
        m = b'\x00' + pk + c
        return m

    def act_one_responder(self, m):
        v, re, c = m[0], PublicKey(m[1:34]), m[34:]
        if v != 0:
            raise ValueError("Unsupported handshake version {}, only version "
                             "0 is supported.".format(v))

        h = Sha256Mixer(b'')
        h.hash = self.handshake['h']
        h.update(re.serializeCompressed())
        es = ecdh(self.local_privkey, re)
        self.handshake['re'] = re
        t = hkdf(salt=self.chaining_key, ikm=es.data, info=b'')
        self.chaining_key, temp_k1 = t[:32], t[32:]

        try:
            decryptWithAD(temp_k1, nonce(0), h.digest(), c)
        except InvalidTag:
            ValueError("Verification of tag failed, remote peer doesn't know "
                       "our node ID.")
        h.update(c)
        self.handshake['h'] = h.digest()

    def act_two_responder(self):
        h = Sha256Mixer(b'')
        h.hash = self.handshake['h']
        h.update(self.handshake['e'].public_key().serializeCompressed())
        ee = ecdh(self.handshake['e'], self.handshake['re'])
        t = hkdf(salt=self.chaining_key, ikm=ee.data, info=b'')
        assert(len(t) == 64)
        self.chaining_key, self.temp_k2 = t[:32], t[32:]
        c = encryptWithAD(self.temp_k2, nonce(0), h.digest(), b'')
        h.update(c)
        self.handshake['h'] = h.digest()
        pk = self.handshake['e'].public_key().serializeCompressed()
        m = b'\x00' + pk + c
        return m

    def act_two_initiator(self, m):
        v, re, c = m[0], PublicKey(m[1:34]), m[34:]
        if v != 0:
            raise ValueError("Unsupported handshake version {}, only version "
                             "0 is supported.".format(v))
        self.re = re
        h = Sha256Mixer(b'')
        h.hash = self.handshake['h']
        h.update(re.serializeCompressed())
        ee = ecdh(self.handshake['e'], re)
        self.chaining_key, self.temp_k2 = hkdf_two_keys(
            salt=self.chaining_key, ikm=ee.data
        )
        try:
            decryptWithAD(self.temp_k2, nonce(0), h.digest(), c)
        except InvalidTag:
            ValueError("Verification of tag failed.")
        h.update(c)
        self.handshake['h'] = h.digest()

    def act_three_initiator(self):
        h = Sha256Mixer(b'')
        h.hash = self.handshake['h']
        pk = self.local_pubkey.serializeCompressed()
        c = encryptWithAD(self.temp_k2, nonce(1), h.digest(), pk)
        h.update(c)
        se = ecdh(self.local_privkey, self.re)

        self.chaining_key, self.temp_k3 = hkdf_two_keys(
            salt=self.chaining_key, ikm=se.data
        )
        t = encryptWithAD(self.temp_k3, nonce(0), h.digest(), b'')
        m = b'\x00' + c + t
        t = hkdf(salt=self.chaining_key, ikm=b'', info=b'')

        self.sk, self.rk = hkdf_two_keys(salt=self.chaining_key, ikm=b'')
        self.rn, self.sn = 0, 0
        self.sck = self.chaining_key
        self.rck = self.chaining_key
        return m

    def act_three_responder(self, m):
        h = Sha256Mixer(b'')
        h.hash = self.handshake['h']
        v, c, t = m[0], m[1:50], m[50:]
        if v != 0:
            raise ValueError("Unsupported handshake version {}, only version "
                             "0 is supported.".format(v))
        rs = decryptWithAD(self.temp_k2, nonce(1), h.digest(), c)
        self.remote_pubkey = PublicKey(rs)
        h.update(c)
        se = ecdh(self.handshake['e'], self.remote_pubkey)

        self.chaining_key, self.temp_k3 = hkdf_two_keys(
            se.data, self.chaining_key
        )
        decryptWithAD(self.temp_k3, nonce(0), h.digest(), t)
        self.rn, self.sn = 0, 0

        self.rk, self.sk = hkdf_two_keys(salt=self.chaining_key, ikm=b'')
        self.sck = self.chaining_key
        self.rck = self.chaining_key


    def _maybe_rotate_keys(self):
        if self.sn == 1000:
            self.sck, self.sk = hkdf_two_keys(salt=self.sck, ikm=self.sk)
            self.sn = 0
        if self.rn == 1000:
            self.rck, self.rk = hkdf_two_keys(salt=self.rck, ikm=self.rk)
            self.rn = 0


    def recv_msg(self, msg):
        lc = msg[:18]
        if len(lc) != 18:
            raise ValueError(
                "Short read reading the message length: 18 != {}".format(
                    len(lc))
            )
        length = decryptWithAD(self.rk, nonce(self.rn), b'', lc)
        length, = struct.unpack("!H", length)
        self.rn += 1

        mc = msg[18:][:length + 16]

        if len(mc) < length + 16:
            raise ValueError(
                "Short read reading the message: {} != {}".format(
                    length + 16, len(lc)
                )
            )
        m = decryptWithAD(self.rk, nonce(self.rn), b'', mc)
        self.rn += 1
        assert(self.rn % 2 == 0)
        self._maybe_rotate_keys()
        return m

    def send_msg(self, msg):
        length = struct.pack("!H", len(msg))
        lc = encryptWithAD(self.sk, nonce(self.sn), b'', length)
        mc = encryptWithAD(self.sk, nonce(self.sn + 1), b'', msg)
        self.sn += 2
        assert(self.sn % 2 == 0)
        self._maybe_rotate_keys()
        return lc + mc


if __name__ == "__main__":
    initiator_privkey = PrivateKey(os.urandom(32))
    initiator_pubkey = initiator_privkey.public_key()
    print("initiator_privkey: %s" % initiator_privkey.rawkey.hex())
    print("initiator_pubkey:  %s" %
          initiator_pubkey.serializeCompressed().hex())
    responder_privkey = PrivateKey(os.urandom(32))
    responder_pubkey = responder_privkey.public_key()
    print("responder_privkey: %s" % responder_privkey.rawkey.hex())
    print("responder_pubkey:  %s" %
          responder_pubkey.serializeCompressed().hex())

    initiator = Bolt8Handshake(responder_pubkey, initiator_privkey, True)
    responder = Bolt8Handshake(initiator_pubkey, responder_privkey, False)

    act_one_msg = initiator.act_one_initiator()
    assert len(act_one_msg) == 50
    print("act one handshake msg: %s" % act_one_msg.hex())
    responder.act_one_responder(act_one_msg)
    act_two_msg = responder.act_two_responder()
    assert len(act_two_msg) == 50
    print("act two handshake msg: %s" % act_two_msg.hex())
    initiator.act_two_initiator(act_two_msg)
    act_three_msg = initiator.act_three_initiator()
    assert len(act_three_msg) == 66
    print("act handshake three msg: %s" % act_three_msg.hex())

    responder.act_three_responder(act_three_msg)

    msg1_send = b'deadbeef'

    print("sending: %s" % msg1_send.hex())
    ciphertext = initiator.send_msg(msg1_send)

    print("ciphertext: %s" % ciphertext.hex())

    msg1_recv = responder.recv_msg(ciphertext)
    print("recvd: %s" % msg1_recv.hex())

    assert msg1_send == msg1_recv
