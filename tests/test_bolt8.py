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
# cosmetically different, but nitty gritty borrowed from:
#   https://github.com/ElementsProject/lightning/blob/master/contrib/pyln-proto/pyln/proto/wire.py
#############################################################################

#############################################################################
# crypto utlities
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

#############################################################################

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

#############################################################################
# coincurve-depends stuff
#############################################################################

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
        a = k.ecdh(rk.public_key)
        return Secret(a)

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


#############################################################################
# Bolt8 implementation
#############################################################################

class Bolt8Handshake():
    def __init__(self, local_privkey):
        assert self.responder_pubkey is not None
        self.chaining_key = None
        self.handshake_hash = None
        self.local_privkey = local_privkey
        self.local_pubkey = local_privkey.public_key()
        self.init_handshake()
        self.rn, self.sn = 0, 0
        self.handshake_finished = False

    def init_handshake(self):
        h = sha256(b'Noise_XK_secp256k1_ChaChaPoly_SHA256').digest()
        self.chaining_key = h
        h = sha256(h + b'lightning').digest()
        h = sha256(h + self.responder_pubkey.to_bytes()).digest()
        self.handshake = {'h': h,
                          'e': PrivateKey.new_ephemeral()}

    def _maybe_rotate_keys(self):
        if self.sn == 1000:
            self.sck, self.sk = hkdf_two_keys(salt=self.sck, ikm=self.sk)
            self.sn = 0
        if self.rn == 1000:
            self.rck, self.rk = hkdf_two_keys(salt=self.rck, ikm=self.rk)
            self.rn = 0

    def denoiseify(self, msg):
        assert self.handshake_finished
        lc = msg[:18]
        if len(lc) != 18:
            raise ValueError(
                "Short read reading the message length: 18 != {}".format(
                    len(lc)))
        length = decryptWithAD(self.rk, nonce(self.rn), b'', lc)
        length, = struct.unpack("!H", length)
        self.rn += 1
        mc = msg[18:][:length + 16]
        if len(mc) < length + 16:
            raise ValueError(
                "Short read reading the message: {} != {}".format(
                    length + 16, len(lc)))
        m = decryptWithAD(self.rk, nonce(self.rn), b'', mc)
        self.rn += 1
        assert(self.rn % 2 == 0)
        self._maybe_rotate_keys()
        return m

    def noiseify(self, msg):
        assert self.handshake_finished
        length = struct.pack("!H", len(msg))
        lc = encryptWithAD(self.sk, nonce(self.sn), b'', length)
        mc = encryptWithAD(self.sk, nonce(self.sn + 1), b'', msg)
        self.sn += 2
        assert(self.sn % 2 == 0)
        self._maybe_rotate_keys()
        return lc + mc

    def finish_handshake(self):
        self.rn, self.sn = 0, 0
        self.sck = self.chaining_key
        self.rck = self.chaining_key
        self.handshake_finished = True

###############################################################################

class Bolt8Initiator(Bolt8Handshake):
    def __init__(self, responder_pubkey, privkey):
        self.responder_pubkey = responder_pubkey
        super().__init__(privkey)

    def act_one_msg(self):
        h = Sha256Mixer(b'')
        h.hash = self.handshake['h']
        h.update(self.handshake['e'].public_key().to_bytes())
        es = self.handshake['e'].ecdh(self.responder_pubkey)
        t = hkdf(salt=self.chaining_key, ikm=es.data, info=b'')
        assert(len(t) == 64)
        self.chaining_key, temp_k1 = t[:32], t[32:]
        c = encryptWithAD(temp_k1, nonce(0), h.digest(), b'')
        self.handshake['h'] = h.update(c)
        pk = self.handshake['e'].public_key().to_bytes()
        m = b'\x00' + pk + c
        return m

    def act_two_ingest(self, m):
        v, re, c = m[0], PublicKey(m[1:34]), m[34:]
        if v != 0:
            raise ValueError("Unsupported handshake version {}, only version "
                             "0 is supported.".format(v))
        self.re = re
        h = Sha256Mixer(b'')
        h.hash = self.handshake['h']
        h.update(re.to_bytes())
        ee = self.handshake['e'].ecdh(re)
        self.chaining_key, self.temp_k2 = hkdf_two_keys(
            salt=self.chaining_key, ikm=ee.data)
        try:
            decryptWithAD(self.temp_k2, nonce(0), h.digest(), c)
        except InvalidTag:
            ValueError("Verification of tag failed.")
        h.update(c)
        self.handshake['h'] = h.digest()

    def act_three_msg(self):
        h = Sha256Mixer(b'')
        h.hash = self.handshake['h']
        pk = self.local_pubkey.to_bytes()
        c = encryptWithAD(self.temp_k2, nonce(1), h.digest(), pk)
        h.update(c)
        se = self.local_privkey.ecdh(self.re)
        self.chaining_key, self.temp_k3 = hkdf_two_keys(
            salt=self.chaining_key, ikm=se.data)
        t = encryptWithAD(self.temp_k3, nonce(0), h.digest(), b'')
        m = b'\x00' + c + t
        self.sk, self.rk = hkdf_two_keys(salt=self.chaining_key, ikm=b'')
        self.finish_handshake()
        return m

###############################################################################

class Bolt8Responder(Bolt8Handshake):
    def __init__(self, privkey):
        self.responder_pubkey = privkey.public_key()
        self.remote_pubkey = None
        super().__init__(privkey)

    def act_one_ingest(self, m):
        v, re, c = m[0], PublicKey(m[1:34]), m[34:]
        if v != 0:
            raise ValueError("Unsupported handshake version {}, only version "
                             "0 is supported.".format(v))
        h = Sha256Mixer(b'')
        h.hash = self.handshake['h']
        h.update(re.to_bytes())
        es = self.local_privkey.ecdh(re)
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

    def act_two_msg(self):
        h = Sha256Mixer(b'')
        h.hash = self.handshake['h']
        h.update(self.handshake['e'].public_key().to_bytes())
        ee = self.handshake['e'].ecdh(self.handshake['re'])
        t = hkdf(salt=self.chaining_key, ikm=ee.data, info=b'')
        assert(len(t) == 64)
        self.chaining_key, self.temp_k2 = t[:32], t[32:]
        c = encryptWithAD(self.temp_k2, nonce(0), h.digest(), b'')
        h.update(c)
        self.handshake['h'] = h.digest()
        pk = self.handshake['e'].public_key().to_bytes()
        m = b'\x00' + pk + c
        return m

    def act_three_ingest(self, m):
        h = Sha256Mixer(b'')
        h.hash = self.handshake['h']
        v, c, t = m[0], m[1:50], m[50:]
        if v != 0:
            raise ValueError("Unsupported handshake version {}, only version "
                             "0 is supported.".format(v))
        rs = decryptWithAD(self.temp_k2, nonce(1), h.digest(), c)
        self.remote_pubkey = PublicKey(rs)
        h.update(c)
        se = self.handshake['e'].ecdh(self.remote_pubkey)
        self.chaining_key, self.temp_k3 = hkdf_two_keys(se.data,
                                                        self.chaining_key)
        decryptWithAD(self.temp_k3, nonce(0), h.digest(), t)
        self.rk, self.sk = hkdf_two_keys(salt=self.chaining_key, ikm=b'')
        self.finish_handshake()


###############################################################################

def test_handshake():
    rs_priv = PrivateKey.from_hex(
        '2121212121212121212121212121212121212121212121212121212121212121')
    rs_pub = rs_priv.public_key()
    assert (rs_pub.to_hex() ==
        '028d7500dd4c12685d1f568b4c2b5048e8534b873319f3a8daa612b469132ec7f7')

    ls_priv = PrivateKey.from_hex(
        '1111111111111111111111111111111111111111111111111111111111111111')
    ls_pub = ls_priv.public_key()
    assert (ls_pub.to_hex() ==
        '034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa')

    initiator = Bolt8Initiator(rs_pub, ls_priv)
    # override random ephemeral key
    initiator.handshake['e'] = PrivateKey.from_hex(
        '1212121212121212121212121212121212121212121212121212121212121212')
    assert (initiator.handshake['e'].public_key().to_hex() ==
        '036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f7')

    responder = Bolt8Responder(rs_priv)
    # override random ephemeral key
    responder.handshake['e'] = PrivateKey.from_hex(
        '2222222222222222222222222222222222222222222222222222222222222222')
    assert (responder.handshake['e'].public_key().to_hex() ==
        '02466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27')


    assert (initiator.handshake['h'].hex() ==
        '8401b3fdcaaa710b5405400536a3d5fd7792fe8e7fe29cd8b687216fe323ecbd')
    assert initiator.handshake['h'] == responder.handshake['h']

    # act one
    act_one_msg = initiator.act_one_msg()
    assert (act_one_msg.hex() ==
        '00036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f7'
        '0df6086551151f58b8afe6c195782c6a')

    responder.act_one_ingest(act_one_msg)
    assert (initiator.handshake['h'].hex() ==
           '9d1ffbb639e7e20021d9259491dc7b160aab270fb1339ef135053f6f2cebe9ce')
    assert (initiator.handshake['h'] == responder.handshake['h'])

    assert (initiator.chaining_key.hex() ==
        'b61ec1191326fa240decc9564369dbb3ae2b34341d1e11ad64ed89f89180582f')
    assert (responder.chaining_key.hex() ==
        'b61ec1191326fa240decc9564369dbb3ae2b34341d1e11ad64ed89f89180582f')

    # act two
    act_two_msg = responder.act_two_msg()
    assert (act_two_msg.hex() ==
        '0002466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27'
        '6e2470b93aac583c9ef6eafca3f730ae')
    assert (responder.handshake['h'].hex() ==
       '90578e247e98674e661013da3c5c1ca6a8c8f48c90b485c0dfa1494e23d56d72')


    initiator.act_two_ingest(act_two_msg)
    assert (initiator.handshake['h'].hex() ==
        '90578e247e98674e661013da3c5c1ca6a8c8f48c90b485c0dfa1494e23d56d72')

    assert (initiator.chaining_key.hex() ==
        'e89d31033a1b6bf68c07d22e08ea4d7884646c4b60a9528598ccb4ee2c8f56ba')
    assert (responder.chaining_key.hex() ==
        'e89d31033a1b6bf68c07d22e08ea4d7884646c4b60a9528598ccb4ee2c8f56ba')

    # act three
    act_three_msg = initiator.act_three_msg()
    assert (act_three_msg.hex() ==
        '00b9e3a702e93e3a9948c2ed6e5fd7590a6e1c3a0344cfc9d5b57357049aa2235536'
        '1aa02e55a8fc28fef5bd6d71ad0c38228dc68b1c466263b47fdf31e560e139ba')
    assert (initiator.sk.hex() ==
        '969ab31b4d288cedf6218839b27a3e2140827047f2c0f01bf5c04435d43511a9')
    assert (initiator.rk.hex() ==
        'bb9020b8965f4df047e07f955f3c4b88418984aadc5cdb35096b9ea8fa5c3442')
    responder.act_three_ingest(act_three_msg)

    # final state
    assert (initiator.rk == responder.sk)
    assert (initiator.sk == responder.rk)
    assert (initiator.sn == responder.rn)
    assert (initiator.rn == responder.sn)
    assert (responder.rk.hex() ==
        '969ab31b4d288cedf6218839b27a3e2140827047f2c0f01bf5c04435d43511a9')
    assert (responder.sk.hex() ==
        'bb9020b8965f4df047e07f955f3c4b88418984aadc5cdb35096b9ea8fa5c3442')

    assert (initiator.chaining_key == responder.chaining_key)
    assert (initiator.chaining_key.hex() ==
        '919219dbb2920afa8db80f9a51787a840bcf111ed8d588caf9ab4be716e42b01')
