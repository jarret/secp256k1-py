from cryptography.exceptions import InvalidTag
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from hashlib import sha256

from coincurve_keys import PrivateKey
from coincurve_keys import PublicKey

#############################################################################
# Bolt8 implementation
#############################################################################

class Bolt8Handshake():
    PUBLIC_KEY_CLASS = PublicKey
    PRIVATE_KEY_CLASS = PrivateKey
    def __init__(self, local_privkey):
        assert self.responder_pubkey is not None
        self.chaining_key = None
        self.handshake_hash = None
        self.local_privkey = local_privkey
        self.local_pubkey = local_privkey.public_key()
        self.init_handshake()
        self.rn, self.sn = 0, 0
        self.handshake_finished = False

    @staticmethod
    def hkdf(ikm, salt=b"", info=b""):
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=salt,
            info=info,
            backend=default_backend())
        return hkdf.derive(ikm)

    @staticmethod
    def hkdf_two_keys(ikm, salt):
        t = Bolt8Handshake.hkdf(ikm, salt)
        return t[:32], t[32:]

    @staticmethod
    def encryptWithAD(k, n, ad, plaintext):
        chacha = ChaCha20Poly1305(k)
        return chacha.encrypt(n, plaintext, ad)

    @staticmethod
    def decryptWithAD(k, n, ad, ciphertext):
        chacha = ChaCha20Poly1305(k)
        return chacha.decrypt(n, ciphertext, ad)

    @staticmethod
    def nonce(n):
        """Transforms a numeric nonce into a byte formatted one

        Nonce n encoded as 32 zero bits, followed by a little-endian 64-bit
        value. Note: this follows the Noise Protocol convention, rather than
        our normal endian.
        """
        return b'\x00' * 4 + n.to_bytes(8, byteorder="little")

    def init_handshake(self):
        h = sha256(b'Noise_XK_secp256k1_ChaChaPoly_SHA256').digest()
        self.chaining_key = h
        h = sha256(h + b'lightning').digest()
        h = sha256(h + self.responder_pubkey.to_bytes()).digest()
        self.handshake = {'h': h,
                          'e': self.PRIVATE_KEY_CLASS.new_ephemeral()}

    def _maybe_rotate_keys(self):
        if self.sn == 1000:
            self.sck, self.sk = Bolt8Handshake.hkdf_two_keys(salt=self.sck,
                                                             ikm=self.sk)
            self.sn = 0
        if self.rn == 1000:
            self.rck, self.rk = Bolt8Handshake.hkdf_two_keys(salt=self.rck,
                                                             ikm=self.rk)
            self.rn = 0

    def denoiseify(self, msg):
        assert self.handshake_finished
        lc = msg[:18]
        if len(lc) != 18:
            raise ValueError(
                "Short read reading the message length: 18 != {}".format(
                    len(lc)))
        length = Bolt8Handshake.decryptWithAD(self.rk,
                                              Bolt8Handshake.nonce(self.rn),
                                              b'', lc)
        length = length.frombytes(length, bytesorder='big')
        self.rn += 1
        mc = msg[18:][:length + 16]
        if len(mc) < length + 16:
            raise ValueError(
                "Short read reading the message: {} != {}".format(
                    length + 16, len(lc)))
        m = Bolt8Handshake.decryptWithAD(self.rk,
                                         Bolt8Handshake.nonce(self.rn), b'', mc)
        self.rn += 1
        assert(self.rn % 2 == 0)
        self._maybe_rotate_keys()
        return m

    def noiseify(self, msg):
        assert self.handshake_finished
        length = len(msg).to_bytes(2, byteorder="big")
        lc = Bolt8Handshake.encryptWithAD(self.sk,
                                          Bolt8Handshake.nonce(self.sn),
                                          b'', length)
        mc = Bolt8Handshake.encryptWithAD(self.sk,
                                          Bolt8Handshake.nonce(self.sn + 1),
                                          b'', msg)
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
        h = sha256(self.handshake['h'])
        h.update(self.handshake['e'].public_key().to_bytes())
        es = self.handshake['e'].ecdh(self.responder_pubkey)
        t = Bolt8Handshake.hkdf(salt=self.chaining_key, ikm=es, info=b'')
        assert(len(t) == 64)
        self.chaining_key, temp_k1 = t[:32], t[32:]
        c = Bolt8Handshake.encryptWithAD(temp_k1,
                                         Bolt8Handshake.nonce(0), h.digest(),
                                         b'')
        h = sha256(h.digest())
        h.update(c)
        self.handshake['h'] = h.digest()
        pk = self.handshake['e'].public_key().to_bytes()
        m = b'\x00' + pk + c
        return m

    def act_two_ingest(self, m):
        v, re, c = m[0], self.PUBLIC_KEY_CLASS(m[1:34]), m[34:]
        if v != 0:
            raise ValueError("Unsupported handshake version {}, only version "
                             "0 is supported.".format(v))
        self.re = re
        h = sha256(self.handshake['h'])
        h.update(re.to_bytes())
        ee = self.handshake['e'].ecdh(re)
        self.chaining_key, self.temp_k2 = Bolt8Handshake.hkdf_two_keys(
            salt=self.chaining_key, ikm=ee)
        try:
            Bolt8Handshake.decryptWithAD(self.temp_k2,
                                         Bolt8Handshake.nonce(0), h.digest(), c)
        except InvalidTag:
            ValueError("Verification of tag failed.")
        h = sha256(h.digest())
        h.update(c)
        self.handshake['h'] = h.digest()

    def act_three_msg(self):
        pk = self.local_pubkey.to_bytes()
        c = Bolt8Handshake.encryptWithAD(self.temp_k2, Bolt8Handshake.nonce(1),
                                         self.handshake['h'], pk)
        h = sha256(self.handshake['h'])
        h.update(c)
        se = self.local_privkey.ecdh(self.re)
        self.chaining_key, self.temp_k3 = Bolt8Handshake.hkdf_two_keys(
            salt=self.chaining_key, ikm=se)
        t = Bolt8Handshake.encryptWithAD(self.temp_k3, Bolt8Handshake.nonce(0),
                                         h.digest(), b'')
        m = b'\x00' + c + t
        self.sk, self.rk = Bolt8Handshake.hkdf_two_keys(salt=self.chaining_key,
                                                        ikm=b'')
        self.finish_handshake()
        return m

###############################################################################

class Bolt8Responder(Bolt8Handshake):
    def __init__(self, privkey):
        self.responder_pubkey = privkey.public_key()
        self.remote_pubkey = None
        super().__init__(privkey)

    def act_one_ingest(self, m):
        v, re, c = m[0], self.PUBLIC_KEY_CLASS(m[1:34]), m[34:]
        if v != 0:
            raise ValueError("Unsupported handshake version {}, only version "
                             "0 is supported.".format(v))
        h = sha256(self.handshake['h'])
        h.update(re.to_bytes())
        es = self.local_privkey.ecdh(re)
        self.handshake['re'] = re
        t = Bolt8Handshake.hkdf(salt=self.chaining_key, ikm=es, info=b'')
        self.chaining_key, temp_k1 = t[:32], t[32:]
        try:
            Bolt8Handshake.decryptWithAD(temp_k1, Bolt8Handshake.nonce(0),
                                         h.digest(), c)
        except InvalidTag:
            ValueError("Verification of tag failed, remote peer doesn't know "
                       "our node ID.")
        h = sha256(h.digest())
        h.update(c)
        self.handshake['h'] = h.digest()

    def act_two_msg(self):
        h = sha256(self.handshake['h'])
        h.update(self.handshake['e'].public_key().to_bytes())
        ee = self.handshake['e'].ecdh(self.handshake['re'])
        t = Bolt8Handshake.hkdf(salt=self.chaining_key, ikm=ee, info=b'')
        assert(len(t) == 64)
        self.chaining_key, self.temp_k2 = t[:32], t[32:]
        c = Bolt8Handshake.encryptWithAD(self.temp_k2, Bolt8Handshake.nonce(0),
                                         h.digest(), b'')
        h = sha256(h.digest())
        h.update(c)
        self.handshake['h'] = h.digest()
        pk = self.handshake['e'].public_key().to_bytes()
        m = b'\x00' + pk + c
        return m

    def act_three_ingest(self, m):
        v, c, t = m[0], m[1:50], m[50:]
        if v != 0:
            raise ValueError("Unsupported handshake version {}, only version "
                             "0 is supported.".format(v))
        rs = Bolt8Handshake.decryptWithAD(self.temp_k2, Bolt8Handshake.nonce(1),
                                          self.handshake['h'], c)
        self.remote_pubkey = self.PUBLIC_KEY_CLASS(rs)
        h = sha256(self.handshake['h'])
        h.update(c)
        se = self.handshake['e'].ecdh(self.remote_pubkey)
        self.chaining_key, self.temp_k3 = Bolt8Handshake.hkdf_two_keys(
            se, self.chaining_key)
        Bolt8Handshake.decryptWithAD(self.temp_k3, Bolt8Handshake.nonce(0),
                                     h.digest(), t)
        self.rk, self.sk = Bolt8Handshake.hkdf_two_keys(salt=self.chaining_key,
                                                        ikm=b'')
        self.finish_handshake()
