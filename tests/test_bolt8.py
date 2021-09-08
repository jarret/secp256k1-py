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
# cosmetically different, but nitty gritty borrowed from:
#   https://github.com/ElementsProject/lightning/blob/master/contrib/pyln-proto/pyln/proto/wire.py
#############################################################################

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
                          'e': PrivateKey.new_ephemeral()}

    def _maybe_rotate_keys(self):
        if self.sn == 1000:
            self.sck, self.sk = Bolt8Handshake.hkdf_two_keys(salt=self.sck, ikm=self.sk)
            self.sn = 0
        if self.rn == 1000:
            self.rck, self.rk = Bolt8Handshake.hkdf_two_keys(salt=self.rck, ikm=self.rk)
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
        v, re, c = m[0], PublicKey(m[1:34]), m[34:]
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
        v, re, c = m[0], PublicKey(m[1:34]), m[34:]
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
        self.remote_pubkey = PublicKey(rs)
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


def test_read_key_rotation():
    ls_priv = PrivateKey.from_hex(
        '1111111111111111111111111111111111111111111111111111111111111111')
    rs_priv = PrivateKey.from_hex(
        '2121212121212121212121212121212121212121212121212121212121212121')
    rs_pub = rs_priv.public_key()

    initiator = Bolt8Initiator(rs_pub, ls_priv)
    # fake the handshake completed by just setting the values
    # ck=0x919219dbb2920afa8db80f9a51787a840bcf111ed8d588caf9ab4be716e42b01
    # sk=0x969ab31b4d288cedf6218839b27a3e2140827047f2c0f01bf5c04435d43511a9
    # rk=0xbb9020b8965f4df047e07f955f3c4b88418984aadc5cdb35096b9ea8fa5c3442
    initiator.chaining_key = bytes.fromhex(
        '919219dbb2920afa8db80f9a51787a840bcf111ed8d588caf9ab4be716e42b01')
    initiator.sk = bytes.fromhex(
        '969ab31b4d288cedf6218839b27a3e2140827047f2c0f01bf5c04435d43511a9')
    initiator.rk = bytes.fromhex(
        'bb9020b8965f4df047e07f955f3c4b88418984aadc5cdb35096b9ea8fa5c3442')
    initiator.sn, initiator.rn = 0, 0
    initiator.sck = initiator.chaining_key
    initiator.rck = initiator.chaining_key
    initiator.handshake_finished = True

    msg = bytes.fromhex('68656c6c6f')
    noise_msg = initiator.noiseify(msg)
    assert (noise_msg.hex() ==
        'cf2b30ddf0cf3f80e7c35a6e6730b59fe802473180f396d88a8fb0db8cbcf25d2f214'
        'cf9ea1d95')

    # Send 498 more messages, to get just below the switch threshold
    for i in range(0, 498):
        noise_msg = initiator.noiseify(msg)
    # Check the last send key against the test vector
    assert (initiator.sk.hex() ==
        '969ab31b4d288cedf6218839b27a3e2140827047f2c0f01bf5c04435d43511a9')

    # This next message triggers the rotation:
    noise_msg = initiator.noiseify(msg)

    # Now try to send with the new keys:
    noise_msg = initiator.noiseify(msg)
    assert (noise_msg.hex() ==
        '178cb9d7387190fa34db9c2d50027d21793c9bc2d40b1e14dcf30ebeeeb220f48364f'
        '7a4c68bf8')

    noise_msg = initiator.noiseify(msg)
    assert (noise_msg.hex() ==
        '1b186c57d44eb6de4c057c49940d79bb838a145cb528d6e8fd26dbe50a60ca2c104b5'
        '6b60e45bd')

    for i in range(0, 498):
        noise_msg = initiator.noiseify(msg)

    noise_msg = initiator.noiseify(msg)
    assert (noise_msg.hex() ==
           '4a2f3cc3b5e78ddb83dcb426d9863d9d9a723b0337c89dd0b005d89f8d3c05c52b'
           '76b29b740f09')

    noise_msg = initiator.noiseify(msg)
    assert (noise_msg.hex() ==
        '2ecd8c8a5629d0d02ab457a0fdd0f7b90a192cd46be5ecb6ca570bfc5e268338b1a16'
        'cf4ef2d36')
