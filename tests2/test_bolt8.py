from coincurve_keys import PrivateKey as CcPrivateKey
from coincurve_keys import PublicKey as CcPublicKey
from secp256k1_keys import PrivateKey as Secp256k1PrivateKey
from secp256k1_keys import PublicKey as Secp256k1PublicKey
from bolt8 import Bolt8Initiator, Bolt8Responder

###############################################################################

def do_handshake(pubclass, privclass):
    Bolt8Initiator.PUBLIC_KEY_CLASS = pubclass
    Bolt8Initiator.PRIVATE_KEY_CLASS = privclass
    Bolt8Responder.PUBLIC_KEY_CLASS = pubclass
    Bolt8Responder.PRIVATE_KEY_CLASS = privclass

    rs_priv = privclass.from_hex(
        '2121212121212121212121212121212121212121212121212121212121212121')
    rs_pub = rs_priv.public_key()
    assert (rs_pub.to_hex() ==
        '028d7500dd4c12685d1f568b4c2b5048e8534b873319f3a8daa612b469132ec7f7')

    ls_priv = privclass.from_hex(
        '1111111111111111111111111111111111111111111111111111111111111111')
    ls_pub = ls_priv.public_key()
    assert (ls_pub.to_hex() ==
        '034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa')

    initiator = Bolt8Initiator(rs_pub, ls_priv)
    # override random ephemeral key
    initiator.handshake['e'] = privclass.from_hex(
        '1212121212121212121212121212121212121212121212121212121212121212')
    assert (initiator.handshake['e'].public_key().to_hex() ==
        '036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f7')

    responder = Bolt8Responder(rs_priv)
    # override random ephemeral key
    responder.handshake['e'] = privclass.from_hex(
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

def test_handshake():
    classes = [(CcPublicKey, CcPrivateKey),
               (Secp256k1PublicKey, Secp256k1PrivateKey)]
    for pubclass, privclass in classes:
        do_handshake(pubclass, privclass)


###############################################################################


def do_read_key_rotation(pubclass, privclass):
    Bolt8Initiator.PUBLIC_KEY_CLASS = pubclass
    Bolt8Initiator.PRIVATE_KEY_CLASS = privclass
    Bolt8Responder.PUBLIC_KEY_CLASS = pubclass
    Bolt8Responder.PRIVATE_KEY_CLASS = privclass

    ls_priv = privclass.from_hex(
        '1111111111111111111111111111111111111111111111111111111111111111')
    rs_priv = privclass.from_hex(
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

def test_read_key_rotation():
    classes = [(CcPublicKey,  CcPrivateKey),
               (Secp256k1PublicKey, Secp256k1PrivateKey)]
    for pubclass, privclass in classes:
        do_read_key_rotation(pubclass, privclass)
