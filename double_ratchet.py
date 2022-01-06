import base64

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_parameters
from paho.mqtt import client as mqtt_client
import threading
import sys
from datetime import datetime
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import cryptography.hazmat.primitives.serialization as serialization
import json

# MQTT client.
client = mqtt_client.Client()

# Initial (shared) Root key (128 bits = 16 bytes). The value has been generated randomly.
rk = b'\x91SI\xef\xd8\xae\xb69kt\x17\x92&J\xbf\x99'

# Initial simulated AD byte sequence (128 bytes = 16 bytes). The value has been generated randomly.
ad = b'\xcf\xe8m\xd4\xb4\xfa\xcb,\xa8\x1a\x0bJX\x88\x00\xe8'


class State:
    def __init__(self):
        # Only Bob (OUT) generates DH parameters. Then, he sends them to Alice (IN),
        # so parameters are common for both.
        if self_tag == "out":
            self.DHparams = dh.generate_parameters(generator=2, key_size=1024)
        else:
            self.DHparams = None
        self.DHs = None  # DH Ratchet key pair (the "sending" or "self" ratchet key)
        self.DHr = None  # DH Ratchet public key (the "received" or "remote" key)
        self.RK = None  # 32-byte R oot Key
        self.CKs = None  # 32-byte Chain Key for sending
        self.CKr = None  # 32-byte Chain Key for receiving
        self.Ns = None  # Message number for sending
        self.Nr = None  # Message number for receiving
        self.PN = None  # Number of messages in previous sending chain


# Creates a new message header containing the DH
# ratchet public key from the key pair in "dh_pair", the previous chain length
# "pn", and the message number n.
class Header:
    def __init__(self, dh_pk, pn, n):
        self.dh = dh_pk  # DH Public key
        self.pn = pn  # Number of messages in previous sending chain
        self.n = n  # Message number for this message


# Callable for making instances of Header class.
def make_header(dh_pk, pn, n):
    return Header(dh_pk, pn, n)


# Create a dictionary containing the current header and a message.
def header_and_msg_to_dict(header, msg):
    return {
        "dh": header.dh.public_bytes(serialization.Encoding.PEM,
                                     serialization.PublicFormat.SubjectPublicKeyInfo).decode(),
        "pn": str(header.pn),
        "n": str(header.n),
        "msg": msg
    }


# Encodes a message header into a parseable byte sequence, prepends the ad byte sequence, and returns the result.
def concat(header):
    dh_public_key_as_bytes = header.dh.public_bytes(serialization.Encoding.PEM,
                                                    serialization.PublicFormat.SubjectPublicKeyInfo)
    pn_as_bytes = header.pn.to_bytes(2, byteorder='big')
    n_as_bytes = header.n.to_bytes(2, byteorder='big')
    return ad + dh_public_key_as_bytes + pn_as_bytes + n_as_bytes


# Ratchet D-H keys using HKDF. RK (Root key) is used as salt, and dh_secret_key calculated from self's private key &
# partners' public key is the input of the function. This function returns both 128bit root key and 128bit chain key.
def kdf_rk(root_key, dh_secret_key):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=root_key,
        info=None,
    )
    derived_key = hkdf.derive(dh_secret_key)
    return derived_key[0:16], derived_key[16:32]


# Init ratchet state for both parties.
# 'out_dh_key' equals to Martin.out's key pair for Martin.out and equals to Martin.out's public key for Martin.in
def ratchet_init(state, out_dh_key):
    if self_tag == "in":
        state.DHs = state.DHparams.generate_private_key()  # generate_dh()
        state.DHr = out_dh_key
        state.RK, state.CKs = kdf_rk(rk, diffie_hellman(state.DHs, state.DHr))
        state.CKr = None
        state.Ns = 0
        state.Nr = 0
        state.PN = 0
    else:
        state.DHs = out_dh_key  # generate_dh()
        state.DHr = None
        state.RK = rk
        state.CKs = None
        state.CKr = None
        state.Ns = 0
        state.Nr = 0
        state.PN = 0


# Ratchet Diffie-Hellman
def diffie_hellman(dh_self_private_key, dh_partner_public_key):
    return dh_self_private_key.exchange(dh_partner_public_key)


# Encrypt messages. First perform a symmetric-key ratchet step, then encrypt the message with the resulting message key.
def ratchet_encrypt(state, plaintext):
    state.CKs, mk = kdf_ck(state.CKs)
    header = make_header(state.DHs.public_key(), state.PN, state.Ns)
    state.Ns += 1
    return header, encrypt(mk, plaintext, concat(header))


# AEAD encrypt a message msg with message key mk.
def encrypt(mk, plaintext, associated_data):
    aesgcm = AESGCM(mk)
    # Nonce fixed to a (generated randomly) constant because each message key is only used once.
    nonce = b'410063020'
    ct = aesgcm.encrypt(nonce, plaintext.encode(), associated_data)
    return str(base64.urlsafe_b64encode(ct), encoding='utf-8')


# Decrypt messages.
def ratchet_decrypt(state, header, ciphertext):
    # If user currently doesn't have partners' PK
    # or received PK doesn't match the current partner's key contained in current state, ratchet DH updating it.
    if state.DHr is None:
        dh_ratchet(state, header)
    else:
        header_dh_to_str = str(header.dh.public_bytes(serialization.Encoding.PEM,
                                                      serialization.PublicFormat.SubjectPublicKeyInfo),
                               encoding='utf-8')
        state_dhr_to_str = str(state.DHr.public_bytes(serialization.Encoding.PEM,
                                                      serialization.PublicFormat.SubjectPublicKeyInfo),
                               encoding='utf-8')

        if header_dh_to_str != state_dhr_to_str:
            dh_ratchet(state, header)

    state.CKr, mk = kdf_ck(state.CKr)
    state.Nr += 1
    return decrypt(mk, ciphertext, concat(header))


# AEAD decrypt a ciphertext ct with message key mk.
def decrypt(mk, ciphertext, associated_data):
    aesgcm = AESGCM(mk)
    # Nonce fixed to a (generated randomly) constant because each message key is only used once.
    nonce = b'410063020'
    msg = aesgcm.decrypt(nonce, base64.urlsafe_b64decode(bytes(ciphertext, encoding='utf-8')), associated_data)
    return msg.decode()


# Perform an update of the receiver's root key and their receiving
# chain key incorporating the ratchet public key value included in the header
# of the received message.
def dh_ratchet(state, header):
    state.PN = state.Ns
    state.Ns = 0
    state.Nr = 0
    state.DHr = header.dh
    state.RK, state.CKr = kdf_rk(state.RK, diffie_hellman(state.DHs, state.DHr))
    state.DHs = state.DHparams.generate_private_key()
    state.RK, state.CKs = kdf_rk(state.RK, diffie_hellman(state.DHs, state.DHr))


# Ratchet symmetric keys (chain keys) using HMAC with SHA-256, using ck as the HMAC key and
# using separate constants as input (e.g. a single byte 0x01 as input to
# produce the message key, and a single byte 0x02 as input to produce the next
# chain key.)
def kdf_ck(ck):
    h = hmac.HMAC(ck, hashes.SHA256())
    h.update(b"0x01")
    h_copy = h.copy()
    h_copy.update(b'0x02')
    mk = h.finalize()
    ck = h_copy.finalize()
    return ck, mk


# Behaviour on MQTT client connection.
def on_connect(cli, userdata, flags, rc):
    if rc == 0:
        print("Connected to MQTT broker! Your identifier: " + name + "." + self_tag)
        if self_tag == "in":
            print("Wait for Martin.out to start the Double Ratchet ping-pong.")
            print("Then start typing text directly in the console to send messages!")
        # Subscribe to partner's channel.
        client.subscribe(name + "." + partner_tag)

        # Connection has been made. Initialize DH key pair to start the interaction.

        # Bob (OUT) sends the first message with its DH public key to Alice (IN)
        # and the DH Parameters (that must be common to both parties)
        if self_tag == "out":
            dh_private_key = double_ratchet_state.DHparams.generate_private_key()
            dh_public_key = dh_private_key.public_key()
            # Public key: PEM with classic format: [-----BEGIN PUBLIC KEY-----...-----END PUBLIC KEY-----].
            dh_public_key_pem = dh_public_key.public_bytes(serialization.Encoding.PEM,
                                                           serialization.PublicFormat.SubjectPublicKeyInfo)
            dh_parameters_pem = double_ratchet_state.DHparams.parameter_bytes(serialization.Encoding.PEM,
                                                                              serialization.ParameterFormat.PKCS3)
            data = {
                "dh_public_start": dh_public_key_pem.decode(),
                "dh_parameters_start": dh_parameters_pem.decode()
            }
            out = json.dumps(data)
            client.publish("Martin." + self_tag, out)

            # Now both parties agreed on root key and self's ratchet public key. Time to initialize ratchet!
            ratchet_init(double_ratchet_state, dh_private_key)

            # At this point Bob (OUT) is ready to receive messages from Alice (IN)

    else:
        print("Failed to connect! Return code: " + str(rc))


# Behaviour on MQTT message received.
def on_message(cli, userdata, msg):
    print("[" + datetime.now().strftime("%d/%m/%Y %H:%M:%S") + "] " + msg.topic + ": " + msg.payload.decode())

    # Detect first message containing partners' DH public key and DH parameters and add them to own state.
    # After that, calculate the shared key.
    if "dh_public_start" in msg.payload.decode():
        data = json.loads(msg.payload.decode())
        dhr_public_key_pem = data["dh_public_start"].encode()
        dhr_public_key = load_pem_public_key(dhr_public_key_pem)
        dhr_params_pem = data["dh_parameters_start"].encode()
        dhr_params = load_pem_parameters(dhr_params_pem)
        double_ratchet_state.DHparams = dhr_params  # Set params in state. Only needed to be done once.

        # Now both parties agreed on root key and partner's ratchet public key. Time to initialize ratchet!
        ratchet_init(double_ratchet_state, dhr_public_key)

        # At this point Alice (IN) is ready to start chatting to Bob (OUT).
        # Alice (IN) sends the first message automatically to start the conversation
        # and to definitely initialize the double ratchet scenario.
        a1 = "Test message"
        a1_header, a1_ct = ratchet_encrypt(double_ratchet_state, a1)
        out = json.dumps(header_and_msg_to_dict(a1_header, a1_ct))
        client.publish("Martin." + self_tag, out)

    # General behaviour: decrypt and ratchet after a message is received (for both ends)
    if "msg" in msg.payload.decode():
        data = json.loads(msg.payload.decode())
        received_header = make_header(load_pem_public_key(data["dh"].encode()), int(data["pn"]), int(data["n"]))
        plaintext = ratchet_decrypt(double_ratchet_state, received_header, data["msg"])
        print("DECRYPTED MESSAGE: " + plaintext)


# Behaviour on MQTT message published.
def on_publish(cli, userdata, result):
    pass


# Connect and maintain the connection established.
def connect_and_subscribe():
    client.on_connect = on_connect
    client.on_message = on_message
    client.on_publish = on_publish

    client.connect("<MQTT server IP>")
    client.loop_forever()


# Main function
if __name__ == '__main__':

    if len(sys.argv) != 2:
        print("ERROR: Wrong arguments.")
        print("CORRECT SYNTAX: python3 double_ratchet.py <role>")
        print("<role> must be 'in' for the first execution of the program and 'out' for the second.")
        sys.exit()

    name = "Martin"
    self_tag = "out"
    partner_tag = "in"

    # Is this client IN or OUT?
    if str(sys.argv[1]) == "in":
        self_tag = "in"
        partner_tag = "out"

    else:
        if str(sys.argv[1]) == "out":
            self_tag = "out"
            partner_tag = "in"
        else:
            print("ERROR: Wrong role.")
            print("AVAILABLE CHAT ROLES: 'in' (must be executed first) or 'out' (must be executed after)")
            sys.exit()

    # Initial State Object (Empty)

    double_ratchet_state = State()

    # Separate thread for dealing with MQTT output. Main process used for keyboard input.
    subscription_thread = threading.Thread(target=connect_and_subscribe)
    subscription_thread.start()

    # Loop executed when input is entered in console.
    while True:
        message = input()
        msg_header, msg_ct = ratchet_encrypt(double_ratchet_state, message)
        data_out = json.dumps(header_and_msg_to_dict(msg_header, msg_ct))
        client.publish("Martin." + self_tag, data_out)
