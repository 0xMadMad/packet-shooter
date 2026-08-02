"""
#============================ unresaan - v1.0.0 ============================#
includes:
  - STUN resistant to DNS filtering
  - manual X25519 (ECDH) key exchange + fingerprint to prevent MITM
  - optional pre-shared passphrase to authenticate the handshake
    (protects against an active man-in-the-middle during key exchange,
    not just a passive eavesdropper)
  - directional keys (separate send/receive keys) to avoid nonce reuse
    between the two peers
  - AEAD encryption with ChaCha20-Poly1305 (unique nonce per message)
  - fixed-size message padding to reduce traffic analysis
  - replay attack protection (anti-replay window on message counter)
  - reliability layer over UDP (ACK/Retransmit)
  - continuous UDP hole punching in the background
  - basic rate limiting against forged/garbage packet floods

requirements: pip install prompt_toolkit cryptography
"""

import socket           # TCP/UDP networking (UDP in here)
import struct           # pack/unpack data into/from binary
import threading        # run multiple threads at same time (multi task)
import time
import os
import hmac             # authentication (handshake authentication)
import hashlib          # hash functions (sha256 on fingerprint & generate HMAC-key from passpharse)
import urllib.request   # http requests (STUN list download)

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,   # private key
    X25519PublicKey,    # public key
)
from cryptography.hazmat.primitives import serialization                    # keys to byte (public key to 32byte)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF                    # generate encryption key based on shared secret
from cryptography.hazmat.primitives.hashes import SHA256                    # sha256 hash function
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305    # authenticated encryption



# ================== STUN server list (prioritized) ==================

STUN_PRIMARY = [
    ("stun.l.google.com", 19302),
    ("stun1.l.google.com", 19302),
    ("stun2.l.google.com", 19302),
    ("stun.cloudflare.com", 3478),
]


STATIC_STUN_IPS = [
    ("136.243.59.79", 3478),
    ("45.15.102.34", 3478),
    ("34.195.177.19", 3478),
    ("52.47.70.236", 3478),
    ("212.53.40.40", 3478),
    ("5.161.52.174", 3478),
    ("185.125.180.70", 3478),
    ("88.99.67.241", 3478),
]


STUN_SECONDARY_HOSTNAMES = [
    ("stun.antisip.com", 3478),
    ("stun.voipbuster.com", 3478),
    ("stun.miwifi.com", 3478),
]


LIVE_LIST_URL = "https://raw.githubusercontent.com/pradt2/always-online-stun/master/valid_ipv4s.txt"

def fetch_live_stun_ips(timeout=2.0, limit=6):
    """
    best-effort fetch of a community-maintained list of live STUN servers.
    this is an external, unauthenticated source used only as a last-resort
    fallback (after STUN_PRIMARY and STATIC_STUN_IPS). a malicious entry
    here can at worst mislead public-address discovery; it cannot decrypt
    or tamper with the end-to-end encrypted chat, since that key exchange
    is independent of STUN.
    """
    try:
        req = urllib.request.Request(LIVE_LIST_URL, headers={"User-Agent": "curl/8"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            text = resp.read().decode("utf-8", errors="ignore")
        result = []
        for line in text.strip().splitlines()[:limit]:
            line = line.strip()
            if ":" not in line:
                continue
            ip, port_str = line.rsplit(":", 1)
            try:
                result.append((ip, int(port_str)))
            except ValueError:
                continue
        return result
    except Exception:
        return []



# ================== Raw STUN client (RFC 5389) ==================

STUN_MAGIC_COOKIE = 0x2112A442
STUN_BINDING_REQUEST = 0x0001
ATTR_XOR_MAPPED_ADDRESS = 0x0020
ATTR_MAPPED_ADDRESS = 0x0001


def _build_stun_request(tx_id: bytes) -> bytes:
    return struct.pack("!HHI12s", STUN_BINDING_REQUEST, 0, STUN_MAGIC_COOKIE, tx_id)


def _parse_stun_response(data: bytes, tx_id: bytes):
    if len(data) < 20:
        return None
    msg_type, msg_len, cookie, resp_tx_id = struct.unpack("!HHI12s", data[:20])
    if resp_tx_id != tx_id:
        return None
    body = data[20:20 + msg_len]
    offset = 0
    while offset + 4 <= len(body):
        attr_type, attr_len = struct.unpack("!HH", body[offset:offset + 4])
        attr_value = body[offset + 4: offset + 4 + attr_len]
        if attr_type == ATTR_XOR_MAPPED_ADDRESS and len(attr_value) >= 8:
            xport = struct.unpack("!H", attr_value[2:4])[0]
            port = xport ^ (STUN_MAGIC_COOKIE >> 16)
            xaddr = struct.unpack("!I", attr_value[4:8])[0]
            ip = socket.inet_ntoa(struct.pack("!I", xaddr ^ STUN_MAGIC_COOKIE))
            return ip, port
        elif attr_type == ATTR_MAPPED_ADDRESS and len(attr_value) >= 8:
            port = struct.unpack("!H", attr_value[2:4])[0]
            ip = socket.inet_ntoa(attr_value[4:8])
            return ip, port
        padded_len = attr_len + (4 - attr_len % 4) % 4
        offset += 4 + padded_len
    return None


def get_public_endpoint(sock: socket.socket, per_try_timeout: float = 1.5, log=print):
    candidates = list(STUN_PRIMARY)
    candidates += fetch_live_stun_ips()
    candidates += STATIC_STUN_IPS
    candidates += STUN_SECONDARY_HOSTNAMES

    last_error = None
    for host, port in candidates:
        try:
            tx_id = os.urandom(12)
            sock.settimeout(per_try_timeout)
            sock.sendto(_build_stun_request(tx_id), (host, port))
            data, _ = sock.recvfrom(2048)
            result = _parse_stun_response(data, tx_id)
            if result:
                log(f"[STUN] response received from {host}:{port}")
                return result
        except (socket.timeout, OSError, socket.gaierror) as e:
            last_error = e
            continue
    raise RuntimeError(f"no STUN server responded. last error: {last_error}")



# ================== Encryption: X25519 key exchange + AEAD ==================

class CryptoSession:
    """
    an encrypted session between two parties.

    steps:
        - each party generates an ephemeral X25519 key pair

        - each party manually sends its public key (along with its address)
          to the other party. If a pre-shared passphrase was agreed on
          beforehand (over a separate channel), the handshake packet is
          also authenticated with an HMAC so an active attacker who does
          not know the passphrase cannot forge a valid handshake

        - both parties see a short "fingerprint" of the derived shared key
          and must explicitly confirm it matches what the other party sees,
          comparing over a separate channel (phone call, another messaging
          app), to catch a MITM if no passphrase was used

        - a shared secret is derived via ECDH. two directional subkeys
          (one for each direction) are then derived from it via HKDF, so
          the two peers never encrypt with the same key+nonce pair.

        - each message is encrypted and authenticated with a unique counter
          (nonce), and padded to a fixed block size to reduce the amount of
          information a network observer can infer from ciphertext length.
    """

    # 12bytes len required by ChaCha20-Poly1305 (RFC8439 standard)
    NONCE_LEN = 12

    # messages are padded to a multiple of this size (bytes) before encryption
    # to reduce traffic-analysis leakage from ciphertext length
    PAD_BLOCK = 64

    def __init__(self):
        self.private_key = X25519PrivateKey.generate()  # fresh key per session, never reused between chats (but stays the same for the whole session, no per-message rotation yet)
        self.public_key = self.private_key.public_key()  # generates 32bytes public key (object) based on private key (to share with peer)
        self.send_aead = None                # left unset until derive_shared_key() runs after a successful handshake (after we get peer public key)
        self.recv_aead = None                # "
        self._shared_key_fingerprint = None  # "

    def public_bytes(self) -> bytes:
        """
        converts X25519 public key object into its 32bytes raw form,
        so it can be shared over the network
        """
        return self.public_key.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)

    def fingerprint(self) -> str:
        """
        returns short and readable fingerprint for manual comparison (anti-MITM)
        this is computed from the *derived shared key* (available only
        after derive_shared_key), not just the local public key, so a
        match confirms both parties really landed on the same shared
        secret rather than just exchanging plausible-looking keys.
        """
        if self._shared_key_fingerprint is None:
            raise RuntimeError("shared key has not been derived yet.")
        return self._shared_key_fingerprint

    def derive_shared_key(self, peer_public_bytes:bytes, am_initiator:bool):
        """
        am_initiator must be True for exactly one side and False for the
        other (determined deterministically by comparing public keys, see
        perform_handshake), so both sides agree on which subkey is used
        for which direction without any extra negotiation.
        """
        
        peer_public_key = X25519PublicKey.from_public_bytes(peer_public_bytes)  # convert peer's raw public-key bytes into X25519 public-key object
        shared_secret = self.private_key.exchange(peer_public_key)  # compute shared secret by X25519 ECDH(using own private key and peer's public key) 

        my_pub = self.public_bytes()
        keys_sorted = sorted([my_pub, peer_public_bytes])  # sorts by byte values
        base_info = b"p2pchat|" + keys_sorted[0] + keys_sorted[1]  # so both peers feed HKDF with the same context => same derived key => successful handshake

        # split the one shared_secret into two separate keys, one per direction
        # "initiator->responder" and "responder->initiator" are fixed labels
        key_i2r = HKDF(algorithm=SHA256(), length=32, salt=None, info=base_info + b"|i2r").derive(shared_secret)
        key_r2i = HKDF(algorithm=SHA256(), length=32, salt=None, info=base_info + b"|r2i").derive(shared_secret)

        # both sides compute the same two keys and each side just picks which one is send/recv for itself.
        if am_initiator:
            send_key, recv_key = key_i2r, key_r2i
        else:
            send_key, recv_key = key_r2i, key_i2r

        self.send_aead = ChaCha20Poly1305(send_key)  # AEAD instance used only for outgoing messages
        self.recv_aead = ChaCha20Poly1305(recv_key)  # AEAD instance used only for incoming messages

        combined = key_i2r + key_r2i  # combine two keys
        digest = hashlib.sha256(combined).hexdigest().upper()  # creates a fingerprint of them
        groups = [digest[i:i + 4] for i in range(0, 20, 4)]  # picks first 20 characters and grouped with 4 length
        self._shared_key_fingerprint = "-".join(groups)  # separate with -
        # ==> a short and readable fingerprint for manual comparison

    @staticmethod  # no dependency on self
    def _pad(plaintext:bytes) -> bytes:
        """
        store the real-length+message first, then pad with zero bytes up to the next 64-byte block
        so ciphertext length reveals only a bucket, not the exact size
        """
        length_prefix = struct.pack("!I", len(plaintext))  # plain:"hello" -> len=5 -> length_prefix=00 00 00 05
        body = length_prefix + plaintext
        remainder = len(body) % CryptoSession.PAD_BLOCK  # remaining bytes after dividing by PAD_BLOCK
        if remainder != 0:
            body += b"\x00" * (CryptoSession.PAD_BLOCK - remainder)  # pad with zero bytes until the total length becomes a multiple of PAD_BLOCK
        return body  # ready to encrypt

    @staticmethod  # no dependency on self
    def _unpad(padded:bytes) -> bytes:
        """
        read the stored length back, then strip off the padding
        """
        if len(padded) < 4:  # at least 4bytes for the length..
            raise ValueError("padded message too short.")
        (length,) = struct.unpack("!I", padded[:4])  # length=NUM (unpacked the returned tuple on the go)
        return padded[4:4+length]  # skip the 4-byte length prefix and return only the original plaintext
        # ready to decrypt 

    def encrypt(self, seq:int, plaintext:bytes) -> bytes:
        """
        encrypts and pads one message. seq must be a number that goes up by
        one every time and is never reused, it's what makes each message's
        nonce unique
        """
        if self.send_aead is None:  # raise instead of encrypt with None object
            raise RuntimeError("shared key has not been derived yet.")
        nonce = seq.to_bytes(self.NONCE_LEN, "big")  # turn the seq number into the 12-byte nonce
        padded = self._pad(plaintext)  # pad the plaintext
        return self.send_aead.encrypt(nonce, padded, None)  # encrypt and appends an auth tag

    def decrypt(self, seq:int, ciphertext:bytes) -> bytes:
        """
        decrypts one message and checks it wasn't tampered with. seq must be
        the same number the sender used for this message, a wrong seq acts
        just like a wrong key and the decryption fails
        """
        if self.recv_aead is None:  # raise instead of decrypt with None object
            raise RuntimeError("shared key has not been derived yet.")
        nonce = seq.to_bytes(self.NONCE_LEN, "big")
        padded = self.recv_aead.decrypt(nonce, ciphertext, None)
        return self._unpad(padded)


class ReplayGuard:
    """
    replay attack protection: anti-replay window on the message counter (seq)
    similar to the anti-replay mechanism in IPsec/TLS
      - messages with a seq much older than the highest seq seen are rejected
      - each seq is accepted only once; a repeat (even if valid) is rejected
    """

    WINDOW_SIZE = 1024

    def __init__(self):
        self.highest_seq = -1  # no seq at start (real seq starts at 0)
        self.seen_bitmap = set()  # all seen seqs (set() because each seq is unique, set() gives O(1) at checks)
        self.lock = threading.Lock()  # only one thread can call

    def check_and_update(self, seq:int) -> bool:
        """True if the message is fresh and acceptable; False if it should be rejected (replay/old)"""
        with self.lock:  # only one thread at one time
            if seq > self.highest_seq:
                self.highest_seq = seq
                self.seen_bitmap.add(seq)
                cutoff = self.highest_seq - self.WINDOW_SIZE  # anything at or below this is now too old (outside the window)
                if len(self.seen_bitmap) > self.WINDOW_SIZE * 2:  # ensures it does not become INF, control it's size
                    self.seen_bitmap = {s for s in self.seen_bitmap if s > cutoff}
                return True
            if seq <= self.highest_seq - self.WINDOW_SIZE:
                return False  # too old, outside the window
            if seq in self.seen_bitmap:
                return False  # already seen -> replay
            self.seen_bitmap.add(seq)  # maybe it's not repetitive, it's just out of order (it's UDP!)
            return True


class RateLimiter:
    """
    simple token-bucket-ish limiter to blunt floods of garbage/forged
    packets (e.g. many 'D' packets with invalid ciphertext, which would
    otherwise each cost a decryption attempt).
    """

    def __init__(self, max_events:int, per_seconds:float):
        self.max_events = max_events  # how many events are allowed
        self.per_seconds = per_seconds  # inside this many seconds
        self.events = []  
        self.lock = threading.Lock()  # only one thread can call at one time

    def allow(self) -> bool:
        now = time.time()
        with self.lock:
            cutoff = now - self.per_seconds  # anything older than this doesn't count anymore
            self.events = [t for t in self.events if t > cutoff]  # drop the old ones, keep only recent
            if len(self.events) >= self.max_events:
                return False  # already at the limit, reject
            self.events.append(now)  # record this one and allow it
            return True



# ================== Reliability layer + encryption over UDP ==================

class SecureReliableChannel:
    """
    reliability layer (ACK/Retransmit) + AEAD encryption + anti-replay.

    packet formats (after handshake):
      type 'D' (Data):  b"D" + seq(4 bytes) + ciphertext
      type 'A' (Ack):   b"A" + seq(4 bytes)
      type 'P' (Punch): b"P"        -- unencrypted, only used to keep the NAT open

    note: 'P' messages carry no data, so they don't need encryption.
    """

    # max invalid/undecryptable data packets accepted per window before further ones are silently dropped without even attempting decryption
    INVALID_PACKET_LIMIT = 20
    INVALID_PACKET_WINDOW = 5.0

    def __init__(self, sock, peer_addr, crypto:CryptoSession, on_message, on_status=None):
        self.sock = sock
        self.peer_addr = peer_addr
        self.crypto = crypto  # must already have a completed handshake
        self.on_message = on_message
        self.on_status = on_status or (lambda *_: None)

        self.send_seq = 0  # counter for outgoing messages, starts at 0
        self.pending = {}  # {seq: [packet, timestamp, tries]}, unacked messages, a list so entry[1]/entry[2] can be updated in place
        self.lock = threading.Lock()
        self.running = True  # flips to False with stop(), all loops check this
        self.peer_seen = threading.Event()  # set the moment ANY packet arrives from peer, even a punch packet

        # separate instance per channel, each chat session tracks its own replay/rate-limit state
        self.replay_guard = ReplayGuard()
        self._invalid_limiter = RateLimiter(self.INVALID_PACKET_LIMIT, self.INVALID_PACKET_WINDOW)

        threading.Thread(target=self._receiver_loop, daemon=True).start()
        threading.Thread(target=self._retransmit_loop, daemon=True).start()

    def send(self, text:str):
        """encrypts text and sends it, keeps it in pending until acked"""
        with self.lock:
            seq = self.send_seq
            self.send_seq += 1
            ciphertext = self.crypto.encrypt(seq, text.encode("utf-8"))
            packet = b"D" + struct.pack("!I", seq) + ciphertext
            self.pending[seq] = [packet, time.time(), 0]
        self.sock.sendto(packet, self.peer_addr)

    def _receiver_loop(self):
        """runs forever, handles D/A/P packets as they arrive"""
        while self.running:
            try:
                self.sock.settimeout(1.0)  # this loop rechecks running every 1s instead of blocking forever
                data, addr = self.sock.recvfrom(65535)  # maximum reads 65535bytes (maximum length of an UDP packet) 
            except socket.timeout:  # nothing came in this round, just loop back and check running again
                continue
            except OSError:  # socket closed elsewhere, exit the loop entirely
                break
            if len(data) < 1:  # empty packet, can't even read the type byte
                continue

            if addr == self.peer_addr:
                self.peer_seen.set()  # set before checking packet type, even a bare punch packet counts as "peer is reachable"

            kind = data[0:1]
            if kind == b"P":  # arriving is the whole point
                continue  # nothing else to do
            elif kind == b"D" and len(data) >= 5:
                seq = struct.unpack("!I", data[1:5])[0]
                ciphertext = data[5:]

                # always send an ACK so the sender knows the packet arrived (even if it's a replay)
                self.sock.sendto(b"A" + struct.pack("!I", seq), addr)

                if not self.replay_guard.check_and_update(seq):
                    continue  # too old or already seen

                if not self._invalid_limiter.allow():
                    continue  # too many bad packets recently, drop without spending more CPU on decryption attempts until the window clears

                try:
                    plaintext = self.crypto.decrypt(seq, ciphertext)
                except Exception:
                    self.on_status(f"[Warning] an invalid/tampered packet was dropped (seq={seq})")
                    continue

                text = plaintext.decode("utf-8", errors="ignore")
                self.on_message(text, addr)

            elif kind == b"A" and len(data) >= 5:
                seq = struct.unpack("!I", data[1:5])[0]
                with self.lock:
                    self.pending.pop(seq, None)  # if it's ACK, pops seq from pending list (pop because it ignores errors if seq was deleted before)

    def _retransmit_loop(self):
        """checks all pendings"""
        while self.running:
            time.sleep(0.5)
            now = time.time()
            with self.lock:
                for seq, entry in list(self.pending.items()):  # use list() to work on copy, because may pops from pending inside this same loop
                    packet, ts, tries = entry
                    if now - ts > 1.0: # try every one second
                        if tries >= 8: # for 8 tries  (+1 try to see the condition is not met)
                            self.pending.pop(seq, None)  # gives up silently
                            continue
                        self.sock.sendto(packet, self.peer_addr)  # retry
                        entry[1] = now
                        entry[2] = tries + 1

    def start_background_punch(self, active_interval=1.5, idle_keepalive_interval=20.0):
        """sends P packets to keep the NAT path open"""
        def loop():
            while self.running:
                self.sock.sendto(b"P", self.peer_addr)
                if self.peer_seen.is_set():  # peer already confirmed reachable, just a slow keep alive now
                    time.sleep(idle_keepalive_interval)
                else:                        # still trying to open the path, punch more often
                    time.sleep(active_interval)

        threading.Thread(target=loop, daemon=True).start()  # creates a thread with loop to keep connection alive

    def wait_for_peer(self, timeout=None):
        """blocks until something arrives from the peer, or timeout runs out"""
        return self.peer_seen.wait(timeout=timeout)

    def stop(self):
        """just flips running to False, threads notice on their own"""
        self.running = False


# ================== Key exchange handshake (before creating SecureReliableChannel) ==================

class HandshakeAuthError(Exception):
    """raised when a pre-shared passphrase was set but the peer's
    handshake packet did not carry a matching authentication tag,
    meaning either a typo'd passphrase or a potential active attacker"""
    pass


def perform_handshake(sock, peer_addr, crypto:CryptoSession, timeout=30.0, passphrase:str=None, log=print):
    """
    exchange X25519 public keys over the same UDP socket, before starting
    the encrypted chat. handshake packets are marked with a b"H" prefix
    so they aren't confused with chat packets (which start with
    b"D"/b"A"/b"P")

    if `passphrase` is provided (agreed with the peer beforehand over a
    separate channel), each handshake packet also carries an HMAC-SHA256
    tag computed with a key derived from that passphrase. a peer that
    doesn't know the same passphrase cannot produce a valid tag, so an
    active attacker without the passphrase cannot inject a forged public
    key into the exchange. if `passphrase` is left as None, the exchange
    falls back to being unauthenticated (only the post-handshake
    fingerprint comparison protects against MITM)

    both parties repeatedly send their own public key until they receive
    the other party's key; this happens simultaneously with initial hole
    punching

    returns True if the local side's public key sorts first, used to
    deterministically assign "initiator" vs "responder" roles for
    directional key derivation, without any extra negotiation
    """
    my_pub = crypto.public_bytes()

    mac_key = None
    if passphrase:
        mac_key = hashlib.sha256(b"p2pchat-hs-auth|" + passphrase.encode("utf-8")).digest()
        # passphrase itself never goes on the wire, only this derived key does

    if mac_key:
        tag = hmac.new(mac_key, my_pub, hashlib.sha256).digest()
        packet = b"H" + my_pub + tag
    else:
        packet = b"H" + my_pub

    received_pub = {"value":None}
    stop_flag = threading.Event()  # tells sender_loop to stop, set once we get the peer's key
    auth_failed = threading.Event()  # set if we saw a packet with a wrong tag

    def sender_loop():
        while not stop_flag.is_set():
            sock.sendto(packet, peer_addr)
            time.sleep(0.5)  # resend every 0.5s until the peer answers, or we give up

    t = threading.Thread(target=sender_loop, daemon=True)
    t.start()

    start = time.time()
    sock.settimeout(0.5)
    while time.time() - start < timeout:
        try:
            data, addr = sock.recvfrom(65535)
        except socket.timeout:
            continue
        if addr != peer_addr:  # not from who we're trying to reach, ignore
            continue
        if data[0:1] != b"H":  # not a handshake packet
            continue

        if mac_key:
            # expect: b"H" + 32-byte pubkey + 32-byte HMAC tag
            if len(data) != 1 + 32 + 32:  # wrong size for an authenticated packet, ignore
                continue
            candidate_pub = data[1:33]
            candidate_tag = data[33:65]
            expected_tag = hmac.new(mac_key, candidate_pub, hashlib.sha256).digest()
            if not hmac.compare_digest(candidate_tag, expected_tag): # wrong/missing passphrase on the other side, or a forged packet from an attacker who doesn't know the passphrase
                auth_failed.set()
                continue  # keep listening, might just be one bad packet
            received_pub["value"] = candidate_pub
            break
        else:
            if len(data) != 33:  # wrong size for an unauthenticated packet, ignore
                continue
            received_pub["value"] = data[1:]
            break

    stop_flag.set()  # tell sender_loop to stop resending
    t.join(timeout=1.0)

    if received_pub["value"] is None:
        if mac_key and auth_failed.is_set():
            raise HandshakeAuthError(
                "received handshake packets with an invalid authentication tag. "
                "check that both sides entered the same passphrase and that no third party is interfering with the connection."
            )
        raise TimeoutError("key exchange handshake failed (no response received from peer)")

    peer_pub = received_pub["value"]
    am_initiator = my_pub < peer_pub  # deterministic, same conclusion on both sides
    crypto.derive_shared_key(peer_pub, am_initiator=am_initiator)
    log("[*] Key exchange complete; the channel is now encrypted.")
    return am_initiator


def setup_connection(prompt_passphrase:bool=True, log=print):
    """
    shared interactive setup used by both the CLI and TUI front-ends:
      1) ask for a local port (with input validation/retry)
      2) bind a UDP socket and discover the public endpoint via STUN
      3) ask for the peer's public address
      4) optionally ask for a pre-shared passphrase to authenticate the
         handshake against active MITM attempts
      5) perform the encrypted key-exchange handshake

    returns (sock, peer_addr, crypto, my_addr_str)
    raises HandshakeAuthError or TimeoutError if the handshake fails
    """
    local_port = _prompt_int("local port to use (like 55000): ")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", local_port))

    log("[*] getting public address from STUN...")
    ip, port = get_public_endpoint(sock)
    my_addr_str = f"{ip}:{port}"
    log(f"\n>>> send this information to the other party: {my_addr_str}\n")

    peer_ip = input("peer's public IP: ").strip()
    peer_port = _prompt_int("peer's public PORT: ")
    peer_addr = (peer_ip, peer_port)

    passphrase = None
    if prompt_passphrase:
        print(
            "\n[*] optional: if you and the peer already agreed on a shared "
            "     passphrase over a separate channel, entering it here will "
            "     authenticate the key exchange against active interception.\n"
            " LEAVE EMPTY TO SKIP (you can still verify the fingerprint manually afterwards) "
        )
        entered = input("shared passphrase (optional): ").strip()
        passphrase = entered if entered else None

    crypto = CryptoSession()
    log("\n[*] exchanging encryption key with the peer (please wait)...")
    perform_handshake(sock, peer_addr, crypto, timeout=60.0, passphrase=passphrase, log=log)

    return sock, peer_addr, crypto, my_addr_str


def confirm_fingerprint_or_raise(crypto: CryptoSession):
    """
    blocks until the user explicitly confirms the fingerprint matches what
    the peer sees. raises RuntimeError if they say it doesn't, so callers
    can abort the connection instead of silently continuing into a
    possibly MITM'd chat.
    """
    print("\n==================== Security Verification (Important) ====================")
    print(f"shared key fingerprint: {crypto.fingerprint()}")
    print("compare this code with the peer over a separate channel (phone call,")
    print("another messaging app, etc.), ONLY CONTINUE IF IT MATCHES EXACTLY.")
    print("==============================================================\n")
    answer = input("does this fingerprint match what the peer sees? [y/n]: ").strip().lower()
    if answer not in ("y", "yes"):
        raise RuntimeError(
            "fingerprint not confirmed by the user. aborting the connection "
            "as a precaution against a possible man-in-the-middle."
        )


def _prompt_int(message: str) -> int:
    """input() + int() with retry on invalid entries, instead of crashing."""
    while True:
        raw = input(message).strip()
        try:
            return int(raw)
        except ValueError:
            print("please enter a valid whole number.")

# _678