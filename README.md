# packet-shooter

**Serverless End-to-End Encrypted Chat Over Raw UDP**

Two peers, A STUN lookup, A direct encrypted tunnel.  No account, No server, No relay to trust.

![Version](https://img.shields.io/badge/version-1.0.0-brightgreen)
![License](https://img.shields.io/badge/license-MIT-blue)
![Language](https://img.shields.io/badge/language-Python_3.9+-yellow)
![Crypto](https://img.shields.io/badge/crypto-X25519_%2B_ChaCha20--Poly1305-purple)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)

[Quick Start](#-quick-start) • [Why packet-shooter?](#why-packet-shooter) • [Security Model](#-security-model) • [Architecture](#️-architecture) • [Reference](#-reference) • [Limitations](#-known-limitations)

---

packet-shooter connects two peers **directly** over UDP. no middle server, ever. It punches through NATs, authenticates the key exchange, and encrypts every message with modern AEAD cryptography, all from a full-screen terminal UI.

---

## why packet-shooter?

- 🔐 **[true end-to-end encryption](#-cryptographic-core)** — X25519 key exchange + ChaCha20-Poly1305 AEAD, with directional subkeys so the two peers never share a key+nonce pair
- 🕵️ **no relay, no server, no logs** — messages go straight from your socket to your peer's; there's no third machine in between that could log or leak anything
- 🧾 **no accounts, no signup** — the only "identity" is an ephemeral keypair generated fresh for the session
- 👁️ **[mandatory fingerprint confirmation](#️-handshake-authentication-anti-mitm)** — the chat will not unlock until you explicitly confirm the derived key fingerprint matches what your peer sees
- 🛡️ **[optional passphrase-authenticated handshake](#️-handshake-authentication-anti-mitm)** — closes the active-MITM window a bare key exchange leaves open
- 🔁 **[replay-resistant, tamper-evident](#-replay-protection)** — every message is authenticated and sequence-checked
- 🕳️ **[DNS-filtering-resistant STUN + continuous hole punching](#️-nat-traversal)** — stays connected even through restrictive networks

---

## 🚀 Quick Start

### install dependencies

```
pip install textual cryptography
```

### run

```
python3 p2pchat_tui.py
```

### what happens next

1. you're asked for a **local port** (like `55000`).
2. the tool queries STUN and shows **your public IP:PORT** — send this to your peer over any channel (phone call, SMS, email, whatever).
3. you enter **your peer's public IP:PORT** (they send you theirs the same way).
4. *(OPTIONAL BUT RECOMMENDED)* you enter a **shared passphrase** agreed on beforehand, which cryptographically authenticates the handshake against active interception.
5. the tool performs the key exchange and shows a **fingerprint**; compare it with your peer over that separate channel. **you must confirm it matches before the chat unlocks.**
>‌ NOT RECOMMENDED but you can confirm and check it in first message in the app.
6. the full-screen chat opens. hole punching keeps running in the background to keep the path open.

> **note:** both peers need to be reachable via UDP hole punching. see [known limitations](#-known-limitations) for the one case this doesn't cover yet.

### in-chat keys

| key | action |
| --- | --- |
| `Enter` | send message |
| `/exit`, `exit`, `/quit`, `quit` | quit |
| `Ctrl+C` | quit immediately |

---

## ✨ features

### 🔐 cryptographic core
- **X25519 (ECDH)** — each session generates a fresh, ephemeral keypair; nothing reused across sessions
- **HKDF-SHA256 directional key derivation** — two independent subkeys (`initiator→responder`, `responder→initiator`) instead of one shared key, so each direction of the conversation uses its own key and nonce space. this rules out the nonce-reuse bug class that naive "one shared key" P2P designs run into
- **ChaCha20-Poly1305 AEAD** — every message is encrypted and authenticated in one step; tampered ciphertext is rejected outright, never silently corrupted
- **message padding** — plaintext is length-prefixed and padded to fixed 64-byte blocks before encryption, so an observer watching ciphertext sizes on the wire learns only a size bucket, not the exact length
- **fingerprint-based verification** — a short, human-comparable code derived from *both* directional keys combined, so a match proves both sides really landed on the same secret, not just that they swapped plausible-looking public keys

### 🛡️ handshake authentication (anti-MITM)
- **optional pre-shared passphrase** — if you and your peer agree on one beforehand over any side channel, handshake packets are authenticated with HMAC-SHA256. an attacker without the passphrase cannot forge a valid handshake packet
- **mandatory fingerprint confirmation** — even without a passphrase, the tool will not proceed into chat until you explicitly type `y` to confirm the fingerprint matches. there's no silent bypass
- **deterministic role assignment** — initiator/responder roles fall out of a plain comparison of the two public keys, so both sides agree on directional key assignment with no extra round-trip

### 🔁 replay protection
a sliding anti-replay window (1024 messages wide) tracks the highest sequence number seen and rejects:

- any sequence number far older than the current window (stale/replayed)
- any sequence number already seen once (exact replay)

this mirrors the anti-replay approach used in IPsec and TLS.

### 🧱 reliability layer over UDP
raw UDP drops and reorders packets, so a lightweight ACK/retransmit layer sits directly on top of the encryption layer:

- every data packet is retried up to 8 times, 1 second apart, until acknowledged
- ACKs are sent even for packets that turn out to be replays. a lost ACK shouldn't make a legitimate retransmit look like an attack
- no connection state machine beyond the crypto handshake, just enough reliability to make chat usable

### 🕳️ NAT traversal
- **layered STUN fallback** — tries Google/Cloudflare first, then a community-maintained live server list fetched from GitHub, then a hardcoded static IP list, then secondary hostnames. resilient to DNS-level blocking of any single provider
- **continuous background hole punching** — sends lightweight, unencrypted `P` packets to keep the NAT mapping alive, backing off to a slow keepalive once the peer is confirmed reachable

### 🚧 abuse resistance
- **rate-limited decryption attempts** — a token-bucket limiter caps how many invalid/undecryptable packets are processed per time window, so a flood of forged ciphertext can't burn unlimited CPU forcing decryption attempts
- **input validation on setup** — port prompts retry on bad input instead of crashing

---

## 🔒 security model

### what this tool protects against

| threat | mitigation |
| --- | --- |
| **passive eavesdropping** | end-to-end AEAD encryption (ChaCha20-Poly1305); a network observer sees only ciphertext |
| **active MITM during key exchange** | optional passphrase-authenticated handshake (HMAC-SHA256) + mandatory fingerprint confirmation |
| **message tampering** | AEAD authentication tag; modified ciphertext fails to decrypt and is dropped |
| **replay attacks** | sliding anti-replay window on the message sequence counter |
| **nonce reuse between peers** | independent directional keys derived via HKDF; the two peers never share a key+nonce pair |
| **traffic analysis on message length** | fixed-block padding before encryption |
| **garbage-packet flooding** | rate-limited decryption attempts |
| **DNS-level STUN blocking** | layered fallback across multiple providers, hostnames, and hardcoded IPs |

### what this tool does *not* protect against

| limitation | notes |
| --- | --- |
| **no forward secrecy within a session** | the session's X25519 keypair is ephemeral per-run but not ratcheted per-message. compromise of that key while the session is still open exposes that session's traffic |
| **IP address exposure** | inherent to any direct P2P tool; your peer learns your public IP. pair with a VPN if that's a concern for your threat model |
| **endpoint compromise** | if either device is compromised, the conversation is compromised — no chat tool can fix this |
| **metadata: that you're chatting, and roughly when** | STUN queries and UDP hole-punch traffic are visible to a network observer even though content is encrypted |
| **symmetric NAT breaks hole punching** | see [known limitations](#-known-limitations) for details and the fallback options being worked on. |

> **bottom line:** the cryptography here (X25519 + ChaCha20-Poly1305 + HKDF) is standard and solid. the weakest link in any P2P handshake is the manual exchange of addresses and keys. that's exactly why the passphrase authentication and mandatory fingerprint confirmation exist. use them.

---

## 🏗️ architecture

```
   Peer A                                              Peer B
     │                                                    │
     │──── 1. STUN query (layered fallback) ────▶  STUN Server
     │◀─── public IP:port ────────────────────────────────│
     │                                                    │
     │            (manual exchange of IP:port,            │
     │             out-of-band, e.g. Telegram/SMS)         │
     │                                                    │
     │──── 2. Handshake: X25519 pubkey (+ optional HMAC) ─▶│
     │◀─── Handshake: X25519 pubkey (+ optional HMAC) ─────│
     │                                                    │
     │   3. HKDF-SHA256 derives TWO directional keys:     │
     │      key_i2r  (initiator → responder)              │
     │      key_r2i  (responder → initiator)               │
     │                                                    │
     │──── 4. Fingerprint shown, user confirms match ─────│
     │            (out-of-band verification)               │
     │                                                    │
     │═══ 5. Encrypted chat (ChaCha20-Poly1305) ══════════│
     │      + ACK/retransmit reliability layer             │
     │      + anti-replay window                           │
     │      + background hole-punch keepalive               │
     ▼                                                    ▼
```

| component | role |
| --- | --- |
| **`p2pcore.py`** | STUN client, `CryptoSession` (X25519/HKDF/ChaCha20-Poly1305), `ReplayGuard`, `RateLimiter`, `SecureReliableChannel` (ACK/retransmit + hole punching), handshake + shared interactive setup |
| **`p2pchat_tui.py`** | full-screen `textual` `Application` (`ChatApp`) — status bar, confirmed-fingerprint bar, scrolling chat log, input line |

### packet formats (post-handshake)

| type | format | purpose |
| --- | --- | --- |
| `D` (data) | `b"D" + seq(4B) + ciphertext` | encrypted chat message |
| `A` (ACK) | `b"A" + seq(4B)` | acknowledges receipt of a `D` packet |
| `P` (punch) | `b"P"` | unencrypted NAT keepalive, no payload |
| `X` (exit) | `b"X"` | unencrypted graceful-disconnect signal, sent when a peer exits cleanly (Ctrl+C or `/exit`) |
| `H` (handshake) | `b"H" + pubkey(32B)` **or** `b"H" + pubkey(32B) + hmac_tag(32B)` | key exchange, with optional passphrase authentication |

---

## 📖 reference

### interactive setup prompts

```
#===== IP:PORT Exchange =====#
local port to use (like 55000):
>>> send this information to the other party: <your_public_ip>:<your_public_port>
peer's public IP:
peer's public PORT:

#===== OPTIONAL PassPhrase =====#
shared passphrase (optional):
```

### fingerprint confirmation (mandatory)

```
#===== FingerPrint Verification (Important) =====#
[*] shared key fingerprint: XXXX-XXXX-XXXX-XXXX-XXXX
    compare this code with the peer over a separate channel
    ONLY CONTINUE IF IT MATCHES EXACTLY.

does this fingerprint match what the peer sees? [y/n]:
```

answering anything other than `y`/`yes` aborts the connection.

### the TUI screen (`ChatApp`)

| element | shows |
| --- | --- |
| status frame | border title shows `WAITING` / `CONNECTED` / `DISCONNECTED`; three columns inside show your address (green), peer's address (blue), and the fingerprint (purple) |
| chat log | timestamped messages from you (`ME >`), your peer (`PEER >`), and system status lines (`*`) |
| input line | where you type; `Enter` sends |

connection status flips to `CONNECTED` only once a real decrypted chat message is received from the peer. a bare hole-punch keepalive packet is 'WAITING' status and is not enough. hole punching runs in a background thread from the start, independent of the UI.

### key `p2pcore.py` functions (for embedding/scripting)

```python
from p2pcore import (
    setup_connection,             # full interactive setup: port, STUN, peer address, passphrase, handshake
    confirm_fingerprint_or_raise, # blocks until user confirms fingerprint; raises RuntimeError on mismatch
    SecureReliableChannel,        # encrypted, reliable, replay-protected channel; takes on_message/on_status/on_disconnect callbacks
    CryptoSession,                # X25519 keypair + directional AEAD encrypt/decrypt
    perform_handshake,            # lower-level handshake if you want to skip the interactive prompts
    HandshakeAuthError,           # raised when a pre-shared passphrase check fails
    get_public_endpoint,          # raw STUN lookup
)
```

---

## 💻 system requirements

| requirement | details |
| --- | --- |
| **python** | 3.9+ |
| **dependencies** | `textual`, `cryptography` |
| **OS** | Linux, macOS, Windows (anywhere Python + these two packages run) |
| **network** | UDP outbound/inbound on your chosen local port; STUN access (UDP/3478 and friends) |
| **RAM** | negligible. no history buffer beyond the visible scrollback |

---

## 📁 files

| file | purpose |
| --- | --- |
| `p2pcore.py` | shared core: STUN client, cryptography (`CryptoSession`), replay protection (`ReplayGuard`), rate limiting (`RateLimiter`), reliable encrypted channel (`SecureReliableChannel`), handshake (`perform_handshake`), interactive setup (`setup_connection`, `confirm_fingerprint_or_raise`) |
| `p2pchat_tui.py` | full-screen TUI front-end (`ChatApp` class) |

no configuration files, no logs, no database. nothing is written to disk.

---

## ⚠️ known limitations

- **no forward secrecy within a session** — one X25519 keypair per run, no per-message or periodic ratcheting.
- **availability under symmetric NAT** — some carrier-grade NATs (CGNAT, common on mobile data) assign a different outbound port per destination. if the affected peer has access to their own Wi-Fi/router, manual port forwarding (or a better method if we find one) is being considered as a fallback, and we're actively testing and documenting this route. for anyone with no router/Wi-Fi access at all, the tool currently can't be used. we're working on finding a way to address this case too.
- **the live STUN list fetch is unauthenticated** — plain HTTPS fetch of a public GitHub list, used only as a lowest-priority fallback. a tampered entry can at worst mislead address discovery, not the encrypted chat itself.
- **`P` (punch) packets are unauthenticated by design** — they carry no data, so spoofing them can only create NAT-state noise, not message compromise.
- **the anti-replay window is fixed at 1024** — a legitimate but very late/reordered packet older than the window is rejected rather than delivered.
- **everything hinges on the user actually doing the fingerprint check** — the software can't verify a human did their part correctly.
- **a sudden/unclean disconnect (crash, network drop) is not detected** — only a clean exit (Ctrl+C or `/exit`) sends a disconnect signal to the peer. if the other side just vanishes without exiting cleanly, the UI stays in `CONNECTED` state with no timeout to catch it.

---

## ⚠️ disclaimer

this is an independent tool built around standard, well-reviewed cryptographic primitives (the `cryptography` library's implementations of X25519, HKDF, and ChaCha20-Poly1305). it has **not** undergone a formal third-party security audit. review the source yourself before relying on it for anything where the stakes are high, and treat the security model section above as the actual scope of what it protects against, not marketing copy.

---

## 📄 license

MIT license.
