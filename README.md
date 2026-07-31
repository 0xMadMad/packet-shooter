# packet-shooter

**Serverless End-to-End Encrypted Chat Over Raw UDP**

No account, No servers, No relay to trust.  just two peers, a STUN lookup, and a direct encrypted tunnel.

![Version](https://img.shields.io/badge/version-2.0-brightgreen)
![License](https://img.shields.io/badge/license-MIT-blue)
![Language](https://img.shields.io/badge/language-Python_3.9+-orange)
![Crypto](https://img.shields.io/badge/crypto-X25519_%2B_ChaCha20--Poly1305-purple)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)

[quick start](#-quick-start) • [features](#-features) • [security model](#-security-model) • [comparison](#-comparison) • [architecture](#️-architecture)

---

packet-shooter is a dependency-light chat tool that connects two peers **directly** over UDP. it punches through NATs, authenticates the key exchange, gives you a TUI terminal, and encrypts every message with modern AEAD cryptography.

```
pip install prompt_toolkit cryptography
python3 p2pchat_tui.py
```

---

## why packet-shooter?

most "secure" chat tools ask you to trust a server operator, a phone number, or a corporate account system. but packet-shooter doesn't:

- 🔐 **true end-to-end encryption** — X25519 key exchange + ChaCha20-Poly1305 AEAD, with **directional subkeys** so the two peers never share a key+nonce pair
- 🕵️ **no relay, no server, no logs** — your messages go directly from your socket to peer's; there is no third machine in between that could log, retain, or leak anything
- 🧾 **no accounts, no phone numbers, no signup** — the only "identity" is an ephemeral cryptographic keypair generated fresh for the session
- 🛡️ **active MITM protection** — optional pre-shared passphrase authenticates the handshake itself (HMAC-SHA256), not just a post-hoc fingerprint check
- 👁️ **mandatory fingerprint confirmation** — the chat will not start until you explicitly confirm the derived key fingerprint matches what your peer sees
- 🔁 **replay-attack resistant** — sliding anti-replay window on the message sequence counter, the same technique used in IPsec/TLS
- 📦 **traffic-analysis resistant** — messages are padded to fixed-size blocks before encryption, so ciphertext length doesn't leak exact message size
- 🧱 **reliability over raw UDP** — custom ACK/retransmit layer, so you get TCP-like delivery guarantees without TCP's fingerprint
- 🕳️ **continuous NAT hole punching** — a background thread keeps the UDP path open even during silence
- 🚧 **rate-limited against forged packets** — a flood of garbage ciphertext can't burn unlimited CPU on decryption attempts
- 🌐 **DNS-filtering-resistant STUN** — falls back through a prioritized list of STUN hostnames, hardcoded IPs, and a live community-maintained list
- 🪶 **two dependencies, two files** — `prompt_toolkit` + `cryptography`, nothing else

---

## 🚀 Quick Start

### install dependencies

```
pip install prompt_toolkit cryptography
```

### run (full-screen TUI version)

```
python3 p2pchat_tui.py
```

### what happens next

1. you're asked for a **local port** (like `55000`).
2. the tool queries STUN and shows **your public IP:PORT**, send this to your peer over any channel (phoneCall, SMS, email, whatever).
3. you enter **your peer's public IP:PORT** (they send you theirs the same way).
4. *(OPTIONAL BUT RECOMMENDED)* you enter a **shared passphrase** agreed on beforehand, which cryptographically authenticates the handshake against active interception.
5. the tool performs the key exchange and shows a **fingerprint**, compare it with your peer over that other separate channel(or in your first message in chat). **you must confirm it matches before chat unlocks.**
6. chat.

> **note:** both peers need to be reachable via UDP hole punching. see [availability under symmetric NAT](#-security-model) for the one case this doesn't cover yet..

---

## ✨ features

### 🔐 cryptographic core

end-to-end encryption is built from well-established primitives, composed carefully rather than reinvented:

- **X25519 (ECDH)** — each session generates a fresh, ephemeral keypair; nothing is reused across sessions
- **HKDF-SHA256 directional key derivation** — instead of one shared key, two independent subkeys are derived (`initiator→responder` and `responder→initiator`), so each direction of the conversation uses its own key and nonce space. this eliminates the nonce-reuse class of bugs that plagues naive "one shared key" P2P designs
- **ChaCha20-Poly1305 AEAD** — every message is both encrypted and authenticated; tampered ciphertext is rejected, not silently corrupted
- **message padding** — plaintext is length-prefixed and padded to fixed 64-byte blocks before encryption, so an observer watching ciphertext sizes on the wire learns much less about what's being said
- **fingerprint-based verification** — a short, human-comparable fingerprint is derived from *both* directional keys combined, so a match proves both sides really derived the same secret, not just that they swapped plausible-looking public keys

### 🛡️  handshake authentication (anti-MITM)

- **optional pre-shared passphrase (`setup_connection`)** — if you and your peer agree on a passphrase beforehand (over any side channel), the handshake packets are authenticated with HMAC-SHA256. an attacker without the passphrase cannot forge a valid handshake packet, closing the active-MITM window that a bare Diffie-Hellman exchange leaves open
- **mandatory fingerprint confirmation (`confirm_fingerprint_or_raise`)** — even without a passphrase, the tool will not proceed into chat until you explicitly type `y` to confirm the fingerprint matches. there is no silent bypass
- **deterministic role assignment** — initiator/responder roles are derived from a simple comparison of the two public keys, so both sides agree on directional key assignment without any extra round-trip

### 🔁 replay Protection

a sliding anti-replay window (1024 messages wide) tracks the highest sequence number seen and rejects:

- any sequence number far older than the current window (stale/replayed)
- any sequence number already seen once (exact replay)

this mirrors the anti-replay mechanism used in IPsec and TLS 1.3

### 🧱 reliability layer over UDP

raw UDP drops and reorders packets. a lightweight ACK/retransmit layer sits directly on top of the encryption layer:

- every data packet is retried (up to 8 times, 1-second spacing) until acknowledged
- ACKs are sent even for packets that turn out to be replays, so legitimate retransmits caused by lost ACKs aren't mistaken for attacks
- no connection state machine, no handshake beyond the crypto handshake, just enough reliability to make chat usable

### 🕳️ NAT traversal

- **STUN with layered fallback** — tries Google/Cloudflare STUN first, then a community-maintained live server list, then a hardcoded static IP list, then secondary hostnames, resilient to DNS-level blocking of any single provider
- **continuous background hole punching** — sends lightweight unencrypted `P` packets to keep the NAT mapping alive, backing off to a slow keepalive once the peer is confirmed reachable

### 🚧 abuse resistance

- **rate-limited decryption attempts** — a token-bucket limiter caps how many invalid/undecryptable packets are processed per time window, blunting a flood of forged ciphertext before it can burn CPU
- **input validation on setup** — local port and peer port prompts retry on invalid input instead of crashing with a traceback

---

## 🔒 security model

### what this tool protects against

| threat | mitigation |
| --- | --- |
| **passive eavesdropping** | end-to-end AEAD encryption (ChaCha20-Poly1305); a network observer sees only ciphertext |
| **active MITM during key exchange** | optional passphrase-authenticated handshake (HMAC-SHA256) + mandatory fingerprint confirmation |
| **message tampering** | AEAD authentication tag; any modified ciphertext fails to decrypt and is dropped |
| **replay attacks** | sliding anti-replay window on the message sequence counter |
| **nonce reuse between peers** | independent directional keys derived via HKDF. the two peers never share a key+nonce pair |
| **traffic analysis on message length** | fixed-block padding before encryption |
| **garbage-packet flooding** | rate-limited decryption attempts |
| **DNS-level STUN blocking** | layered STUN fallback across multiple providers, hostnames, and hardcoded IPs |

### what this tool does *not* protect against (by design or by nature of P2P)

| limitation | notes |
| --- | --- |
| **no forward secrecy across the session lifetime** | session keys are ephemeral per-run, but not ratcheted per-message. memory compromise during an active session can expose that session's traffic |
| **IP address exposure** | this is inherent to any P2P tool, your peer (and anyone they share it with) learns your public IP. use a VPN alongside this tool if that's a concern for your threat model |
| **endpoint compromise** | if either device is compromised, the conversation is compromised. no chat tool can fix this |
| **metadata about *that* you're chatting, and roughly *when*** | STUN queries and UDP hole-punch traffic are visible to network observers, even though content is encrypted |
| **availability under symmetric NAT** | some carrier-grade NATs (common on mobile data) assign a different outbound port per destination, breaking hole punching entirely. manual port forwarding on a router fixes this for a peer who controls their own router. |

> **note:** port forwarding can't help when *both* peers are behind carrier-grade NAT with no router access, since neither side can forward anything.

> **bottom line:** the cryptography here (X25519 + ChaCha20-Poly1305 + HKDF) is standard and solid. the weakest link in any P2P handshake is the manual exchange of addresses/keys, which is exactly why the passphrase authentication and mandatory fingerprint confirmation exist.use them.

---

## 📊 comparison

| Feature | **Packet-Shooter** | **Signal** | **Telegram (secret chat)** | **Plain netcat/socat + TLS** |
| --- | --- | --- | --- | --- |
| **Requires a server/relay** | ❌ Direct P2P only | ✅ Signal servers | ✅ Telegram servers | ❌ Direct |
| **Requires phone number/account** | ❌ None | ✅ Phone number | ✅ Phone number | ❌ None |
| **End-to-end encryption** | ✅ X25519 + ChaCha20-Poly1305 | ✅ Double Ratchet | ✅ MTProto (secret chats only) | ⚠️ Depends on setup |
| **Forward secrecy (per-message ratcheting)** | ❌ Not implemented yet | ✅ Double Ratchet | ✅ | ❌ |
| **Directional key separation** | ✅ HKDF-derived subkeys | ✅ | ✅ | ⚠️ Depends on cipher suite |
| **Active MITM protection on handshake** | ✅ Optional passphrase HMAC | ✅ Safety numbers | ⚠️ Manual key comparison | ❌ Usually none |
| **Mandatory fingerprint confirmation** | ✅ Blocks chat until confirmed | ⚠️ Optional/manual | ⚠️ Optional/manual | ❌ N/A |
| **Replay protection** | ✅ Sliding window | ✅ | ✅ | ⚠️ Depends on TLS config |
| **Message length padding** | ✅ Fixed 64-byte blocks | ✅ (Sealed Sender + padding) | ❌ | ❌ |
| **NAT traversal (STUN + hole punching)** | ✅ Built-in | N/A (uses servers) | N/A (uses servers) | ❌ Manual |
| **Works with no internet infra besides STUN** | ✅ | ❌ | ❌ | ✅ (with manual IP exchange) |
| **Message history stored anywhere** | ❌ Never persisted | ✅ (encrypted, on-device) | ✅ (server + device) | ❌ |
| **Dependencies** | 2 Python packages | Full mobile/desktop app | Full mobile/desktop app | `openssl`/`socat` |
| **Codebase size** | ~2 small files | Large, complex | Large, complex | Minimal, but no built-in auth |

### why not just use Signal or Telegram?

Signal and Telegram are excellent for daily use and battle-tested at scale. packet-shooter exists for a different, narrower case: when you specifically want **no server in the loop at all**, don't want to hand over a phone number, and are comfortable manually exchanging a handshake with your peer. it trades convenience and mobile support for architectural simplicity and zero third-party infrastructure.

### why not raw netcat + TLS?

you *can* build an encrypted tunnel with `openssl s_server`/`s_client` or `socat`, but you're on your own for NAT traversal, replay protection, reliability over UDP, and critically, certificate trust (there's no fingerprint-confirmation workflow built in).

---

## 🏗️  architecture

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
| **`p2pchat_tui.py`** | full-screen `prompt_toolkit` `Application` with a live status bar, fingerprint bar, and scrolling chat buffer |

### packet formats (post-handshake)

| type | format | purpose |
| --- | --- | --- |
| `D` (data) | `b"D" + seq(4B) + ciphertext` | encrypted chat message |
| `A` (ACK) | `b"A" + seq(4B)` | acknowledges receipt of a `D` packet |
| `P` (punch) | `b"P"` | unencrypted NAT keepalive, no payload |
| `H` (handshake) | `b"H" + pubkey(32B)` **or** `b"H" + pubkey(32B) + hmac_tag(32B)` | key exchange, with optional passphrase authentication |

---

## 📖 what happens when running the tool?

```
python3 p2pchat_tui.py      # Full-screen TUI chat
```

### interactive setup prompts (both interfaces) 

```
local port to use (like 55000):
>>> send this information to the other party: <your_public_ip>:<your_public_port>
peer's public IP:
peer's public PORT:
shared passphrase (optional):
```

### fingerprint confirmation (both interfaces, mandatory)

```
==================== Security Verification (Important) ====================
shared key fingerprint: XXXX-XXXX-XXXX-XXXX-XXXX
compare this code with the peer over a separate channel (phone call, SMS, another messaging app, etc.). ONLY CONTINUE IF IT MATCHES EXACTLY.
==============================================================

does this fingerprint match what the peer sees? [y/n]:
```

answering anything other than `y`/`yes` aborts the connection.

### in-chat commands

| interface | command | action |
| --- | --- | --- |
| TUI | `Enter` | send message |
| TUI | `/exit`, `exit`, `/quit`, `quit` | quit |
| TUI | `Ctrl+C` | quit immediately |

### key `p2pcore.py` functions (for embedding/scripting)

```python
from p2pcore import (
    setup_connection,           # full interactive setup: port, STUN, peer address, passphrase, handshake
    confirm_fingerprint_or_raise,  # blocks until user confirms fingerprint; raises RuntimeError on mismatch
    SecureReliableChannel,      # encrypted, reliable, replay-protected channel over a UDP socket
    CryptoSession,              # X25519 keypair + directional AEAD encrypt/decrypt
    perform_handshake,          # lower-level handshake if you want to skip the interactive prompts
    HandshakeAuthError,         # raised when a pre-shared passphrase check fails
    get_public_endpoint,        # raw STUN lookup
)
```

---

## 💻 system requirements

| Requirement | Details |
| --- | --- |
| **python** | 3.9+ |
| **dependencies** | `prompt_toolkit`, `cryptography` |
| **OS** | linux, macOS, windows (anywhere python + these two packages run) |
| **network** | UDP outbound/inbound on your chosen local port; STUN access (UDP/3478 and friends) |
| **RAM** | negligible. no persistent storage, no message history buffer beyond the visible scrollback |

---

## 📁 files

| file | purpose |
| --- | --- |
| `p2pcore.py` | shared core: STUN client, cryptography (`CryptoSession`), replay protection (`ReplayGuard`), rate limiting (`RateLimiter`), reliable encrypted channel (`SecureReliableChannel`), handshake (`perform_handshake`), and interactive setup (`setup_connection`, `confirm_fingerprint_or_raise`) |
| `p2pchat_tui.py` | full-screen TUI front-end (`ChatTUI` class) |

no configuration files, no logs, no database. nothing is written to disk. closing either program leaves no trace beyond process memory that has already been freed.

---

## ⚠️  disclaimer

this is an independent tool built around standard, well-reviewed cryptographic primitives (`cryptography` library implementations of X25519, HKDF, and ChaCha20-Poly1305). it has **not** undergone a formal third-party security audit. review the source yourself before relying on it for anything where the stakes are high, and treat the security model section above as the actual scope of what it protects against, not marketing copy.

---

## 📄 license

MIT license.
