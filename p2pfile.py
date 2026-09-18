"""
file transfer layer on top of SecureReliableChannel.

design:
  - every payload sent through channel.send() starts with one "step" byte,
    so the receiver can tell a plain chat line apart from a file protocol
    message (offer/accept/reject/chunk/done/result). this is a convention
    enforced by callers, not by SecureReliableChannel itself.
  - chunked file transfer uses a sliding window: several chunks are kept
    "in flight" at once (each with its own seq/on_ack via
    SecureReliableChannel.send), instead of waiting for one ack before
    sending the next chunk. this is what makes transfer speed reasonable
    over a single UDP round-trip latency.
  - a slower, one-chunk-at-a-time alternative is included below,
    commented out, in case you want simpler/more predictable behavior
    instead of the windowed version.
  - WINDOW_SIZE here determines the channel's replay window (see
    ChatApp.__init__, which passes replay_window=WINDOW_SIZE * 100 to
    SecureReliableChannel), so it never needs manual syncing against
    p2pcore.ReplayGuard's default.

requirements: none beyond the stdlib (uses SecureReliableChannel from p2pcore)
"""

import os
import struct
import hashlib
import threading


# ================== step bytes (first byte of every payload) ==================
# STEP_CHAT is consumed directly in p2pchat_tui.py; everything else is
# routed here via FileTransferManager.handle_payload()

STEP_CHAT   = 0x01
STEP_OFFER  = 0x02
STEP_ACCEPT = 0x03
STEP_REJECT = 0x04
STEP_CHUNK  = 0x05
STEP_DONE   = 0x06
STEP_RESULT = 0x07

CHUNK_SIZE   = 1100  # bytes of file data per chunk. plus a 9-byte step/id/idx header, padded to 64B, 
                     # plus a 16B AEAD tag, plus a 5B "D"+seq header, plus 28B IP/UDP -> ~1201B total, 
                     # comfortably under the common 1500B MTU
WINDOW_SIZE  = 48  # how many chunks may be "in flight" (sent, unacked) at once


class FileTransferManager:
    """
    owns both directions of file transfer:
      - outgoing: send_file() -> offer -> wait for accept -> stream chunks -> done
      - incoming: handle_payload() routes offers/chunks -> on_offer/on_progress/on_result callbacks

    one instance per chat session (constructed once in ChatApp.__init__).
    """

    def __init__(self, channel, on_progress, on_offer, on_result):
        self.channel = channel
        self.on_progress = on_progress      # (transfer_id, direction, done, total) -> None
        self.on_offer = on_offer            # (transfer_id, name, file_size) -> None
        self.on_result = on_result          # (transfer_id, direction, ok, name) -> None

        self.dest_dir = "received_files"
        os.makedirs(self.dest_dir, exist_ok=True)

        self._next_id = 1
        self._lock = threading.Lock()

        self.outgoing = {}  # transfer_id -> outgoing state dict
        self.incoming = {}  # transfer_id -> incoming state dict

        # only one transfer (send or receive) may be actively streaming chunks at a time;
        # this holds the transfer_id currently allowed to stream, or None if the channel is free.
        self._active_stream_id = None


    # ---------------- outgoing ----------------
    def send_file(self, path: str):
        """
        creates the outgoing transfer state and sends a file offer for "path".
        returns the transfer_id, or None if the file does not exist, or "busy" if another transfer is currently streaming.
        """
        if not os.path.isfile(path):
            return None

        with self._lock:
            if self._active_stream_id is not None:
                return "busy"

        file_size = os.path.getsize(path)
        total_chunks = (file_size + CHUNK_SIZE - 1) // CHUNK_SIZE
        file_hash = self._hash_file(path)
        name = os.path.basename(path)
        name_bytes = name.encode("utf-8")[:200]

        with self._lock:
            transfer_id = self._next_id
            self._next_id += 1

        self.outgoing[transfer_id] = {
            "path": path,
            "name": name,
            "file_size": file_size,
            "total_chunks": total_chunks,
            "next_chunk": 0,     # next chunk index not yet sent
            "in_flight": 0,      # how many chunks currently unacked
            "acked": 0,          # how many chunks acked so far
            "done_sent": False,
            "rejected": False,
            "lock": threading.Lock(),
        }

        offer_body = (
            struct.pack("!III", transfer_id, file_size, total_chunks)
            + struct.pack("!H", len(name_bytes)) + name_bytes
            + file_hash
        )
        self.channel.send(bytes([STEP_OFFER]) + offer_body)
        return transfer_id

    def accept_transfer(self, transfer_id: int):
        """accepts an incoming file offer and tells the sender to start the transfer."""
        self.channel.send(bytes([STEP_ACCEPT]) + struct.pack("!I", transfer_id))

    def reject_transfer(self, transfer_id: int):
        """rejects an incoming file offer and removes its pending transfer state."""
        self.channel.send(bytes([STEP_REJECT]) + struct.pack("!I", transfer_id))
        self.incoming.pop(transfer_id, None)

    def _begin_stream(self, transfer_id: int):
        """
        starts the outgoing transfer by filling the initial sliding window with file chunks after the peer accepts the offer.
        claims the channel-wide active-stream slot; refuses to start (and tells the peer) if another transfer is already streaming.
        """
        state = self.outgoing.get(transfer_id)
        if not state:
            return
        with self._lock:
            if self._active_stream_id not in (None, transfer_id):
                self.channel.send(bytes([STEP_REJECT]) + struct.pack("!I", transfer_id))
                self.outgoing.pop(transfer_id, None)
                self.on_result(transfer_id, "send", False, state["name"])
                return
            self._active_stream_id = transfer_id
        with state["lock"]:
            if state["next_chunk"] != 0:
                return  # already streaming. ignore a duplicate ACCEPT
            first_batch = min(WINDOW_SIZE, state["total_chunks"])
            state["next_chunk"] = first_batch
            state["in_flight"] = first_batch
        for idx in range(first_batch):
            self._send_chunk(transfer_id, idx)

    def _send_chunk(self, transfer_id: int, idx: int):
        state = self.outgoing.get(transfer_id)
        if not state:
            return
        with open(state["path"], "rb") as f:
            f.seek(idx * CHUNK_SIZE)
            chunk_data = f.read(CHUNK_SIZE)
            # re-opened per chunk: keeps each send independent of any shared file cursor, since chunks can be sent from multiple call sites (initial window, retries)
        payload = bytes([STEP_CHUNK]) + struct.pack("!II", transfer_id, idx) + chunk_data

        def on_ack(ok: bool):
            if not ok:
                # retransmission gave up entirely -> treat as a failed transfer
                self.outgoing.pop(transfer_id, None)
                self._release_stream_slot(transfer_id)
                self.on_result(transfer_id, "send", False, state["name"])
                return
            self._on_chunk_acked(transfer_id)

        self.channel.send(payload, on_ack=on_ack)

    def _on_chunk_acked(self, transfer_id: int):
        """
        runs on the ack/retransmit thread for each acked chunk: slides the
        window forward by one, reports progress, and sends STEP_DONE once
        every chunk has been acked.
        """
        state = self.outgoing.get(transfer_id)
        if not state:
            return
        with state["lock"]:
            state["in_flight"] -= 1
            state["acked"] += 1
            acked = state["acked"]
            total = state["total_chunks"]
            next_idx = state["next_chunk"]
            send_next = next_idx < total
            if send_next:
                state["next_chunk"] += 1
                state["in_flight"] += 1
            all_done = state["in_flight"] == 0 and acked >= total and not state["done_sent"]
            if all_done:
                state["done_sent"] = True

        self.on_progress(transfer_id, "send", acked, total)

        if send_next:
            self._send_chunk(transfer_id, next_idx)
        elif all_done:
            self.channel.send(bytes([STEP_DONE]) + struct.pack("!I", transfer_id))


    # ---------------- incoming ----------------
    def handle_payload(self, payload: bytes, addr):
        """
        handles incoming file-transfer protocol payloads and dispatches them
        to the appropriate transfer handler based on the leading step byte.
        """
        if len(payload) < 1:
            return
        step = payload[0]
        body = payload[1:]

        if step == STEP_OFFER:
            self._handle_offer(body)
        elif step == STEP_ACCEPT:
            transfer_id = struct.unpack("!I", body[:4])[0]
            self._begin_stream(transfer_id)
        elif step == STEP_REJECT:
            transfer_id = struct.unpack("!I", body[:4])[0]
            state = self.outgoing.pop(transfer_id, None)
            if state:
                self.on_result(transfer_id, "send", False, state["name"])
        elif step == STEP_CHUNK:
            self._handle_chunk(body)
        elif step == STEP_DONE:
            transfer_id = struct.unpack("!I", body[:4])[0]
            self._finalize_incoming(transfer_id)
        elif step == STEP_RESULT:
            transfer_id, ok = struct.unpack("!IB", body[:5])
            state = self.outgoing.pop(transfer_id, None)
            self._release_stream_slot(transfer_id)
            name = state["name"] if state else "?"
            self.on_result(transfer_id, "send", bool(ok), name)

    def _handle_offer(self, body: bytes):
        transfer_id, file_size, total_chunks = struct.unpack("!III", body[:12])
        name_len = struct.unpack("!H", body[12:14])[0]
        name = body[14:14 + name_len].decode("utf-8", errors="ignore")
        file_hash = body[14 + name_len: 14 + name_len + 32]

        existing = self.incoming.get(transfer_id)
        if existing and existing["file"] is not None:
            return  # a transfer with this id is already in progress, ignore the duplicate/conflicting offer instead of clobbering it

        self.incoming[transfer_id] = {
            "name": name,
            "file_size": file_size,
            "total_chunks": total_chunks,
            "hash": file_hash,
            "received": 0,
            "file": None,
            "part_path": None,  # "received_idxs" is created lazily in _handle_chunk, together with the .part file, once the first chunk arrives
        }
        self.on_offer(transfer_id, name, file_size)

    def _handle_chunk(self, body: bytes):
        """
        writes one incoming chunk at its offset in the .part file. idx and chunk_data are
        range-checked against the offer's total_chunks and CHUNK_SIZE before anything is written, 
        so a misbehaving peer can't grow the .part file past the size implied by its own offer.
        """
        transfer_id, idx = struct.unpack("!II", body[:8])
        chunk_data = body[8:]
        state = self.incoming.get(transfer_id)
        if not state:
            return
        if idx >= state["total_chunks"] or len(chunk_data) > CHUNK_SIZE:
            return  # out-of-range or oversized chunk, ignore

        if state["file"] is None:
            part_path = os.path.join(self.dest_dir, state["name"] + ".part")
            state["part_path"] = part_path
            state["file"] = open(part_path, "wb")
            state["received_idxs"] = set()

        if idx not in state["received_idxs"]:
            state["file"].seek(idx * CHUNK_SIZE)
            state["file"].write(chunk_data)
            state["received_idxs"].add(idx)
            state["received"] = len(state["received_idxs"])
            self.on_progress(transfer_id, "recv", state["received"], state["total_chunks"])

    def _finalize_incoming(self, transfer_id: int):
        state = self.incoming.get(transfer_id)
        if not state or not state["file"]:
            return
        state["file"].close()

        ok = self._hash_file(state["part_path"]) == state["hash"]
        final_path = os.path.join(self.dest_dir, state["name"])
        if ok:
            try:
                os.replace(state["part_path"], final_path)
            except OSError:
                ok = False
        else:
            try:
                os.remove(state["part_path"])
            except OSError:
                pass

        self.channel.send(bytes([STEP_RESULT]) + struct.pack("!IB", transfer_id, 1 if ok else 0))
        self.on_result(transfer_id, "recv", ok, state["name"])
        self.incoming.pop(transfer_id, None)


    # ---------------- shared ----------------
    @staticmethod
    def _hash_file(path: str) -> bytes:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(1024 * 1024):
                h.update(chunk)
        return h.digest()

    def _release_stream_slot(self, transfer_id: int):
        with self._lock:
            if self._active_stream_id == transfer_id:
                self._active_stream_id = None

# _326