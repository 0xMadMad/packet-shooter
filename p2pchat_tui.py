"""
text user interface with:
  - continuous UDP hole punching in the background
  - full-screen UI with textual (chat window + status bar + input line)

requirements: pip install textual

run:
  python3 p2pchat_textual.py

keys:
  Enter                 send message
  Ctrl+C or '/exit'     quit

colors:
  blue:   #4da6ff
  red:    #ff5555
  yellow: #ffaa00
  purple: #cc66ff
  green:  #00ff66
  gray:   #aaaaaa || #999999
  white:  #eeeeee || #ffffff
"""


import datetime
import threading

from textual.app import App, ComposeResult
from textual.containers import Vertical, Container, Horizontal
from textual.widgets import Static, Input, RichLog
from textual.reactive import reactive
from textual import work

from p2pcore import (
    SecureReliableChannel,
    setup_connection,
    confirm_fingerprint_or_raise,
    HandshakeAuthError,
)


class StatusBar(Container):
    """
    top status frame of the chat UI.
    renders the ME/PEER/FINGERPRINT columns and shows the
    current connection state (WAITING/CONNECTED/DISCONNECTED) as the
    frame's own border title. owns the logic that decides which of those
    three states to display based on two reactive flags.
    this is a Container (not a Static) because it holds a row of child 
    widgets (ME/PEER/FINGERPRINT columns) via compose().
    """

    # `connected`: True exactly while we currently believe the peer is reachable and exchanging real messages with us right now
    connected = reactive(False)

    # `ever_connected`: True forever, the moment `connected` has been True at least once
    # lets us tell "never connected yet" (WAITING) apart from "was connected, isn't anymore" (DISCONNECTED)
    ever_connected = reactive(False)

    def __init__(self, my_addr_str: str, peer_addr, fingerprint: str, **kwargs):
        super().__init__(**kwargs)
        self.my_addr_str = my_addr_str
        self.peer_addr = peer_addr
        self.fingerprint = fingerprint
        # my_addr_str/peer_addr/fingerprint are just stored for display
        # they're set once at construction and never change afterwards

    def on_mount(self) -> None:
        """
        textual lifecycle hook, runs once this widget is actually
        on screen. used here only to paint the initial border title
        (otherwise it would stay blank until the first state change).
        """
        self._update_border_title()

    def watch_connected(self, value:bool) -> None:
        """
        textual reactive watcher; auto-called every time
        `connected` changes value. updates `ever_connected` once we've
        connected at least once, refreshes the border title text, and
        toggles the CSS state classes (connected/waiting/disconnected)
        that control the frame's border color.
        """
        if value:  # the moment we connect for the first time, this is what makes DISCONNECTED (below) possible later on
            self.ever_connected = True
        self._update_border_title()  # re-paint the border title text (WAITING/CONNECTED/DISCONNECTED)
        
        self.set_class(value, "connected")  # toggle CSS classes so the border color reflects the new state
        self.set_class(not value and not self.ever_connected, "waiting")  # "waiting" only applies if we've never receive message yet
        self.set_class(not value and self.ever_connected, "disconnected")  # "disconnected" applies once we've connected before, but aren't now

    def _update_border_title(self) -> None:
        """
        builds the text that sits on top of the frame's border
        (e.g. "Packet Shooter v1.0.0 ●CONNECTED") based on the current
        connected/ever_connected flags, and assigns it to self.border_title
        """
        if self.connected:
            state = "CONNECTED"
        elif self.ever_connected:
            state = "DISCONNECTED"
        else:
            state = "WAITING"

        dot = "●"
        if self.connected:
            state_text = f"[#00ff66]{dot}{state}[/]"
        else:
            state_text = f"{dot}{state}"
        self.border_title = f" Packet Shooter v1.0.0  {state_text} "

    def compose(self) -> ComposeResult:
        """
        textual layout hook; yields the child widgets that make
        up this frame's body: a header row (ME/PEER/FINGERPRINT labels) 
        and a value row underneath it (the actual address/fingerprint values,
        each with its own color class).
        """

        # header row: just column labels, styled gray via "status-header" (defined in CSS below))
        yield Horizontal(
            Static("ME", classes="status-column status-header"),
            Static("PEER", classes="status-column status-header"),
            Static("FINGERPRINT", classes="status-column status-header"),
            classes="status-row",
        )

        # peer_addr is a (host, port) tuple, format it as "host:port" for display
        peer = f"{self.peer_addr[0]}:{self.peer_addr[1]}"

        # value row: the actual data, each column with its own color class
        # (value-me/value-peer/value-fingerprint, defined in CSS below)
        yield Horizontal(
            Static(self.my_addr_str, classes="status-column value-me"),
            Static(peer, classes="status-column value-peer"),
            Static(self.fingerprint, classes="status-column value-fingerprint"),
            classes="status-row",
        )


class ChatApp(App):
    """
    main textual application.

    owns the full-screen layout (status frame + chat log + input
    line), wires the encrypted network channel (SecureReliableChannel) to
    the UI via callbacks, and handles user input, thread-safety for
    background network events, and clean shutdown.
    """

    CSS = """
        Screen {
            background: black;
        }

        #status-frame {
            background: black;
        }

        /* the bordered frame around the status columns. border_title
           (set in StatusBar._update_border_title) draws on this border's
           top edge. that's the "title on the frame" requirement. */
        StatusBar {
            border: round white;
            height: 4;
            width: 100%;
            padding: 0 1;
            background: black;
        }

        /* frame colors */
        StatusBar.waiting {
            border: round #ffaa00;
        }

        StatusBar.connected {
            border: round white;
        }

        StatusBar.disconnected {
            border: round #ff5555;
        }

        /* frame items */
        .status-row {
            width: 100%;
            height: 1;
            background: black;
        }

        .status-column {
            width: 33.33%;
            padding: 0 1;
            background: black;
        }

        .status-header {
            color: #aaaaaa;
            text-style: bold;
        }

        .value-me {
            color: #00ff66;
        }

        .value-peer {
            color: #4da6ff;
        }

        .value-fingerprint {
            color: #cc66ff;
        }

        /* chat window */
        RichLog {
            background: black;
            color: #eeeeee;
        }

        /* input window */
        Input {
            background: black;
            color: #ffffff;
            border: none;
            height: 1;
        }
    """

    # Ctrl+C is bound to the "quit_app" action (defined below as action_quit_app) instead of textual's default Ctrl+C handling
    BINDINGS = [
        ("ctrl+c", "quit_app", "Quit"),
    ]

    def __init__(self, sock, peer_addr, crypto, my_addr_str):
        super().__init__()
        self.sock = sock
        self.peer_addr = peer_addr
        self.crypto = crypto
        self.my_addr_str = my_addr_str
        self.connected = False

        self.channel = SecureReliableChannel(
            sock, peer_addr, crypto,
            on_message=self._on_peer_message,
            on_status=self._on_status,
            on_disconnect=self._on_peer_disconnect  
        )

    # ---------------- layout ----------------
    def compose(self) -> ComposeResult:
        """
        textual layout hook for the whole app; builds the
        StatusBar, the RichLog (scrolling chat history), and the Input
        (message entry line), then yields them stacked vertically.
        """
        self.status_bar = StatusBar(self.my_addr_str, self.peer_addr, self.crypto.fingerprint(), id="status-frame")
        self.chat_log = RichLog(wrap=True, markup=True, highlight=False)
        self.input_line = Input(placeholder="> type message and press Enter")

        yield Vertical(
            self.status_bar,
            self.chat_log,
            self.input_line,
        )

    def on_mount(self) -> None:
        """
        textual lifecycle hook, runs once the app is fully on
        screen. sets the initial disconnected state, focuses keyboard on
        the input line so the user can type immediately, and kicks off the
        background connection setup (hole punching + wait for peer).
        """
        self.status_bar.connected = False
        self.input_line.focus()
        self._background_setup()

    # ---------------- internal logic ----------------
    def _timestamp(self) -> str:
        """returns the current time as an HH:MM:SS string, used to prefix every chat/status line."""
        return datetime.datetime.now().strftime("%H:%M:%S")

    def _append_line(self, line:str) -> None:
        """
        writes one line to the chat log. called from both the main UI
        thread and background threads (network callbacks, setup worker).
        call_from_thread() only works when we're NOT on the app's own
        thread, so we check first instead of calling it every time.
        """
        if threading.get_ident() == self._thread_id:
            self.chat_log.write(line)
        else:
            self.call_from_thread(self.chat_log.write, line)

    def _set_connected(self, value:bool) -> None:
        """
        updates self.connected and the StatusBar's connected property.
        uses call_from_thread because this is always called from a
        background thread (network callback or the setup worker).
        """
        self.connected = value
        self.call_from_thread(setattr, self.status_bar, "connected", value)

    def _on_peer_message(self, text:str, addr) -> None:
        """
        callback passed to SecureReliableChannel as on_message.
        fires whenever a real decrypted chat message arrives from the
        peer. marks us as connected and writes the message to the log.
        
        ** NOTE deliberately not named _on_message. textual reserves that
        exact name on App/Widget as its internal message-dispatch hook
        (used for framework events like Unmount), so defining our own
        _on_message here would silently override it and break shutdown. **
        """
        self._set_connected(True)
        self._append_line(f"[#4da6ff][{self._timestamp()}] PEER > {text}[/]")

    def _on_peer_disconnect(self, reason:str) -> None:
        """
        callback passed to SecureReliableChannel as on_disconnect.
        fires when the peer signals it's leaving (e.g. sent an "X" packet
        on exit), flips us back to disconnected and logs why.
        """
        self._set_connected(False)
        self._append_line(f"[#ff5555 bold][{self._timestamp()}] * peer disconnected; {reason}[/]")

    def _on_status(self, text:str) -> None:
        """
        callback passed to SecureReliableChannel as on_status.
        fires for informational/warning messages from the network layer
        (not actual chat content), logged in gray italics.
        """
        self._append_line(f"[#999999 italic][{self._timestamp()}] * {text}[/]")

    def on_input_submitted(self, event:Input.Submitted) -> None:
        """
        textual event handler, auto-called when the user presses
        Enter in the Input widget. reads and clears the input box, then
        hands non-empty text off to _handle_input.
        """
        text = event.value.strip()
        self.input_line.value = ""
        if not text:
            return
        self._handle_input(text)

    def _handle_input(self, text:str) -> None:
        """
        processes one submitted line of user input. either an
        exit command (which quits the app) or a chat message (which gets
        encrypted/sent via the channel and echoed into the log).
        """
        if text.lower() in ("/exit", "exit", "/quit", "quit"):
            self.exit()
            return
        self.channel.send(text)
        self._append_line(f"[#00ff66][{self._timestamp()}] ME   > {text}[/]")

    @work(thread=True)
    def _background_setup(self) -> None:
        """
        runs in a background worker thread (via @work(thread=True)
        so it doesn't block the UI). starts continuous UDP hole punching
        and blocks waiting for any packet from the peer, up to 120s, then
        logs the outcome. does NOT mark us as "connected" by itself. that
        only happens once a real message arrives via
        _on_peer_message, see the commented-out lines below.
        """
        self._append_line("[#999999 italic]* opening the path (hole punching) in the background...[/]")
        self.channel.start_background_punch()
        if self.channel.wait_for_peer(timeout=120):
            #self._set_connected(True)
            #self._append_line("[#999999 italic]* connection with the peer established. Chat is ready.[/]")
            self._append_line("[#999999 italic]* path to peer is open (still waiting for a message)...[/]")
        else:
            self._append_line("[#999999 italic]* nothing received from the peer yet; still trying in the background.[/]")

    def action_quit_app(self) -> None:
        """handler for the "quit_app" action bound to Ctrl+C. just exits the app."""
        self.exit()

    def on_unmount(self) -> None:
        """
        textual lifecycle hook, runs right before the app fully
        shuts down (any exit path). stops the network channel, which
        (per p2pcore.py) also sends a farewell packet to the peer.
        """
        self.channel.stop()


def main():
    """
    entry point. runs the plain-print setup flow (STUN, peer
    address, passphrase, handshake) before any full-screen UI exists,
    then requires manual fingerprint confirmation, then launches the
    textual ChatApp. always closes the socket on the way out.
    """
    
    print("\n\n#=== SETTING UP Packet Shooter v1.0.0 ===#\n")
    try:
        sock, peer_addr, crypto, my_addr_str = setup_connection()
    except HandshakeAuthError as e:
        print(f"\n[!] {e}")
        return
    except TimeoutError as e:
        print(f"\n[!] {e}")
        return

    try:
        confirm_fingerprint_or_raise(crypto)
    except RuntimeError as e:
        print(f"\n[!] {e}")
        sock.close()
        return

    print("[*] entering the chat interface...\n")

    app = ChatApp(sock, peer_addr, crypto, my_addr_str)
    try:
        app.run()
    finally:
        sock.close()


if __name__ == "__main__":
    main()

# _428