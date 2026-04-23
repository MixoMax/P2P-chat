"""
ui.py — htop-style curses TUI.

Layout (terminal)
─────────────────
┌─ PEERS ──────────────────┬─ CHAT: <peer> ─────────────────────────────────┐
│ ● alice   [READY]        │ 14:02  alice: hello                             │
│   bob     [OFFLINE]      │ 14:02  you:   hey!                              │
│ ● carol   [READY]        │ 14:03  [FILE] photo.jpg (1.2 MB) — sending…    │
│                          │                                                 │
│ ─ GROUPS ──────────────  │                                                 │
│   #friends               │                                                 │
│                          │                                                 │
│ ─ RELAY CACHE ─────────  │                                                 │
│   128 MB / 512 MB        │                                                 │
└──────────────────────────┴─────────────────────────────────────── INPUT ──┘
│ > _                                                                        │
└────────────────────────────────────────────────────────────────────────────┘

Keybindings
───────────
  ↑ / ↓           navigate peer/group list
  Enter / →        open conversation with selected peer/group
  ←  / Esc         back to peer list
  Tab              switch focus: list ↔ chat scroll
  PgUp / PgDn      scroll chat history
  F2  / a          add peer (prompt)
  F3  / f          send file (prompt)
  F4  / g          create/join group (prompt)
  F5  / r          refresh peer list
  F10 / q          quit
  Any printable    type in input bar
  Backspace        delete char
  Enter            send message
"""

import curses, curses.textpad, logging, os, threading, time
from collections import defaultdict
from datetime import datetime
from typing import Callable, Optional

log = logging.getLogger("ui")

# ── Colour pairs ──────────────────────────────────────────────────────────────
C_NORMAL  = 0
C_HEADER  = 1
C_STATUS_ON  = 2
C_STATUS_OFF = 3
C_STATUS_BUSY= 4
C_SELECTED = 5
C_TIMESTAMP = 6
C_SYSTEM  = 7
C_INPUT   = 8
C_RELAY   = 9
C_WARN    = 10

def _init_colors():
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(C_HEADER,      curses.COLOR_CYAN,    -1)
    curses.init_pair(C_STATUS_ON,   curses.COLOR_GREEN,   -1)
    curses.init_pair(C_STATUS_OFF,  curses.COLOR_RED,     -1)
    curses.init_pair(C_STATUS_BUSY, curses.COLOR_YELLOW,  -1)
    curses.init_pair(C_SELECTED,    curses.COLOR_BLACK,   curses.COLOR_CYAN)
    curses.init_pair(C_TIMESTAMP,   curses.COLOR_YELLOW,  -1)
    curses.init_pair(C_SYSTEM,      curses.COLOR_MAGENTA, -1)
    curses.init_pair(C_INPUT,       curses.COLOR_WHITE,   -1)
    curses.init_pair(C_RELAY,       curses.COLOR_BLUE,    -1)
    curses.init_pair(C_WARN,        curses.COLOR_RED,     -1)

# ── Data models ───────────────────────────────────────────────────────────────

class PeerEntry:
    def __init__(self, name: str):
        self.name   = name
        self.state  = "OFFLINE"   # OFFLINE | PUNCHING | READY | DEAD
        self.unread = 0

class GroupEntry:
    def __init__(self, gid: str, name: str, members: list[str]):
        self.gid     = gid
        self.name    = name
        self.members = members
        self.unread  = 0

class Message:
    def __init__(self, sender: str, text: str = "", ts: float | None = None,
                 is_system: bool = False, is_media: bool = False,
                 media_name: str = "", media_size: int = 0,
                 media_progress: int = -1):
        self.sender   = sender
        self.text     = text
        self.ts       = ts or time.time()
        self.is_system = is_system
        self.is_media  = is_media
        self.media_name = media_name
        self.media_size = media_size
        self.media_progress = media_progress  # -1 = done, 0-100 = %

# ── Main TUI class ────────────────────────────────────────────────────────────

class TUI:
    LIST_WIDTH = 26

    def __init__(self,
                 my_name: str,
                 on_send_chat: Callable,      # on_send_chat(peer, text)
                 on_send_file: Callable,      # on_send_file(peer, path)
                 on_connect: Callable,        # on_connect(peer_name)
                 on_create_group: Callable,   # on_create_group(name, [members])
                 on_refresh: Callable,        # on_refresh()  → fetch peer list
                 on_quit: Callable,
                 relay_cache_fn: Callable,    # relay_cache_fn() → (used_mb, limit_mb)
                 ):
        self._name          = my_name
        self._on_send_chat  = on_send_chat
        self._on_send_file  = on_send_file
        self._on_connect    = on_connect
        self._on_create_group = on_create_group
        self._on_refresh    = on_refresh
        self._on_quit       = on_quit
        self._relay_cache   = relay_cache_fn

        self._peers:  list[PeerEntry]  = []
        self._groups: list[GroupEntry] = []
        self._history: dict[str, list[Message]] = defaultdict(list)  # key = peer/group name

        self._lock         = threading.Lock()
        self._selected_idx = 0          # index in combined peer+group list
        self._active_conv: str | None = None    # currently open conversation
        self._scroll_offset = 0          # lines scrolled up in chat pane
        self._input_buf    = ""
        self._focus        = "list"      # "list" | "chat"
        self._prompt: Optional[dict] = None  # modal prompt state

        self._stdscr = None
        self._running = True

    # ── Public thread-safe API (called from networking threads) ───────────────

    def add_peer(self, name: str):
        with self._lock:
            if not any(p.name == name for p in self._peers):
                self._peers.append(PeerEntry(name))

    def update_peer_state(self, name: str, state: str):
        with self._lock:
            for p in self._peers:
                if p.name == name:
                    p.state = state
                    break
            else:
                p = PeerEntry(name)
                p.state = state
                self._peers.append(p)

    def add_group(self, gid: str, name: str, members: list[str]):
        with self._lock:
            if not any(g.gid == gid for g in self._groups):
                self._groups.append(GroupEntry(gid, name, members))

    def push_message(self, conv: str, sender: str, text: str = "",
                     is_system: bool = False, is_media: bool = False,
                     media_name: str = "", media_size: int = 0,
                     media_progress: int = -1):
        msg = Message(sender, text, is_system=is_system, is_media=is_media,
                      media_name=media_name, media_size=media_size,
                      media_progress=media_progress)
        with self._lock:
            self._history[conv].append(msg)
            if conv != self._active_conv:
                # Mark unread
                for p in self._peers:
                    if p.name == conv:
                        p.unread += 1
                for g in self._groups:
                    if g.name == conv:
                        g.unread += 1

    def set_media_progress(self, conv: str, media_name: str, progress: int):
        with self._lock:
            for m in reversed(self._history[conv]):
                if m.is_media and m.media_name == media_name:
                    m.media_progress = progress
                    break

    # ── Main run (blocks, must be called from main thread) ────────────────────

    def run(self):
        curses.wrapper(self._main)

    def _main(self, stdscr):
        self._stdscr = stdscr
        _init_colors()
        curses.curs_set(1)
        stdscr.nodelay(False)
        stdscr.timeout(250)   # refresh rate ms
        stdscr.keypad(True)
        curses.cbreak()
        curses.noecho()

        while self._running:
            try:
                self._draw()
                key = stdscr.getch()
                if key != -1:
                    self._handle_key(key)
            except curses.error:
                pass

    def stop(self):
        self._running = False

    # ── Drawing ───────────────────────────────────────────────────────────────

    def _draw(self):
        scr = self._stdscr
        scr.erase()
        H, W = scr.getmaxyx()
        lw = min(self.LIST_WIDTH, W // 3)
        cw = W - lw - 1   # chat pane width
        input_row = H - 2

        self._draw_list_pane(scr, H, lw, input_row)
        self._draw_separator(scr, H, lw, input_row)
        self._draw_chat_pane(scr, H, lw + 1, cw, input_row)
        self._draw_input_bar(scr, input_row, W)
        self._draw_status_bar(scr, H - 1, W)

        if self._prompt:
            self._draw_prompt(scr, H, W)

        scr.refresh()

    def _draw_list_pane(self, scr, H, lw, input_row):
        row = 0
        # Header
        title = f" {self._name[:lw-3]} "
        self._addstr_clipped(scr, row, 0, title.ljust(lw), curses.color_pair(C_HEADER) | curses.A_BOLD)
        row += 1

        combined = self._list_items()
        visible  = input_row - row

        # Adjust scroll if needed
        if self._selected_idx >= visible:
            start = self._selected_idx - visible + 1
        else:
            start = 0

        for i, item in enumerate(combined[start:start+visible]):
            screen_row = row + i
            if screen_row >= input_row:
                break
            idx = start + i
            selected = (idx == self._selected_idx) and self._focus == "list"
            self._draw_list_item(scr, screen_row, lw, item, selected)

        # Relay cache bar
        bar_row = input_row - 1
        used_mb, limit_mb = self._relay_cache()
        pct = int(used_mb / limit_mb * 100) if limit_mb else 0
        bar_text = f" relay {used_mb:.0f}/{limit_mb:.0f}MB"
        self._addstr_clipped(scr, bar_row, 0, bar_text.ljust(lw),
                              curses.color_pair(C_RELAY))

    def _draw_list_item(self, scr, row, lw, item, selected):
        attr = curses.color_pair(C_SELECTED) if selected else C_NORMAL
        if isinstance(item, str):  # section header
            self._addstr_clipped(scr, row, 0, f" {item}".ljust(lw),
                                  curses.color_pair(C_HEADER))
            return
        if isinstance(item, PeerEntry):
            dot, dot_color = {
                "READY":    ("●", C_STATUS_ON),
                "PUNCHING": ("◌", C_STATUS_BUSY),
                "DEAD":     ("✕", C_STATUS_OFF),
                "OFFLINE":  ("○", C_STATUS_OFF),
            }.get(item.state, ("○", C_STATUS_OFF))
            unread = f" [{item.unread}]" if item.unread else ""
            label = f" {item.name}{unread}"
            if selected:
                scr.addstr(row, 0, " " * lw, attr)
                scr.addstr(row, 0, dot, curses.color_pair(dot_color) | curses.A_BOLD)
                self._addstr_clipped(scr, row, 1, label[:lw-1], attr)
            else:
                try:
                    scr.addstr(row, 0, dot, curses.color_pair(dot_color))
                    self._addstr_clipped(scr, row, 1, label[:lw-1], C_NORMAL)
                except curses.error:
                    pass
        elif isinstance(item, GroupEntry):
            unread = f" [{item.unread}]" if item.unread else ""
            label  = f"  #{item.name}{unread}"
            self._addstr_clipped(scr, row, 0, label.ljust(lw), attr)

    def _draw_separator(self, scr, H, lw, input_row):
        for r in range(input_row):
            try:
                scr.addch(r, lw, curses.ACS_VLINE)
            except curses.error:
                pass

    def _draw_chat_pane(self, scr, H, cx, cw, input_row):
        conv = self._active_conv
        # Header
        conv_label = f" CHAT: {conv} " if conv else " (select a peer) "
        self._addstr_clipped(scr, 0, cx, conv_label.ljust(cw),
                              curses.color_pair(C_HEADER) | curses.A_BOLD)
        if not conv:
            shortcuts = [
                "↑↓  navigate    Enter open    F2/a add peer",
                "F3/f send file  F4/g  group   F5/r refresh",
                "Tab  focus chat PgUp/Dn scroll F10/q quit",
            ]
            for i, s in enumerate(shortcuts):
                self._addstr_clipped(scr, 4 + i, cx + 2, s, curses.color_pair(C_SYSTEM))
            return

        msgs = self._history.get(conv, [])
        visible_rows = input_row - 1
        rendered = self._render_messages(msgs, cw - 2)

        # Apply scroll
        total = len(rendered)
        start = max(0, total - visible_rows - self._scroll_offset)
        end   = start + visible_rows

        for i, (line, attr) in enumerate(rendered[start:end]):
            self._addstr_clipped(scr, 1 + i, cx + 1, line[:cw-1], attr)

    def _render_messages(self, msgs: list[Message], width: int) -> list[tuple[str, int]]:
        """Returns list of (line_text, curses_attr) for rendering."""
        lines = []
        for m in msgs:
            ts = datetime.fromtimestamp(m.ts).strftime("%H:%M")
            if m.is_system:
                lines.append((f"  ── {m.text} ──", curses.color_pair(C_SYSTEM)))
                continue
            if m.is_media:
                prog = f"{m.media_progress}%" if m.media_progress >= 0 else "done"
                sz   = f"{m.media_size/1024/1024:.1f}MB" if m.media_size else ""
                line = f"{ts}  [FILE] {m.media_name} {sz} {prog}"
                lines.append((line, curses.color_pair(C_RELAY)))
                continue
            sender_label = "you" if m.sender == "you" else m.sender
            prefix = f"{ts}  {sender_label}: "
            body   = m.text
            # Word-wrap the body
            body_width = max(1, width - len(prefix))
            while body:
                chunk = body[:body_width]
                body  = body[body_width:]
                attr  = curses.color_pair(C_TIMESTAMP) if m.sender == "you" else C_NORMAL
                lines.append((prefix + chunk, attr))
                prefix = " " * len(prefix)   # continuation lines indented
        return lines

    def _draw_input_bar(self, scr, row, W):
        prompt = "> "
        buf    = self._input_buf
        # Ensure cursor visible (clip to width)
        max_input = W - len(prompt) - 2
        display   = buf[-max_input:] if len(buf) > max_input else buf
        line      = (prompt + display).ljust(W - 1)
        try:
            scr.addstr(row, 0, line, curses.color_pair(C_INPUT))
            scr.move(row, len(prompt) + len(display))
        except curses.error:
            pass

    def _draw_status_bar(self, scr, row, W):
        items = [
            "F2:addpeer", "F3:sendfile", "F4:group",
            "F5:refresh", "Tab:focus", "F10:quit",
        ]
        bar = "  ".join(items)
        try:
            scr.addstr(row, 0, bar[:W-1], curses.color_pair(C_HEADER))
        except curses.error:
            pass

    def _draw_prompt(self, scr, H, W):
        p    = self._prompt
        pw   = min(60, W - 4)
        ph   = 5
        py   = H // 2 - ph // 2
        px   = W // 2 - pw // 2
        # Draw box
        for r in range(ph):
            scr.addstr(py + r, px, " " * pw, curses.color_pair(C_SELECTED))
        scr.addstr(py,     px, f" {p['title']}".ljust(pw), curses.color_pair(C_HEADER) | curses.A_BOLD)
        scr.addstr(py + 1, px, f" {p['label']}".ljust(pw), curses.color_pair(C_SELECTED))
        inp = p.get("input", "")
        scr.addstr(py + 2, px, f" > {inp}".ljust(pw), curses.color_pair(C_INPUT))
        hint = p.get("hint", "Enter=confirm  Esc=cancel")
        scr.addstr(py + 4, px, f" {hint}".ljust(pw), curses.color_pair(C_SYSTEM))
        try:
            scr.move(py + 2, px + 3 + len(inp))
        except curses.error:
            pass

    # ── Key handling ──────────────────────────────────────────────────────────

    def _handle_key(self, key):
        if self._prompt:
            self._handle_prompt_key(key)
            return

        if key in (curses.KEY_F10, ord('q')):
            self._running = False
            self._on_quit()
            return

        if key == curses.KEY_F5 or key == ord('r'):
            self._on_refresh()
            return

        if key == curses.KEY_F2 or key == ord('a'):
            self._open_prompt("Add Peer", "Peer name:", self._do_add_peer)
            return

        if key == curses.KEY_F3 or key == ord('f'):
            if self._active_conv:
                self._open_prompt("Send File", "File path:", self._do_send_file)
            return

        if key == curses.KEY_F4 or key == ord('g'):
            self._open_prompt("Create Group", "Group name:", self._do_create_group)
            return

        if key == ord('\t'):   # Tab — switch focus
            self._focus = "chat" if self._focus == "list" else "list"
            return

        if self._focus == "list":
            self._handle_list_key(key)
        else:
            self._handle_chat_key(key)

    def _handle_list_key(self, key):
        items   = self._list_items()
        n       = len(items)
        if key == curses.KEY_UP:
            self._selected_idx = max(0, self._selected_idx - 1)
            # Skip section headers
            while self._selected_idx > 0 and isinstance(items[self._selected_idx], str):
                self._selected_idx -= 1
        elif key == curses.KEY_DOWN:
            self._selected_idx = min(n - 1, self._selected_idx + 1)
            while self._selected_idx < n - 1 and isinstance(items[self._selected_idx], str):
                self._selected_idx += 1
        elif key in (curses.KEY_ENTER, 10, 13, curses.KEY_RIGHT):
            item = items[self._selected_idx] if 0 <= self._selected_idx < n else None
            if isinstance(item, PeerEntry):
                self._open_conv(item.name)
                item.unread = 0
            elif isinstance(item, GroupEntry):
                self._open_conv(item.name)
                item.unread = 0

    def _handle_chat_key(self, key):
        if key == curses.KEY_LEFT or key == 27:   # ← or Esc → back to list
            self._focus = "list"
            return
        if key == curses.KEY_PPAGE:   # PgUp
            self._scroll_offset += 10
            return
        if key == curses.KEY_NPAGE:   # PgDn
            self._scroll_offset = max(0, self._scroll_offset - 10)
            return
        if key == curses.KEY_UP:
            self._scroll_offset += 1
            return
        if key == curses.KEY_DOWN:
            self._scroll_offset = max(0, self._scroll_offset - 1)
            return
        if key in (curses.KEY_ENTER, 10, 13):
            self._do_send()
            return
        if key in (curses.KEY_BACKSPACE, 127, 8):
            self._input_buf = self._input_buf[:-1]
            return
        if 32 <= key <= 126:
            self._input_buf += chr(key)
        # Any printable key also moves focus to input implicitly
        self._focus = "chat"

    def _handle_prompt_key(self, key):
        p = self._prompt
        if key == 27:   # Esc
            self._prompt = None
            return
        if key in (curses.KEY_ENTER, 10, 13):
            cb  = p["callback"]
            val = p["input"]
            self._prompt = None
            if val.strip():
                cb(val.strip())
            return
        if key in (curses.KEY_BACKSPACE, 127, 8):
            p["input"] = p["input"][:-1]
            return
        if 32 <= key <= 126:
            p["input"] += chr(key)

    # ── Actions ───────────────────────────────────────────────────────────────

    def _open_conv(self, name: str):
        self._active_conv   = name
        self._scroll_offset = 0
        self._focus         = "chat"
        self._on_connect(name)

    def _do_send(self):
        text = self._input_buf.strip()
        if not text or not self._active_conv:
            return
        self._input_buf = ""
        self._scroll_offset = 0
        self.push_message(self._active_conv, "you", text)
        self._on_send_chat(self._active_conv, text)

    def _do_add_peer(self, name: str):
        self.add_peer(name)
        self._on_connect(name)
        self._open_conv(name)

    def _do_send_file(self, path: str):
        if self._active_conv:
            self._on_send_file(self._active_conv, path)

    def _do_create_group(self, name: str):
        # Second prompt: member list
        self._open_prompt(
            "Create Group",
            f"Members for #{name} (comma separated):",
            lambda members: self._on_create_group(name, [m.strip() for m in members.split(",")]),
        )

    def _open_prompt(self, title: str, label: str, callback: Callable, hint: str = ""):
        self._prompt = {"title": title, "label": label,
                        "input": "", "callback": callback, "hint": hint}

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _list_items(self) -> list:
        """Returns interleaved list of section headers + peer/group entries."""
        with self._lock:
            items: list = []
            if self._peers:
                items.append("── PEERS")
                items.extend(self._peers)
            if self._groups:
                items.append("── GROUPS")
                items.extend(self._groups)
            return items

    @staticmethod
    def _addstr_clipped(scr, row, col, text, attr=0):
        H, W = scr.getmaxyx()
        if row < 0 or row >= H or col < 0:
            return
        max_len = W - col - 1
        if max_len <= 0:
            return
        try:
            scr.addstr(row, col, text[:max_len], attr)
        except curses.error:
            pass