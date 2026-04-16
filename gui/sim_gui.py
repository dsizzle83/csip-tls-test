#!/usr/bin/env python3
"""
sim_gui.py  —  Live dashboard for DER simulator Pis.

  pip install -r requirements.txt
  python sim_gui.py                                     # all sims on localhost
  python sim_gui.py --host 192.168.10.1                 # all sims on one Pi
  python sim_gui.py --solar 192.168.10.10 \\
                    --battery 192.168.10.11 \\
                    --grid 192.168.10.12 \\
                    --load 192.168.10.13 \\
                    --ev 192.168.10.14

API ports (fixed):  solar=6020  battery=6021  grid=6022  load=6023  ev=6024
"""

import argparse
import json
import queue
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import customtkinter as ctk
import requests
import websocket

# ── appearance ────────────────────────────────────────────────────────────────
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

C_GREEN  = "#4CAF50"
C_RED    = "#F44336"
C_YELLOW = "#FFC107"
C_GRAY   = "#888888"
C_WHITE  = "#DDDDDD"


# ── simulator descriptors ─────────────────────────────────────────────────────

@dataclass
class SimDef:
    name:           str
    tab_label:      str
    api_port:       int
    # (key, human label, default entry text)
    inject_fields:  List[Tuple[str, str, str]]
    # (section title, [state keys to display])
    state_sections: List[Tuple[str, List[str]]]
    ev_mode:        bool = False
    has_animation:  bool = True


SIMS: List[SimDef] = [
    SimDef(
        name="solar",
        tab_label="Solar",
        api_port=6020,
        inject_fields=[
            ("W_W",            "AC Power (W)",       ""),
            ("V_V",            "AC Voltage (V)",      ""),
            ("Hz_Hz",          "Frequency (Hz)",      ""),
            ("DCV_V",          "DC Voltage (V)",      ""),
            ("TmpCab_C",       "Cabinet Temp (C)",    ""),
            ("WMaxLimPct_pct", "WMax Limit (%)",       ""),
            ("Conn",           "Connected (0/1)",      ""),
        ],
        state_sections=[
            ("Measurements", ["W_W", "V_V", "Hz_Hz", "DCV_V", "TmpCab_C"]),
            ("Controls",     ["WMaxLimPct_pct", "Conn", "St", "St_text"]),
            ("Nameplate",    ["WMax_W"]),
        ],
    ),
    SimDef(
        name="battery",
        tab_label="Battery",
        api_port=6021,
        inject_fields=[
            ("W_W",            "AC Power (W, neg=charge)", ""),
            ("V_V",            "AC Voltage (V)",            ""),
            ("TmpCab_C",       "Cabinet Temp (C)",          ""),
            ("SoC_pct",        "State of Charge (%)",       ""),
            ("SoH_pct",        "State of Health (%)",       ""),
            ("WMaxLimPct_pct", "WMax Limit (%)",             ""),
            ("Conn",           "Connected (0/1)",            ""),
            ("ChaSt",          "Charge Status (0-7)",        ""),
        ],
        state_sections=[
            ("Measurements", ["W_W", "V_V", "Hz_Hz", "TmpCab_C"]),
            ("Battery",      ["SoC_pct", "DoD_pct", "SoH_pct", "ChaSt", "ChaSt_text"]),
            ("Controls",     ["WMaxLimPct_pct", "Conn", "St", "St_text"]),
            ("Nameplate",    ["WMax_W", "capacity_kWh"]),
        ],
    ),
    SimDef(
        name="grid",
        tab_label="Grid",
        api_port=6022,
        inject_fields=[
            ("W_W",   "Power (W, neg=export)", ""),
            ("V_V",   "Voltage (V)",            ""),
            ("Hz_Hz", "Frequency (Hz)",         ""),
        ],
        state_sections=[
            ("Measurements", ["W_W", "V_V", "Hz_Hz", "VA_VA", "PF", "A_A"]),
        ],
    ),
    SimDef(
        name="load",
        tab_label="Home Load",
        api_port=6023,
        inject_fields=[
            ("W_W",   "Power (W)",      ""),
            ("V_V",   "Voltage (V)",    ""),
            ("Hz_Hz", "Frequency (Hz)", ""),
        ],
        state_sections=[
            ("Measurements", ["W_W", "V_V", "Hz_Hz", "VA_VA", "PF", "A_A"]),
        ],
    ),
    SimDef(
        name="ev",
        tab_label="EV Charger",
        api_port=6024,
        ev_mode=True,
        has_animation=False,
        inject_fields=[
            ("status",       "Connector Status", "Available"),
            ("connector_id", "Connector ID",      "1"),
        ],
        state_sections=[],   # EV state is built specially
    ),
]


# ── SimPanel ──────────────────────────────────────────────────────────────────

class SimPanel(ctk.CTkFrame):
    """Live dashboard panel for one simulator instance."""

    def __init__(self, parent: Any, sim: SimDef, host: str, **kwargs):
        super().__init__(parent, **kwargs)
        self.sim  = sim
        self.host = host
        self._q:        queue.Queue = queue.Queue()
        self._running:  bool        = True
        self._val_labels: Dict[str, ctk.CTkLabel] = {}
        self._entries:    Dict[str, ctk.CTkEntry]  = {}
        self._left_row  = 0
        self._right_row = 0

        self._build_ui()
        self._start_ws()
        self.after(200, self._drain)

    # ── UI construction ───────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        self.grid_columnconfigure(0, weight=3)
        self.grid_columnconfigure(1, weight=2)
        self.grid_rowconfigure(1, weight=1)

        # ── status bar ──
        bar = ctk.CTkFrame(self, height=38, corner_radius=0, fg_color="gray17")
        bar.grid(row=0, column=0, columnspan=2, sticky="ew")
        bar.grid_columnconfigure(0, weight=1)

        self._status_lbl = ctk.CTkLabel(
            bar, text="  Disconnected",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=C_RED,
        )
        self._status_lbl.grid(row=0, column=0, sticky="w", padx=10, pady=6)

        self._latency_lbl = ctk.CTkLabel(
            bar, text="", font=ctk.CTkFont(size=11), text_color=C_GRAY)
        self._latency_lbl.grid(row=0, column=1, sticky="e", padx=6, pady=6)

        ctk.CTkButton(bar, text="Reconnect", width=88, height=26,
                      command=self._reconnect).grid(
            row=0, column=2, padx=8, pady=5)

        # ── left: live state ──
        left = ctk.CTkScrollableFrame(
            self, label_text="Live State",
            label_font=ctk.CTkFont(size=13, weight="bold"),
            corner_radius=6,
        )
        left.grid(row=1, column=0, sticky="nsew", padx=(8, 4), pady=8)
        left.grid_columnconfigure(1, weight=1)
        self._left = left

        if self.sim.ev_mode:
            self._build_ev_state_section(left)
        else:
            for section_title, keys in self.sim.state_sections:
                self._section_header(left, section_title)
                for k in keys:
                    self._val_row(left, k)

        # ── animation bar (non-EV) ──
        if self.sim.has_animation:
            abar = ctk.CTkFrame(self, height=52, corner_radius=6, fg_color="gray17")
            abar.grid(row=2, column=0, sticky="ew", padx=(8, 4), pady=(0, 8))
            self._build_anim_bar(abar)

        # ── right: inject + controls ──
        right = ctk.CTkScrollableFrame(
            self, label_text="Inject / Control",
            label_font=ctk.CTkFont(size=13, weight="bold"),
            corner_radius=6,
        )
        right.grid(row=1, column=1, rowspan=2, sticky="nsew", padx=(4, 8), pady=8)
        right.grid_columnconfigure(1, weight=1)
        self._right = right

        self._build_inject_panel(right)
        if self.sim.ev_mode:
            self._build_ev_actions(right)
        self._build_registers_button(right)

    # ── section helpers ───────────────────────────────────────────────────────

    def _section_header(self, parent: Any, title: str) -> None:
        ctk.CTkLabel(
            parent, text=title,
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=C_YELLOW,
            anchor="w",
        ).grid(row=self._left_row, column=0, columnspan=2,
               sticky="w", padx=8, pady=(10, 2))
        self._left_row += 1

    def _val_row(self, parent: Any, key: str) -> None:
        ctk.CTkLabel(
            parent, text=key,
            font=ctk.CTkFont(size=12),
            text_color=C_GRAY, anchor="w",
        ).grid(row=self._left_row, column=0, sticky="w", padx=(18, 4), pady=1)

        lbl = ctk.CTkLabel(
            parent, text="—",
            font=ctk.CTkFont(size=12, family="Courier New"),
            text_color=C_WHITE, anchor="e",
        )
        lbl.grid(row=self._left_row, column=1, sticky="e", padx=(4, 10), pady=1)
        self._val_labels[key] = lbl
        self._left_row += 1

    def _build_ev_state_section(self, parent: Any) -> None:
        self._section_header(parent, "OCPP Connection")
        for k in ("connected", "last_heartbeat"):
            self._val_row(parent, k)

        self._section_header(parent, "Connectors")
        for i in range(1, 3):
            self._val_row(parent, f"connector_{i}")

        self._section_header(parent, "Session")
        for k in ("session_active", "session_connector", "energy_Wh"):
            self._val_row(parent, k)

        self._section_header(parent, "Last Charging Profile")
        for k in ("profile_connector", "limit_A"):
            self._val_row(parent, k)

    # ── animation bar ─────────────────────────────────────────────────────────

    def _build_anim_bar(self, parent: Any) -> None:
        parent.grid_columnconfigure(3, weight=1)

        ctk.CTkLabel(parent, text="Animation:",
                     font=ctk.CTkFont(size=12)).grid(
            row=0, column=0, padx=(12, 4), pady=10)

        self._anim_lbl = ctk.CTkLabel(
            parent, text="unknown",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=C_GRAY, width=64,
        )
        self._anim_lbl.grid(row=0, column=1, padx=4, pady=10)

        ctk.CTkButton(parent, text="Pause", width=72,
                      command=lambda: self._post_control({"cmd": "pause"})).grid(
            row=0, column=2, padx=4, pady=10)
        ctk.CTkButton(parent, text="Resume", width=72,
                      command=lambda: self._post_control({"cmd": "resume"})).grid(
            row=0, column=3, padx=(4, 12), pady=10)

        ctk.CTkLabel(parent, text="Speed:",
                     font=ctk.CTkFont(size=12)).grid(
            row=0, column=4, padx=(12, 2), pady=10)

        self._speed_var = ctk.DoubleVar(value=1.0)
        ctk.CTkSlider(
            parent, from_=0.1, to=20.0, number_of_steps=199,
            variable=self._speed_var, width=130,
            command=self._on_speed_drag,
        ).grid(row=0, column=5, padx=4, pady=10)

        self._speed_lbl = ctk.CTkLabel(
            parent, text="1.0x",
            font=ctk.CTkFont(size=12), width=40,
        )
        self._speed_lbl.grid(row=0, column=6, padx=(2, 12), pady=10)

    def _on_speed_drag(self, val: float) -> None:
        speed = round(float(val), 1)
        self._speed_lbl.configure(text=f"{speed:.1f}x")
        if hasattr(self, "_speed_after_id"):
            self.after_cancel(self._speed_after_id)
        self._speed_after_id = self.after(
            400, lambda: self._post_control({"speed": speed}))

    # ── inject panel ──────────────────────────────────────────────────────────

    def _build_inject_panel(self, parent: Any) -> None:
        ctk.CTkLabel(
            parent, text="Inject Fields",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=C_YELLOW,
        ).grid(row=self._right_row, column=0, columnspan=2,
               sticky="w", padx=8, pady=(10, 4))
        self._right_row += 1

        for key, label, default in self.sim.inject_fields:
            ctk.CTkLabel(
                parent, text=label,
                font=ctk.CTkFont(size=11), text_color=C_GRAY, anchor="w",
            ).grid(row=self._right_row, column=0, sticky="w", padx=(10, 4), pady=2)
            e = ctk.CTkEntry(parent, placeholder_text=key, width=108)
            e.grid(row=self._right_row, column=1, sticky="ew", padx=(0, 8), pady=2)
            if default:
                e.insert(0, default)
            self._entries[key] = e
            self._right_row += 1

        ctk.CTkButton(
            parent, text="Send Inject",
            command=self._send_inject,
        ).grid(row=self._right_row, column=0, columnspan=2,
               sticky="ew", padx=8, pady=(8, 2))
        self._right_row += 1

        ctk.CTkButton(
            parent, text="Clear",
            fg_color="gray30", hover_color="gray40",
            command=self._clear_entries,
        ).grid(row=self._right_row, column=0, columnspan=2,
               sticky="ew", padx=8, pady=(0, 8))
        self._right_row += 1

    def _build_ev_actions(self, parent: Any) -> None:
        ctk.CTkLabel(
            parent, text="Quick Actions",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=C_YELLOW,
        ).grid(row=self._right_row, column=0, columnspan=2,
               sticky="w", padx=8, pady=(12, 4))
        self._right_row += 1

        actions = [
            ("Start Session C1",  {"action": "start_session", "connector_id": 1}),
            ("Start Session C2",  {"action": "start_session", "connector_id": 2}),
            ("Stop Session",      {"action": "stop_session"}),
            ("Available  C1",     {"status": "Available",   "connector_id": 1}),
            ("Unavailable C1",    {"status": "Unavailable", "connector_id": 1}),
            ("Fault C1",          {"status": "Faulted",     "connector_id": 1}),
            ("Available  C2",     {"status": "Available",   "connector_id": 2}),
            ("Fault C2",          {"status": "Faulted",     "connector_id": 2}),
        ]
        for label, payload in actions:
            ctk.CTkButton(
                parent, text=label, height=28,
                command=lambda p=payload: self._post_inject(p),
            ).grid(row=self._right_row, column=0, columnspan=2,
                   sticky="ew", padx=8, pady=2)
            self._right_row += 1

    def _build_registers_button(self, parent: Any) -> None:
        self._right_row += 1
        ctk.CTkButton(
            parent, text="Show Registers",
            fg_color="gray25", hover_color="gray35",
            command=self._show_registers,
        ).grid(row=self._right_row, column=0, columnspan=2,
               sticky="ew", padx=8, pady=4)
        self._right_row += 1

    # ── HTTP ──────────────────────────────────────────────────────────────────

    def _base(self) -> str:
        return f"http://{self.host}:{self.sim.api_port}"

    def _send_inject(self) -> None:
        payload: Dict[str, Any] = {}
        for key, entry in self._entries.items():
            raw = entry.get().strip()
            if not raw:
                continue
            try:
                payload[key] = float(raw) if "." in raw else int(raw)
            except ValueError:
                payload[key] = raw
        if payload:
            self._post_inject(payload)

    def _post_inject(self, payload: dict) -> None:
        threading.Thread(
            target=self._http_post, args=("/inject", payload), daemon=True
        ).start()

    def _post_control(self, payload: dict) -> None:
        threading.Thread(
            target=self._http_post, args=("/control", payload), daemon=True
        ).start()

    def _http_post(self, path: str, payload: dict) -> None:
        try:
            requests.post(f"{self._base()}{path}", json=payload, timeout=4)
        except Exception as exc:
            print(f"[{self.sim.name}] POST {path}: {exc}")

    def _clear_entries(self) -> None:
        for e in self._entries.values():
            e.delete(0, "end")

    def _show_registers(self) -> None:
        def fetch():
            try:
                r = requests.get(f"{self._base()}/registers", timeout=4)
                data = r.json()
            except Exception as exc:
                data = {"error": str(exc)}
            self.after(0, lambda: _open_reg_window(self, self.sim.name, data))
        threading.Thread(target=fetch, daemon=True).start()

    # ── WebSocket ─────────────────────────────────────────────────────────────

    def _start_ws(self) -> None:
        threading.Thread(target=self._ws_worker, daemon=True).start()

    def _reconnect(self) -> None:
        self._set_status(False)

    def _ws_worker(self) -> None:
        while self._running:
            url = f"ws://{self.host}:{self.sim.api_port}/ws"
            try:
                ws = websocket.WebSocketApp(
                    url,
                    on_open=lambda ws: self._q.put("__connected__"),
                    on_message=lambda ws, msg: self._q.put(msg),
                    on_close=lambda ws, code, msg: self._q.put("__disconnected__"),
                    on_error=lambda ws, e: None,
                )
                ws.run_forever(ping_interval=15, ping_timeout=8)
            except Exception:
                pass
            if self._running:
                time.sleep(3)

    # ── drain loop ────────────────────────────────────────────────────────────

    def _drain(self) -> None:
        t0 = time.monotonic()
        while not self._q.empty():
            try:
                item = self._q.get_nowait()
            except queue.Empty:
                break
            if item == "__connected__":
                self._set_status(True)
            elif item == "__disconnected__":
                self._set_status(False)
            else:
                try:
                    self._update(json.loads(item))
                    ms = int((time.monotonic() - t0) * 1000)
                    self._latency_lbl.configure(text=f"{ms} ms")
                except Exception:
                    pass
        self.after(200, self._drain)

    # ── state update ──────────────────────────────────────────────────────────

    def _set_status(self, connected: bool) -> None:
        if connected:
            self._status_lbl.configure(text="  Connected", text_color=C_GREEN)
        else:
            self._status_lbl.configure(text="  Disconnected", text_color=C_RED)
            self._latency_lbl.configure(text="")

    def _set_val(self, key: str, val: Any) -> None:
        lbl = self._val_labels.get(key)
        if lbl is None:
            return
        if isinstance(val, float):
            lbl.configure(text=f"{val:.2f}")
        else:
            lbl.configure(text=str(val))

    def _update(self, data: dict) -> None:
        if self.sim.ev_mode:
            self._update_ev(data)
            return

        # flatten nested dicts so "measurements.W_W" → flat["W_W"]
        flat: Dict[str, Any] = {}
        for v in data.values():
            if isinstance(v, dict):
                flat.update(v)

        for key in self._val_labels:
            if key in flat:
                self._set_val(key, flat[key])

        # animation bar
        anim = data.get("animation", {})
        if anim and hasattr(self, "_anim_lbl"):
            paused = anim.get("paused", False)
            speed  = float(anim.get("speed", 1.0))
            self._anim_lbl.configure(
                text="Paused" if paused else "Running",
                text_color=C_YELLOW if paused else C_GREEN,
            )
            self._speed_lbl.configure(text=f"{speed:.1f}x")
            self._speed_var.set(speed)

    def _update_ev(self, data: dict) -> None:
        self._set_val("connected",
                      "Yes" if data.get("connected") else "No")
        hb = data.get("last_heartbeat") or "—"
        self._set_val("last_heartbeat", hb[:19] if len(hb) > 19 else hb)

        for c in data.get("connectors", []):
            self._set_val(f"connector_{c['id']}", c.get("status", "—"))

        sess = data.get("session") or {}
        self._set_val("session_active",    "Yes" if sess.get("active") else "No")
        self._set_val("session_connector", str(sess.get("connector_id", "—")))
        self._set_val("energy_Wh",
                      f"{sess['energy_Wh']:.0f}" if sess.get("energy_Wh") else "—")

        prof = data.get("last_profile") or {}
        self._set_val("profile_connector", str(prof.get("connector_id", "—")))
        self._set_val("limit_A",
                      f"{prof['limit_A']:.1f} A" if prof.get("limit_A") else "—")

    def destroy(self) -> None:
        self._running = False
        super().destroy()


# ── register popup ────────────────────────────────────────────────────────────

def _open_reg_window(parent: Any, sim_name: str, data: dict) -> None:
    win = ctk.CTkToplevel(parent)
    win.title(f"{sim_name} — Registers")
    win.geometry("540x480")
    win.grid_columnconfigure(0, weight=1)
    win.grid_rowconfigure(0, weight=1)

    txt = ctk.CTkTextbox(win, font=ctk.CTkFont(size=11, family="Courier New"))
    txt.grid(row=0, column=0, sticky="nsew", padx=8, pady=8)

    # format as sorted table
    lines = []
    if "error" in data:
        lines.append(f"Error: {data['error']}")
    else:
        lines.append(f"{'Register':<12}  {'Value':>6}")
        lines.append("-" * 22)
        for k, v in sorted(data.items()):
            lines.append(f"{k:<12}  {v:>6}")

    txt.insert("1.0", "\n".join(lines))
    txt.configure(state="disabled")

    ctk.CTkButton(win, text="Close", command=win.destroy).grid(
        row=1, column=0, pady=(0, 8), padx=8, sticky="e")


# ── main app ──────────────────────────────────────────────────────────────────

class App(ctk.CTk):
    def __init__(self, hosts: Dict[str, str]) -> None:
        super().__init__()
        self.title("DER Simulator Dashboard")
        self.geometry("1180x660")
        self.minsize(900, 520)
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        tabs = ctk.CTkTabview(self, corner_radius=8)
        tabs.grid(row=0, column=0, sticky="nsew", padx=8, pady=8)

        for sim in SIMS:
            host = hosts.get(sim.name, hosts["_default"])
            tab  = tabs.add(sim.tab_label)
            tab.grid_columnconfigure(0, weight=1)
            tab.grid_rowconfigure(0, weight=1)
            SimPanel(tab, sim, host, corner_radius=6).grid(
                row=0, column=0, sticky="nsew")


def main() -> None:
    p = argparse.ArgumentParser(description="DER Simulator Dashboard")
    p.add_argument("--host",    default="localhost",
                   help="Default host for all simulators (default: localhost)")
    p.add_argument("--solar",   default=None, metavar="IP",
                   help="Host for solar simulator Pi")
    p.add_argument("--battery", default=None, metavar="IP",
                   help="Host for battery simulator Pi")
    p.add_argument("--grid",    default=None, metavar="IP",
                   help="Host for grid meter simulator Pi")
    p.add_argument("--load",    default=None, metavar="IP",
                   help="Host for home load simulator Pi")
    p.add_argument("--ev",      default=None, metavar="IP",
                   help="Host for EV charger simulator Pi")
    args = p.parse_args()

    hosts = {
        "_default": args.host,
        "solar":    args.solar   or args.host,
        "battery":  args.battery or args.host,
        "grid":     args.grid    or args.host,
        "load":     args.load    or args.host,
        "ev":       args.ev      or args.host,
    }

    App(hosts).mainloop()


if __name__ == "__main__":
    main()
