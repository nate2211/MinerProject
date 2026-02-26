from __future__ import annotations

import json
import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

from PyQt5.QtCore import (
    Qt,
    QThread,
    pyqtSignal,
    QTimer,
    QStandardPaths,
)
from PyQt5.QtGui import QFont, QPalette, QColor
from PyQt5.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QFormLayout,
    QGroupBox,
    QLabel,
    QLineEdit,
    QPushButton,
    QPlainTextEdit,
    QMessageBox,
    QSplitter,
    QTabWidget,
    QSpinBox,
    QCheckBox,
    QFileDialog,
    QSizePolicy,
)

# --- your miner core ---
from miner_core import Miner

# --- optional: use your BlockNet blocks (keeps your "block structure") ---
from registry import BLOCKS
import blocks_blocknet  # registers blocknet_heartbeat / blocknet_put


# ----------------------------- Paths + config -----------------------------

def app_data_dir(app_name: str = "MoneroMinerGUI") -> Path:
    base = QStandardPaths.writableLocation(QStandardPaths.AppDataLocation)
    p = Path(base) / app_name
    p.mkdir(parents=True, exist_ok=True)
    return p


CFG_PATH = app_data_dir() / "miner_gui_config.json"


# ----------------------------- Theme -----------------------------

def apply_dark_theme(app: QApplication) -> None:
    app.setStyle("Fusion")

    pal = QPalette()
    pal.setColor(QPalette.Window, QColor(24, 24, 24))
    pal.setColor(QPalette.WindowText, QColor(235, 235, 235))
    pal.setColor(QPalette.Base, QColor(16, 16, 16))
    pal.setColor(QPalette.AlternateBase, QColor(28, 28, 28))
    pal.setColor(QPalette.ToolTipBase, QColor(255, 255, 255))
    pal.setColor(QPalette.ToolTipText, QColor(0, 0, 0))
    pal.setColor(QPalette.Text, QColor(235, 235, 235))
    pal.setColor(QPalette.Button, QColor(34, 34, 34))
    pal.setColor(QPalette.ButtonText, QColor(235, 235, 235))
    pal.setColor(QPalette.Link, QColor(110, 180, 255))
    pal.setColor(QPalette.Highlight, QColor(70, 130, 220))
    pal.setColor(QPalette.HighlightedText, QColor(255, 255, 255))
    app.setPalette(pal)

    app.setStyleSheet("""
        QWidget { font-size: 12px; }
        QGroupBox {
            border: 1px solid #3a3a3a;
            border-radius: 10px;
            margin-top: 10px;
            padding: 10px;
        }
        QGroupBox::title {
            subcontrol-origin: margin;
            left: 10px;
            padding: 0 8px 0 8px;
            color: #dcdcdc;
            font-weight: 600;
        }
        QLineEdit, QPlainTextEdit, QSpinBox {
            border: 1px solid #404040;
            border-radius: 8px;
            padding: 7px;
            background: #101010;
            selection-background-color: #467fdc;
        }
        QPushButton {
            border: 1px solid #4a4a4a;
            border-radius: 10px;
            padding: 9px 12px;
            background: #242424;
            font-weight: 600;
        }
        QPushButton:hover { background: #2a2a2a; }
        QPushButton:pressed { background: #171717; }
        QPushButton:disabled {
            color: #7b7b7b;
            border-color: #2f2f2f;
            background: #202020;
        }
        QTabWidget::pane {
            border: 1px solid #3a3a3a;
            border-radius: 10px;
            top: -1px;
        }
        QTabBar::tab {
            background: #242424;
            border: 1px solid #3a3a3a;
            padding: 9px 14px;
            border-top-left-radius: 10px;
            border-top-right-radius: 10px;
            margin-right: 2px;
        }
        QTabBar::tab:selected { background: #161616; }
        QLabel#Pill {
            border-radius: 12px;
            padding: 5px 12px;
            font-weight: 700;
        }
        QSplitter::handle { background: #3a3a3a; }
        QSplitter::handle:horizontal { width: 10px; border-radius: 5px; }
        QSplitter::handle:vertical { height: 10px; border-radius: 5px; }
    """)


# ----------------------------- Worker thread -----------------------------

@dataclass
class MinerConfig:
    stratum: str
    wallet: str
    password: str
    threads: int
    agent: str
    randomx_lib: str

    # BlockNet (optional)
    use_blocknet: bool
    blocknet_relay: str
    blocknet_token: str
    blocknet_id: str
    blocknet_key: str


class MinerWorker(QThread):
    log_line = pyqtSignal(str)
    stats_updated = pyqtSignal(dict)
    state_changed = pyqtSignal(str)   # "RUNNING" | "STOPPED"
    fatal_error = pyqtSignal(str)

    def __init__(self, cfg: MinerConfig) -> None:
        super().__init__()
        self.cfg = cfg
        self._miner: Optional[Miner] = None
        self._stop_requested = False

        # optional BlockNet blocks (keep your "block structure")
        self._bn_heartbeat = None
        self._bn_put = None

    def stop(self) -> None:
        self._stop_requested = True
        if self._miner:
            try:
                self._miner.stop()
            except Exception:
                pass

    def _setup_blocknet(self) -> None:
        if not self.cfg.use_blocknet:
            return
        if not self.cfg.blocknet_relay.strip():
            return

        self._bn_heartbeat = BLOCKS.create("blocknet_heartbeat")
        if self.cfg.blocknet_key.strip():
            self._bn_put = BLOCKS.create("blocknet_put")

    def run(self) -> None:
        try:
            self.state_changed.emit("RUNNING")

            # Set RandomX lib override (ctypes loader reads this)
            if self.cfg.randomx_lib.strip():
                os.environ["RANDOMX_LIB"] = self.cfg.randomx_lib.strip()

            self._setup_blocknet()

            host, port_s = self.cfg.stratum.rsplit(":", 1)
            port = int(port_s)

            self._miner = Miner(
                stratum_host=host.strip(),
                stratum_port=port,
                wallet=self.cfg.wallet.strip(),
                password=self.cfg.password,
                threads=int(self.cfg.threads),
                agent=self.cfg.agent.strip() or "py-blockminer/0.1",
            )

            last_stats: Dict[str, Any] = {}

            def on_stats(stats: Dict[str, Any]) -> None:
                nonlocal last_stats
                last_stats = dict(stats or {})
                self.stats_updated.emit(last_stats)

                # Lightweight, readable periodic line
                hps = float(last_stats.get("hashrate_hs") or 0.0)
                acc = int(last_stats.get("accepted") or 0)
                rej = int(last_stats.get("rejected") or 0)
                height = last_stats.get("height")
                job_id = (last_stats.get("job_id") or "")[:10]
                self.log_line.emit(
                    f"[stats] {hps:,.0f} H/s | A:{acc} R:{rej} | height={height} | job={job_id}"
                )

                # Optional BlockNet reporting (in-thread)
                if self._bn_heartbeat:
                    try:
                        self._bn_heartbeat.execute(
                            last_stats,
                            params={
                                "relay": self.cfg.blocknet_relay,
                                "token": self.cfg.blocknet_token,
                                "id": self.cfg.blocknet_id,
                            },
                        )
                    except Exception as e:
                        self.log_line.emit(f"[blocknet] heartbeat error: {e}")

                if self._bn_put and self.cfg.blocknet_key.strip():
                    try:
                        payload = json.dumps(last_stats).encode("utf-8")
                        self._bn_put.execute(
                            payload,
                            params={
                                "relay": self.cfg.blocknet_relay,
                                "token": self.cfg.blocknet_token,
                                "key": self.cfg.blocknet_key,
                                "mime": "application/json",
                            },
                        )
                    except Exception as e:
                        self.log_line.emit(f"[blocknet] put error: {e}")

            # Run miner (this blocks until stop / error)
            try:
                import asyncio
                asyncio.run(self._miner.run(on_stats=on_stats))
            except KeyboardInterrupt:
                pass

            self.state_changed.emit("STOPPED")

        except Exception as e:
            import traceback
            self.state_changed.emit("STOPPED")
            self.fatal_error.emit(traceback.format_exc())


# ----------------------------- GUI -----------------------------

def _mono_font() -> QFont:
    f = QFont("Consolas")
    f.setStyleHint(QFont.Monospace)
    f.setPointSize(10)
    return f


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Nate's Monero Miner (P2Pool) — BlockNet Edition")

        self.worker: Optional[MinerWorker] = None
        self.started_at: float = 0.0

        # root layout
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(10)

        # header
        header = QHBoxLayout()
        title = QLabel("Monero Miner")
        tf = QFont()
        tf.setPointSize(16)
        tf.setBold(True)
        title.setFont(tf)

        self.pill = QLabel("STOPPED")
        self.pill.setObjectName("Pill")


        header.addWidget(title)
        header.addStretch(1)
        header.addWidget(self.pill)
        root.addLayout(header)

        # main splitter
        self.main_split = QSplitter(Qt.Horizontal)
        self.main_split.setChildrenCollapsible(False)
        self.main_split.setHandleWidth(10)
        root.addWidget(self.main_split, 1)

        # LEFT: controls (vertical splitter)
        self.left_split = QSplitter(Qt.Vertical)
        self.left_split.setChildrenCollapsible(False)
        self.left_split.setHandleWidth(10)
        self.left_split.setMinimumWidth(420)
        self.left_split.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.main_split.addWidget(self.left_split)

        # RIGHT: tabs (dashboard/log/raw)
        right = QWidget()
        right_l = QVBoxLayout(right)
        right_l.setContentsMargins(0, 0, 0, 0)

        self.tabs = QTabWidget()
        right_l.addWidget(self.tabs)
        self.main_split.addWidget(right)

        self.main_split.setStretchFactor(0, 1)
        self.main_split.setStretchFactor(1, 2)

        # ---- Controls groups ----

        # Mining connection
        gb_conn = QGroupBox("Mining (P2Pool Stratum)")
        fl = QFormLayout(gb_conn)

        self.ed_stratum = QLineEdit("127.0.0.1:3333")
        self.ed_wallet = QLineEdit("")
        self.ed_pass = QLineEdit("x")
        self.ed_agent = QLineEdit("py-blockminer/0.1")

        fl.addRow("Stratum (host:port)", self.ed_stratum)
        fl.addRow("Wallet address", self.ed_wallet)
        fl.addRow("Password", self.ed_pass)
        fl.addRow("Agent", self.ed_agent)

        self.left_split.addWidget(gb_conn)

        # Performance
        gb_perf = QGroupBox("Performance")
        pfl = QFormLayout(gb_perf)

        self.sp_threads = QSpinBox()
        self.sp_threads.setRange(1, 256)
        self.sp_threads.setValue(4)

        self.ed_randomx = QLineEdit("")
        self.btn_browse_randomx = QPushButton("Browse…")
        self.btn_browse_randomx.clicked.connect(self._browse_randomx)

        pfl.addRow("Threads", self.sp_threads)
        pfl.addRow("RandomX lib (optional)", self._hbox(self.ed_randomx, self.btn_browse_randomx))

        self.left_split.addWidget(gb_perf)

        # BlockNet reporting
        gb_bn = QGroupBox("BlockNet Reporting (optional)")
        bfl = QFormLayout(gb_bn)

        self.cb_bn = QCheckBox("Enable BlockNet heartbeat + stats PUT")
        self.cb_bn.setChecked(False)

        self.ed_bn_relay = QLineEdit("127.0.0.1:38887")
        self.ed_bn_token = QLineEdit("")
        self.ed_bn_token.setEchoMode(QLineEdit.Password)
        self.ed_bn_id = QLineEdit("miner1")
        self.ed_bn_key = QLineEdit("miner/stats")

        bfl.addRow(self.cb_bn)
        bfl.addRow("Relay (host:port)", self.ed_bn_relay)
        bfl.addRow("Token", self.ed_bn_token)
        bfl.addRow("Heartbeat ID", self.ed_bn_id)
        bfl.addRow("PUT key", self.ed_bn_key)

        self.left_split.addWidget(gb_bn)

        # Controls
        gb_ctrl = QGroupBox("Controls")
        cl = QVBoxLayout(gb_ctrl)

        btn_row = QHBoxLayout()
        self.btn_start = QPushButton("Start Mining")
        self.btn_stop = QPushButton("Stop")
        self.btn_stop.setDisabled(True)

        self.btn_start.clicked.connect(self._start)
        self.btn_stop.clicked.connect(self._stop)
        self._set_running(False)
        btn_row.addWidget(self.btn_start)
        btn_row.addWidget(self.btn_stop)
        cl.addLayout(btn_row)

        btn_row2 = QHBoxLayout()
        self.btn_save = QPushButton("Save Config")
        self.btn_load = QPushButton("Load Config")
        self.btn_clear = QPushButton("Clear Log")

        self.btn_save.clicked.connect(self._save_cfg)
        self.btn_load.clicked.connect(self._load_cfg)
        self.btn_clear.clicked.connect(lambda: self.txt_log.setPlainText(""))

        btn_row2.addWidget(self.btn_save)
        btn_row2.addWidget(self.btn_load)
        btn_row2.addWidget(self.btn_clear)
        cl.addLayout(btn_row2)

        self.left_split.addWidget(gb_ctrl)

        # ---- Right tabs ----

        # Dashboard tab
        dash = QWidget()
        dl = QVBoxLayout(dash)
        dl.setContentsMargins(10, 10, 10, 10)
        dl.setSpacing(10)

        self.lbl_hashrate = QLabel("0 H/s")
        hf = QFont()
        hf.setPointSize(28)
        hf.setBold(True)
        self.lbl_hashrate.setFont(hf)

        self.lbl_sub = QLabel("Accepted: 0    Rejected: 0    Height: —    Threads: —")
        sf = QFont()
        sf.setPointSize(12)
        self.lbl_sub.setFont(sf)

        self.lbl_uptime = QLabel("Uptime: 00:00:00")
        self.lbl_uptime.setStyleSheet("color:#cfcfcf;")

        dl.addWidget(self.lbl_hashrate)
        dl.addWidget(self.lbl_sub)
        dl.addWidget(self.lbl_uptime)
        dl.addStretch(1)

        self.tabs.addTab(dash, "Dashboard")

        # Log tab
        log = QWidget()
        ll = QVBoxLayout(log)
        ll.setContentsMargins(10, 10, 10, 10)
        self.txt_log = QPlainTextEdit()
        self.txt_log.setReadOnly(True)
        self.txt_log.setFont(_mono_font())
        ll.addWidget(self.txt_log)
        self.tabs.addTab(log, "Log")

        # Raw stats tab
        raw = QWidget()
        rl = QVBoxLayout(raw)
        rl.setContentsMargins(10, 10, 10, 10)
        self.txt_raw = QPlainTextEdit()
        self.txt_raw.setReadOnly(True)
        self.txt_raw.setFont(_mono_font())
        rl.addWidget(self.txt_raw)
        self.tabs.addTab(raw, "Raw Stats")

        # timers
        self.uptime_timer = QTimer(self)
        self.uptime_timer.setInterval(500)
        self.uptime_timer.timeout.connect(self._tick_uptime)

        # initial sizing
        self.left_split.setSizes([220, 150, 200, 120])
        self.main_split.setSizes([520, 900])

        # load config
        self._load_cfg()

        self.statusBar().showMessage("Ready")

    # ---------- helpers ----------

    @staticmethod
    def _hbox(*widgets: QWidget) -> QWidget:
        w = QWidget()
        l = QHBoxLayout(w)
        l.setContentsMargins(0, 0, 0, 0)
        l.setSpacing(8)
        for x in widgets:
            l.addWidget(x)
        return w

    def _append_log(self, s: str) -> None:
        s = (s or "").replace("\r\n", "\n").replace("\r", "\n").strip()
        if not s:
            return
        self.txt_log.appendPlainText(s)

        # cap blocks
        MAX_BLOCKS = 5000
        doc = self.txt_log.document()
        if doc.blockCount() > MAX_BLOCKS:
            cur = self.txt_log.textCursor()
            cur.movePosition(cur.Start)
            for _ in range(doc.blockCount() - MAX_BLOCKS):
                cur.select(cur.LineUnderCursor)
                cur.removeSelectedText()
                cur.deleteChar()

    def _set_running(self, running: bool) -> None:
        if running:
            self.pill.setText("RUNNING")
            self.pill.setStyleSheet("background:#143d27; color:#eaffea;")
        else:
            self.pill.setText("STOPPED")
            self.pill.setStyleSheet("background:#4a1f1f; color:#ffecec;")

        self.btn_start.setDisabled(running)
        self.btn_stop.setDisabled(not running)

    def _browse_randomx(self) -> None:
        start = str(Path.home())
        cur = self.ed_randomx.text().strip()
        if cur:
            p = Path(cur)
            if p.exists():
                start = str(p.parent)

        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select RandomX library",
            start,
            "RandomX Library (*.dll *.so *.dylib);;All files (*.*)"
        )
        if path:
            self.ed_randomx.setText(path)

    def _tick_uptime(self) -> None:
        if not self.started_at:
            self.lbl_uptime.setText("Uptime: 00:00:00")
            return
        dt = int(max(0, time.time() - self.started_at))
        h = dt // 3600
        m = (dt % 3600) // 60
        s = dt % 60
        self.lbl_uptime.setText(f"Uptime: {h:02d}:{m:02d}:{s:02d}")

    # ---------- start/stop ----------

    def _start(self) -> None:
        if self.worker and self.worker.isRunning():
            return

        stratum = self.ed_stratum.text().strip()
        wallet = self.ed_wallet.text().strip()
        password = self.ed_pass.text()
        agent = self.ed_agent.text().strip() or "py-blockminer/0.1"
        threads = int(self.sp_threads.value())
        randomx_lib = self.ed_randomx.text().strip()

        if ":" not in stratum:
            QMessageBox.critical(self, "Invalid Stratum", "Stratum must be in the form host:port (e.g. 127.0.0.1:3333).")
            return
        if not wallet:
            QMessageBox.critical(self, "Missing Wallet", "Please enter your Monero wallet address.")
            return

        use_bn = bool(self.cb_bn.isChecked())
        cfg = MinerConfig(
            stratum=stratum,
            wallet=wallet,
            password=password,
            threads=threads,
            agent=agent,
            randomx_lib=randomx_lib,

            use_blocknet=use_bn,
            blocknet_relay=self.ed_bn_relay.text().strip(),
            blocknet_token=self.ed_bn_token.text().strip(),
            blocknet_id=self.ed_bn_id.text().strip() or "miner1",
            blocknet_key=self.ed_bn_key.text().strip(),
        )

        self._save_cfg()

        self.txt_log.appendPlainText("[gui] starting miner…")
        self._set_running(True)
        self.started_at = time.time()
        self.uptime_timer.start()

        self.worker = MinerWorker(cfg)
        self.worker.log_line.connect(self._append_log)
        self.worker.stats_updated.connect(self._on_stats)
        self.worker.state_changed.connect(self._on_state)
        self.worker.fatal_error.connect(self._on_fatal)
        self.worker.start()

    def _stop(self) -> None:
        if self.worker and self.worker.isRunning():
            self._append_log("[gui] stopping…")
            self.worker.stop()
        else:
            self._set_running(False)

    def _on_state(self, s: str) -> None:
        if s == "RUNNING":
            self._set_running(True)
        else:
            self._set_running(False)
            self.started_at = 0.0
            self.uptime_timer.stop()
            self._tick_uptime()
            self._append_log("[gui] stopped")

    def _on_fatal(self, msg: str) -> None:
        self._append_log(f"[fatal] {msg}")
        QMessageBox.critical(self, "Miner Error", msg)
        self._set_running(False)
        self.started_at = 0.0
        self.uptime_timer.stop()
        self._tick_uptime()

    def _on_stats(self, stats: dict) -> None:
        # Pretty dashboard
        hps = float(stats.get("hashrate_hs") or 0.0)
        acc = int(stats.get("accepted") or 0)
        rej = int(stats.get("rejected") or 0)
        height = stats.get("height")
        th = int(stats.get("threads") or self.sp_threads.value())

        self.lbl_hashrate.setText(f"{hps:,.0f} H/s")
        self.lbl_sub.setText(f"Accepted: {acc}    Rejected: {rej}    Height: {height if height is not None else '—'}    Threads: {th}")

        # Raw JSON
        try:
            self.txt_raw.setPlainText(json.dumps(stats, indent=2))
        except Exception:
            self.txt_raw.setPlainText(str(stats))

    # ---------- config ----------

    def _save_cfg(self) -> None:
        try:
            j = {
                "stratum": self.ed_stratum.text().strip(),
                "wallet": self.ed_wallet.text().strip(),
                "pass": self.ed_pass.text(),
                "agent": self.ed_agent.text().strip(),
                "threads": int(self.sp_threads.value()),
                "randomx_lib": self.ed_randomx.text().strip(),

                "blocknet_enabled": bool(self.cb_bn.isChecked()),
                "blocknet_relay": self.ed_bn_relay.text().strip(),
                "blocknet_token": self.ed_bn_token.text().strip(),
                "blocknet_id": self.ed_bn_id.text().strip(),
                "blocknet_key": self.ed_bn_key.text().strip(),
            }
            CFG_PATH.write_text(json.dumps(j, indent=2), encoding="utf-8")
            self.statusBar().showMessage("Config saved", 1500)
        except Exception as e:
            self.statusBar().showMessage(f"Config save failed: {e}", 2000)

    def _load_cfg(self) -> None:
        if not CFG_PATH.exists():
            return
        try:
            j = json.loads(CFG_PATH.read_text(encoding="utf-8"))

            self.ed_stratum.setText(j.get("stratum", self.ed_stratum.text()))
            self.ed_wallet.setText(j.get("wallet", self.ed_wallet.text()))
            self.ed_pass.setText(j.get("pass", self.ed_pass.text()))
            self.ed_agent.setText(j.get("agent", self.ed_agent.text()))
            self.sp_threads.setValue(int(j.get("threads", int(self.sp_threads.value()))))
            self.ed_randomx.setText(j.get("randomx_lib", self.ed_randomx.text()))

            self.cb_bn.setChecked(bool(j.get("blocknet_enabled", False)))
            self.ed_bn_relay.setText(j.get("blocknet_relay", self.ed_bn_relay.text()))
            self.ed_bn_token.setText(j.get("blocknet_token", self.ed_bn_token.text()))
            self.ed_bn_id.setText(j.get("blocknet_id", self.ed_bn_id.text()))
            self.ed_bn_key.setText(j.get("blocknet_key", self.ed_bn_key.text()))

            self.statusBar().showMessage("Config loaded", 1500)
        except Exception as e:
            self.statusBar().showMessage(f"Config load failed: {e}", 2000)

    # ---------- window lifecycle ----------

    def closeEvent(self, ev) -> None:
        # stop miner cleanly
        try:
            if self.worker and self.worker.isRunning():
                self.worker.stop()
                self.worker.wait(2000)
        except Exception:
            pass
        super().closeEvent(ev)


def main() -> int:
    app = QApplication(sys.argv)
    apply_dark_theme(app)

    w = MainWindow()
    w.resize(1280, 820)
    w.show()
    return app.exec_()


if __name__ == "__main__":
    raise SystemExit(main())