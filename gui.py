from __future__ import annotations

import inspect
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
    QScrollArea,
)

from miner_core import Miner

from registry import BLOCKS
import blocks_blocknet  # registers blocknet_heartbeat / blocknet_put


def app_data_dir(app_name: str = "MoneroMinerGUI") -> Path:
    base = QStandardPaths.writableLocation(QStandardPaths.AppDataLocation)
    p = Path(base) / app_name
    p.mkdir(parents=True, exist_ok=True)
    return p


CFG_PATH = app_data_dir() / "miner_gui_config.json"


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
        QScrollArea {
            border: none;
            background: transparent;
        }
        QScrollBar:vertical {
            background: #1b1b1b;
            width: 12px;
            margin: 0px;
            border-radius: 6px;
        }
        QScrollBar::handle:vertical {
            background: #4a4a4a;
            min-height: 24px;
            border-radius: 6px;
        }
        QScrollBar::handle:vertical:hover {
            background: #5a5a5a;
        }
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
            height: 0px;
        }
        QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {
            background: transparent;
        }
    """)


@dataclass
class MinerConfig:
    stratum: str
    wallet: str
    password: str
    threads: int
    agent: str
    randomx_lib: str

    # BlockNet reporting (optional)
    use_blocknet: bool
    blocknet_relay: str
    blocknet_token: str
    blocknet_id: str
    blocknet_key: str

    # BlockNet mining backends (optional)
    use_bn_p2pool: bool
    use_bn_randomx: bool

    # scan toggles
    use_bn_p2pool_scan: bool
    use_bn_randomx_scan: bool
    use_bn_gpu_scan: bool
    use_bn_cpu_scan: bool

    bn_api_relay: str
    bn_api_token: str
    bn_api_prefix: str
    bn_rx_batch: int
    scan_iters: int
    submit_workers: int


class MinerWorker(QThread):
    log_line = pyqtSignal(str)
    stats_updated = pyqtSignal(dict)
    state_changed = pyqtSignal(str)   # "RUNNING" | "STOPPED"
    fatal_error = pyqtSignal(str)

    def __init__(self, cfg: MinerConfig) -> None:
        super().__init__()
        self.cfg = cfg
        self._miner: Optional[Miner] = None

        self._bn_heartbeat = None
        self._bn_put = None

    def stop(self) -> None:
        if self._miner:
            try:
                self._miner.stop()
            except Exception:
                pass

    def _setup_blocknet_reporting(self) -> None:
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

            # Only matters for LOCAL RandomX
            if (not self.cfg.use_bn_randomx) and self.cfg.randomx_lib.strip():
                os.environ["RANDOMX_LIB"] = self.cfg.randomx_lib.strip()

            self._setup_blocknet_reporting()

            # Stratum host/port is only required when NOT using BlockNet P2Pool backend
            stratum = (self.cfg.stratum or "").strip()
            if ":" in stratum:
                host, port_s = stratum.rsplit(":", 1)
                host = host.strip() or "127.0.0.1"
                port = int(port_s)
            else:
                host = "127.0.0.1"
                port = 3333

            miner_kwargs: Dict[str, Any] = dict(
                stratum_host=host,
                stratum_port=port,
                wallet=self.cfg.wallet.strip(),
                password=self.cfg.password,
                threads=int(self.cfg.threads),
                agent=self.cfg.agent.strip() or "py-blockminer/0.1",
                logger=self.log_line.emit,

                use_blocknet_p2pool=bool(self.cfg.use_bn_p2pool),
                blocknet_api_relay=self.cfg.bn_api_relay.strip(),
                blocknet_api_token=self.cfg.bn_api_token.strip(),
                blocknet_api_prefix=(self.cfg.bn_api_prefix.strip() or "/v1"),

                use_blocknet_randomx=bool(self.cfg.use_bn_randomx),
                randomx_batch_size=int(self.cfg.bn_rx_batch),
                submit_workers=int(self.cfg.submit_workers),
            )

            sig = inspect.signature(Miner.__init__)
            if "submit_workers" in sig.parameters:
                miner_kwargs["submit_workers"] = int(self.cfg.submit_workers)
            if "use_blocknet_p2pool_scan" in sig.parameters:
                miner_kwargs["use_blocknet_p2pool_scan"] = bool(self.cfg.use_bn_p2pool_scan)
            if "use_blocknet_randomx_scan" in sig.parameters:
                miner_kwargs["use_blocknet_randomx_scan"] = bool(self.cfg.use_bn_randomx_scan)
            if "use_blocknet_gpu_scan" in sig.parameters:
                miner_kwargs["use_blocknet_gpu_scan"] = bool(self.cfg.use_bn_gpu_scan)
            if "use_blocknet_cpu_scan" in sig.parameters:
                miner_kwargs["use_blocknet_cpu_scan"] = bool(self.cfg.use_bn_cpu_scan)
            if "scan_iters" in sig.parameters:
                miner_kwargs["scan_iters"] = int(self.cfg.scan_iters)

            self._miner = Miner(**miner_kwargs)

            last_stats: Dict[str, Any] = {}

            def on_stats(stats: Dict[str, Any]) -> None:
                nonlocal last_stats
                last_stats = dict(stats or {})
                self.stats_updated.emit(last_stats)

                hps = float(last_stats.get("hashrate_hs") or 0.0)
                acc = int(last_stats.get("accepted") or 0)
                rej = int(last_stats.get("rejected") or 0)
                height = last_stats.get("height")
                job_id = (last_stats.get("job_id") or "")[:10]
                b_p2 = last_stats.get("backend_p2pool")
                b_rx = last_stats.get("backend_randomx")

                self.log_line.emit(
                    f"[stats] {hps:,.0f} H/s | A:{acc} R:{rej} | height={height} | job={job_id} | p2pool={b_p2} rx={b_rx}"
                )

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

            import asyncio
            asyncio.run(self._miner.run(on_stats=on_stats))

            self.state_changed.emit("STOPPED")

        except Exception:
            import traceback
            self.state_changed.emit("STOPPED")
            self.fatal_error.emit(traceback.format_exc())


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

        self._saved_main_split_sizes: Optional[list[int]] = None
        self._log_focus_enabled: bool = False

        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(10)

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

        self.main_split = QSplitter(Qt.Horizontal)
        self.main_split.setChildrenCollapsible(False)
        self.main_split.setHandleWidth(10)
        root.addWidget(self.main_split, 1)

        self.left_scroll = QScrollArea()
        self.left_scroll.setWidgetResizable(True)
        self.left_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.left_scroll.setMinimumWidth(420)
        self.left_scroll.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        self.left_container = QWidget()
        self.left_scroll.setWidget(self.left_container)

        self.left_layout = QVBoxLayout(self.left_container)
        self.left_layout.setContentsMargins(0, 0, 8, 0)
        self.left_layout.setSpacing(10)

        self.main_split.addWidget(self.left_scroll)

        right = QWidget()
        right_l = QVBoxLayout(right)
        right_l.setContentsMargins(0, 0, 0, 0)

        self.tabs = QTabWidget()
        self.tabs.currentChanged.connect(self._on_tab_changed)
        right_l.addWidget(self.tabs)
        self.main_split.addWidget(right)

        self.main_split.setStretchFactor(0, 1)
        self.main_split.setStretchFactor(1, 2)

        # ---------------- Controls groups ----------------

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

        self.left_layout.addWidget(gb_conn)

        gb_perf = QGroupBox("Performance")
        pfl = QFormLayout(gb_perf)

        self.sp_threads = QSpinBox()
        self.sp_threads.setRange(1, 256)
        self.sp_threads.setValue(4)

        self.ed_randomx = QLineEdit("")
        self.btn_browse_randomx = QPushButton("Browse…")
        self.btn_browse_randomx.clicked.connect(self._browse_randomx)

        pfl.addRow("Threads", self.sp_threads)
        pfl.addRow("RandomX lib (local only)", self._hbox(self.ed_randomx, self.btn_browse_randomx))

        self.left_layout.addWidget(gb_perf)

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

        self.left_layout.addWidget(gb_bn)

        gb_bn_mine = QGroupBox("BlockNet Mining Backends (optional)")
        mfl = QFormLayout(gb_bn_mine)

        self.cb_bn_gpu_scan = QCheckBox("Use BlockNet GPU scan (/gpu/scan) — OpenCL GPU server-side scanning")
        self.cb_bn_cpu_scan = QCheckBox("Use BlockNet CPU scan (/cpu/scan) — CPU server-side scanning")
        self.cb_bn_p2pool = QCheckBox("Use BlockNet P2Pool API (instead of direct Stratum TCP)")
        self.cb_bn_randomx = QCheckBox("Use BlockNet RandomX API (remote hashing)")

        self.cb_bn_p2pool_scan = QCheckBox("Use BlockNet P2Pool scan (/p2pool/scan) — server-side scanning")
        self.cb_bn_randomx_scan = QCheckBox("Use BlockNet RandomX scan (/randomx/scan) — server-side scanning")

        self.ed_bn_api_relay = QLineEdit("127.0.0.1:38888")
        self.ed_bn_api_token = QLineEdit("")
        self.ed_bn_api_token.setEchoMode(QLineEdit.Password)
        self.ed_bn_api_prefix = QLineEdit("/v1")

        self.sp_bn_rx_batch = QSpinBox()
        self.sp_bn_rx_batch.setRange(1, 4096)
        self.sp_bn_rx_batch.setValue(64)

        self.sp_submit_workers = QSpinBox()
        self.sp_submit_workers.setRange(1, 32)
        self.sp_submit_workers.setValue(4)

        self.sp_scan_iters = QSpinBox()
        self.sp_scan_iters.setRange(1, 10_000_000)
        self.sp_scan_iters.setSingleStep(100)
        self.sp_scan_iters.setValue(1000)

        mfl.addRow(self.cb_bn_gpu_scan)
        mfl.addRow(self.cb_bn_cpu_scan)
        mfl.addRow(self.cb_bn_p2pool)
        mfl.addRow(self.cb_bn_randomx)
        mfl.addRow(self.cb_bn_p2pool_scan)
        mfl.addRow(self.cb_bn_randomx_scan)
        mfl.addRow("API Relay (host:port)", self.ed_bn_api_relay)
        mfl.addRow("API Token", self.ed_bn_api_token)
        mfl.addRow("API Prefix", self.ed_bn_api_prefix)
        mfl.addRow("RandomX batch size", self.sp_bn_rx_batch)
        mfl.addRow("Share workers", self.sp_submit_workers)
        mfl.addRow("Scan iterations", self.sp_scan_iters)

        self.left_layout.addWidget(gb_bn_mine)

        self.cb_bn_p2pool.toggled.connect(self._sync_scan_checks)
        self.cb_bn_randomx.toggled.connect(self._sync_scan_checks)
        self.cb_bn_p2pool_scan.toggled.connect(self._sync_scan_mode_exclusive)
        self.cb_bn_randomx_scan.toggled.connect(self._sync_scan_mode_exclusive)
        self.cb_bn_gpu_scan.toggled.connect(self._sync_scan_mode_exclusive)
        self.cb_bn_cpu_scan.toggled.connect(self._sync_scan_mode_exclusive)
        self._sync_scan_checks()

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

        self.left_layout.addWidget(gb_ctrl)
        self.left_layout.addStretch(1)

        # ---------------- Right tabs ----------------

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

        log = QWidget()
        ll = QVBoxLayout(log)
        ll.setContentsMargins(0, 0, 0, 0)
        ll.setSpacing(0)
        self.txt_log = QPlainTextEdit()
        self.txt_log.setReadOnly(True)
        self.txt_log.setFont(_mono_font())
        ll.addWidget(self.txt_log)
        self.tabs.addTab(log, "Log")

        raw = QWidget()
        rl = QVBoxLayout(raw)
        rl.setContentsMargins(10, 10, 10, 10)
        self.txt_raw = QPlainTextEdit()
        self.txt_raw.setReadOnly(True)
        self.txt_raw.setFont(_mono_font())
        rl.addWidget(self.txt_raw)
        self.tabs.addTab(raw, "Raw Stats")

        self.uptime_timer = QTimer(self)
        self.uptime_timer.setInterval(500)
        self.uptime_timer.timeout.connect(self._tick_uptime)

        self.main_split.setSizes([560, 900])

        self._load_cfg()
        self.statusBar().showMessage("Ready")

    def _sync_scan_mode_exclusive(self) -> None:
        sender = self.sender()
        if not isinstance(sender, QCheckBox):
            return
        if not sender.isChecked():
            return

        for cb in (
            self.cb_bn_p2pool_scan,
            self.cb_bn_randomx_scan,
            self.cb_bn_gpu_scan,
            self.cb_bn_cpu_scan,
        ):
            if cb is sender:
                continue
            old = cb.blockSignals(True)
            cb.setChecked(False)
            cb.blockSignals(old)

    def _sync_scan_checks(self) -> None:
        p2 = bool(self.cb_bn_p2pool.isChecked())
        rx = bool(self.cb_bn_randomx.isChecked())

        self.cb_bn_p2pool_scan.setEnabled(p2)
        if not p2:
            self.cb_bn_p2pool_scan.setChecked(False)

        self.cb_bn_randomx_scan.setEnabled(rx)
        if not rx:
            self.cb_bn_randomx_scan.setChecked(False)

        # gpu/cpu scan can work with direct jobs or BlockNet P2Pool jobs
        self.cb_bn_gpu_scan.setEnabled(True)
        self.cb_bn_cpu_scan.setEnabled(True)

    def _on_tab_changed(self, idx: int) -> None:
        tab_name = self.tabs.tabText(idx)
        focus = (tab_name == "Log")
        self._set_log_focus(focus)

    def _set_log_focus(self, enable: bool) -> None:
        if enable and not self._log_focus_enabled:
            self._saved_main_split_sizes = self.main_split.sizes()
            self.left_scroll.setVisible(False)
            self.main_split.setSizes([0, max(1, self.width())])
            self._log_focus_enabled = True
        elif (not enable) and self._log_focus_enabled:
            self.left_scroll.setVisible(True)
            if self._saved_main_split_sizes:
                self.main_split.setSizes(self._saved_main_split_sizes)
            else:
                self.main_split.setSizes([560, 900])
            self._log_focus_enabled = False

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

    def _start(self) -> None:
        if self.worker and self.worker.isRunning():
            return

        stratum = self.ed_stratum.text().strip()
        wallet = self.ed_wallet.text().strip()
        password = self.ed_pass.text()
        agent = self.ed_agent.text().strip() or "py-blockminer/0.1"
        threads = int(self.sp_threads.value())
        randomx_lib = self.ed_randomx.text().strip()
        scan_iters = int(self.sp_scan_iters.value())
        submit_workers = int(self.sp_submit_workers.value())

        use_bn_p2pool = bool(self.cb_bn_p2pool.isChecked())
        use_bn_randomx = bool(self.cb_bn_randomx.isChecked())
        use_bn_p2pool_scan = bool(self.cb_bn_p2pool_scan.isChecked())
        use_bn_randomx_scan = bool(self.cb_bn_randomx_scan.isChecked())
        use_bn_gpu_scan = bool(self.cb_bn_gpu_scan.isChecked())
        use_bn_cpu_scan = bool(self.cb_bn_cpu_scan.isChecked())

        if not wallet:
            QMessageBox.critical(self, "Missing Wallet", "Please enter your Monero wallet address.")
            return

        if (not use_bn_p2pool) and (":" not in stratum):
            QMessageBox.critical(self, "Invalid Stratum", "Stratum must be host:port (e.g. 127.0.0.1:3333).")
            return

        bn_api_relay = self.ed_bn_api_relay.text().strip()
        if (use_bn_p2pool or use_bn_randomx or use_bn_p2pool_scan or use_bn_randomx_scan or use_bn_gpu_scan or use_bn_cpu_scan) and not bn_api_relay:
            QMessageBox.critical(self, "Missing BlockNet API Relay", "Please enter BlockNet API relay host:port (e.g. 1.2.3.4:38888).")
            return

        use_bn_reporting = bool(self.cb_bn.isChecked())

        cfg = MinerConfig(
            stratum=stratum,
            wallet=wallet,
            password=password,
            threads=threads,
            agent=agent,
            randomx_lib=randomx_lib,

            use_blocknet=use_bn_reporting,
            blocknet_relay=self.ed_bn_relay.text().strip(),
            blocknet_token=self.ed_bn_token.text().strip(),
            blocknet_id=self.ed_bn_id.text().strip() or "miner1",
            blocknet_key=self.ed_bn_key.text().strip(),

            use_bn_p2pool=use_bn_p2pool,
            use_bn_randomx=use_bn_randomx,
            use_bn_gpu_scan=use_bn_gpu_scan,
            use_bn_cpu_scan=use_bn_cpu_scan,
            use_bn_p2pool_scan=use_bn_p2pool_scan,
            use_bn_randomx_scan=use_bn_randomx_scan,

            submit_workers=submit_workers,
            bn_api_relay=bn_api_relay,
            bn_api_token=self.ed_bn_api_token.text().strip(),
            bn_api_prefix=self.ed_bn_api_prefix.text().strip() or "/v1",
            bn_rx_batch=int(self.sp_bn_rx_batch.value()),
            scan_iters=scan_iters,
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
        hps = float(stats.get("hashrate_hs") or 0.0)
        acc = int(stats.get("accepted") or 0)
        rej = int(stats.get("rejected") or 0)
        height = stats.get("height")
        th = int(stats.get("threads") or self.sp_threads.value())

        self.lbl_hashrate.setText(f"{hps:,.0f} H/s")
        self.lbl_sub.setText(
            f"Accepted: {acc}    Rejected: {rej}    Height: {height if height is not None else '—'}    Threads: {th}"
        )

        try:
            self.txt_raw.setPlainText(json.dumps(stats, indent=2))
        except Exception:
            self.txt_raw.setPlainText(str(stats))

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

                "bn_p2pool": bool(self.cb_bn_p2pool.isChecked()),
                "bn_randomx": bool(self.cb_bn_randomx.isChecked()),
                "bn_gpu_scan": bool(self.cb_bn_gpu_scan.isChecked()),
                "bn_cpu_scan": bool(self.cb_bn_cpu_scan.isChecked()),
                "bn_p2pool_scan": bool(self.cb_bn_p2pool_scan.isChecked()),
                "bn_randomx_scan": bool(self.cb_bn_randomx_scan.isChecked()),

                "submit_workers": int(self.sp_submit_workers.value()),
                "bn_api_relay": self.ed_bn_api_relay.text().strip(),
                "bn_api_token": self.ed_bn_api_token.text().strip(),
                "bn_api_prefix": self.ed_bn_api_prefix.text().strip(),
                "bn_rx_batch": int(self.sp_bn_rx_batch.value()),
                "scan_iters": int(self.sp_scan_iters.value()),
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
            self.sp_submit_workers.setValue(int(j.get("submit_workers", int(self.sp_submit_workers.value()))))

            self.cb_bn.setChecked(bool(j.get("blocknet_enabled", False)))
            self.ed_bn_relay.setText(j.get("blocknet_relay", self.ed_bn_relay.text()))
            self.ed_bn_token.setText(j.get("blocknet_token", self.ed_bn_token.text()))
            self.ed_bn_id.setText(j.get("blocknet_id", self.ed_bn_id.text()))
            self.ed_bn_key.setText(j.get("blocknet_key", self.ed_bn_key.text()))

            self.cb_bn_p2pool.setChecked(bool(j.get("bn_p2pool", False)))
            self.cb_bn_randomx.setChecked(bool(j.get("bn_randomx", False)))
            self.cb_bn_gpu_scan.setChecked(bool(j.get("bn_gpu_scan", False)))
            self.cb_bn_cpu_scan.setChecked(bool(j.get("bn_cpu_scan", False)))
            self.cb_bn_p2pool_scan.setChecked(bool(j.get("bn_p2pool_scan", False)))
            self.cb_bn_randomx_scan.setChecked(bool(j.get("bn_randomx_scan", False)))

            self.ed_bn_api_relay.setText(j.get("bn_api_relay", self.ed_bn_api_relay.text()))
            self.ed_bn_api_token.setText(j.get("bn_api_token", self.ed_bn_api_token.text()))
            self.ed_bn_api_prefix.setText(j.get("bn_api_prefix", self.ed_bn_api_prefix.text()))
            self.sp_bn_rx_batch.setValue(int(j.get("bn_rx_batch", int(self.sp_bn_rx_batch.value()))))
            self.sp_scan_iters.setValue(int(j.get("scan_iters", int(self.sp_scan_iters.value()))))

            self._sync_scan_checks()
            self.statusBar().showMessage("Config loaded", 1500)
        except Exception as e:
            self.statusBar().showMessage(f"Config load failed: {e}", 2000)

    def closeEvent(self, ev) -> None:
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