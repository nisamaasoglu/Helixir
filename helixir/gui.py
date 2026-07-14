"""
Helixir GUI (PyQt6).

Two tabs:
  1. Encrypt / Decrypt — the real tool. Pick a file, choose a passphrase,
     encrypt to a DNA sequence (AES-256-GCM under the hood), export as .fasta or
     .helix container, and decrypt any past entry from the audit log.
  2. Visual Scramble (preview - NON-SECURE) — an optional webcam block-shuffle,
     clearly labelled as a visual effect only. Requires opencv-python.

The webcam tab degrades gracefully: if OpenCV is not installed, the tab shows a
notice instead of crashing.
"""

from __future__ import annotations

import os

from PyQt6.QtCore import Qt, QThread, QObject, pyqtSignal
from PyQt6.QtGui import QFont, QImage, QPixmap
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QLabel, QPushButton, QVBoxLayout,
    QHBoxLayout, QGridLayout, QLineEdit, QListWidget, QListWidgetItem,
    QFileDialog, QMessageBox, QTabWidget, QTextEdit, QCheckBox,
    QSizePolicy,
)

from . import crypto, dna_codec
from .storage import AuditLog

try:  # OpenCV/numpy are only needed for the optional webcam tab
    import cv2
    from . import scramble
    _HAS_CV = True
except Exception:  # pragma: no cover - environment dependent
    _HAS_CV = False


DB_NAME = "encryption_log.db"


# --------------------------------------------------------------------------
# Optional webcam worker (visual scramble preview only)
# --------------------------------------------------------------------------
if _HAS_CV:

    class CameraWorker(QObject):
        frameReady = pyqtSignal(object)
        error = pyqtSignal(str)
        finished = pyqtSignal()

        def __init__(self, index: int = 0):
            super().__init__()
            self.index = index
            self.running = False

        def run(self):
            self.running = True
            cap = cv2.VideoCapture(self.index)
            if not cap.isOpened():
                self.error.emit(f"Could not open camera {self.index}.")
                self.finished.emit()
                return
            while self.running:
                ok, frame = cap.read()
                if not ok:
                    break
                self.frameReady.emit(frame)
            cap.release()
            self.finished.emit()

        def stop(self):
            self.running = False


# --------------------------------------------------------------------------
# Main window
# --------------------------------------------------------------------------
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Helixir — DNA-encoded file encryption")
        self.setGeometry(120, 120, 1100, 720)
        self.setStyleSheet(_DARK_STYLE)

        self.log = AuditLog(DB_NAME)
        self._source_path: str | None = None
        self._source_bytes: bytes | None = None
        self._last_dna: str | None = None

        tabs = QTabWidget()
        self.setCentralWidget(tabs)
        tabs.addTab(self._build_crypto_tab(), "Encrypt / Decrypt")
        tabs.addTab(self._build_scramble_tab(), "Visual Scramble (preview · non-secure)")

        self.statusBar().showMessage("Ready.")
        self.refresh_log()

    # ---- Tab 1: real encryption -----------------------------------------
    def _build_crypto_tab(self) -> QWidget:
        w = QWidget()
        root = QVBoxLayout(w)

        # Input row
        row = QGridLayout()
        self.file_label = QLineEdit()
        self.file_label.setReadOnly(True)
        self.file_label.setPlaceholderText("No file selected")
        pick = QPushButton("Choose File…")
        pick.clicked.connect(self.choose_file)
        row.addWidget(QLabel("Input file:"), 0, 0)
        row.addWidget(self.file_label, 0, 1)
        row.addWidget(pick, 0, 2)

        self.pass_input = QLineEdit()
        self.pass_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.pass_input.setPlaceholderText("Passphrase (this is your only key — do not lose it)")
        row.addWidget(QLabel("Passphrase:"), 1, 0)
        row.addWidget(self.pass_input, 1, 1)
        self.show_pass = QCheckBox("Show")
        self.show_pass.toggled.connect(self._toggle_pass)
        row.addWidget(self.show_pass, 1, 2)

        self.complement_box = QCheckBox("Apply Watson-Crick complement (A↔T, G↔C)")
        self.complement_box.setChecked(True)
        row.addWidget(self.complement_box, 2, 1)
        root.addLayout(row)

        # Action buttons
        actions = QHBoxLayout()
        enc = QPushButton("Encrypt → DNA")
        enc.clicked.connect(self.do_encrypt)
        exp_fasta = QPushButton("Export .fasta")
        exp_fasta.clicked.connect(self.export_fasta)
        exp_helix = QPushButton("Export .helix container")
        exp_helix.clicked.connect(self.export_container)
        for b in (enc, exp_fasta, exp_helix):
            actions.addWidget(b)
        root.addLayout(actions)

        # DNA output
        root.addWidget(QLabel("DNA sequence (ciphertext, encoded):"))
        self.dna_view = QTextEdit()
        self.dna_view.setReadOnly(True)
        self.dna_view.setFont(QFont("Courier New", 9))
        self.dna_view.setMaximumHeight(140)
        root.addWidget(self.dna_view)
        self.stats_label = QLabel("")
        root.addWidget(self.stats_label)

        # Audit log + decrypt
        root.addWidget(QLabel("Audit log (metadata + ciphertext only — never your key):"))
        self.log_list = QListWidget()
        root.addWidget(self.log_list)

        log_actions = QHBoxLayout()
        refresh = QPushButton("Refresh")
        refresh.clicked.connect(self.refresh_log)
        dec = QPushButton("Decrypt Selected → Save…")
        dec.clicked.connect(self.decrypt_selected)
        clear = QPushButton("Clear Log")
        clear.clicked.connect(self.clear_log)
        for b in (refresh, dec, clear):
            log_actions.addWidget(b)
        root.addLayout(log_actions)
        return w

    # ---- Tab 2: optional webcam scramble --------------------------------
    def _build_scramble_tab(self) -> QWidget:
        w = QWidget()
        root = QVBoxLayout(w)
        note = QLabel(
            "This is a VISUAL EFFECT, not encryption. Blocks are shuffled by a "
            "key-seeded order; the histogram is unchanged and content stays "
            "exposed. For real protection use the Encrypt / Decrypt tab."
        )
        note.setWordWrap(True)
        note.setStyleSheet("color:#E8A13A; padding:6px; border:1px solid #E8A13A; border-radius:4px;")
        root.addWidget(note)

        if not _HAS_CV:
            root.addWidget(QLabel("OpenCV not installed. Run: pip install -r requirements-gui.txt"))
            root.addStretch()
            return w

        feeds = QHBoxLayout()
        self.cam_original = self._video_label("Original (live)")
        self.cam_scrambled = self._video_label("Scrambled (live)")
        feeds.addWidget(self.cam_original)
        feeds.addWidget(self.cam_scrambled)
        root.addLayout(feeds)

        controls = QHBoxLayout()
        self.scramble_key = QLineEdit("demo")
        controls.addWidget(QLabel("Seed key:"))
        controls.addWidget(self.scramble_key)
        start = QPushButton("Start Camera")
        start.clicked.connect(self.start_camera)
        stop = QPushButton("Stop Camera")
        stop.clicked.connect(self.stop_camera)
        controls.addWidget(start)
        controls.addWidget(stop)
        root.addLayout(controls)

        self._cam_thread = None
        self._cam_worker = None
        return w

    # ---- helpers --------------------------------------------------------
    def _video_label(self, title: str) -> QLabel:
        label = QLabel(f"{title}\n(no image)")
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        label.setMinimumSize(360, 270)
        label.setStyleSheet("border:1px solid #555; background:#222; color:#AAA;")
        label.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        return label

    def _toggle_pass(self, shown: bool):
        self.pass_input.setEchoMode(
            QLineEdit.EchoMode.Normal if shown else QLineEdit.EchoMode.Password
        )

    def _warn(self, msg: str):
        self.statusBar().showMessage(msg, 6000)
        QMessageBox.warning(self, "Helixir", msg)

    # ---- crypto actions -------------------------------------------------
    def choose_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Choose a file to encrypt")
        if not path:
            return
        try:
            with open(path, "rb") as fh:
                self._source_bytes = fh.read()
        except OSError as exc:
            self._warn(f"Could not read file: {exc}")
            return
        self._source_path = path
        self.file_label.setText(path)
        self.statusBar().showMessage(f"Loaded {os.path.basename(path)} ({len(self._source_bytes)} bytes).")

    def do_encrypt(self):
        if self._source_bytes is None:
            self._warn("Choose a file first.")
            return
        passphrase = self.pass_input.text()
        if not passphrase:
            self._warn("Enter a passphrase.")
            return

        dna, result = crypto.encrypt_to_dna(
            self._source_bytes, passphrase,
            apply_complement=self.complement_box.isChecked(),
        )
        self._last_dna = dna

        preview = dna if len(dna) <= 4000 else dna[:4000] + f"… (+{len(dna) - 4000} more)"
        self.dna_view.setPlainText(preview)
        gc = dna_codec.gc_content(dna)
        self.stats_label.setText(
            f"AES-256-GCM · scrypt · DNA length {len(dna):,} bases · GC-content {gc:.1%}"
        )

        self.log.record(
            source_name=os.path.basename(self._source_path or "input"),
            source_bytes=self._source_bytes,
            container=result.container,
            salt_hex=result.salt_hex,
            nonce_hex=result.nonce_hex,
            dna_length=len(dna),
            gc_content=gc,
        )
        self.refresh_log()
        self.statusBar().showMessage("Encrypted and logged.")

    def export_fasta(self):
        if not self._last_dna:
            self._warn("Encrypt something first.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export FASTA", "helixir.fasta", "FASTA (*.fasta)")
        if not path:
            return
        header = os.path.basename(self._source_path or "helixir")
        with open(path, "w") as fh:
            fh.write(dna_codec.to_fasta(self._last_dna, header=header))
        self.statusBar().showMessage(f"Wrote {path}")

    def export_container(self):
        if not self._last_dna:
            self._warn("Encrypt something first.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export container", "output.helix", "Helixir (*.helix)")
        if not path:
            return
        complement = self.complement_box.isChecked()
        container = dna_codec.decode(
            dna_codec.complement(self._last_dna) if complement else self._last_dna
        )
        with open(path, "wb") as fh:
            fh.write(container)
        self.statusBar().showMessage(f"Wrote {path}")

    def refresh_log(self):
        self.log_list.clear()
        entries = self.log.list_entries()
        if not entries:
            item = QListWidgetItem("No entries yet.")
            item.setFlags(Qt.ItemFlag.NoItemFlags)
            self.log_list.addItem(item)
            return
        for e in entries:
            item = QListWidgetItem(
                f"ID {e.id} · {e.created_at} · {e.source_name} · "
                f"{e.algorithm} · {e.dna_length:,} bases · GC {e.gc_content:.0%}"
            )
            item.setData(Qt.ItemDataRole.UserRole, e.id)
            self.log_list.addItem(item)

    def decrypt_selected(self):
        items = self.log_list.selectedItems()
        if not items or items[0].data(Qt.ItemDataRole.UserRole) is None:
            self._warn("Select a log entry.")
            return
        passphrase = self.pass_input.text()
        if not passphrase:
            self._warn("Enter the passphrase used for that entry.")
            return
        entry_id = items[0].data(Qt.ItemDataRole.UserRole)
        container = self.log.get_container(entry_id)
        if container is None:
            self._warn("Entry not found.")
            return
        try:
            plaintext = crypto.decrypt(container, passphrase)
        except crypto.DecryptionError as exc:
            self._warn(str(exc))
            return
        path, _ = QFileDialog.getSaveFileName(self, "Save decrypted output")
        if not path:
            return
        with open(path, "wb") as fh:
            fh.write(plaintext)
        self.statusBar().showMessage(f"Decrypted → {path}")

    def clear_log(self):
        if QMessageBox.question(self, "Confirm", "Delete all log entries?") == \
                QMessageBox.StandardButton.Yes:
            self.log.clear()
            self.refresh_log()

    # ---- webcam (optional) ---------------------------------------------
    def start_camera(self):
        if not _HAS_CV or self._cam_worker is not None:
            return
        self._cam_thread = QThread()
        self._cam_worker = CameraWorker(0)
        self._cam_worker.moveToThread(self._cam_thread)
        self._cam_worker.frameReady.connect(self._on_frame)
        self._cam_worker.error.connect(self._warn)
        self._cam_worker.finished.connect(self._on_cam_finished)
        self._cam_thread.started.connect(self._cam_worker.run)
        self._cam_thread.start()

    def stop_camera(self):
        if self._cam_worker:
            self._cam_worker.stop()

    def _on_cam_finished(self):
        if self._cam_thread:
            self._cam_thread.quit()
            self._cam_thread.wait()
        self._cam_thread = None
        self._cam_worker = None

    def _on_frame(self, frame):
        rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        self._show(self.cam_original, rgb)
        scrambled = scramble.scramble_blocks(rgb, self.scramble_key.text() or "demo")
        self._show(self.cam_scrambled, scrambled)

    def _show(self, label: QLabel, rgb):
        h, w, ch = rgb.shape
        img = QImage(rgb.data, w, h, ch * w, QImage.Format.Format_RGB888)
        pix = QPixmap.fromImage(img).scaled(
            label.size(), Qt.AspectRatioMode.KeepAspectRatio,
            Qt.TransformationMode.SmoothTransformation,
        )
        label.setPixmap(pix)

    def closeEvent(self, event):
        self.stop_camera()
        event.accept()


_DARK_STYLE = """
QMainWindow, QTabWidget::pane { background:#2E2E2E; }
QWidget { color:#E0E0E0; background:#3C3C3C; font-size:10pt; }
QLabel { background:transparent; }
QPushButton { background:#555; color:#fff; border:1px solid #666; padding:6px 12px;
  border-radius:4px; min-width:90px; }
QPushButton:hover { background:#6A6A6A; }
QPushButton:pressed { background:#4A4A4A; }
QLineEdit, QComboBox, QListWidget, QTextEdit { background:#555; color:#fff;
  border:1px solid #666; padding:4px; border-radius:4px; }
QListWidget::item:selected { background:#0078D7; color:#fff; }
QTabBar::tab { background:#444; color:#ddd; padding:8px 14px; }
QTabBar::tab:selected { background:#0078D7; color:#fff; }
QStatusBar { color:#fff; background:#2E2E2E; }
"""


def main():
    import sys
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
