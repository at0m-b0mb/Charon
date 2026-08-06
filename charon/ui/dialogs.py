"""Every dialog that asks the user a security question.

The house style here is deliberate: a security prompt states **what is
happening**, **what it means**, and **what the safe answer is** — and the safe
answer is the default button.  There are no "Are you sure? [OK]" dialogs,
because a dialog that can be dismissed without reading is a dialog that trains
people to click through the one that mattered.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from ..core.model import AuthMethod, Credentials, Protocol, Site
from ..core.secretstore import StorageMode, keychain_available
from ..core.store import Settings, SiteStore
from ..core.transfer import Conflict
from ..core.trust import HostIdentity
from .icons import icon
from .theme import Palette
from .util import human_size


def _hairline(color: str) -> QFrame:
    line = QFrame()
    line.setFrameShape(QFrame.Shape.HLine)
    line.setFixedHeight(1)
    line.setStyleSheet(f"background: {color}; border: none;")
    return line


class ConnectDialog(QDialog):
    """Pick or define a server, and collect the credential for it."""

    def __init__(self, sites: SiteStore, settings: Settings, palette: Palette,
                 parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Connect to a server")
        self.setMinimumWidth(680)
        self.sites = sites
        self.settings = settings
        self.p = palette
        self.result_site: Optional[Site] = None
        self.result_credentials = Credentials()
        self.save_site = True

        root = QHBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ---- saved sites -------------------------------------------------
        left = QVBoxLayout()
        left.setContentsMargins(16, 16, 8, 16)
        label = QLabel("SAVED SERVERS")
        label.setProperty("role", "section")
        left.addWidget(label)
        self.site_list = QListWidget()
        self.site_list.setFixedWidth(210)
        self.site_list.currentItemChanged.connect(self._site_selected)
        left.addWidget(self.site_list, 1)
        row = QHBoxLayout()
        self.new_button = QPushButton("New")
        self.new_button.clicked.connect(self._new_site)
        self.forget_button = QPushButton("Forget")
        self.forget_button.setProperty("role", "danger")
        self.forget_button.clicked.connect(self._forget_site)
        row.addWidget(self.new_button)
        row.addWidget(self.forget_button)
        left.addLayout(row)
        root.addLayout(left)

        # ---- the form ----------------------------------------------------
        right = QVBoxLayout()
        right.setContentsMargins(16, 16, 16, 16)
        right.setSpacing(12)

        form = QFormLayout()
        form.setSpacing(9)
        self.name_edit = QLineEdit()
        self.name_edit.setPlaceholderText("My server")
        form.addRow("Name", self.name_edit)

        self.protocol_box = QComboBox()
        for proto in Protocol:
            self.protocol_box.addItem(proto.display, proto)
        self.protocol_box.currentIndexChanged.connect(self._protocol_changed)
        form.addRow("Protocol", self.protocol_box)

        host_row = QHBoxLayout()
        self.host_edit = QLineEdit()
        self.host_edit.setPlaceholderText("files.example.com")
        self.port_spin = QSpinBox()
        self.port_spin.setRange(1, 65535)
        self.port_spin.setFixedWidth(90)
        host_row.addWidget(self.host_edit, 1)
        host_row.addWidget(QLabel("Port"))
        host_row.addWidget(self.port_spin)
        form.addRow("Server", host_row)

        self.user_edit = QLineEdit()
        form.addRow("Username", self.user_edit)

        self.auth_box = QComboBox()
        self.auth_box.addItem("Password", AuthMethod.PASSWORD)
        self.auth_box.addItem("Private key file", AuthMethod.KEY)
        self.auth_box.addItem("SSH agent", AuthMethod.AGENT)
        self.auth_box.currentIndexChanged.connect(self._auth_changed)
        form.addRow("Sign in with", self.auth_box)

        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_edit.setPlaceholderText("Password")
        form.addRow("Password", self.password_edit)

        key_row = QHBoxLayout()
        self.key_edit = QLineEdit()
        self.key_edit.setPlaceholderText("~/.ssh/id_ed25519")
        browse = QPushButton("Browse…")
        browse.clicked.connect(self._browse_key)
        key_row.addWidget(self.key_edit, 1)
        key_row.addWidget(browse)
        self.key_row_widget = QWidget()
        self.key_row_widget.setLayout(key_row)
        form.addRow("Private key", self.key_row_widget)

        self.remote_edit = QLineEdit()
        self.remote_edit.setPlaceholderText("Leave blank for the server's default")
        form.addRow("Start folder", self.remote_edit)
        right.addLayout(form)

        right.addWidget(_hairline(palette.border))

        self.save_check = QCheckBox("Remember this server")
        self.save_check.setChecked(True)
        self.remember_check = QCheckBox()
        self.remember_check.setChecked(True)
        self._update_remember_label()
        right.addWidget(self.save_check)
        right.addWidget(self.remember_check)

        self.verify_check = QCheckBox("Verify the server's TLS certificate (recommended)")
        self.verify_check.setChecked(True)
        right.addWidget(self.verify_check)

        self.warning = QLabel("")
        self.warning.setWordWrap(True)
        self.warning.setVisible(False)
        right.addWidget(self.warning)

        right.addStretch(1)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Cancel | QDialogButtonBox.StandardButton.Ok
        )
        self.ok_button = buttons.button(QDialogButtonBox.StandardButton.Ok)
        self.ok_button.setText("Connect")
        self.ok_button.setProperty("role", "primary")
        self.ok_button.setDefault(True)
        buttons.accepted.connect(self._accept)
        buttons.rejected.connect(self.reject)
        right.addWidget(buttons)
        root.addLayout(right, 1)

        self._reload_sites()
        self._protocol_changed()
        self._auth_changed()

    # ------------------------------------------------------------ populate

    def _reload_sites(self) -> None:
        self.site_list.clear()
        for site in self.sites.by_recency():
            item = QListWidgetItem(site.name)
            item.setToolTip(site.label)
            item.setData(Qt.ItemDataRole.UserRole, site)
            item.setIcon(icon("lock" if site.protocol.is_encrypted else "warning",
                              self.p.secure if site.protocol.is_encrypted else self.p.danger))
            self.site_list.addItem(item)
        if self.site_list.count():
            self.site_list.setCurrentRow(0)

    def _site_selected(self, current: Optional[QListWidgetItem], _prev) -> None:
        if current is None:
            return
        site: Site = current.data(Qt.ItemDataRole.UserRole)
        self.name_edit.setText(site.name)
        self.protocol_box.setCurrentIndex(list(Protocol).index(site.protocol))
        self.host_edit.setText(site.host)
        self.port_spin.setValue(site.port)
        self.user_edit.setText(site.username)
        index = self.auth_box.findData(site.auth)
        self.auth_box.setCurrentIndex(max(0, index))
        self.key_edit.setText(site.key_path)
        self.remote_edit.setText(site.remote_dir)
        self.verify_check.setChecked(site.verify_tls)
        self.password_edit.clear()

    def _new_site(self) -> None:
        self.site_list.clearSelection()
        self.site_list.setCurrentItem(None)
        for widget in (self.name_edit, self.host_edit, self.user_edit,
                       self.key_edit, self.remote_edit, self.password_edit):
            widget.clear()
        self.protocol_box.setCurrentIndex(0)
        self.name_edit.setFocus()

    def _forget_site(self) -> None:
        item = self.site_list.currentItem()
        if item is None:
            return
        site: Site = item.data(Qt.ItemDataRole.UserRole)
        confirm = QMessageBox(self)
        confirm.setWindowTitle("Forget server")
        confirm.setText(f"Remove “{site.name}” from the saved list?")
        confirm.setInformativeText(
            "Its saved password is deleted too. The pinned host key stays, so the "
            "server is still recognised if you connect again."
        )
        confirm.setStandardButtons(QMessageBox.StandardButton.Cancel |
                                   QMessageBox.StandardButton.Yes)
        confirm.setDefaultButton(QMessageBox.StandardButton.Cancel)
        if confirm.exec() == QMessageBox.StandardButton.Yes:
            self.sites.remove(site.name)
            self._reload_sites()

    # ----------------------------------------------------------- reactions

    def _current_protocol(self) -> Protocol:
        return self.protocol_box.currentData()

    def _protocol_changed(self) -> None:
        proto = self._current_protocol()
        if self.port_spin.value() in (p.default_port for p in Protocol):
            self.port_spin.setValue(proto.default_port)
        is_ssh = proto is Protocol.SFTP
        self.auth_box.setEnabled(is_ssh)
        if not is_ssh:
            self.auth_box.setCurrentIndex(0)
        self.verify_check.setVisible(proto is Protocol.FTPS)

        if proto is Protocol.FTP:
            allowed = self.settings.policy.allow_plaintext_ftp
            self.warning.setVisible(True)
            self.warning.setText(
                "Plain FTP sends your password and every file in readable text. "
                + ("It is enabled in Settings, so Charon will ask you to confirm "
                   "before connecting."
                   if allowed else
                   "It is switched off — turn on “Allow plaintext FTP” in Settings → "
                   "Security if you truly need it.")
            )
            self.warning.setStyleSheet(
                f"color: {self.p.danger if not allowed else self.p.caution};")
            self.ok_button.setEnabled(allowed)
        else:
            self.warning.setVisible(False)
            self.ok_button.setEnabled(True)
        self._auth_changed()

    def _auth_changed(self) -> None:
        method: AuthMethod = self.auth_box.currentData()
        wants_key = method is AuthMethod.KEY
        self.key_row_widget.setVisible(wants_key)
        self.password_edit.setVisible(method is not AuthMethod.AGENT)
        self.password_edit.setPlaceholderText(
            "Key passphrase (blank if the key has none)" if wants_key else "Password"
        )
        self.remember_check.setVisible(method is not AuthMethod.AGENT)
        self._update_remember_label()

    def _update_remember_label(self) -> None:
        mode = self.settings.storage_mode
        where = {
            StorageMode.KEYCHAIN: "in the OS keychain",
            StorageMode.VAULT: "in Charon's encrypted vault",
            StorageMode.NEVER: "nowhere — storing secrets is turned off",
        }[mode]
        self.remember_check.setText(f"Remember this password ({where})")
        self.remember_check.setEnabled(mode is not StorageMode.NEVER)
        if mode is StorageMode.NEVER:
            self.remember_check.setChecked(False)

    def _browse_key(self) -> None:
        start = str(Path.home() / ".ssh")
        path, _ = QFileDialog.getOpenFileName(self, "Choose a private key", start)
        if path:
            self.key_edit.setText(path)

    # -------------------------------------------------------------- accept

    def _accept(self) -> None:
        host = self.host_edit.text().strip()
        if not host:
            self.host_edit.setFocus()
            return
        proto = self._current_protocol()
        method: AuthMethod = self.auth_box.currentData() if proto is Protocol.SFTP \
            else AuthMethod.PASSWORD
        site = Site(
            name=self.name_edit.text().strip() or host,
            host=host,
            protocol=proto,
            port=self.port_spin.value(),
            username=self.user_edit.text().strip(),
            auth=method,
            key_path=self.key_edit.text().strip(),
            remote_dir=self.remote_edit.text().strip(),
            verify_tls=self.verify_check.isChecked(),
            save_password=self.remember_check.isChecked(),
        )
        creds = Credentials(remember=self.remember_check.isChecked())
        secret = self.password_edit.text()
        if method is AuthMethod.KEY:
            creds.passphrase = secret or None
        else:
            creds.password = secret or None

        self.result_site = site
        self.result_credentials = creds
        self.save_site = self.save_check.isChecked()
        self.accept()


class TrustDialog(QDialog):
    """Show a server's fingerprint and ask the user to make a decision.

    The two cases look deliberately different.  A first connection is a calm
    "check this and approve".  A *changed* key is red, the approve button says
    what it actually does, and Cancel is the default — the interception case
    must not be one keystroke away from acceptance.
    """

    def __init__(self, identity: HostIdentity, kind: str, message: str,
                 palette: Palette, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.p = palette
        self.identity = identity
        alarming = kind.endswith("changed")
        self.setWindowTitle("Server key changed" if alarming else "Unrecognised server")
        self.setMinimumWidth(600)

        root = QVBoxLayout(self)
        root.setContentsMargins(22, 20, 22, 18)
        root.setSpacing(14)

        head = QHBoxLayout()
        head.setSpacing(12)
        glyph = QLabel()
        glyph.setPixmap(icon("warning" if alarming else "shield",
                             palette.danger if alarming else palette.accent,
                             34).pixmap(34, 34))
        head.addWidget(glyph, 0, Qt.AlignmentFlag.AlignTop)
        title = QLabel(
            "This server's key does not match the one you trusted"
            if alarming else f"First connection to {identity.label}"
        )
        title.setProperty("role", "title")
        title.setWordWrap(True)
        head.addWidget(title, 1)
        root.addLayout(head)

        body = QLabel(message)
        body.setWordWrap(True)
        body.setStyleSheet(f"color: {palette.text_muted};")
        root.addWidget(body)

        card = QFrame()
        card.setProperty("role", "pane")
        grid = QGridLayout(card)
        grid.setContentsMargins(16, 14, 16, 14)
        grid.setHorizontalSpacing(14)
        grid.setVerticalSpacing(7)
        rows = [("Server", identity.label), ("Key type", identity.key_type)]
        if identity.subject:
            rows.append(("Subject", identity.subject))
        if identity.issuer:
            rows.append(("Issuer", identity.issuer))
        if identity.not_after:
            rows.append(("Expires", identity.not_after))
        rows.append(("Fingerprint", identity.fingerprint))
        if identity.legacy_fingerprint:
            rows.append(("Legacy", identity.legacy_fingerprint))
        for row, (key, value) in enumerate(rows):
            key_label = QLabel(key)
            key_label.setStyleSheet(f"color: {palette.text_muted};")
            value_label = QLabel(value)
            value_label.setProperty("role", "mono")
            value_label.setTextInteractionFlags(
                Qt.TextInteractionFlag.TextSelectableByMouse)
            value_label.setWordWrap(True)
            grid.addWidget(key_label, row, 0, Qt.AlignmentFlag.AlignTop)
            grid.addWidget(value_label, row, 1)
        grid.setColumnStretch(1, 1)
        root.addWidget(card)

        how = QLabel(
            "Verify it out of band — run <code>ssh-keyscan -p {port} {host} | ssh-keygen -lf -</code> "
            "on the server, or read the fingerprint from your hosting panel. "
            "Comparing it against what this dialog says is the whole point: an "
            "attacker can fake everything here except the real key."
            .format(port=identity.port, host=identity.host)
            if identity.key_type != "TLS certificate" else
            "Verify it out of band — compare this fingerprint with the one on the "
            "server itself. An attacker can fake everything here except the real key."
        )
        how.setWordWrap(True)
        how.setStyleSheet(f"color: {palette.text_muted}; font-size: 12px;")
        root.addWidget(how)

        buttons = QHBoxLayout()
        buttons.addStretch(1)
        cancel = QPushButton("Cancel — do not connect")
        cancel.clicked.connect(self.reject)
        cancel.setDefault(True)
        cancel.setAutoDefault(True)
        buttons.addWidget(cancel)

        accept = QPushButton(
            "Replace the trusted key" if alarming else "Trust this server"
        )
        accept.setProperty("role", "danger" if alarming else "primary")
        accept.setAutoDefault(False)
        accept.clicked.connect(self.accept)
        buttons.addWidget(accept)
        root.addLayout(buttons)


class InsecureConnectionDialog(QDialog):
    """The confirmation shown before a plaintext FTP connection is opened."""

    def __init__(self, site: Site, reason: str, detail: str, palette: Palette,
                 parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Unencrypted connection")
        self.setMinimumWidth(560)
        self.remember_choice = False

        root = QVBoxLayout(self)
        root.setContentsMargins(22, 20, 22, 18)
        root.setSpacing(13)

        head = QHBoxLayout()
        glyph = QLabel()
        glyph.setPixmap(icon("warning", palette.danger, 34).pixmap(34, 34))
        head.addWidget(glyph, 0, Qt.AlignmentFlag.AlignTop)
        title = QLabel(reason)
        title.setProperty("role", "title")
        title.setStyleSheet(f"color: {palette.danger};")
        title.setWordWrap(True)
        head.addWidget(title, 1)
        root.addLayout(head)

        body = QLabel(
            f"{detail}\n\nAnyone able to watch this network — another guest on the "
            f"Wi-Fi, a compromised router, your ISP — can read your password for "
            f"{site.host} and every file you transfer, and can change files in "
            f"flight without either end noticing."
        )
        body.setWordWrap(True)
        body.setStyleSheet(f"color: {palette.text_muted};")
        root.addWidget(body)

        self.remember_box = QCheckBox("Do not ask again for this server")
        root.addWidget(self.remember_box)

        buttons = QHBoxLayout()
        buttons.addStretch(1)
        cancel = QPushButton("Cancel")
        cancel.setDefault(True)
        cancel.clicked.connect(self.reject)
        buttons.addWidget(cancel)
        proceed = QPushButton("Connect without encryption")
        proceed.setProperty("role", "danger")
        proceed.setAutoDefault(False)
        proceed.clicked.connect(self._accept)
        buttons.addWidget(proceed)
        root.addLayout(buttons)

    def _accept(self) -> None:
        self.remember_choice = self.remember_box.isChecked()
        self.accept()


class VaultDialog(QDialog):
    """Create or unlock the encrypted vault."""

    def __init__(self, creating: bool, palette: Palette,
                 parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.creating = creating
        self.password = ""
        self.setWindowTitle("Create vault" if creating else "Unlock vault")
        self.setMinimumWidth(460)

        root = QVBoxLayout(self)
        root.setContentsMargins(22, 20, 22, 18)
        root.setSpacing(13)

        head = QHBoxLayout()
        glyph = QLabel()
        glyph.setPixmap(icon("lock", palette.accent, 30).pixmap(30, 30))
        head.addWidget(glyph, 0, Qt.AlignmentFlag.AlignTop)
        title = QLabel("Choose a master password" if creating else "Unlock your vault")
        title.setProperty("role", "title")
        head.addWidget(title, 1)
        root.addLayout(head)

        blurb = QLabel(
            "This password encrypts every stored server password with AES-256-GCM. "
            "It is never written anywhere and cannot be recovered — if you forget "
            "it, the saved passwords are gone and you re-enter them by hand."
            if creating else
            "Enter your master password to use saved server passwords."
        )
        blurb.setWordWrap(True)
        blurb.setStyleSheet(f"color: {palette.text_muted};")
        root.addWidget(blurb)

        self.first = QLineEdit()
        self.first.setEchoMode(QLineEdit.EchoMode.Password)
        self.first.setPlaceholderText("Master password")
        root.addWidget(self.first)

        self.second = QLineEdit()
        self.second.setEchoMode(QLineEdit.EchoMode.Password)
        self.second.setPlaceholderText("Confirm master password")
        self.second.setVisible(creating)
        root.addWidget(self.second)

        self.error = QLabel("")
        self.error.setStyleSheet(f"color: {palette.danger};")
        self.error.setVisible(False)
        self.error.setWordWrap(True)
        root.addWidget(self.error)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Cancel | QDialogButtonBox.StandardButton.Ok)
        ok = buttons.button(QDialogButtonBox.StandardButton.Ok)
        ok.setText("Create" if creating else "Unlock")
        ok.setProperty("role", "primary")
        buttons.accepted.connect(self._accept)
        buttons.rejected.connect(self.reject)
        root.addWidget(buttons)
        self.first.returnPressed.connect(self._accept)
        self.second.returnPressed.connect(self._accept)

    def show_error(self, message: str) -> None:
        self.error.setText(message)
        self.error.setVisible(True)

    def _accept(self) -> None:
        value = self.first.text()
        if self.creating:
            if len(value) < 8:
                self.show_error("Use at least 8 characters.")
                return
            if value != self.second.text():
                self.show_error("The two passwords do not match.")
                return
        elif not value:
            self.show_error("Enter your master password.")
            return
        self.password = value
        self.accept()


class PasteDialog(QDialog):
    """Confirm a paste, and choose what happens to files that already exist."""

    def __init__(self, count: int, total: int, destination: str, direction: str,
                 palette: Palette, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Paste")
        self.setMinimumWidth(520)
        self.conflict = Conflict.RENAME

        root = QVBoxLayout(self)
        root.setContentsMargins(22, 20, 22, 18)
        root.setSpacing(13)

        title = QLabel(
            f"{direction} {count} item{'s' if count != 1 else ''}"
            + (f" · {human_size(total)}" if total else "")
        )
        title.setProperty("role", "title")
        root.addWidget(title)

        where = QLabel(f"Into: {destination}")
        where.setProperty("role", "mono")
        where.setStyleSheet(f"color: {palette.text_muted};")
        where.setWordWrap(True)
        root.addWidget(where)

        root.addWidget(_hairline(palette.border))

        label = QLabel("If something with the same name is already there")
        label.setProperty("role", "section")
        root.addWidget(label)

        self.conflict_box = QComboBox()
        self.conflict_box.addItem("Keep both — add a number to the new file",
                                  Conflict.RENAME)
        self.conflict_box.addItem("Resume — continue an interrupted transfer",
                                  Conflict.RESUME)
        self.conflict_box.addItem("Skip it — leave the existing file alone",
                                  Conflict.SKIP)
        self.conflict_box.addItem("Overwrite — replace the existing file",
                                  Conflict.OVERWRITE)
        root.addWidget(self.conflict_box)

        note = QLabel(
            "Files land in a “.charon-part” file first and are only moved into place "
            "once the whole transfer has been checked, so an interrupted copy can "
            "never be mistaken for a complete one."
        )
        note.setWordWrap(True)
        note.setStyleSheet(f"color: {palette.text_muted}; font-size: 12px;")
        root.addWidget(note)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Cancel | QDialogButtonBox.StandardButton.Ok)
        ok = buttons.button(QDialogButtonBox.StandardButton.Ok)
        ok.setText("Start")
        ok.setProperty("role", "primary")
        buttons.accepted.connect(self._accept)
        buttons.rejected.connect(self.reject)
        root.addWidget(buttons)

    def _accept(self) -> None:
        self.conflict = self.conflict_box.currentData()
        self.accept()


class SettingsDialog(QDialog):
    """Security policy, credential storage, and appearance."""

    def __init__(self, settings: Settings, palette: Palette,
                 parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.settings = settings
        self.p = palette
        self.setWindowTitle("Settings")
        self.setMinimumWidth(620)

        root = QVBoxLayout(self)
        root.setContentsMargins(18, 18, 18, 16)
        root.setSpacing(14)

        tabs = QTabWidget()
        tabs.addTab(self._security_tab(), "Security")
        tabs.addTab(self._storage_tab(), "Passwords")
        tabs.addTab(self._transfers_tab(), "Transfers")
        root.addWidget(tabs)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Cancel | QDialogButtonBox.StandardButton.Ok)
        ok = buttons.button(QDialogButtonBox.StandardButton.Ok)
        ok.setText("Save")
        ok.setProperty("role", "primary")
        buttons.accepted.connect(self._accept)
        buttons.rejected.connect(self.reject)
        root.addWidget(buttons)

    # ------------------------------------------------------------ the tabs

    def _security_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(11)

        self.tls_check = QCheckBox("Require TLS 1.2 or newer for FTPS")
        self.tls_check.setChecked(self.settings.policy.require_tls_1_2)
        layout.addWidget(self.tls_check)

        self.tofu_check = QCheckBox(
            "Allow trusting a new server after showing me its fingerprint")
        self.tofu_check.setChecked(self.settings.policy.allow_tofu)
        layout.addWidget(self.tofu_check)
        layout.addWidget(self._note(
            "With this off, Charon will only connect to servers whose key you have "
            "already pinned — safest, but you must add each key by hand."))

        layout.addWidget(_hairline(self.p.border))

        self.plain_check = QCheckBox("Allow plaintext FTP connections")
        self.plain_check.setChecked(self.settings.policy.allow_plaintext_ftp)
        self.plain_check.toggled.connect(self._plain_toggled)
        layout.addWidget(self.plain_check)
        self.plain_note = self._note(
            "Off by default, and it should stay off. Plain FTP sends your password "
            "and your files in readable text; anyone on the network path can capture "
            "both. Only turn this on for a server that genuinely speaks nothing else, "
            "and never over Wi-Fi you do not control."
        )
        self.plain_note.setStyleSheet(f"color: {self.p.danger}; font-size: 12px;")
        layout.addWidget(self.plain_note)

        layout.addWidget(_hairline(self.p.border))

        idle_row = QHBoxLayout()
        idle_row.addWidget(QLabel("Disconnect and re-lock after"))
        self.idle_spin = QSpinBox()
        self.idle_spin.setRange(0, 240)
        self.idle_spin.setSuffix(" minutes idle")
        self.idle_spin.setSpecialValueText("never")
        self.idle_spin.setValue(self.settings.policy.lock_after_minutes)
        idle_row.addWidget(self.idle_spin)
        idle_row.addStretch(1)
        layout.addLayout(idle_row)
        layout.addStretch(1)
        return page

    def _storage_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(11)

        layout.addWidget(QLabel("Where should saved passwords be kept?"))
        self.storage_box = QComboBox()
        available = keychain_available()
        self.storage_box.addItem(
            "OS keychain" + ("" if available else " — not available on this system"),
            StorageMode.KEYCHAIN)
        self.storage_box.addItem("Charon's encrypted vault (master password)",
                                 StorageMode.VAULT)
        self.storage_box.addItem("Never store passwords — ask every time",
                                 StorageMode.NEVER)
        if not available:
            item = self.storage_box.model().item(0)
            if item is not None:
                item.setEnabled(False)
        index = self.storage_box.findData(self.settings.storage_mode)
        self.storage_box.setCurrentIndex(max(0, index))
        layout.addWidget(self.storage_box)

        layout.addWidget(self._note(
            "The OS keychain hands key management to the system and unlocks with your "
            "login session. The vault is a single AES-256-GCM file whose key is "
            "derived from a master password with scrypt — portable, and the right "
            "choice on a machine with no keychain service."))
        layout.addStretch(1)
        return page

    def _transfers_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(11)

        self.verify_check = QCheckBox("Verify every transfer with SHA-256")
        self.verify_check.setChecked(self.settings.policy.verify_downloads)
        layout.addWidget(self.verify_check)
        layout.addWidget(self._note(
            "Charon always hashes what it writes. When the server can hash too "
            "(FTPS servers with HASH/XSHA256, SFTP servers with check-file), the two "
            "are compared and a mismatch throws the file away."))

        self.private_check = QCheckBox("Make downloads readable only by me (0600)")
        self.private_check.setChecked(self.settings.private_downloads)
        layout.addWidget(self.private_check)

        self.hidden_check = QCheckBox("Show hidden files")
        self.hidden_check.setChecked(self.settings.show_hidden)
        layout.addWidget(self.hidden_check)

        self.confirm_check = QCheckBox("Ask before deleting")
        self.confirm_check.setChecked(self.settings.confirm_delete)
        layout.addWidget(self.confirm_check)

        row = QHBoxLayout()
        row.addWidget(QLabel("Default download folder"))
        self.download_edit = QLineEdit(self.settings.download_dir)
        browse = QPushButton("Browse…")
        browse.clicked.connect(self._browse_download)
        row.addWidget(self.download_edit, 1)
        row.addWidget(browse)
        layout.addLayout(row)

        theme_row = QHBoxLayout()
        theme_row.addWidget(QLabel("Appearance"))
        self.theme_box = QComboBox()
        self.theme_box.addItem("Dark", "dark")
        self.theme_box.addItem("Light", "light")
        self.theme_box.setCurrentIndex(0 if self.settings.theme == "dark" else 1)
        theme_row.addWidget(self.theme_box)
        theme_row.addStretch(1)
        layout.addLayout(theme_row)
        layout.addStretch(1)
        return page

    def _note(self, text: str) -> QLabel:
        label = QLabel(text)
        label.setWordWrap(True)
        label.setStyleSheet(f"color: {self.p.text_muted}; font-size: 12px;")
        return label

    def _plain_toggled(self, on: bool) -> None:
        if not on:
            return
        box = QMessageBox(self)
        box.setWindowTitle("Enable plaintext FTP?")
        box.setText("Allow connections that send your password in the clear?")
        box.setInformativeText(
            "Charon will still warn you every time you connect to such a server, and "
            "the window stays marked as insecure for the whole session."
        )
        box.setStandardButtons(QMessageBox.StandardButton.Cancel |
                               QMessageBox.StandardButton.Yes)
        box.setDefaultButton(QMessageBox.StandardButton.Cancel)
        if box.exec() != QMessageBox.StandardButton.Yes:
            self.plain_check.setChecked(False)

    def _browse_download(self) -> None:
        path = QFileDialog.getExistingDirectory(
            self, "Default download folder", self.download_edit.text())
        if path:
            self.download_edit.setText(path)

    # -------------------------------------------------------------- accept

    def _accept(self) -> None:
        s = self.settings
        s.policy.require_tls_1_2 = self.tls_check.isChecked()
        s.policy.allow_tofu = self.tofu_check.isChecked()
        s.policy.allow_plaintext_ftp = self.plain_check.isChecked()
        s.policy.lock_after_minutes = self.idle_spin.value()
        s.policy.verify_downloads = self.verify_check.isChecked()
        s.storage_mode = self.storage_box.currentData()
        s.private_downloads = self.private_check.isChecked()
        s.show_hidden = self.hidden_check.isChecked()
        s.confirm_delete = self.confirm_check.isChecked()
        s.download_dir = self.download_edit.text().strip() or s.download_dir
        s.theme = self.theme_box.currentData()
        s.save()
        self.accept()
