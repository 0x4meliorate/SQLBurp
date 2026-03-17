# -*- coding: utf-8 -*-
# SQLBurp - Burp Suite Extension
from burp import IBurpExtender, IContextMenuFactory, ITab
from javax.swing import (
    JPanel, JButton, JTextArea, JScrollPane, JLabel, JTextField,
    JSplitPane, JCheckBox, JComboBox, JSpinner, SpinnerNumberModel,
    BoxLayout, BorderFactory, JOptionPane, SwingUtilities, Box,
    JTable, ListSelectionModel, JMenuItem, JPopupMenu
)
from javax.swing.border import TitledBorder
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer
from java.awt import (BorderLayout, Dimension, Color, Font, FlowLayout)
import java.awt.event
import java.awt.event.ActionListener
from javax.swing.table import TableRowSorter
from java.util import Comparator
from java.lang import Runnable, Thread, String
from java.net import URL
from java.io import OutputStreamWriter, BufferedReader, InputStreamReader
import json
import time
import hashlib
import uuid

COL_RUNNING = Color(0xFF, 0xA5, 0x00)
COL_VULN    = Color(0xBF, 0x00, 0x00)
COL_CLEAN   = Color(0x00, 0x80, 0x00)
COL_ERROR   = Color(0x80, 0x00, 0x80)
COL_QUEUED  = Color(0x60, 0x60, 0x60)
COL_STOPPED = Color(0x40, 0x40, 0x40)


def _api_request(method, base_url, path, payload=None):
    url  = URL(base_url.rstrip("/") + path)
    conn = url.openConnection()
    conn.setRequestMethod(method.upper())
    conn.setRequestProperty("Content-Type", "application/json")
    conn.setRequestProperty("Accept", "application/json")
    conn.setConnectTimeout(5000)
    conn.setReadTimeout(30000)
    if method.upper() == "POST" and payload is not None:
        conn.setDoOutput(True)
        writer = OutputStreamWriter(conn.getOutputStream(), "UTF-8")
        writer.write(json.dumps(payload))
        writer.flush()
        writer.close()
    status = conn.getResponseCode()
    stream = conn.getInputStream() if status < 400 else conn.getErrorStream()
    reader = BufferedReader(InputStreamReader(stream, "UTF-8"))
    lines  = []
    line   = reader.readLine()
    while line is not None:
        lines.append(line)
        line = reader.readLine()
    reader.close()
    return json.loads("".join(lines))


class _SetText(Runnable):
    def __init__(self, component, text):
        self._c = component
        self._t = text
    def run(self):
        self._c.setText(self._t)


class _RunLater(Runnable):
    def __init__(self, fn):
        self._fn = fn
    def run(self):
        self._fn()


STATUS_QUEUED  = "Queued"
STATUS_RUNNING = "Running"
STATUS_DONE    = "Finished"
STATUS_VULN    = "Vulnerable"
STATUS_ERROR   = "Error"
STATUS_STOPPED = "Stopped"


class ScanOptions(object):
    def __init__(self, level=1, risk=1, threads=1, technique="BEUSTQ",
                 dbms="(auto)", tamper="", batch=True, random_agent=False,
                 forms=False, get_dbs=True, current_user=True, banner=True,
                 is_dba=False, force_ssl=False, verbose=2):
        self.level        = level
        self.risk         = risk
        self.threads      = threads
        self.technique    = technique
        self.dbms         = dbms
        self.tamper       = tamper
        self.batch        = batch
        self.random_agent = random_agent
        self.forms        = forms
        self.get_dbs      = get_dbs
        self.current_user = current_user
        self.banner       = banner
        self.is_dba       = is_dba
        self.force_ssl    = force_ssl
        self.verbose      = verbose

    @classmethod
    def from_ui(cls, ext, force_ssl=False):
        dbms = str(ext._dbms_combo.getSelectedItem())
        return cls(
            level        = int(ext._level_spin.getValue()),
            risk         = int(ext._risk_spin.getValue()),
            threads      = int(ext._threads_spin.getValue()),
            technique    = ext._technique_field.getText().strip() or "BEUSTQ",
            dbms         = dbms,
            tamper       = ext._tamper_field.getText().strip(),
            batch        = bool(ext._batch_check.isSelected()),
            random_agent = bool(ext._random_agent_check.isSelected()),
            forms        = bool(ext._forms_check.isSelected()),
            get_dbs      = bool(ext._dbs_check.isSelected()),
            current_user = bool(ext._user_check.isSelected()),
            banner       = bool(ext._banner_check.isSelected()),
            is_dba       = bool(ext._isdba_check.isSelected()),
            force_ssl    = force_ssl,
            verbose      = 2,
        )

    @classmethod
    def from_api(cls, options_dict):
        d = options_dict or {}
        dbms = d.get("dbms") or "(auto)"
        return cls(
            level        = d.get("level", 1),
            risk         = d.get("risk", 1),
            threads      = d.get("threads", 1),
            technique    = d.get("technique", "BEUSTQ") or "BEUSTQ",
            dbms         = dbms,
            tamper       = d.get("tamper", "") or "",
            batch        = bool(d.get("batch", True)),
            random_agent = bool(d.get("randomAgent", False)),
            forms        = bool(d.get("forms", False)),
            get_dbs      = bool(d.get("getDbs", True)),
            current_user = bool(d.get("getCurrentUser", True)),
            banner       = bool(d.get("getBanner", True)),
            is_dba       = bool(d.get("isDba", False)),
            force_ssl    = bool(d.get("forceSSL", False)),
            verbose      = d.get("verbose", 2),
        )

    def to_api_dict(self, request_file):
        d = {
            "requestFile":    request_file,
            "level":          self.level,
            "risk":           self.risk,
            "threads":        self.threads,
            "technique":      self.technique,
            "batch":          self.batch,
            "randomAgent":    self.random_agent,
            "forms":          self.forms,
            "getDbs":         self.get_dbs,
            "getCurrentUser": self.current_user,
            "getBanner":      self.banner,
            "isDba":          self.is_dba,
            "forceSSL":       self.force_ssl,
            "verbose":        self.verbose,
        }
        if self.dbms and self.dbms != "(auto)":
            d["dbms"] = self.dbms
        if self.tamper:
            d["tamper"] = self.tamper
        return d

    def summary_lines(self):
        flags = []
        if self.batch:        flags.append("batch")
        if self.random_agent: flags.append("random-agent")
        if self.forms:        flags.append("forms")
        if self.get_dbs:      flags.append("enum-dbs")
        if self.current_user: flags.append("current-user")
        if self.banner:       flags.append("banner")
        if self.is_dba:       flags.append("is-dba")
        if self.force_ssl:    flags.append("force-ssl")
        return [
            "Level     : %d" % self.level,
            "Risk      : %d" % self.risk,
            "Threads   : %d" % self.threads,
            "Technique : %s" % self.technique,
            "DBMS      : %s" % self.dbms,
            "Tamper    : %s" % (self.tamper or "(none)"),
            "Verbose   : %d" % self.verbose,
            "Flags     : %s" % (", ".join(flags) if flags else "(none)"),
        ]


class ScanRecord(object):
    def __init__(self, task_id, target, method, options=None):
        self.task_id   = task_id
        self.target    = target
        self.method    = method
        self.status    = STATUS_QUEUED
        self.findings  = 0
        self.started   = time.strftime("%H:%M:%S")
        self.log_lines = []
        self.results   = []
        self.options   = options or ScanOptions()


class _StatusRenderer(DefaultTableCellRenderer):
    _COLOURS = {
        STATUS_QUEUED:  COL_QUEUED,
        STATUS_RUNNING: COL_RUNNING,
        STATUS_DONE:    COL_CLEAN,
        STATUS_VULN:    COL_VULN,
        STATUS_ERROR:   COL_ERROR,
        STATUS_STOPPED: COL_STOPPED,
    }
    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, col):
        c = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table, value, isSelected, hasFocus, row, col)
        if not isSelected:
            c.setForeground(self._COLOURS.get(str(value), COL_QUEUED))
            c.setFont(c.getFont().deriveFont(Font.BOLD))
        return c


class _ScanTableModel(DefaultTableModel):
    COLS = ["#", "Task ID", "Target", "Method", "Status", "Findings", "Started"]
    def __init__(self):
        DefaultTableModel.__init__(self, 0, len(self.COLS))
        self.setColumnIdentifiers(self.COLS)
    def isCellEditable(self, row, col):
        return False
    def getColumnClass(self, col):
        return String


class _IntComparator(Comparator):
    def compare(self, a, b):
        try:
            return int(str(a)) - int(str(b))
        except Exception:
            return str(a).compareTo(str(b))
    def equals(self, obj):
        return obj is self


class _StatusComparator(Comparator):
    _ORDER = {STATUS_VULN: 0, STATUS_RUNNING: 1, STATUS_ERROR: 2,
              STATUS_QUEUED: 3, STATUS_DONE: 4, STATUS_STOPPED: 5}
    def compare(self, a, b):
        return self._ORDER.get(str(a), 99) - self._ORDER.get(str(b), 99)
    def equals(self, obj):
        return obj is self


class _StringComparator(Comparator):
    def compare(self, a, b):
        sa, sb = str(a).lower(), str(b).lower()
        return -1 if sa < sb else (1 if sa > sb else 0)
    def equals(self, obj):
        return obj is self


class PollThread(Runnable):
    def __init__(self, extension, record):
        self._ext     = extension
        self._record  = record
        self._running = True

    def stop(self):
        self._running = False

    def _log(self, msg):
        self._record.log_lines.append(msg)
        self._ext._maybe_refresh_preview(self._record.task_id)
        self._ext._save_scan_record(self._record)

    def run(self):
        rec  = self._record
        ext  = self._ext
        tid  = rec.task_id
        base = ext.get_api_base()
        self._log("[%s] Polling started." % time.strftime("%H:%M:%S"))
        seen_log_count = getattr(self, "_seen_log_count_override", 0)
        try:
            while self._running:
                try:
                    resp = _api_request("GET", base, "/scan/%s/status" % tid)
                except Exception as e:
                    self._log("[%s] Poll error: %s" % (time.strftime("%H:%M:%S"), str(e)))
                    rec.status = STATUS_ERROR
                    SwingUtilities.invokeLater(_RunLater(lambda: ext._refresh_row(tid)))
                    time.sleep(5)
                    continue
                api_status = resp.get("status", "unknown")
                try:
                    log_resp  = _api_request("GET", base, "/scan/%s/log" % tid)
                    api_lines = log_resp.get("log") or []
                    new_lines = api_lines[seen_log_count:]
                    seen_log_count = len(api_lines)
                    for entry in new_lines:
                        self._log("[%s][%s] %s" % (
                            entry.get("time", ""), entry.get("level", "INFO"),
                            entry.get("message", "")))
                except Exception:
                    pass
                if api_status == "running":
                    rec.status = STATUS_RUNNING
                    SwingUtilities.invokeLater(_RunLater(lambda: ext._refresh_row(tid)))
                elif api_status in ("terminated", "not running"):
                    try:
                        data_resp = _api_request("GET", base, "/scan/%s/data" % tid)
                        rec.results = data_resp.get("data") or []
                    except Exception as e:
                        self._log("[%s] Data fetch error: %s" % (time.strftime("%H:%M:%S"), str(e)))
                    if rec.results:
                        rec.findings = len(rec.results)
                        rec.status   = STATUS_VULN
                        self._log("\n=== INJECTION POINTS CONFIRMED ===")
                        for entry in rec.results:
                            self._log(json.dumps(entry, indent=2))
                    else:
                        rec.status = STATUS_DONE
                        self._log("[%s] Scan complete. No injections confirmed." % time.strftime("%H:%M:%S"))
                    SwingUtilities.invokeLater(_RunLater(lambda: ext._refresh_row(tid)))
                    # Persist full scan record so it survives API restarts
                    ext._save_scan_record(rec)
                    break
                time.sleep(ext.get_poll_interval())
        except Exception as e:
            import traceback
            self._log("[Fatal] %s\n%s" % (str(e), traceback.format_exc()))
            rec.status = STATUS_ERROR
            SwingUtilities.invokeLater(_RunLater(lambda: ext._refresh_row(tid)))
        self._log("[%s] Polling stopped." % time.strftime("%H:%M:%S"))
        ext._maybe_refresh_preview(tid)


class BurpExtender(IBurpExtender, IContextMenuFactory, ITab):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks    = callbacks
        self._helpers      = callbacks.getHelpers()
        callbacks.setExtensionName("SQLBurp")
        self._records      = []
        self._records_map  = {}
        self._poll_threads = {}
        self._selected_tid = None
        self._project_id   = self._resolve_project_id()
        try:
            SwingUtilities.invokeAndWait(_RunLater(self._init_ui))
        except Exception:
            import traceback
            callbacks.printError("SQLBurp init error:\n" + traceback.format_exc())

    # ------------------------------------------------------------------
    # Project-scoped settings helpers
    #
    # Burp's saveExtensionSetting / loadExtensionSetting are backed by the
    # global user-preferences file, NOT the .burp project file, so every
    # project shares the same key-space by default.  We work around this by
    # deriving a stable fingerprint for the current project and namespacing
    # every key under it.
    #
    # Fingerprint strategy (in order of preference):
    #   1. Hash the raw bytes of the first few proxy-history entries.
    #      These live in the project file and are stable across restarts.
    #   2. If proxy history is empty (fresh/temporary project), generate a
    #      UUID and store it under a bare sentinel key so it survives for
    #      the lifetime of that Burp session.
    # ------------------------------------------------------------------

    def _resolve_project_id(self):
        """Return a 16-char hex string that is stable per project."""
        try:
            history = self._callbacks.getProxyHistory()
            if history:
                h = hashlib.sha256()
                for msg in history[:5]:
                    raw = msg.getRequest()
                    if raw:
                        h.update(bytes(raw))
                return h.hexdigest()[:16]
        except Exception:
            pass
        # Fallback: reuse or mint a UUID stored under a bare sentinel key.
        sentinel = "sqlburp_pid"
        try:
            existing = self._callbacks.loadExtensionSetting(sentinel)
            if existing:
                return existing
        except Exception:
            pass
        new_id = uuid.uuid4().hex[:16]
        try:
            self._callbacks.saveExtensionSetting(sentinel, new_id)
        except Exception:
            pass
        return new_id

    def _pkey(self, suffix):
        """Return a project-namespaced settings key."""
        return "sqlburp_%s_%s" % (self._project_id, suffix)

    def _load_stored_tasks(self):
        """Load task IDs scoped to the current project."""
        try:
            raw = self._callbacks.loadExtensionSetting(self._pkey("tasks"))
            if raw:
                return json.loads(raw)
        except Exception:
            pass
        return []

    def _save_stored_tasks(self, task_ids):
        """Persist task IDs scoped to the current project."""
        try:
            self._callbacks.saveExtensionSetting(self._pkey("tasks"), json.dumps(task_ids))
        except Exception:
            pass

    def _save_scan_record(self, rec):
        """Persist a scan record scoped to the current project."""
        try:
            payload = {
                "task_id":   rec.task_id,
                "target":    rec.target,
                "method":    rec.method,
                "status":    rec.status,
                "findings":  rec.findings,
                "started":   rec.started,
                "log_lines": rec.log_lines,
                "results":   rec.results,
                "options":   {
                    "level":        rec.options.level,
                    "risk":         rec.options.risk,
                    "threads":      rec.options.threads,
                    "technique":    rec.options.technique,
                    "dbms":         rec.options.dbms,
                    "tamper":       rec.options.tamper,
                    "batch":        rec.options.batch,
                    "random_agent": rec.options.random_agent,
                    "forms":        rec.options.forms,
                    "get_dbs":      rec.options.get_dbs,
                    "current_user": rec.options.current_user,
                    "banner":       rec.options.banner,
                    "is_dba":       rec.options.is_dba,
                    "force_ssl":    rec.options.force_ssl,
                    "verbose":      rec.options.verbose,
                },
            }
            self._callbacks.saveExtensionSetting(
                self._pkey("scan_%s" % rec.task_id), json.dumps(payload))
        except Exception:
            pass

    def _load_scan_record(self, task_id):
        """Load a persisted scan record for this project. Returns dict or None."""
        try:
            raw = self._callbacks.loadExtensionSetting(self._pkey("scan_%s" % task_id))
            if raw:
                return json.loads(raw)
        except Exception:
            pass
        return None

    def _init_ui(self):
        try:
            self._build_ui()
            self._callbacks.registerContextMenuFactory(self)
            self._callbacks.addSuiteTab(self)
            t = Thread(_RunLater(self._restore_existing_tasks))
            t.setDaemon(True)
            t.start()
        except Exception:
            import traceback
            self._callbacks.printError("SQLBurp UI build error:\n" + traceback.format_exc())

    def _restore_existing_tasks(self):
        """
        On extension load, restore all tasks from Burp project settings.
        For completed scans the full record is loaded from cache — no API call needed.
        For any task with no cached record (was running when extension last closed),
        we attempt to query the live API.
        """
        stored = self._load_stored_tasks()
        if not stored:
            return
        self._callbacks.printOutput("SQLBurp: restoring %d stored task(s)." % len(stored))
        base = self.get_api_base()
        for task_id in stored:
            try:
                cached = self._load_scan_record(task_id)
                if cached:
                    # Fast path — restore entirely from Burp project, no API needed
                    self._restore_one_task(base, task_id, cached.get("status", STATUS_DONE))
                else:
                    # Scan had no saved record — was likely still running; try live API
                    try:
                        status_resp = _api_request("GET", base, "/scan/%s/status" % task_id)
                        api_status  = status_resp.get("status", "terminated")
                    except Exception:
                        api_status = "terminated"
                    self._restore_one_task(base, task_id, api_status)
            except Exception:
                import traceback
                self._callbacks.printError("SQLBurp restore error for task %s:\n%s" % (
                    task_id, traceback.format_exc()))

    def _restore_one_task(self, base, task_id, api_status):
        """
        Restore a single task into the table.
        First tries the local persisted record (written at scan completion).
        Falls back to querying the live API only if the record isn't cached
        (e.g. for tasks that were running when the extension was last unloaded).
        """
        # --- fast path: use locally persisted data ---
        cached = self._load_scan_record(task_id)
        if cached:
            opts = cached.get("options") or {}
            snap = ScanOptions(
                level        = opts.get("level", 1),
                risk         = opts.get("risk", 1),
                threads      = opts.get("threads", 1),
                technique    = opts.get("technique", "BEUSTQ"),
                dbms         = opts.get("dbms", "(auto)"),
                tamper       = opts.get("tamper", ""),
                batch        = opts.get("batch", True),
                random_agent = opts.get("random_agent", False),
                forms        = opts.get("forms", False),
                get_dbs      = opts.get("get_dbs", True),
                current_user = opts.get("current_user", True),
                banner       = opts.get("banner", True),
                is_dba       = opts.get("is_dba", False),
                force_ssl    = opts.get("force_ssl", False),
                verbose      = opts.get("verbose", 2),
            )
            rec            = ScanRecord(task_id, cached["target"], cached["method"], options=snap)
            rec.status     = cached.get("status", STATUS_DONE)
            rec.findings   = cached.get("findings", 0)
            rec.started    = cached.get("started", rec.started)
            rec.log_lines  = cached.get("log_lines", [])
            rec.results    = cached.get("results", [])
            self._records.append(rec)
            self._records_map[task_id] = rec
            SwingUtilities.invokeLater(_RunLater(lambda: self._add_row_edt(rec)))
            return

        # --- slow path: query live API (task still known to this sqlmapapi session) ---
        target = "(unknown)"
        method = "GET"
        try:
            opt_resp = _api_request("POST", base, "/option/%s/get" % task_id,
                                    {"requestFile": None, "url": None, "forceSSL": None})
            options   = opt_resp.get("options") or {}
            req_file  = options.get("requestFile") or ""
            url_opt   = options.get("url") or ""
            force_ssl = bool(options.get("forceSSL", False))
            if req_file:
                try:
                    import java.io.File          as JavaFile
                    import java.io.FileReader     as JavaFileReader
                    import java.io.BufferedReader as JavaBufReader
                    reader = JavaBufReader(JavaFileReader(JavaFile(req_file)))
                    lines  = []
                    line   = reader.readLine()
                    while line is not None:
                        lines.append(line)
                        line = reader.readLine()
                    reader.close()
                    if lines:
                        parts  = lines[0].split(" ")
                        method = parts[0].strip() if parts else "GET"
                    host = None
                    for hdr in lines[1:]:
                        if not hdr.strip():
                            break
                        if hdr.lower().startswith("host:"):
                            host = hdr.split(":", 1)[1].strip()
                            break
                    if host:
                        scheme = "https" if force_ssl else "http"
                        target = "%s://%s" % (scheme, host)
                except Exception as e:
                    self._callbacks.printError("SQLBurp restore: error reading requestFile %s: %s" % (req_file, str(e)))
            if target == "(unknown)" and url_opt:
                try:
                    from java.net import URL as JavaURL
                    u      = JavaURL(url_opt)
                    scheme = "https" if (force_ssl or u.getProtocol() == "https") else "http"
                    port   = u.getPort()
                    host   = u.getHost()
                    if port != -1 and port not in (80, 443):
                        target = "%s://%s:%d" % (scheme, host, port)
                    else:
                        target = "%s://%s" % (scheme, host)
                    method = "GET"
                except Exception:
                    target = url_opt
        except Exception as e:
            self._callbacks.printError("SQLBurp restore: option fetch failed for task %s: %s" % (task_id, str(e)))

        snap = ScanOptions()
        try:
            list_resp = _api_request("GET", base, "/option/%s/list" % task_id)
            snap = ScanOptions.from_api(list_resp.get("options") or {})
        except Exception as e:
            self._callbacks.printError("SQLBurp restore: option list failed for task %s: %s" % (task_id, str(e)))

        rec = ScanRecord(task_id, target, method, options=snap)
        try:
            log_resp  = _api_request("GET", base, "/scan/%s/log" % task_id)
            api_lines = log_resp.get("log") or []
            if api_lines:
                rec.started = api_lines[0].get("time", rec.started)
            for entry in api_lines:
                rec.log_lines.append("[%s][%s] %s" % (
                    entry.get("time", ""), entry.get("level", "INFO"),
                    entry.get("message", "")))
        except Exception as e:
            self._callbacks.printError("SQLBurp restore: log fetch failed for task %s: %s" % (task_id, str(e)))

        seen_log_count = len(rec.log_lines)

        if api_status == "running":
            rec.status = STATUS_RUNNING
        else:
            try:
                data_resp   = _api_request("GET", base, "/scan/%s/data" % task_id)
                rec.results = data_resp.get("data") or []
            except Exception:
                pass
            if rec.results:
                rec.findings = len(rec.results)
                rec.status   = STATUS_VULN
                rec.log_lines.append("")
                rec.log_lines.append("=== INJECTION POINTS CONFIRMED ===")
                for entry in rec.results:
                    rec.log_lines.append(json.dumps(entry, indent=2))
            else:
                rec.status = STATUS_DONE

        self._records.append(rec)
        self._records_map[task_id] = rec
        SwingUtilities.invokeLater(_RunLater(lambda: self._add_row_edt(rec)))

        if rec.status == STATUS_RUNNING:
            poll = PollThread(self, rec)
            poll._seen_log_count_override = seen_log_count
            self._poll_threads[task_id] = poll
            t = Thread(poll)
            t.setDaemon(True)
            t.start()

    # ------------------------------------------------------------------
    # ITab / IContextMenuFactory
    # ------------------------------------------------------------------

    def getTabCaption(self):
        return "SQLBurp"

    def getUiComponent(self):
        return self._main_panel

    def createMenuItems(self, invocation):
        from java.util import ArrayList
        items = ArrayList()
        mi = JMenuItem("Send to SQLBurp")
        mi.addActionListener(self._MenuAction(self, invocation))
        items.add(mi)
        return items

    class _MenuAction(java.awt.event.ActionListener):
        def __init__(self, ext, invocation):
            self._ext        = ext
            self._invocation = invocation
        def actionPerformed(self, e):
            self._ext._handle_send(self._invocation)

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _build_ui(self):
        self._main_panel = JPanel(BorderLayout())
        cfg_panel     = self._build_config_panel()
        table_panel   = self._build_table_panel()
        preview_panel = self._build_preview_panel()
        top_split = JSplitPane(JSplitPane.VERTICAL_SPLIT, cfg_panel, table_panel)
        top_split.setDividerLocation(165)
        top_split.setResizeWeight(0.0)
        main_split = JSplitPane(JSplitPane.VERTICAL_SPLIT, top_split, preview_panel)
        main_split.setDividerLocation(430)
        main_split.setResizeWeight(0.55)
        self._main_panel.add(main_split, BorderLayout.CENTER)

    def _build_config_panel(self):
        panel = JPanel()
        panel.setLayout(BoxLayout(panel, BoxLayout.Y_AXIS))
        panel.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createEtchedBorder(),
            "SQLBurp Configuration", TitledBorder.LEFT, TitledBorder.TOP))

        r1 = JPanel(FlowLayout(FlowLayout.LEFT, 6, 2))
        r1.add(JLabel("API URL:"))
        self._url_field = JTextField("http://127.0.0.1:8775", 28)
        r1.add(self._url_field)
        ping_btn = JButton("Ping")
        ping_btn.addActionListener(lambda e: Thread(_RunLater(self._ping_server)).start())
        r1.add(ping_btn)
        panel.add(r1)

        r2 = JPanel(FlowLayout(FlowLayout.LEFT, 6, 2))
        r2.add(JLabel("Level:"))
        self._level_spin = JSpinner(SpinnerNumberModel(1, 1, 5, 1))
        self._level_spin.setPreferredSize(Dimension(50, 24))
        r2.add(self._level_spin)
        r2.add(JLabel("Risk:"))
        self._risk_spin = JSpinner(SpinnerNumberModel(1, 1, 3, 1))
        self._risk_spin.setPreferredSize(Dimension(50, 24))
        r2.add(self._risk_spin)
        r2.add(JLabel("Threads:"))
        self._threads_spin = JSpinner(SpinnerNumberModel(1, 1, 10, 1))
        self._threads_spin.setPreferredSize(Dimension(50, 24))
        r2.add(self._threads_spin)
        r2.add(JLabel("Technique:"))
        self._technique_field = JTextField("BEUSTQ", 7)
        r2.add(self._technique_field)
        r2.add(JLabel("DBMS:"))
        self._dbms_combo = JComboBox(["(auto)", "MySQL", "PostgreSQL",
                                      "Microsoft SQL Server", "Oracle", "SQLite", "MariaDB"])
        r2.add(self._dbms_combo)
        r2.add(JLabel("Tamper:"))
        self._tamper_field = JTextField("", 16)
        self._tamper_field.setToolTipText("e.g. space2comment,randomcase")
        r2.add(self._tamper_field)
        panel.add(r2)

        r3 = JPanel(FlowLayout(FlowLayout.LEFT, 6, 2))
        self._batch_check        = JCheckBox("Batch",        True)
        self._random_agent_check = JCheckBox("Random Agent", False)
        self._forms_check        = JCheckBox("Parse Forms",  False)
        self._dbs_check          = JCheckBox("Enum DBs",     True)
        self._user_check         = JCheckBox("Current User", True)
        self._banner_check       = JCheckBox("Banner",       True)
        self._isdba_check        = JCheckBox("Is DBA",       False)
        for cb in [self._batch_check, self._random_agent_check, self._forms_check,
                   self._dbs_check, self._user_check, self._banner_check, self._isdba_check]:
            r3.add(cb)
        r3.add(Box.createHorizontalStrut(10))
        r3.add(JLabel("Poll (s):"))
        self._poll_spin = JSpinner(SpinnerNumberModel(5, 1, 60, 1))
        self._poll_spin.setPreferredSize(Dimension(50, 24))
        r3.add(self._poll_spin)
        panel.add(r3)
        return panel

    def _build_table_panel(self):
        self._table_model = _ScanTableModel()
        self._table = JTable(self._table_model)
        self._table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        self._table.setRowHeight(20)
        self._table.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS)
        self._table.setFillsViewportHeight(True)
        for i, w in enumerate([35, 130, 300, 65, 90, 75, 70]):
            self._table.getColumnModel().getColumn(i).setPreferredWidth(w)
        self._table.getColumnModel().getColumn(4).setCellRenderer(_StatusRenderer())
        self._sorter = TableRowSorter(self._table_model)
        self._sorter.setComparator(0, _IntComparator())
        self._sorter.setComparator(4, _StatusComparator())
        self._sorter.setComparator(6, _StringComparator())
        for col in [1, 2, 3, 5]:
            self._sorter.setSortable(col, False)
        self._table.setRowSorter(self._sorter)
        self._table.getSelectionModel().addListSelectionListener(
            lambda e: self._on_row_selected() if not e.getValueIsAdjusting() else None)
        self._table.addMouseListener(self._TableMouse(self))
        scroll = JScrollPane(self._table)
        scroll.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createEtchedBorder(), "Scans",
            TitledBorder.LEFT, TitledBorder.TOP))
        return scroll

    def _build_preview_panel(self):
        outer = JPanel(BorderLayout())
        outer.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createEtchedBorder(), "Scan Detail",
            TitledBorder.LEFT, TitledBorder.TOP))

        self._options_area = JTextArea()
        self._options_area.setEditable(False)
        self._options_area.setFont(Font("Monospaced", Font.PLAIN, 12))
        self._options_area.setText("Select a scan row to view its options.")
        options_scroll = JScrollPane(self._options_area)
        options_scroll.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createEtchedBorder(), "Scan Options",
            TitledBorder.LEFT, TitledBorder.TOP))
        options_scroll.setPreferredSize(Dimension(220, 0))

        self._preview_area = JTextArea()
        self._preview_area.setEditable(False)
        self._preview_area.setFont(Font("Monospaced", Font.PLAIN, 12))
        self._preview_area.setText("Select a scan row above to view its log.")
        log_scroll = JScrollPane(self._preview_area)
        log_scroll.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createEtchedBorder(), "Scan Log / Results",
            TitledBorder.LEFT, TitledBorder.TOP))

        detail_split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, options_scroll, log_scroll)
        detail_split.setDividerLocation(230)
        detail_split.setResizeWeight(0.0)

        # Toolbar
        toolbar = JPanel(FlowLayout(FlowLayout.LEFT, 6, 2))

        stop_all_btn = JButton("Stop All")
        stop_all_btn.addActionListener(lambda e: self._stop_all_tasks())
        toolbar.add(stop_all_btn)

        rm_done_btn = JButton("Remove Finished")
        rm_done_btn.addActionListener(lambda e: self._remove_finished())
        toolbar.add(rm_done_btn)

        outer.add(toolbar, BorderLayout.NORTH)
        outer.add(detail_split, BorderLayout.CENTER)
        return outer

    # ------------------------------------------------------------------
    # Inner class: table right-click listener
    # ------------------------------------------------------------------

    class _TableMouse(java.awt.event.MouseAdapter):
        def __init__(self, ext):
            self._ext = ext
        def mousePressed(self, e):  self._maybe_popup(e)
        def mouseReleased(self, e): self._maybe_popup(e)
        def _maybe_popup(self, e):
            if not e.isPopupTrigger():
                return
            tbl = self._ext._table
            row = tbl.rowAtPoint(e.getPoint())
            if row < 0:
                return
            tbl.setRowSelectionInterval(row, row)
            menu = JPopupMenu()
            stop_mi = JMenuItem("Stop Task")
            stop_mi.addActionListener(lambda ev: self._ext._stop_selected_task())
            menu.add(stop_mi)
            rm_mi = JMenuItem("Delete Task")
            rm_mi.addActionListener(lambda ev: self._ext._delete_selected_task())
            menu.add(rm_mi)
            menu.show(e.getComponent(), e.getX(), e.getY())

    # ------------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------------

    def get_api_base(self):
        return self._url_field.getText().strip()

    def get_poll_interval(self):
        return int(self._poll_spin.getValue())

    # ------------------------------------------------------------------
    # Table management
    # ------------------------------------------------------------------

    def _add_row_edt(self, record):
        idx = len(self._records) - 1
        self._table_model.addRow([
            str(idx + 1),
            record.task_id[:16],
            record.target,
            record.method,
            record.status,
            str(record.findings),
            record.started,
        ])

    def _refresh_row(self, task_id):
        rec = self._records_map.get(task_id)
        if rec is None:
            return
        try:
            row = self._records.index(rec)
        except ValueError:
            return
        self._table_model.setValueAt(rec.status,        row, 4)
        self._table_model.setValueAt(str(rec.findings), row, 5)

    def _on_row_selected(self):
        view_row = self._table.getSelectedRow()
        if view_row < 0:
            return
        model_row = self._table.convertRowIndexToModel(view_row)
        if model_row < 0 or model_row >= len(self._records):
            return
        rec = self._records[model_row]
        self._selected_tid = rec.task_id
        self._render_preview(rec)

    def _render_preview(self, rec):
        opt_text = "\n".join(rec.options.summary_lines())
        SwingUtilities.invokeLater(_SetText(self._options_area, opt_text))
        log_text = "\n".join(rec.log_lines) if rec.log_lines else "(no log yet)"
        SwingUtilities.invokeLater(_SetText(self._preview_area, log_text))
        SwingUtilities.invokeLater(_RunLater(
            lambda: self._preview_area.setCaretPosition(
                self._preview_area.getDocument().getLength())))

    def _maybe_refresh_preview(self, task_id):
        if self._selected_tid == task_id:
            rec = self._records_map.get(task_id)
            if rec:
                self._render_preview(rec)

    def _force_refresh_preview(self):
        if self._selected_tid:
            rec = self._records_map.get(self._selected_tid)
            if rec:
                self._render_preview(rec)

    def _clear_selected_log(self):
        if self._selected_tid:
            rec = self._records_map.get(self._selected_tid)
            if rec:
                rec.log_lines = []
                SwingUtilities.invokeLater(_SetText(self._preview_area, ""))
                opt_text = "\n".join(rec.options.summary_lines())
                SwingUtilities.invokeLater(_SetText(self._options_area, opt_text))

    # ------------------------------------------------------------------
    # Toolbar actions
    # ------------------------------------------------------------------

    def _stop_selected_task(self):
        view_row = self._table.getSelectedRow()
        if view_row < 0:
            return
        model_row = self._table.convertRowIndexToModel(view_row)
        if 0 <= model_row < len(self._records):
            self._stop_task(self._records[model_row].task_id)

    def _delete_selected_task(self):
        view_row = self._table.getSelectedRow()
        if view_row < 0:
            return
        model_row = self._table.convertRowIndexToModel(view_row)
        if model_row < 0 or model_row >= len(self._records):
            return
        rec = self._records[model_row]
        task_id = rec.task_id
        # Stop poll thread and kill running scan
        self._stop_task(task_id)
        # Delete from sqlmapapi (best-effort — may already be gone after restart)
        try:
            _api_request("GET", self.get_api_base(), "/task/%s/delete" % task_id)
        except Exception:
            pass
        # Purge from Burp project settings
        self._purge_scan_record(task_id)
        # Remove from in-memory state and table
        self._records.pop(model_row)
        self._records_map.pop(task_id, None)
        self._poll_threads.pop(task_id, None)
        self._table_model.removeRow(model_row)
        for i in range(model_row, self._table_model.getRowCount()):
            self._table_model.setValueAt(str(i + 1), i, 0)
        if self._selected_tid == task_id:
            self._selected_tid = None
            SwingUtilities.invokeLater(
                _SetText(self._preview_area, "Select a scan row above to view its log."))

    def _remove_selected_row(self):
        """Remove row from table and purge all Burp project data, but don't touch the API."""
        view_row = self._table.getSelectedRow()
        if view_row < 0:
            return
        model_row = self._table.convertRowIndexToModel(view_row)
        if model_row < 0 or model_row >= len(self._records):
            return
        rec = self._records[model_row]
        task_id = rec.task_id
        self._stop_task(task_id)
        self._purge_scan_record(task_id)
        self._records.pop(model_row)
        self._records_map.pop(task_id, None)
        self._poll_threads.pop(task_id, None)
        self._table_model.removeRow(model_row)
        for i in range(model_row, self._table_model.getRowCount()):
            self._table_model.setValueAt(str(i + 1), i, 0)
        if self._selected_tid == task_id:
            self._selected_tid = None
            SwingUtilities.invokeLater(
                _SetText(self._preview_area, "Select a scan row above to view its log."))

    def _purge_scan_record(self, task_id):
        """Remove all Burp project data for a task (scan record + task ID from list)."""
        try:
            self._callbacks.saveExtensionSetting(self._pkey("scan_%s" % task_id), None)
        except Exception:
            pass
        stored = self._load_stored_tasks()
        if task_id in stored:
            stored.remove(task_id)
            self._save_stored_tasks(stored)

    def _stop_task(self, task_id):
        pt = self._poll_threads.pop(task_id, None)
        if pt:
            pt.stop()
        rec = self._records_map.get(task_id)
        if rec and rec.status == STATUS_RUNNING:
            rec.status = STATUS_STOPPED
            try:
                _api_request("GET", self.get_api_base(), "/scan/%s/stop" % task_id)
            except Exception:
                pass
            self._save_scan_record(rec)
            SwingUtilities.invokeLater(_RunLater(lambda: self._refresh_row(task_id)))

    def _stop_all_tasks(self):
        for tid in list(self._poll_threads.keys()):
            self._stop_task(tid)

    def _remove_finished(self):
        terminal = {STATUS_DONE, STATUS_STOPPED, STATUS_ERROR}
        for i in range(self._table_model.getRowCount() - 1, -1, -1):
            if i >= len(self._records):
                continue
            rec = self._records[i]
            if rec.status in terminal:
                self._purge_scan_record(rec.task_id)
                self._poll_threads.pop(rec.task_id, None)
                self._records.pop(i)
                self._records_map.pop(rec.task_id, None)
                self._table_model.removeRow(i)
                if self._selected_tid == rec.task_id:
                    self._selected_tid = None
        for i in range(self._table_model.getRowCount()):
            self._table_model.setValueAt(str(i + 1), i, 0)

    def _ping_server(self):
        base = self.get_api_base()
        try:
            resp = _api_request("GET", base, "/task/new")
            tid  = resp.get("taskid")
            if not tid:
                raise Exception("Unexpected response: %s" % str(resp))
            try:
                _api_request("GET", base, "/task/%s/delete" % tid)
            except Exception:
                pass
            JOptionPane.showMessageDialog(
                self._main_panel,
                "sqlmapapi server is reachable.\n%s" % base,
                "Ping OK", JOptionPane.INFORMATION_MESSAGE)
        except Exception as e:
            JOptionPane.showMessageDialog(
                self._main_panel,
                "Could not reach sqlmapapi server:\n%s\n\nError: %s" % (base, str(e)),
                "Ping Failed", JOptionPane.ERROR_MESSAGE)

    # ------------------------------------------------------------------
    # Context-menu entry point
    # ------------------------------------------------------------------

    def _handle_send(self, invocation):
        messages = invocation.getSelectedMessages()
        if not messages:
            return
        seen = set()
        for msg in messages:
            raw_request  = self._helpers.bytesToString(msg.getRequest())
            http_service = msg.getHttpService()
            key = (http_service.getHost(), http_service.getPort(),
                   hashlib.md5(raw_request.encode("utf-8", "replace")).hexdigest())
            if key in seen:
                continue
            seen.add(key)
            Thread(self._ScanTask(self, http_service, raw_request)).start()

    class _ScanTask(Runnable):
        def __init__(self, ext, http_service, raw_request):
            self._ext          = ext
            self._http_service = http_service
            self._raw_request  = raw_request

        def run(self):
            ext      = self._ext
            base     = ext.get_api_base()
            protocol = self._http_service.getProtocol()
            host     = self._http_service.getHost()
            port     = self._http_service.getPort()
            target   = "%s://%s:%d" % (protocol, host, port)
            method   = "GET"
            try:
                method = self._raw_request.split(" ", 1)[0].strip()
            except Exception:
                pass

            task_id = None
            rec     = None
            try:
                resp    = _api_request("GET", base, "/task/new")
                task_id = resp.get("taskid")
                if not task_id:
                    raise Exception("No taskid returned: %s" % str(resp))

                rec = ScanRecord(task_id, target, method)
                ext._records.append(rec)
                ext._records_map[task_id] = rec
                SwingUtilities.invokeLater(_RunLater(lambda: ext._add_row_edt(rec)))

                import java.io.File      as JavaFile
                import java.io.FileWriter as JavaFileWriter
                tmp = JavaFile.createTempFile("sqlburp_", ".txt")
                tmp.deleteOnExit()
                fw  = JavaFileWriter(tmp)
                fw.write(self._raw_request)
                fw.close()

                use_ssl = protocol.lower() == "https"
                snap = ScanOptions.from_ui(ext, force_ssl=use_ssl)
                rec.options = snap

                _api_request("POST", base, "/option/%s/set" % task_id,
                             snap.to_api_dict(tmp.getAbsolutePath()))

                start_resp = _api_request("POST", base, "/scan/%s/start" % task_id, {})
                rec.log_lines.append("[%s] Scan started (engineid=%s)" % (
                    time.strftime("%H:%M:%S"), start_resp.get("engineid", "?")))
                rec.status = STATUS_RUNNING
                SwingUtilities.invokeLater(_RunLater(lambda: ext._refresh_row(task_id)))
                ext._maybe_refresh_preview(task_id)
                # Persist task ID and initial record into Burp project settings
                stored = ext._load_stored_tasks()
                if task_id not in stored:
                    stored.append(task_id)
                    ext._save_stored_tasks(stored)
                ext._save_scan_record(rec)

                poll = PollThread(ext, rec)
                ext._poll_threads[task_id] = poll
                t = Thread(poll)
                t.setDaemon(True)
                t.start()

            except Exception as e:
                import traceback
                msg = "[Error] %s\n%s" % (str(e), traceback.format_exc())
                if rec is not None:
                    rec.status = STATUS_ERROR
                    rec.log_lines.append(msg)
                    SwingUtilities.invokeLater(_RunLater(lambda: ext._refresh_row(rec.task_id)))
                    ext._maybe_refresh_preview(rec.task_id)
