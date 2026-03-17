package com.sqlburp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import javax.swing.*;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.FileWriter;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

public class SQLBurp implements BurpExtension {

    private MontoyaApi          api;
    private Logging             logging;
    private PersistenceManager  persist;
    private ApiClient           apiClient;

    private ConfigPanel         configPanel;
    private ScanTableModel      tableModel;
    private JTable              scanTable;
    private JTextArea           previewArea;
    private JPanel              mainPanel;

    private final Map<String, Thread>     pollThreads = new ConcurrentHashMap<>();
    private final Map<String, ScanRecord> recordsMap  = new ConcurrentHashMap<>();
    private volatile String               selectedTid = null;

    // ------------------------------------------------------------------
    // BurpExtension entry point
    // ------------------------------------------------------------------

    @Override
    public void initialize(MontoyaApi api) {
        this.api       = api;
        this.logging   = api.logging();
        this.apiClient = new ApiClient();

        api.extension().setName("SQLBurp");

        this.persist = new PersistenceManager(
            api.persistence().extensionData(),
            apiClient.mapper()
        );

        SwingUtilities.invokeLater(this::buildUi);
    }

    // ------------------------------------------------------------------
    // UI construction
    // ------------------------------------------------------------------

    private void buildUi() {
        mainPanel = new JPanel(new BorderLayout());

        // --- Toolbar ---
        JToolBar toolbar = new JToolBar();
        toolbar.setFloatable(false);
        JButton stopAllBtn       = new JButton("Stop All");
        JButton removeFinishedBtn = new JButton("Remove Finished");
        stopAllBtn.addActionListener(e -> stopAllTasks());
        removeFinishedBtn.addActionListener(e -> removeFinished());
        toolbar.add(stopAllBtn);
        toolbar.add(removeFinishedBtn);
        mainPanel.add(toolbar, BorderLayout.NORTH);

        // --- Config panel (left) ---
        configPanel = new ConfigPanel();
        configPanel.pingBtn.addActionListener(e -> pingServer());
        JScrollPane configScroll = new JScrollPane(configPanel);

        // --- Scan table (middle) ---
        tableModel = new ScanTableModel();
        scanTable  = new JTable(tableModel);
        scanTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        scanTable.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
        scanTable.getColumnModel().getColumn(4).setCellRenderer(new StatusCellRenderer());

        TableRowSorter<ScanTableModel> sorter = new TableRowSorter<>(tableModel);
        scanTable.setRowSorter(sorter);

        scanTable.getSelectionModel().addListSelectionListener(e -> {
            if (e.getValueIsAdjusting()) return;
            int vrow = scanTable.getSelectedRow();
            if (vrow < 0) return;
            int mrow = scanTable.convertRowIndexToModel(vrow);
            ScanRecord rec = tableModel.getRecord(mrow);
            if (rec != null) {
                selectedTid = rec.taskId;
                refreshPreview(rec);
            }
        });

        scanTable.addMouseListener(new MouseAdapter() {
            @Override public void mouseReleased(MouseEvent e) {
                if (e.isPopupTrigger()) showContextMenu(e);
            }
            @Override public void mousePressed(MouseEvent e) {
                if (e.isPopupTrigger()) showContextMenu(e);
            }
        });

        JScrollPane tableScroll = new JScrollPane(scanTable);

        // --- Preview area (bottom) ---
        previewArea = new JTextArea("Select a scan row above to view its log.");
        previewArea.setEditable(false);
        previewArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        previewArea.setLineWrap(true);
        previewArea.setWrapStyleWord(true);
        JScrollPane previewScroll = new JScrollPane(previewArea);

        // Three-way vertical split: config | table | preview
        JSplitPane bottomSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, previewScroll);
        bottomSplit.setResizeWeight(0.5);

        JSplitPane vertSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, configScroll, bottomSplit);
        vertSplit.setResizeWeight(0.25);

        mainPanel.add(vertSplit, BorderLayout.CENTER);

        // Apply Burp theme
        api.userInterface().applyThemeToComponent(mainPanel);

        // Register tab
        api.userInterface().registerSuiteTab("SQLBurp", mainPanel);

        // Register context menu
        api.userInterface().registerContextMenuItemsProvider(new SqlBurpMenuProvider());

        // Restore persisted scans
        new Thread(this::restorePersistedScans, "sqlburp-restore").start();
    }

    // ------------------------------------------------------------------
    // Context menu provider
    // ------------------------------------------------------------------

    private class SqlBurpMenuProvider implements ContextMenuItemsProvider {
        @Override
        public List<Component> provideMenuItems(ContextMenuEvent event) {
            List<MessageEditorHttpRequestResponse> messages =
                event.messageEditorRequestResponse()
                     .map(List::of)
                     .orElse(Collections.emptyList());

            if (messages.isEmpty()) {
                // Also handle selection from other tools
                List<burp.api.montoya.http.message.HttpRequestResponse> selected =
                    event.selectedRequestResponses();
                if (selected.isEmpty()) return Collections.emptyList();

                JMenuItem item = new JMenuItem("Send to SQLMap API");
                item.addActionListener(e -> {
                    Set<String> seen = new HashSet<>();
                    for (var rr : selected) {
                        if (rr.request() == null) continue;
                        String key = dedupKey(rr.httpService().host(),
                                              rr.httpService().port(),
                                              rr.request().toByteArray());
                        if (seen.add(key)) {
                            String proto = rr.httpService().secure() ? "https" : "http";
                            String target = proto + "://" + rr.httpService().host()
                                          + ":" + rr.httpService().port();
                            String method = rr.request().method();
                            String raw    = rr.request().toString();
                            new Thread(() -> submitScan(target, method, raw,
                                rr.httpService().secure()), "sqlburp-scan").start();
                        }
                    }
                });
                return List.of(item);
            }

            JMenuItem item = new JMenuItem("Send to SQLMap API");
            item.addActionListener(e -> {
                for (var msg : messages) {
                    if (msg.requestResponse().request() == null) continue;
                    var rr     = msg.requestResponse();
                    String raw = rr.request().toString();
                    String key = dedupKey(rr.httpService().host(),
                                          rr.httpService().port(),
                                          rr.request().toByteArray());
                    String proto  = rr.httpService().secure() ? "https" : "http";
                    String target = proto + "://" + rr.httpService().host()
                                  + ":" + rr.httpService().port();
                    String method = rr.request().method();
                    new Thread(() -> submitScan(target, method, raw,
                        rr.httpService().secure()), "sqlburp-scan").start();
                }
            });
            return List.of(item);
        }
    }

    private String dedupKey(String host, int port, ByteArray rawBytes) {
        return host + ":" + port + ":" + Arrays.hashCode(rawBytes.getBytes());
    }

    // ------------------------------------------------------------------
    // Scan submission
    // ------------------------------------------------------------------

    private void submitScan(String target, String method, String rawRequest, boolean ssl) {
        String taskId = null;
        ScanRecord rec = null;
        try {
            String baseUrl = configPanel.getApiUrl();
            taskId = apiClient.newTask(baseUrl);

            rec = new ScanRecord(taskId, target, method);
            ScanOptions opts = configPanel.readOptions(ssl);
            rec.options = opts;

            final ScanRecord fRec = rec;
            recordsMap.put(taskId, rec);
            SwingUtilities.invokeLater(() -> tableModel.addRow(fRec));

            // Write request to a temp file for sqlmap
            File tmp = File.createTempFile("sqlburp_", ".txt");
            tmp.deleteOnExit();
            try (FileWriter fw = new FileWriter(tmp)) { fw.write(rawRequest); }

            ObjectNode optDict = opts.toApiDict(apiClient.mapper(), tmp.getAbsolutePath());
            apiClient.post(baseUrl, "/option/" + taskId + "/set", optDict);

            ObjectNode empty = apiClient.mapper().createObjectNode();
            var startResp = apiClient.post(baseUrl, "/scan/" + taskId + "/start", empty);
            rec.appendLog("[" + ts() + "] Scan started (engineid="
                + startResp.path("engineid").asText("?") + ")");
            rec.status = ScanRecord.STATUS_RUNNING;

            persist.addTaskId(taskId);
            persist.saveScanRecord(rec);

            SwingUtilities.invokeLater(() -> {
                tableModel.refreshRow(fRec);
                maybeRefreshPreview(fRec);
            });

            startPollThread(rec, baseUrl);

        } catch (Exception ex) {
            String msg = "[Error] " + ex.getMessage();
            logging.logToError(msg);
            if (rec != null) {
                rec.status = ScanRecord.STATUS_ERROR;
                rec.appendLog(msg);
                final ScanRecord fRec = rec;
                SwingUtilities.invokeLater(() -> {
                    tableModel.refreshRow(fRec);
                    maybeRefreshPreview(fRec);
                });
                persist.saveScanRecord(rec);
            }
        }
    }

    // ------------------------------------------------------------------
    // Poll thread management
    // ------------------------------------------------------------------

    private void startPollThread(ScanRecord rec, String baseUrl) {
        PollWorker worker = new PollWorker(
            rec, apiClient, baseUrl,
            configPanel.getPollMs(),
            persist, logging,
            updated -> SwingUtilities.invokeLater(() -> {
                tableModel.refreshRow(updated);
                maybeRefreshPreview(updated);
            })
        );
        Thread t = new Thread(worker, "sqlburp-poll-" + rec.taskId);
        t.setDaemon(true);
        pollThreads.put(rec.taskId, t);
        t.start();
    }

    private void stopTask(String taskId) {
        Thread pt = pollThreads.remove(taskId);
        if (pt != null) pt.interrupt();
        ScanRecord rec = recordsMap.get(taskId);
        if (rec != null && ScanRecord.STATUS_RUNNING.equals(rec.status)) {
            rec.status = ScanRecord.STATUS_STOPPED;
            apiClient.stopTask(configPanel.getApiUrl(), taskId);
            persist.saveScanRecord(rec);
            SwingUtilities.invokeLater(() -> {
                tableModel.refreshRow(rec);
                maybeRefreshPreview(rec);
            });
        }
    }

    private void stopAllTasks() {
        new ArrayList<>(pollThreads.keySet()).forEach(this::stopTask);
    }

    // ------------------------------------------------------------------
    // Row removal
    // ------------------------------------------------------------------

    private void deleteSelectedRow() {
        int vrow = scanTable.getSelectedRow();
        if (vrow < 0) return;
        int mrow = scanTable.convertRowIndexToModel(vrow);
        ScanRecord rec = tableModel.getRecord(mrow);
        if (rec == null) return;
        stopTask(rec.taskId);
        apiClient.deleteTask(configPanel.getApiUrl(), rec.taskId);
        persist.deleteScanRecord(rec.taskId);
        recordsMap.remove(rec.taskId);
        if (rec.taskId.equals(selectedTid)) {
            selectedTid = null;
            previewArea.setText("Select a scan row above to view its log.");
        }
        tableModel.removeRow(mrow);
    }

    private void removeSelectedRowNoApi() {
        int vrow = scanTable.getSelectedRow();
        if (vrow < 0) return;
        int mrow = scanTable.convertRowIndexToModel(vrow);
        ScanRecord rec = tableModel.getRecord(mrow);
        if (rec == null) return;
        stopTask(rec.taskId);
        persist.deleteScanRecord(rec.taskId);
        recordsMap.remove(rec.taskId);
        if (rec.taskId.equals(selectedTid)) {
            selectedTid = null;
            previewArea.setText("Select a scan row above to view its log.");
        }
        tableModel.removeRow(mrow);
    }

    private void removeFinished() {
        Set<String> terminal = Set.of(
            ScanRecord.STATUS_DONE, ScanRecord.STATUS_STOPPED, ScanRecord.STATUS_ERROR);
        List<ScanRecord> toRemove = new ArrayList<>();
        for (ScanRecord r : tableModel.getRecords()) {
            if (terminal.contains(r.status)) toRemove.add(r);
        }
        for (ScanRecord r : toRemove) {
            persist.deleteScanRecord(r.taskId);
            recordsMap.remove(r.taskId);
            pollThreads.remove(r.taskId);
            if (r.taskId.equals(selectedTid)) {
                selectedTid = null;
                previewArea.setText("Select a scan row above to view its log.");
            }
        }
        // Remove from table in reverse index order
        for (int i = tableModel.getRowCount() - 1; i >= 0; i--) {
            ScanRecord r = tableModel.getRecord(i);
            if (r != null && terminal.contains(r.status)) tableModel.removeRow(i);
        }
    }

    // ------------------------------------------------------------------
    // Context menu for table rows
    // ------------------------------------------------------------------

    private void showContextMenu(MouseEvent e) {
        int vrow = scanTable.rowAtPoint(e.getPoint());
        if (vrow < 0) return;
        scanTable.setRowSelectionInterval(vrow, vrow);
        int mrow = scanTable.convertRowIndexToModel(vrow);
        ScanRecord rec = tableModel.getRecord(mrow);
        if (rec == null) return;

        JPopupMenu menu = new JPopupMenu();
        JMenuItem stopItem   = new JMenuItem("Stop Task");
        JMenuItem deleteItem = new JMenuItem("Delete Task");
        JMenuItem removeItem = new JMenuItem("Remove Row");
        stopItem.addActionListener(ev -> stopTask(rec.taskId));
        deleteItem.addActionListener(ev -> deleteSelectedRow());
        removeItem.addActionListener(ev -> removeSelectedRowNoApi());
        menu.add(stopItem);
        menu.add(deleteItem);
        menu.add(removeItem);
        menu.show(e.getComponent(), e.getX(), e.getY());
    }

    // ------------------------------------------------------------------
    // Preview
    // ------------------------------------------------------------------

    private void maybeRefreshPreview(ScanRecord rec) {
        if (rec.taskId.equals(selectedTid)) refreshPreview(rec);
    }

    private void refreshPreview(ScanRecord rec) {
        StringBuilder sb = new StringBuilder();
        sb.append("=== ").append(rec.target).append(" [").append(rec.method).append("] ===\n");
        sb.append("Task ID : ").append(rec.taskId).append("\n");
        sb.append("Status  : ").append(rec.status).append("\n");
        sb.append("Started : ").append(rec.started).append("\n\n");
        sb.append("--- Options ---\n");
        for (String line : rec.options.summaryLines()) sb.append(line).append("\n");
        sb.append("\n--- Log ---\n");
        for (String line : rec.logLines) sb.append(line).append("\n");
        previewArea.setText(sb.toString());
        previewArea.setCaretPosition(0);
    }

    // ------------------------------------------------------------------
    // Ping
    // ------------------------------------------------------------------

    private void pingServer() {
        String base = configPanel.getApiUrl();
        new Thread(() -> {
            try {
                String tid = apiClient.newTask(base);
                apiClient.deleteTask(base, tid);
                SwingUtilities.invokeLater(() ->
                    JOptionPane.showMessageDialog(mainPanel,
                        "sqlmapapi server is reachable.\n" + base,
                        "Ping OK", JOptionPane.INFORMATION_MESSAGE));
            } catch (Exception ex) {
                SwingUtilities.invokeLater(() ->
                    JOptionPane.showMessageDialog(mainPanel,
                        "Could not reach sqlmapapi server:\n" + base
                            + "\n\nError: " + ex.getMessage(),
                        "Ping Failed", JOptionPane.ERROR_MESSAGE));
            }
        }, "sqlburp-ping").start();
    }

    // ------------------------------------------------------------------
    // Restore persisted scans on load
    // ------------------------------------------------------------------

    private void restorePersistedScans() {
        List<String> stored = persist.loadTaskIds();
        if (stored.isEmpty()) return;
        logging.logToOutput("SQLBurp: restoring " + stored.size() + " stored scan(s).");
        String base = configPanel.getApiUrl();
        for (String taskId : stored) {
            try {
                ScanRecord rec = persist.loadScanRecord(taskId);
                if (rec != null) {
                    recordsMap.put(taskId, rec);
                    SwingUtilities.invokeLater(() -> tableModel.addRow(rec));
                    // If was running, try to reconnect poll
                    if (ScanRecord.STATUS_RUNNING.equals(rec.status)) {
                        try {
                            String apiStatus = apiClient.scanStatus(base, taskId);
                            if ("running".equals(apiStatus)) {
                                startPollThread(rec, base);
                            } else {
                                rec.status = ScanRecord.STATUS_STOPPED;
                                persist.saveScanRecord(rec);
                                SwingUtilities.invokeLater(() -> tableModel.refreshRow(rec));
                            }
                        } catch (Exception ignored) {
                            rec.status = ScanRecord.STATUS_STOPPED;
                            persist.saveScanRecord(rec);
                            SwingUtilities.invokeLater(() -> tableModel.refreshRow(rec));
                        }
                    }
                }
            } catch (Exception ex) {
                logging.logToError("SQLBurp: error restoring task " + taskId + ": " + ex.getMessage());
            }
        }
    }

    // ------------------------------------------------------------------
    // Utility
    // ------------------------------------------------------------------

    private String ts() {
        return LocalTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss"));
    }
}