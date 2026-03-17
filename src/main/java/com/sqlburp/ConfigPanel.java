package com.sqlburp;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;

public class ConfigPanel extends JPanel {

    final JTextField  apiUrlField;
    final JSpinner    levelSpin;
    final JSpinner    riskSpin;
    final JSpinner    threadsSpin;
    final JTextField  techniqueField;
    final JComboBox<String> dbmsCombo;
    final JTextField  tamperField;
    final JCheckBox   batchCheck;
    final JCheckBox   randomAgentCheck;
    final JCheckBox   formsCheck;
    final JCheckBox   dbsCheck;
    final JCheckBox   userCheck;
    final JCheckBox   bannerCheck;
    final JCheckBox   isdbaCheck;
    final JSpinner    pollSpin;
    final JButton     pingBtn;

    public ConfigPanel() {
        setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
        setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        // --- API URL ---
        JPanel urlPanel = titledPanel("API");
        apiUrlField = new JTextField("http://127.0.0.1:8775", 20);
        urlPanel.add(label("URL")); urlPanel.add(apiUrlField);
        pingBtn = new JButton("Ping");
        urlPanel.add(pingBtn);
        add(urlPanel);

        // --- Scan options ---
        JPanel optPanel = titledPanel("Options");
        levelSpin     = new JSpinner(new SpinnerNumberModel(1, 1, 5, 1));
        riskSpin      = new JSpinner(new SpinnerNumberModel(1, 1, 3, 1));
        threadsSpin   = new JSpinner(new SpinnerNumberModel(1, 1, 10, 1));
        techniqueField = new JTextField("BEUSTQ", 8);
        dbmsCombo     = new JComboBox<>(new String[]{
            "(auto)", "MySQL", "PostgreSQL", "Microsoft SQL Server",
            "Oracle", "SQLite", "Microsoft Access", "Firebird",
            "Sybase", "SAP MaxDB", "HSQLDB", "Informix"
        });
        tamperField = new JTextField("", 14);
        pollSpin    = new JSpinner(new SpinnerNumberModel(3, 1, 30, 1));

        optPanel.add(label("Level"));    optPanel.add(levelSpin);
        optPanel.add(label("Risk"));     optPanel.add(riskSpin);
        optPanel.add(label("Threads"));  optPanel.add(threadsSpin);
        optPanel.add(label("Technique"));optPanel.add(techniqueField);
        optPanel.add(label("DBMS"));     optPanel.add(dbmsCombo);
        optPanel.add(label("Tamper"));   optPanel.add(tamperField);
        optPanel.add(label("Poll (s)")); optPanel.add(pollSpin);
        add(optPanel);

        // --- Flags ---
        JPanel flagPanel = titledPanel("Flags");
        batchCheck       = new JCheckBox("Batch",        true);
        randomAgentCheck = new JCheckBox("Random Agent", false);
        formsCheck       = new JCheckBox("Forms",        false);
        dbsCheck         = new JCheckBox("Enum DBs",     true);
        userCheck        = new JCheckBox("Current User", true);
        bannerCheck      = new JCheckBox("Banner",       true);
        isdbaCheck       = new JCheckBox("Is DBA",       false);
        flagPanel.add(batchCheck);
        flagPanel.add(randomAgentCheck);
        flagPanel.add(formsCheck);
        flagPanel.add(dbsCheck);
        flagPanel.add(userCheck);
        flagPanel.add(bannerCheck);
        flagPanel.add(isdbaCheck);
        add(flagPanel);

        add(Box.createVerticalGlue());
    }

    public ScanOptions readOptions(boolean forceSSL) {
        ScanOptions o = new ScanOptions();
        o.level       = (int) levelSpin.getValue();
        o.risk        = (int) riskSpin.getValue();
        o.threads     = (int) threadsSpin.getValue();
        o.technique   = techniqueField.getText().trim().isEmpty() ? "BEUSTQ" : techniqueField.getText().trim();
        o.dbms        = (String) dbmsCombo.getSelectedItem();
        o.tamper      = tamperField.getText().trim();
        o.batch       = batchCheck.isSelected();
        o.randomAgent = randomAgentCheck.isSelected();
        o.forms       = formsCheck.isSelected();
        o.getDbs      = dbsCheck.isSelected();
        o.currentUser = userCheck.isSelected();
        o.banner      = bannerCheck.isSelected();
        o.isDba       = isdbaCheck.isSelected();
        o.forceSSL    = forceSSL;
        o.verbose     = 2;
        return o;
    }

    public String getApiUrl() { return apiUrlField.getText().trim(); }
    public int    getPollMs() { return (int) pollSpin.getValue() * 1_000; }

    private JPanel titledPanel(String title) {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
        p.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createEtchedBorder(), title,
            TitledBorder.LEFT, TitledBorder.TOP));
        p.setAlignmentX(Component.LEFT_ALIGNMENT);
        return p;
    }

    private JLabel label(String text) {
        JLabel l = new JLabel(text + ":");
        l.setPreferredSize(new Dimension(72, 20));
        return l;
    }
}
