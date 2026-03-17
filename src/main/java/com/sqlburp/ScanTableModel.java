package com.sqlburp;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

public class ScanTableModel extends AbstractTableModel {

    private static final String[] COLS = {"#", "Task ID", "Target", "Method", "Status", "Findings", "Started"};

    private final List<ScanRecord> rows = new ArrayList<>();

    @Override public int getRowCount()    { return rows.size(); }
    @Override public int getColumnCount() { return COLS.length; }
    @Override public String getColumnName(int col) { return COLS[col]; }
    @Override public boolean isCellEditable(int r, int c) { return false; }

    @Override
    public Object getValueAt(int row, int col) {
        if (row < 0 || row >= rows.size()) return "";
        ScanRecord r = rows.get(row);
        return switch (col) {
            case 0 -> String.valueOf(row + 1);
            case 1 -> r.taskId;
            case 2 -> r.target;
            case 3 -> r.method;
            case 4 -> r.status;
            case 5 -> String.valueOf(r.findings);
            case 6 -> r.started;
            default -> "";
        };
    }

    public void addRow(ScanRecord rec) {
        rows.add(rec);
        fireTableRowsInserted(rows.size() - 1, rows.size() - 1);
    }

    public void refreshRow(ScanRecord rec) {
        int idx = rows.indexOf(rec);
        if (idx >= 0) fireTableRowsUpdated(idx, idx);
    }

    public void removeRow(int modelRow) {
        if (modelRow < 0 || modelRow >= rows.size()) return;
        rows.remove(modelRow);
        fireTableRowsDeleted(modelRow, modelRow);
        // Refresh # column
        if (modelRow < rows.size()) fireTableRowsUpdated(modelRow, rows.size() - 1);
    }

    public ScanRecord getRecord(int modelRow) {
        if (modelRow < 0 || modelRow >= rows.size()) return null;
        return rows.get(modelRow);
    }

    public List<ScanRecord> getRecords() { return rows; }
}
