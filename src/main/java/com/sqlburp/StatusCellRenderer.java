package com.sqlburp;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;

public class StatusCellRenderer extends DefaultTableCellRenderer {

    private static final Color COL_RUNNING = new Color(0xFF, 0xA5, 0x00);
    private static final Color COL_VULN    = new Color(0xBF, 0x00, 0x00);
    private static final Color COL_CLEAN   = new Color(0x00, 0x80, 0x00);
    private static final Color COL_ERROR   = new Color(0x80, 0x00, 0x80);
    private static final Color COL_QUEUED  = new Color(0x60, 0x60, 0x60);
    private static final Color COL_STOPPED = new Color(0x40, 0x40, 0x40);

    @Override
    public Component getTableCellRendererComponent(JTable table, Object value,
                                                   boolean isSelected, boolean hasFocus,
                                                   int row, int column) {
        super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
        if (!isSelected) {
            String s = value == null ? "" : value.toString();
            Color c = switch (s) {
                case ScanRecord.STATUS_RUNNING -> COL_RUNNING;
                case ScanRecord.STATUS_VULN    -> COL_VULN;
                case ScanRecord.STATUS_DONE    -> COL_CLEAN;
                case ScanRecord.STATUS_ERROR   -> COL_ERROR;
                case ScanRecord.STATUS_STOPPED -> COL_STOPPED;
                default                        -> COL_QUEUED;
            };
            setForeground(c);
            setFont(getFont().deriveFont(Font.BOLD));
        }
        return this;
    }
}
