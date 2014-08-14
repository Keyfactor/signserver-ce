/*************************************************************************
 *                                                                       *
 *  SignServer: The OpenSource Automated Signing Server                  *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.signserver.admin.gui;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JOptionPane;
import org.cesecore.audit.impl.integrityprotected.AuditRecordData;
import org.cesecore.util.ValidityDate;
import org.signserver.admin.gui.adminws.gen.EventStatus;
import org.signserver.admin.gui.adminws.gen.RelationalOperator;

/**
 * Dialog for adding query conditions.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class AddConditionDialog extends javax.swing.JDialog {

    // TODO: Sort of Duplicated in AuditlogTableModel and other places?
    /*
    private static final AuditlogColumn[] COLUMNS =  {
        new AuditlogColumn(AuditRecordData.FIELD_ADDITIONAL_DETAILS, "Details"),
        new AuditlogColumn(AuditRecordData.FIELD_AUTHENTICATION_TOKEN, "Admin Subject"),
        new AuditlogColumn(AuditRecordData.FIELD_CUSTOM_ID, "Admin Issuer"),
        new AuditlogColumn(AuditRecordData.FIELD_EVENTSTATUS, "Outcome"),
        new AuditlogColumn(AuditRecordData.FIELD_EVENTTYPE, "Event"),
        new AuditlogColumn(AuditRecordData.FIELD_MODULE, "Module"),
        new AuditlogColumn(AuditRecordData.FIELD_NODEID, "Node"),
        new AuditlogColumn(AuditRecordData.FIELD_SEARCHABLE_DETAIL1, "Admin Serial Number"),
        new AuditlogColumn(AuditRecordData.FIELD_SEARCHABLE_DETAIL2, "Worker ID"),
        new AuditlogColumn(AuditRecordData.FIELD_SERVICE, "Service"),
        new AuditlogColumn(AuditRecordData.FIELD_SEQUENCENUMBER, "Sequence Number"),
        new AuditlogColumn(AuditRecordData.FIELD_TIMESTAMP, "Time")
    };
     */
    
    // TODO: this should be overridable to enable dynamically changing the dialog
    private static final Object[] COLUMNS = AuditlogColumn.values();
    
    /** Relational operator used by each column. */
    /*
    private static final HashMap<String, QueryOperator[]> OPERATORS = new HashMap<String, QueryOperator[]>();
     */

    /** Available values by each column. */
    //private static final HashMap<String, List<String>> VALUES = new HashMap<String, List<String>>();
    
    /** Relational operators useful for text values. */
    private static final QueryOperator[] TEXT_OPERATORS = {
        QueryOperator.fromEnum(RelationalOperator.EQ),
        QueryOperator.fromEnum(RelationalOperator.LIKE),
        QueryOperator.fromEnum(RelationalOperator.NEQ),
        QueryOperator.fromEnum(RelationalOperator.NOTNULL),
        QueryOperator.fromEnum(RelationalOperator.NULL)
    };
    
    /** Relational operators useful for fixed-type values. */
    private static final QueryOperator[] TYPE_OPERATORS = {
        QueryOperator.fromEnum(RelationalOperator.EQ),
        QueryOperator.fromEnum(RelationalOperator.NEQ)
    };
    
    /** Relational operators useful for number values. */
    private static final QueryOperator[] NUMBER_OPERATORS = {
        QueryOperator.fromEnum(RelationalOperator.EQ),
        QueryOperator.fromEnum(RelationalOperator.NEQ),
        QueryOperator.fromEnum(RelationalOperator.GE),
        QueryOperator.fromEnum(RelationalOperator.GT),
        QueryOperator.fromEnum(RelationalOperator.LE),
        QueryOperator.fromEnum(RelationalOperator.LT),
        QueryOperator.fromEnum(RelationalOperator.NOTNULL),
        QueryOperator.fromEnum(RelationalOperator.NULL)
    };
    
    /** Available values for event status. */
    //private static final List<String> STATUS_VALUES; 
    
    /** Available values for time. */
    //private static final List<String> TIME_VALUES;
    
    private static final SimpleDateFormat SDF = new SimpleDateFormat("yyyy-MM-dd HH:mm:ssZ");
    
    static {
        /*
        OPERATORS.put(AuditRecordData.FIELD_ADDITIONAL_DETAILS, TEXT_OPERATORS);
        OPERATORS.put(AuditRecordData.FIELD_AUTHENTICATION_TOKEN, TEXT_OPERATORS);
        OPERATORS.put(AuditRecordData.FIELD_CUSTOM_ID, TEXT_OPERATORS);
        OPERATORS.put(AuditRecordData.FIELD_EVENTSTATUS, TYPE_OPERATORS);
        OPERATORS.put(AuditRecordData.FIELD_EVENTTYPE, TEXT_OPERATORS);
        OPERATORS.put(AuditRecordData.FIELD_MODULE, TEXT_OPERATORS);
        OPERATORS.put(AuditRecordData.FIELD_NODEID, TEXT_OPERATORS);
        OPERATORS.put(AuditRecordData.FIELD_SEARCHABLE_DETAIL1, TEXT_OPERATORS);
        OPERATORS.put(AuditRecordData.FIELD_SEARCHABLE_DETAIL2, TEXT_OPERATORS);
        OPERATORS.put(AuditRecordData.FIELD_SERVICE, TEXT_OPERATORS);
        OPERATORS.put(AuditRecordData.FIELD_SEQUENCENUMBER, NUMBER_OPERATORS);
        OPERATORS.put(AuditRecordData.FIELD_TIMESTAMP, NUMBER_OPERATORS);
         */

        /*
        STATUS_VALUES = new ArrayList<String>();
        for (EventStatus st : EventStatus.values()) {
            STATUS_VALUES.add(st.name());
        }
        VALUES.put(AuditRecordData.FIELD_EVENTSTATUS, STATUS_VALUES);
        
        final long time = System.currentTimeMillis();
        TIME_VALUES = new ArrayList<String>();
        TIME_VALUES.add(SDF.format(new Date(time)));
        TIME_VALUES.add(String.valueOf(time));
        VALUES.put(AuditRecordData.FIELD_TIMESTAMP, TIME_VALUES);
        */
    }
    
    private boolean okPressed;
    private QueryColumn column;
    private QueryOperator condition;
    private String value;
    
    /** Creates new form EditConditionDialog */
    public AddConditionDialog(java.awt.Frame parent, boolean modal) {
        super(parent, modal);
        initComponents();
        columnCombobox.setModel(new DefaultComboBoxModel(COLUMNS));
        columnComboboxItemStateChanged(null);
        getRootPane().setDefaultButton(jButtonOk);
    }
    
    /** This method is called from within the constructor to
     * initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is
     * always regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jLabel1 = new javax.swing.JLabel();
        columnCombobox = new javax.swing.JComboBox();
        jLabel2 = new javax.swing.JLabel();
        conditionCombobox = new javax.swing.JComboBox();
        jLabel3 = new javax.swing.JLabel();
        valueCombobox = new javax.swing.JComboBox();
        jPanel1 = new javax.swing.JPanel();
        jButtonOk = new javax.swing.JButton();
        jButtonCancel = new javax.swing.JButton();

        setDefaultCloseOperation(javax.swing.WindowConstants.DISPOSE_ON_CLOSE);
        org.jdesktop.application.ResourceMap resourceMap = org.jdesktop.application.Application.getInstance(org.signserver.admin.gui.SignServerAdminGUIApplication.class).getContext().getResourceMap(AddConditionDialog.class);
        setTitle(resourceMap.getString("Form.title")); // NOI18N
        setLocationByPlatform(true);
        setName("Form"); // NOI18N

        jLabel1.setText(resourceMap.getString("jLabel1.text")); // NOI18N
        jLabel1.setName("jLabel1"); // NOI18N

        columnCombobox.setModel(new javax.swing.DefaultComboBoxModel(new String[] { "Time", "EventType", "Outcome", "Administrator", "Module", "Certificate Authority", "Certificate", "Username", "Node", "Details" }));
        columnCombobox.setName("columnCombobox"); // NOI18N
        columnCombobox.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                columnComboboxItemStateChanged(evt);
            }
        });

        jLabel2.setText(resourceMap.getString("jLabel2.text")); // NOI18N
        jLabel2.setName("jLabel2"); // NOI18N

        conditionCombobox.setModel(new javax.swing.DefaultComboBoxModel(new String[] { "Item 1", "Item 2", "Item 3", "Item 4" }));
        conditionCombobox.setName("conditionCombobox"); // NOI18N

        jLabel3.setText(resourceMap.getString("jLabel3.text")); // NOI18N
        jLabel3.setName("jLabel3"); // NOI18N

        valueCombobox.setEditable(true);
        valueCombobox.setName("valueCombobox"); // NOI18N

        jPanel1.setName("jPanel1"); // NOI18N

        jButtonOk.setText(resourceMap.getString("jButtonOk.text")); // NOI18N
        jButtonOk.setName("jButtonOk"); // NOI18N
        jButtonOk.setPreferredSize(new java.awt.Dimension(70, 30));
        jButtonOk.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonOkActionPerformed(evt);
            }
        });
        jPanel1.add(jButtonOk);

        jButtonCancel.setText(resourceMap.getString("jButtonCancel.text")); // NOI18N
        jButtonCancel.setName("jButtonCancel"); // NOI18N
        jButtonCancel.setPreferredSize(new java.awt.Dimension(70, 30));
        jButtonCancel.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonCancelActionPerformed(evt);
            }
        });
        jPanel1.add(jButtonCancel);

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(jPanel1, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, 478, Short.MAX_VALUE)
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING, false)
                            .addComponent(jLabel3, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(jLabel1, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(jLabel2, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.PREFERRED_SIZE, 88, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(columnCombobox, 0, 378, Short.MAX_VALUE)
                            .addComponent(conditionCombobox, 0, 378, Short.MAX_VALUE)
                            .addComponent(valueCombobox, 0, 378, Short.MAX_VALUE))))
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel1)
                    .addComponent(columnCombobox, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(conditionCombobox, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel2))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel3)
                    .addComponent(valueCombobox, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 19, Short.MAX_VALUE)
                .addComponent(jPanel1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap())
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

private void jButtonOkActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButtonOkActionPerformed
    column = (QueryColumn) columnCombobox.getSelectedItem();
    condition = (QueryOperator) conditionCombobox.getSelectedItem();
    
    if (RelationalOperator.NOTNULL.equals(condition.getOperator())
                || RelationalOperator.NULL.equals(condition.getOperator())) {
        value = null;
    } else {
        value = (String) valueCombobox.getSelectedItem();
        if (column.getType() == QueryColumn.Type.TIME) {    
            final Long time = getTimeValue(value);
            if (time == null) {
                JOptionPane.showMessageDialog(this, "Incorrect value", "Add condition", JOptionPane.ERROR_MESSAGE);
                return;
            } else {
                value = String.valueOf(time);
            }
        }
    }
    
    okPressed = true;
    dispose();
}//GEN-LAST:event_jButtonOkActionPerformed

private void jButtonCancelActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButtonCancelActionPerformed
    dispose();
}//GEN-LAST:event_jButtonCancelActionPerformed

private void columnComboboxItemStateChanged(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_columnComboboxItemStateChanged
    final QueryColumn col = (QueryColumn) columnCombobox.getSelectedItem();
    if (col != null) {
        conditionCombobox.setModel(new DefaultComboBoxModel(getOperatorsForColumn(col)));
        
        if (col.getType() == QueryColumn.Type.TYPE) {
            valueCombobox.setModel(new DefaultComboBoxModel(col.getTypeValues().toArray()));
        } else {
            valueCombobox.setModel(new DefaultComboBoxModel());
        }
    }
}//GEN-LAST:event_columnComboboxItemStateChanged

    private QueryOperator[] getOperatorsForColumn(final QueryColumn column) {
        switch (column.getType()) {
            case TEXT:
                return TEXT_OPERATORS;
            case NUMBER:
            case TIME:
                return NUMBER_OPERATORS;
            case TYPE:
                return TYPE_OPERATORS;
            default:
                throw new IllegalArgumentException("Unknown column type");
        }
    }

    public boolean isOkPressed() {
        return okPressed;
    }

    public QueryColumn getColumn() {
        return column;
    }

    public QueryOperator getCondition() {
        return condition;
    }

    public String getValue() {
        return value;
    }
    
    
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JComboBox columnCombobox;
    private javax.swing.JComboBox conditionCombobox;
    private javax.swing.JButton jButtonCancel;
    private javax.swing.JButton jButtonOk;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JComboBox valueCombobox;
    // End of variables declaration//GEN-END:variables

    private Long getTimeValue(String value) {
        Long result = null;
        try {
            result = Long.parseLong(value);
        } catch (NumberFormatException ex) {
            try {
                result = ValidityDate.parseAsIso8601(value).getTime();
            } catch (ParseException ignored) {} // NOPMD
        }
        return result;
    }
}
