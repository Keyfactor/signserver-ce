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

import javax.swing.event.ListSelectionEvent;
import org.jdesktop.application.Action;
import org.jdesktop.application.ResourceMap;
import org.jdesktop.application.SingleFrameApplication;
import org.jdesktop.application.FrameView;
import org.jdesktop.application.Task;
import org.jdesktop.application.TaskMonitor;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.util.Map.Entry;
import java.util.Set;
import javax.swing.Timer;
import javax.swing.Icon;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JList;
import javax.swing.JOptionPane;
import javax.swing.event.ListSelectionListener;
import javax.swing.table.DefaultTableModel;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerStatus;

/**
 * Frame for displaying worker statuses.
 *
 * @author markus
 * @version $Id: WorkerStatusesView.java 1034 2010-05-28 18:48:15Z netmackan $
 */
public class WorkerConfigurationView extends FrameView {

    private int[] workerIds;

    private static String[] statusColumns = {
        "Property", "Value"
    };

    private StatusData statusData;


    public WorkerConfigurationView(SingleFrameApplication app, int[] workerIds) {
        super(app);

        this.workerIds = workerIds;
        initComponents();
        getFrame().setTitle("Configuration of " + workerIds.length + " workers");

        propertiesTable.getSelectionModel().addListSelectionListener(
                new ListSelectionListener() {

            @Override
            public void valueChanged(final ListSelectionEvent e) {
                if (!e.getValueIsAdjusting()) {
                    final boolean enable
                            = propertiesTable.getSelectedRowCount() > 0;
                    editButton.setEnabled(enable);
                    removeButton.setEnabled(enable);
                }
            }
        });

        // status bar initialization - message timeout, idle icon and busy animation, etc
        ResourceMap resourceMap = getResourceMap();
        int messageTimeout = resourceMap.getInteger("StatusBar.messageTimeout");
        messageTimer = new Timer(messageTimeout, new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                statusMessageLabel.setText("");
            }
        });
        messageTimer.setRepeats(false);
        int busyAnimationRate = resourceMap.getInteger("StatusBar.busyAnimationRate");
        for (int i = 0; i < busyIcons.length; i++) {
            busyIcons[i] = resourceMap.getIcon("StatusBar.busyIcons[" + i + "]");
        }
        busyIconTimer = new Timer(busyAnimationRate, new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                busyIconIndex = (busyIconIndex + 1) % busyIcons.length;
                statusAnimationLabel.setIcon(busyIcons[busyIconIndex]);
            }
        });
        idleIcon = resourceMap.getIcon("StatusBar.idleIcon");
        statusAnimationLabel.setIcon(idleIcon);
        progressBar.setVisible(false);

        // connecting action tasks to status bar via TaskMonitor
        TaskMonitor taskMonitor = new TaskMonitor(getApplication().getContext());
        taskMonitor.addPropertyChangeListener(new java.beans.PropertyChangeListener() {
            public void propertyChange(java.beans.PropertyChangeEvent evt) {
                String propertyName = evt.getPropertyName();
                if ("started".equals(propertyName)) {
                    if (!busyIconTimer.isRunning()) {
                        statusAnimationLabel.setIcon(busyIcons[0]);
                        busyIconIndex = 0;
                        busyIconTimer.start();
                    }
                    progressBar.setVisible(true);
                    progressBar.setIndeterminate(true);
                } else if ("done".equals(propertyName)) {
                    busyIconTimer.stop();
                    statusAnimationLabel.setIcon(idleIcon);
                    progressBar.setVisible(false);
                    progressBar.setValue(0);
                } else if ("message".equals(propertyName)) {
                    String text = (String)(evt.getNewValue());
                    statusMessageLabel.setText((text == null) ? "" : text);
                    messageTimer.restart();
                } else if ("progress".equals(propertyName)) {
                    int value = (Integer)(evt.getNewValue());
                    progressBar.setVisible(true);
                    progressBar.setIndeterminate(false);
                    progressBar.setValue(value);
                }
            }
        });

//        getContext().getTaskService().execute(refreshView());
        refreshButton.doClick();
    }

    @Action
    public void showAboutBox() {
        if (aboutBox == null) {
            JFrame mainFrame = SignServerAdminGUIApplication.getApplication().getMainFrame();
            aboutBox = new SignServerAdminGUIApplicationAboutBox(mainFrame);
            aboutBox.setLocationRelativeTo(mainFrame);
        }
        SignServerAdminGUIApplication.getApplication().show(aboutBox);
    }

    /** This method is called from within the constructor to
     * initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is
     * always regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        mainPanel = new javax.swing.JPanel();
        refreshButton = new javax.swing.JButton();
        jSplitPane2 = new javax.swing.JSplitPane();
        jScrollPane2 = new javax.swing.JScrollPane();
        jList1 = new javax.swing.JList();
        jTabbedPane1 = new javax.swing.JTabbedPane();
        jPanel1 = new javax.swing.JPanel();
        jScrollPane4 = new javax.swing.JScrollPane();
        propertiesTable = new javax.swing.JTable();
        addButton = new javax.swing.JButton();
        editButton = new javax.swing.JButton();
        removeButton = new javax.swing.JButton();
        statusPanel = new javax.swing.JPanel();
        javax.swing.JSeparator statusPanelSeparator = new javax.swing.JSeparator();
        statusMessageLabel = new javax.swing.JLabel();
        statusAnimationLabel = new javax.swing.JLabel();
        progressBar = new javax.swing.JProgressBar();
        editPanel = new javax.swing.JPanel();
        jLabel1 = new javax.swing.JLabel();
        editPropertyTextField = new javax.swing.JTextField();
        jLabel2 = new javax.swing.JLabel();
        jScrollPane1 = new javax.swing.JScrollPane();
        editPropertyValueTextArea = new javax.swing.JTextArea();

        mainPanel.setName("mainPanel"); // NOI18N

        javax.swing.ActionMap actionMap = org.jdesktop.application.Application.getInstance(org.signserver.admin.gui.SignServerAdminGUIApplication.class).getContext().getActionMap(WorkerConfigurationView.class, this);
        refreshButton.setAction(actionMap.get("refreshView")); // NOI18N
        org.jdesktop.application.ResourceMap resourceMap = org.jdesktop.application.Application.getInstance(org.signserver.admin.gui.SignServerAdminGUIApplication.class).getContext().getResourceMap(WorkerConfigurationView.class);
        refreshButton.setText(resourceMap.getString("refreshButton.text")); // NOI18N
        refreshButton.setName("refreshButton"); // NOI18N

        jSplitPane2.setOrientation(javax.swing.JSplitPane.VERTICAL_SPLIT);
        jSplitPane2.setName("jSplitPane2"); // NOI18N

        jScrollPane2.setMinimumSize(new java.awt.Dimension(27, 100));
        jScrollPane2.setName("jScrollPane2"); // NOI18N
        jScrollPane2.setPreferredSize(new java.awt.Dimension(45, 100));

        jList1.setModel(new javax.swing.AbstractListModel() {
            String[] strings = { "SODSigner", "Sod1", "Sod2", "Sod3", "Sod4", "Sod5" };
            public int getSize() { return strings.length; }
            public Object getElementAt(int i) { return strings[i]; }
        });
        jList1.setSelectionMode(javax.swing.ListSelectionModel.SINGLE_SELECTION);
        jList1.setName("jList1"); // NOI18N
        jList1.addListSelectionListener(new javax.swing.event.ListSelectionListener() {
            public void valueChanged(javax.swing.event.ListSelectionEvent evt) {
                jList1ValueChanged(evt);
            }
        });
        jScrollPane2.setViewportView(jList1);

        jSplitPane2.setTopComponent(jScrollPane2);

        jTabbedPane1.setName("jTabbedPane1"); // NOI18N

        jPanel1.setName("jPanel1"); // NOI18N

        jScrollPane4.setVerticalScrollBarPolicy(javax.swing.ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS);
        jScrollPane4.setName("jScrollPane4"); // NOI18N

        propertiesTable.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {
                {"ID", "71", null},
                {"Name", "Sod1", null},
                {"Token status", "ACTIVE", null},
                {"Signatures:", "0", null},
                {"Signature limit:", "100000", null},
                {"Validity not before:", "2010-05-20", null},
                {"Validity not after:", "2020-05-20", null},
                {"Certificate chain:", "CN=Sod1, O=Document Signer Pecuela 11, C=PE issued by CN=CSCA Pecuela,O=Pecuela MOI,C=PE", "..."}
            },
            new String [] {
                "Property", "Value", ""
            }
        ) {
            Class[] types = new Class [] {
                java.lang.Object.class, java.lang.Object.class, java.lang.String.class
            };

            public Class getColumnClass(int columnIndex) {
                return types [columnIndex];
            }
        });
        propertiesTable.setName("propertiesTable"); // NOI18N
        jScrollPane4.setViewportView(propertiesTable);
        propertiesTable.getColumnModel().getColumn(0).setHeaderValue(resourceMap.getString("propertiesTable.columnModel.title0")); // NOI18N
        propertiesTable.getColumnModel().getColumn(1).setHeaderValue(resourceMap.getString("propertiesTable.columnModel.title1")); // NOI18N
        propertiesTable.getColumnModel().getColumn(2).setHeaderValue(resourceMap.getString("propertiesTable.columnModel.title2")); // NOI18N

        addButton.setText(resourceMap.getString("addButton.text")); // NOI18N
        addButton.setName("addButton"); // NOI18N
        addButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                addButtonActionPerformed(evt);
            }
        });

        editButton.setText(resourceMap.getString("editButton.text")); // NOI18N
        editButton.setEnabled(false);
        editButton.setName("editButton"); // NOI18N
        editButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                editButtonActionPerformed(evt);
            }
        });

        removeButton.setText(resourceMap.getString("removeButton.text")); // NOI18N
        removeButton.setEnabled(false);
        removeButton.setName("removeButton"); // NOI18N
        removeButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                removeButtonActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout jPanel1Layout = new javax.swing.GroupLayout(jPanel1);
        jPanel1.setLayout(jPanel1Layout);
        jPanel1Layout.setHorizontalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel1Layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jScrollPane4, javax.swing.GroupLayout.DEFAULT_SIZE, 671, Short.MAX_VALUE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(addButton)
                    .addComponent(editButton)
                    .addComponent(removeButton, javax.swing.GroupLayout.PREFERRED_SIZE, 98, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap())
        );

        jPanel1Layout.linkSize(javax.swing.SwingConstants.HORIZONTAL, new java.awt.Component[] {addButton, editButton, removeButton});

        jPanel1Layout.setVerticalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jScrollPane4, javax.swing.GroupLayout.DEFAULT_SIZE, 415, Short.MAX_VALUE)
                    .addGroup(jPanel1Layout.createSequentialGroup()
                        .addComponent(addButton)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(editButton)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(removeButton)))
                .addContainerGap())
        );

        jTabbedPane1.addTab(resourceMap.getString("jPanel1.TabConstraints.tabTitle"), jPanel1); // NOI18N

        jSplitPane2.setBottomComponent(jTabbedPane1);

        javax.swing.GroupLayout mainPanelLayout = new javax.swing.GroupLayout(mainPanel);
        mainPanel.setLayout(mainPanelLayout);
        mainPanelLayout.setHorizontalGroup(
            mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, mainPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(jSplitPane2, javax.swing.GroupLayout.DEFAULT_SIZE, 817, Short.MAX_VALUE)
                    .addComponent(refreshButton))
                .addContainerGap())
        );
        mainPanelLayout.setVerticalGroup(
            mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, mainPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jSplitPane2, javax.swing.GroupLayout.DEFAULT_SIZE, 588, Short.MAX_VALUE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(refreshButton)
                .addContainerGap())
        );

        statusPanel.setName("statusPanel"); // NOI18N

        statusPanelSeparator.setName("statusPanelSeparator"); // NOI18N

        statusMessageLabel.setName("statusMessageLabel"); // NOI18N

        statusAnimationLabel.setHorizontalAlignment(javax.swing.SwingConstants.LEFT);
        statusAnimationLabel.setName("statusAnimationLabel"); // NOI18N

        progressBar.setName("progressBar"); // NOI18N

        javax.swing.GroupLayout statusPanelLayout = new javax.swing.GroupLayout(statusPanel);
        statusPanel.setLayout(statusPanelLayout);
        statusPanelLayout.setHorizontalGroup(
            statusPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(statusPanelSeparator, javax.swing.GroupLayout.DEFAULT_SIZE, 841, Short.MAX_VALUE)
            .addGroup(statusPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(statusMessageLabel)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 657, Short.MAX_VALUE)
                .addComponent(progressBar, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(statusAnimationLabel)
                .addContainerGap())
        );
        statusPanelLayout.setVerticalGroup(
            statusPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(statusPanelLayout.createSequentialGroup()
                .addComponent(statusPanelSeparator, javax.swing.GroupLayout.PREFERRED_SIZE, 2, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addGroup(statusPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(statusMessageLabel)
                    .addComponent(statusAnimationLabel)
                    .addComponent(progressBar, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(3, 3, 3))
        );

        editPanel.setName("editPanel"); // NOI18N

        jLabel1.setText(resourceMap.getString("jLabel1.text")); // NOI18N
        jLabel1.setName("jLabel1"); // NOI18N

        editPropertyTextField.setEditable(false);
        editPropertyTextField.setText(resourceMap.getString("editPropertyTextField.text")); // NOI18N
        editPropertyTextField.setName("editPropertyTextField"); // NOI18N

        jLabel2.setText(resourceMap.getString("jLabel2.text")); // NOI18N
        jLabel2.setName("jLabel2"); // NOI18N

        jScrollPane1.setName("jScrollPane1"); // NOI18N

        editPropertyValueTextArea.setColumns(20);
        editPropertyValueTextArea.setRows(5);
        editPropertyValueTextArea.setName("editPropertyValueTextArea"); // NOI18N
        jScrollPane1.setViewportView(editPropertyValueTextArea);

        javax.swing.GroupLayout editPanelLayout = new javax.swing.GroupLayout(editPanel);
        editPanel.setLayout(editPanelLayout);
        editPanelLayout.setHorizontalGroup(
            editPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, editPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(editPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(jScrollPane1, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, 372, Short.MAX_VALUE)
                    .addComponent(editPropertyTextField, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, 372, Short.MAX_VALUE)
                    .addComponent(jLabel1, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, 372, Short.MAX_VALUE)
                    .addComponent(jLabel2, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, 372, Short.MAX_VALUE))
                .addContainerGap())
        );
        editPanelLayout.setVerticalGroup(
            editPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(editPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jLabel1)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(editPropertyTextField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(jLabel2)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 193, Short.MAX_VALUE)
                .addContainerGap())
        );

        setComponent(mainPanel);
        setStatusBar(statusPanel);
    }// </editor-fold>//GEN-END:initComponents

    private void jList1ValueChanged(javax.swing.event.ListSelectionEvent evt) {//GEN-FIRST:event_jList1ValueChanged

        if (!evt.getValueIsAdjusting()) {
            final JList list = (JList) evt.getSource();
            displayStatus(list.getSelectedIndex());
        }
}//GEN-LAST:event_jList1ValueChanged

    private void addButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_addButtonActionPerformed
        
        editPropertyTextField.setText("");
        editPropertyTextField.setEditable(true);
        editPropertyValueTextArea.setText("");

        final int res = JOptionPane.showConfirmDialog(getFrame(), editPanel,
                "Add property", JOptionPane.OK_CANCEL_OPTION,
                JOptionPane.PLAIN_MESSAGE);
        if (res == JOptionPane.OK_OPTION) {
            int workerId = workerIds[jList1.getSelectedIndex()];


            SignServerAdminGUIApplication.getWorkerSession()
                    .setWorkerProperty(workerId,
                    editPropertyTextField.getText(),
                    editPropertyValueTextArea.getText());
            SignServerAdminGUIApplication.getWorkerSession()
                    .reloadConfiguration(workerId);

            refreshButton.doClick();
        }
    }//GEN-LAST:event_addButtonActionPerformed

    private void editButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_editButtonActionPerformed
        
        final int row = propertiesTable.getSelectedRow();
        
        if (row != -1) {

            editPropertyTextField.setText(
                    (String) propertiesTable.getValueAt(row, 0));
            editPropertyTextField.setEditable(true);
            editPropertyValueTextArea.setText(
                    (String) propertiesTable.getValueAt(row, 1));

            final int res = JOptionPane.showConfirmDialog(getFrame(), editPanel,
                    "Edit property", JOptionPane.OK_CANCEL_OPTION,
                    JOptionPane.PLAIN_MESSAGE);
            if (res == JOptionPane.OK_OPTION) {
                int workerId = workerIds[jList1.getSelectedIndex()];


                SignServerAdminGUIApplication.getWorkerSession()
                        .setWorkerProperty(workerId,
                        editPropertyTextField.getText(),
                        editPropertyValueTextArea.getText());
                SignServerAdminGUIApplication.getWorkerSession()
                        .reloadConfiguration(workerId);

                refreshButton.doClick();
            }
        }
    }//GEN-LAST:event_editButtonActionPerformed

    private void removeButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_removeButtonActionPerformed
        final int row = propertiesTable.getSelectedRow();

        if (row != -1) {
            final int res = JOptionPane.showConfirmDialog(getFrame(), "Are you sure you want to remove the property?",
                    "Remove property", JOptionPane.YES_NO_CANCEL_OPTION,
                    JOptionPane.QUESTION_MESSAGE);
            if (res == JOptionPane.YES_OPTION) {
                int workerId = workerIds[jList1.getSelectedIndex()];
                SignServerAdminGUIApplication.getWorkerSession()
                        .removeWorkerProperty(workerId,
                        editPropertyTextField.getText());
                SignServerAdminGUIApplication.getWorkerSession()
                        .reloadConfiguration(workerId);

                refreshButton.doClick();
            }
        }
    }//GEN-LAST:event_removeButtonActionPerformed

    private void displayStatus(final int row) {
        if (row == -1) {
            
        } else {
            

            propertiesTable.setModel(new DefaultTableModel(
                statusData.getConfigData()[row], statusColumns) {

                @Override
                public boolean isCellEditable(int row, int column) {
                    return false;
                }

            });
        }
    }

     private static class StatusData {

        private String[] names;
        private String[] statuses;
        private Object[][][] statusData;
        private Object[][][] configData;

        public StatusData(String[] names, String[] statuses,
                Object[][][] statusData, Object[][][] configData) {
            this.names = names;
            this.statuses = statuses;
            this.statusData = statusData;
            this.configData = configData;
        }

        public String[] getNames() {
            return names;
        }

        public Object[][][] getStatusData() {
            return statusData;
        }

        public String[] getStatuses() {
            return statuses;
        }

        public Object[][][] getConfigData() {
            return configData;
        }

    }

    @Action(block = Task.BlockingScope.WINDOW)
    public Task refreshView() {
        return new RefreshViewTask(getApplication());
    }

    private class RefreshViewTask extends org.jdesktop.application.Task<Object, Void> {
        RefreshViewTask(org.jdesktop.application.Application app) {
            // Runs on the EDT.  Copy GUI state that
            // doInBackground() depends on from parameters
            // to RefreshViewTask fields, here.
            super(app);
        }
        @Override protected Object doInBackground() {
            // Your Task's code here.  This method runs
            // on a background thread, so don't reference
            // the Swing GUI from here.
            String[] names = new String[workerIds.length];
            String[] newStatuses = new String[workerIds.length];
            String[][][] newStatusData = new String[workerIds.length][][];
            String[][][] newConfigData = new String[workerIds.length][][];

            setProgress(0);

            for (int i = 0; i < workerIds.length; i++) {

                final int workerId = workerIds[i];
                System.out.println("WorkerId: " + workerId);

                ByteArrayOutputStream out = new ByteArrayOutputStream();

                final WorkerConfig config = SignServerAdminGUIApplication
                    .getWorkerSession().getCurrentWorkerConfig(workerId);
                Set<Entry<Object, Object>> entries
                        = config.getProperties().entrySet();
                newConfigData[i] = new String[entries.size()][];
                int j = 0;
                for (Entry<Object, Object> entry : entries) {
                    newConfigData[i][j] = new String[2];
                    newConfigData[i][j][0] = (String) entry.getKey();
                    newConfigData[i][j][1] = (String) entry.getValue();
                    System.out.println("Value: \"" + entry.getValue() + "\"");
                    j++;
                }

                names[i] = config.getProperty("NAME") + " (" + workerId + ")";
                WorkerStatus status = null;
                try {
                    status = SignServerAdminGUIApplication.getWorkerSession()
                            .getStatus(workerId);
                    status.displayStatus(workerId,
                            new PrintStream(out), true);
                    newStatuses[i] = out.toString();
                } catch (InvalidWorkerIdException ex) {
                    newStatuses[i] = ("No such worker");
                }
                setProgress(i + 1, 0, workerIds.length);
            }
            return new StatusData(names, newStatuses, newStatusData, newConfigData);
        }
        @Override protected void succeeded(Object result) {
            // Runs on the EDT.  Update the GUI based on
            // the result computed by doInBackground().
            final StatusData data = (StatusData) result;

            WorkerConfigurationView.this.statusData = data;

            final int selected = jList1.getSelectedIndex();

            jList1.setListData(WorkerConfigurationView.this.statusData.getNames());

            if (selected == -1) {
                jList1.setSelectedIndex(0);
            } else {
                jList1.setSelectedIndex(selected);
            }
        }
    }


    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton addButton;
    private javax.swing.JButton editButton;
    private javax.swing.JPanel editPanel;
    private javax.swing.JTextField editPropertyTextField;
    private javax.swing.JTextArea editPropertyValueTextArea;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JList jList1;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JScrollPane jScrollPane4;
    private javax.swing.JSplitPane jSplitPane2;
    private javax.swing.JTabbedPane jTabbedPane1;
    private javax.swing.JPanel mainPanel;
    private javax.swing.JProgressBar progressBar;
    private javax.swing.JTable propertiesTable;
    private javax.swing.JButton refreshButton;
    private javax.swing.JButton removeButton;
    private javax.swing.JLabel statusAnimationLabel;
    private javax.swing.JLabel statusMessageLabel;
    private javax.swing.JPanel statusPanel;
    // End of variables declaration//GEN-END:variables

    private final Timer messageTimer;
    private final Timer busyIconTimer;
    private final Icon idleIcon;
    private final Icon[] busyIcons = new Icon[15];
    private int busyIconIndex = 0;

    private JDialog aboutBox;
}
