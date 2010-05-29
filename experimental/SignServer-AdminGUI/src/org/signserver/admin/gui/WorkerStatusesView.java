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
import java.security.cert.Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.Map.Entry;
import java.util.Set;
import javax.swing.Timer;
import javax.swing.Icon;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JList;
import javax.swing.table.DefaultTableModel;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerStatus;

/**
 * Frame for displaying worker statuses.
 *
 * @author markus
 * @version $Id$
 */
public class WorkerStatusesView extends FrameView {

    private int[] workerIds;

    private static String[] statusColumns = {
        "Property", "Value"
    };

    private StatusData statusData;


    public WorkerStatusesView(SingleFrameApplication app, int[] workerIds) {
        super(app);

        this.workerIds = workerIds;
        initComponents();
        getFrame().setTitle("Status for " + workerIds.length + " workers");
        

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
        jButton1.doClick();
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
        jButton1 = new javax.swing.JButton();
        jSplitPane2 = new javax.swing.JSplitPane();
        jScrollPane2 = new javax.swing.JScrollPane();
        jList1 = new javax.swing.JList();
        jTabbedPane1 = new javax.swing.JTabbedPane();
        jScrollPane1 = new javax.swing.JScrollPane();
        jTextPane2 = new javax.swing.JTextPane();
        jScrollPane4 = new javax.swing.JScrollPane();
        propertiesTable = new javax.swing.JTable();
        statusPanel = new javax.swing.JPanel();
        javax.swing.JSeparator statusPanelSeparator = new javax.swing.JSeparator();
        statusMessageLabel = new javax.swing.JLabel();
        statusAnimationLabel = new javax.swing.JLabel();
        progressBar = new javax.swing.JProgressBar();

        mainPanel.setName("mainPanel"); // NOI18N

        javax.swing.ActionMap actionMap = org.jdesktop.application.Application.getInstance(org.signserver.admin.gui.SignServerAdminGUIApplication.class).getContext().getActionMap(WorkerStatusesView.class, this);
        jButton1.setAction(actionMap.get("refreshView")); // NOI18N
        org.jdesktop.application.ResourceMap resourceMap = org.jdesktop.application.Application.getInstance(org.signserver.admin.gui.SignServerAdminGUIApplication.class).getContext().getResourceMap(WorkerStatusesView.class);
        jButton1.setText(resourceMap.getString("jButton1.text")); // NOI18N
        jButton1.setName("jButton1"); // NOI18N

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

        jScrollPane1.setBorder(javax.swing.BorderFactory.createEmptyBorder(1, 1, 1, 1));
        jScrollPane1.setVerticalScrollBarPolicy(javax.swing.ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS);
        jScrollPane1.setName("jScrollPane1"); // NOI18N

        jTextPane2.setEditable(false);
        jTextPane2.setText(resourceMap.getString("jTextPane2.text")); // NOI18N
        jTextPane2.setName("jTextPane2"); // NOI18N
        jScrollPane1.setViewportView(jTextPane2);

        jTabbedPane1.addTab(resourceMap.getString("jScrollPane1.TabConstraints.tabTitle"), jScrollPane1); // NOI18N

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

        jTabbedPane1.addTab(resourceMap.getString("jScrollPane4.TabConstraints.tabTitle"), jScrollPane4); // NOI18N

        jSplitPane2.setBottomComponent(jTabbedPane1);

        javax.swing.GroupLayout mainPanelLayout = new javax.swing.GroupLayout(mainPanel);
        mainPanel.setLayout(mainPanelLayout);
        mainPanelLayout.setHorizontalGroup(
            mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, mainPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(jSplitPane2, javax.swing.GroupLayout.DEFAULT_SIZE, 817, Short.MAX_VALUE)
                    .addComponent(jButton1))
                .addContainerGap())
        );
        mainPanelLayout.setVerticalGroup(
            mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, mainPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jSplitPane2, javax.swing.GroupLayout.DEFAULT_SIZE, 588, Short.MAX_VALUE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jButton1)
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

        setComponent(mainPanel);
        setStatusBar(statusPanel);
    }// </editor-fold>//GEN-END:initComponents

    private void jList1ValueChanged(javax.swing.event.ListSelectionEvent evt) {//GEN-FIRST:event_jList1ValueChanged

        if (!evt.getValueIsAdjusting()) {
            final JList list = (JList) evt.getSource();
            displayStatus(list.getSelectedIndex());
        }
}//GEN-LAST:event_jList1ValueChanged

    private void displayStatus(final int row) {
        if (row == -1) {
            jTextPane2.setText("");
        } else {
            jTextPane2.setText(statusData.getStatuses()[row]);

            propertiesTable.setModel(new DefaultTableModel(
                statusData.getConfigData()[row], statusColumns) {

                @Override
                public boolean isCellEditable(int row, int column) {
                    return false;
                }

            });
        }
        jTextPane2.setCaretPosition(0);
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
            Object[][][] newConfigData = new Object[workerIds.length][][];

            setProgress(0);

            for (int i = 0; i < workerIds.length; i++) {

                final int workerId = workerIds[i];
                System.out.println("WorkerId: " + workerId);

                ByteArrayOutputStream out = new ByteArrayOutputStream();

                final WorkerConfig config = SignServerAdminGUIApplication
                    .getWorkerSession().getCurrentWorkerConfig(workerId);

                names[i] = config.getProperty("NAME") + " (" + workerId + ")";
                String tokenStatus;
                WorkerStatus status = null;
                try {
                    status = SignServerAdminGUIApplication.getWorkerSession()
                            .getStatus(workerId);
                    status.displayStatus(workerId,
                            new PrintStream(out), true);
                    newStatuses[i] = out.toString();
                    tokenStatus = status.isOK() == null ? "ACTIVE" : "OFFLINE";
                } catch (InvalidWorkerIdException ex) {
                    newStatuses[i] = ("No such worker");
                    tokenStatus = "Unknown";
                }

                Date notBefore = null;
                Date notAfter = null;
                Certificate certificate = null;
                Collection<Certificate> certificateChain = null;

                newConfigData[i] = new Object[][] {
                    {"ID", workerId},
                    {"Name", names[i]},
                    {"Token status", tokenStatus},
                    {},
                    {},
                    {},
                    {},
                };

                try {
                    notBefore = SignServerAdminGUIApplication
                            .getWorkerSession()
                            .getSigningValidityNotBefore(workerId);
                    notAfter = SignServerAdminGUIApplication
                            .getWorkerSession()
                            .getSigningValidityNotAfter(workerId);
                    certificate = SignServerAdminGUIApplication
                            .getWorkerSession().getSignerCertificate(workerId);
                    certificateChain = SignServerAdminGUIApplication
                            .getWorkerSession().getSignerCertificateChain(workerId);

                    newConfigData[i][3] = new Object[] {
                        "Validity not before:", notBefore
                    };
                    newConfigData[i][4] = new Object[] {
                        "Validity not after:", notAfter
                    };
                    newConfigData[i][5] = new Object[] {
                        "Signer certificate", certificate
                    };
                    newConfigData[i][6] = new Object[] {
                        "Certificate chain:", certificateChain
                    };

                } catch (CryptoTokenOfflineException ex) {
                    System.out.println("offline: " + workerId);
                }


                setProgress(i + 1, 0, workerIds.length);
            }
            return new StatusData(names, newStatuses, newStatusData, newConfigData);
        }
        @Override protected void succeeded(Object result) {
            // Runs on the EDT.  Update the GUI based on
            // the result computed by doInBackground().
            final StatusData data = (StatusData) result;

            WorkerStatusesView.this.statusData = data;

            final int selected = jList1.getSelectedIndex();

            jList1.setListData(WorkerStatusesView.this.statusData.getNames());

            if (selected == -1) {
                jList1.setSelectedIndex(0);
            } else {
                jList1.setSelectedIndex(selected);
            }
        }
    }


    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton jButton1;
    private javax.swing.JList jList1;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JScrollPane jScrollPane4;
    private javax.swing.JSplitPane jSplitPane2;
    private javax.swing.JTabbedPane jTabbedPane1;
    private javax.swing.JTextPane jTextPane2;
    private javax.swing.JPanel mainPanel;
    private javax.swing.JProgressBar progressBar;
    private javax.swing.JTable propertiesTable;
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
