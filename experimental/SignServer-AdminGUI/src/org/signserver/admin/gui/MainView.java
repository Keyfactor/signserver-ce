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

import java.awt.Component;
import javax.swing.JList;
import javax.swing.event.ListDataListener;
import javax.swing.event.ListSelectionEvent;
import org.jdesktop.application.Action;
import org.jdesktop.application.SingleFrameApplication;
import org.jdesktop.application.FrameView;
import org.jdesktop.application.Task;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map.Entry;
import java.util.Set;
import java.util.Vector;
import javax.ejb.EJBException;
import javax.swing.AbstractListModel;
import javax.swing.ComboBoxModel;
import javax.swing.DefaultListCellRenderer;
import javax.swing.Icon;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.Timer;
import javax.swing.event.ListSelectionListener;
import javax.swing.table.DefaultTableModel;
import org.apache.log4j.Logger;
import org.jdesktop.application.ResourceMap;
import org.jdesktop.application.TaskMonitor;
import org.signserver.common.CryptoTokenAuthenticationFailureException;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerStatus;

/**
 * The application's main frame.
 *
 * @author markus
 * @version $Id$
 */
public class MainView extends FrameView {

    private Logger LOG = Logger.getLogger(MainView.class);


//    private Vector<Vector<Object>> workersList
//            = new Vector<Vector<Object>>();

    private Vector<String> columnNames = new Vector<String>();

    private DefaultTableModel workersModel;

    private List<Worker> signers = new ArrayList<Worker>();

    private List<Worker> selectedSigners = new ArrayList<Worker>();
    private Worker selectedWorker;
    private Worker selectedWorkerBeforeRefresh;
    

    private static String[] statusColumns = {
        "Property", "Value"
    };

    public MainView(SingleFrameApplication app) {
        super(app);

        columnNames.add("Status");
        columnNames.add("Id");
        columnNames.add("Name");

        initComponents();

//        jList1.setCellRenderer(new DefaultListCellRenderer() {
//
//            @Override
//            public Component getListCellRendererComponent(JList list, Object value, int index, boolean isSelected, boolean cellHasFocus) {
//                if (value instanceof Worker) {
//                    final Worker worker  = (Worker) value;
//                    value = worker.getName() + " (" + worker.getWorkerId() + ")";
//
//                    listItemLabel1.setText((String) value);
//                    listItemLabel2.setText(worker.isActive()
//                            ? "ACTIVE" : "OFFLINE");
//                    return listItemPanel;
//                }
//                return super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
//            }
//
//        });

        jList1.setCellRenderer(new MyListCellRenderer());

        jList1.getSelectionModel().addListSelectionListener(new ListSelectionListener() {

            @Override
            public void valueChanged(final ListSelectionEvent evt) {
                if (!evt.getValueIsAdjusting()) {
                    final boolean active
                            = jList1.getSelectedIndices().length > 0;
                    authorizationsMenu.setEnabled(active);
                    statusMenu.setEnabled(active);
                    configurationMenu.setEnabled(active);
                    activateButton.setEnabled(active);
                    activateMenu.setEnabled(active);
                    deactivateButton.setEnabled(active);
                    deactivateMenu.setEnabled(active);
                    generateRequestsButton.setEnabled(active);
                    generateRequestMenu.setEnabled(active);
                    installCertificatesButton.setEnabled(active);
                    installCertificatesMenu.setEnabled(active);
                    
                    selectedSigners = new ArrayList<Worker>();

                    for(Object o : jList1.getSelectedValues()) {
                        if (o instanceof Worker) {
                            selectedSigners.add((Worker) o);
                        }
                    }

                    jList2.setModel(new MyComboBoxModel(selectedSigners));

                    if (selectedSigners.size() > 0) {

                        System.out.println("Previously selected: "
                                + selectedWorkerBeforeRefresh);

                        int comboBoxSelection = 0;

                        // Try to set the previously selected
                        if (selectedWorkerBeforeRefresh != null) {
                            comboBoxSelection = selectedSigners
                                .indexOf(selectedWorkerBeforeRefresh);
                            if (comboBoxSelection == -1) {
                                comboBoxSelection = 0;
                            }
                        }
                        jList2.setSelectedIndex(comboBoxSelection);
                    } else {
                        displayWorker(null);
                    }
                }
            }
        });

        jList2.setRenderer(new DefaultListCellRenderer() {

            @Override
            public Component getListCellRendererComponent(JList list, Object value, int index, boolean isSelected, boolean cellHasFocus) {
                if (value instanceof Worker) {
                    final Worker signer  = (Worker) value;
                    value = signer.getName() + " (" + signer.getWorkerId() + ")";
                }
                return super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
            }

        });

        jList2.addActionListener(new ActionListener() {

            @Override
            public void actionPerformed(ActionEvent e) {
                if (jList2.getSelectedItem() instanceof Worker) {
                    final Worker selectedWorker
                            = (Worker) jList2.getSelectedItem();

                    displayWorker(selectedWorker);
                }
            }
        });

        configurationTable.getSelectionModel().addListSelectionListener(
                new ListSelectionListener() {

            @Override
            public void valueChanged(final ListSelectionEvent e) {
                if (!e.getValueIsAdjusting()) {
                    final boolean enable
                            = configurationTable.getSelectedRowCount() > 0;
                    editButton.setEnabled(enable);
                    removeButton.setEnabled(enable);
                }
            }
        });

        displayWorker(null);

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
        getContext().getTaskService().execute(refreshWorkers());
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
        jSplitPane1 = new javax.swing.JSplitPane();
        jScrollPane2 = new javax.swing.JScrollPane();
        jList1 = new javax.swing.JList();
        jPanel1 = new javax.swing.JPanel();
        jList2 = new javax.swing.JComboBox();
        jTabbedPane1 = new javax.swing.JTabbedPane();
        jScrollPane4 = new javax.swing.JScrollPane();
        statusSummaryTextPane = new javax.swing.JTextPane();
        jScrollPane5 = new javax.swing.JScrollPane();
        propertiesTable = new javax.swing.JTable();
        jPanel2 = new javax.swing.JPanel();
        jScrollPane6 = new javax.swing.JScrollPane();
        configurationTable = new javax.swing.JTable();
        addButton = new javax.swing.JButton();
        editButton = new javax.swing.JButton();
        removeButton = new javax.swing.JButton();
        jPanel3 = new javax.swing.JPanel();
        jScrollPane7 = new javax.swing.JScrollPane();
        authTable = new javax.swing.JTable();
        authAddButton = new javax.swing.JButton();
        authEditButton = new javax.swing.JButton();
        removeButton1 = new javax.swing.JButton();
        menuBar = new javax.swing.JMenuBar();
        javax.swing.JMenu fileMenu = new javax.swing.JMenu();
        javax.swing.JMenuItem exitMenuItem = new javax.swing.JMenuItem();
        editMenu = new javax.swing.JMenu();
        activateMenu = new javax.swing.JMenuItem();
        deactivateMenu = new javax.swing.JMenuItem();
        generateRequestMenu = new javax.swing.JMenuItem();
        installCertificatesMenu = new javax.swing.JMenuItem();
        viewMenu = new javax.swing.JMenu();
        refreshMenu = new javax.swing.JMenuItem();
        statusMenu = new javax.swing.JMenuItem();
        configurationMenu = new javax.swing.JMenuItem();
        authorizationsMenu = new javax.swing.JMenuItem();
        javax.swing.JMenu helpMenu = new javax.swing.JMenu();
        javax.swing.JMenuItem aboutMenuItem = new javax.swing.JMenuItem();
        jToolBar1 = new javax.swing.JToolBar();
        refreshButton = new javax.swing.JButton();
        jSeparator1 = new javax.swing.JToolBar.Separator();
        activateButton = new javax.swing.JButton();
        deactivateButton = new javax.swing.JButton();
        jSeparator2 = new javax.swing.JToolBar.Separator();
        generateRequestsButton = new javax.swing.JButton();
        installCertificatesButton = new javax.swing.JButton();
        statusPanel = new javax.swing.JPanel();
        statusMessageLabel = new javax.swing.JLabel();
        statusAnimationLabel = new javax.swing.JLabel();
        progressBar = new javax.swing.JProgressBar();
        editPanel = new javax.swing.JPanel();
        jLabel1 = new javax.swing.JLabel();
        editPropertyTextField = new javax.swing.JTextField();
        jLabel2 = new javax.swing.JLabel();
        jScrollPane1 = new javax.swing.JScrollPane();
        editPropertyValueTextArea = new javax.swing.JTextArea();
        listItemPanel = new javax.swing.JPanel();
        jLabel3 = new javax.swing.JLabel();
        listItemLabel1 = new javax.swing.JLabel();
        listItemLabel2 = new javax.swing.JLabel();

        mainPanel.setName("mainPanel"); // NOI18N

        jSplitPane1.setName("jSplitPane1"); // NOI18N

        jScrollPane2.setMinimumSize(new java.awt.Dimension(250, 26));
        jScrollPane2.setName("jScrollPane2"); // NOI18N
        jScrollPane2.setPreferredSize(new java.awt.Dimension(530, 202));

        jList1.setModel(new javax.swing.AbstractListModel() {
            String[] strings = { "Item 1", "Item 2", "Item 3", "Item 4", "Item 5" };
            public int getSize() { return strings.length; }
            public Object getElementAt(int i) { return strings[i]; }
        });
        jList1.setName("jList1"); // NOI18N
        jScrollPane2.setViewportView(jList1);

        jSplitPane1.setLeftComponent(jScrollPane2);

        jPanel1.setName("jPanel1"); // NOI18N

        jList2.setMinimumSize(new java.awt.Dimension(39, 60));
        jList2.setName("jList2"); // NOI18N

        jTabbedPane1.setName("jTabbedPane1"); // NOI18N

        jScrollPane4.setBorder(javax.swing.BorderFactory.createEmptyBorder(1, 1, 1, 1));
        jScrollPane4.setVerticalScrollBarPolicy(javax.swing.ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS);
        jScrollPane4.setName("jScrollPane4"); // NOI18N

        statusSummaryTextPane.setEditable(false);
        org.jdesktop.application.ResourceMap resourceMap = org.jdesktop.application.Application.getInstance(org.signserver.admin.gui.SignServerAdminGUIApplication.class).getContext().getResourceMap(MainView.class);
        statusSummaryTextPane.setText(resourceMap.getString("statusSummaryTextPane.text")); // NOI18N
        statusSummaryTextPane.setName("statusSummaryTextPane"); // NOI18N
        jScrollPane4.setViewportView(statusSummaryTextPane);

        jTabbedPane1.addTab(resourceMap.getString("jScrollPane4.TabConstraints.tabTitle"), jScrollPane4); // NOI18N

        jScrollPane5.setVerticalScrollBarPolicy(javax.swing.ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS);
        jScrollPane5.setName("jScrollPane5"); // NOI18N

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
        jScrollPane5.setViewportView(propertiesTable);

        jTabbedPane1.addTab(resourceMap.getString("jScrollPane5.TabConstraints.tabTitle"), jScrollPane5); // NOI18N

        jPanel2.setName("jPanel2"); // NOI18N

        jScrollPane6.setVerticalScrollBarPolicy(javax.swing.ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS);
        jScrollPane6.setName("jScrollPane6"); // NOI18N

        configurationTable.setModel(new javax.swing.table.DefaultTableModel(
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
        configurationTable.setName("configurationTable"); // NOI18N
        jScrollPane6.setViewportView(configurationTable);

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

        javax.swing.GroupLayout jPanel2Layout = new javax.swing.GroupLayout(jPanel2);
        jPanel2.setLayout(jPanel2Layout);
        jPanel2Layout.setHorizontalGroup(
            jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel2Layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jScrollPane6, javax.swing.GroupLayout.DEFAULT_SIZE, 668, Short.MAX_VALUE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(addButton)
                    .addComponent(editButton)
                    .addComponent(removeButton, javax.swing.GroupLayout.PREFERRED_SIZE, 98, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap())
        );

        jPanel2Layout.linkSize(javax.swing.SwingConstants.HORIZONTAL, new java.awt.Component[] {addButton, editButton, removeButton});

        jPanel2Layout.setVerticalGroup(
            jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel2Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jScrollPane6, javax.swing.GroupLayout.DEFAULT_SIZE, 707, Short.MAX_VALUE)
                    .addGroup(jPanel2Layout.createSequentialGroup()
                        .addComponent(addButton)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(editButton)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(removeButton)))
                .addContainerGap())
        );

        jTabbedPane1.addTab("Configuration", jPanel2);

        jPanel3.setName("jPanel3"); // NOI18N

        jScrollPane7.setVerticalScrollBarPolicy(javax.swing.ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS);
        jScrollPane7.setName("jScrollPane7"); // NOI18N

        authTable.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {
                {null, null},
                {null, null},
                {null, null},
                {null, null},
                {null, null},
                {null, null},
                {null, null},
                {null, null}
            },
            new String [] {
                "Certificate serial number", "Issuer DN"
            }
        ) {
            Class[] types = new Class [] {
                java.lang.String.class, java.lang.String.class
            };
            boolean[] canEdit = new boolean [] {
                false, false
            };

            public Class getColumnClass(int columnIndex) {
                return types [columnIndex];
            }

            public boolean isCellEditable(int rowIndex, int columnIndex) {
                return canEdit [columnIndex];
            }
        });
        authTable.setName("authTable"); // NOI18N
        authTable.setSelectionMode(javax.swing.ListSelectionModel.SINGLE_SELECTION);
        jScrollPane7.setViewportView(authTable);

        javax.swing.ActionMap actionMap = org.jdesktop.application.Application.getInstance(org.signserver.admin.gui.SignServerAdminGUIApplication.class).getContext().getActionMap(MainView.class, this);
        authAddButton.setAction(actionMap.get("add")); // NOI18N
        authAddButton.setText(resourceMap.getString("authAddButton.text")); // NOI18N
        authAddButton.setName("authAddButton"); // NOI18N

        authEditButton.setAction(actionMap.get("edit")); // NOI18N
        authEditButton.setText(resourceMap.getString("authEditButton.text")); // NOI18N
        authEditButton.setName("authEditButton"); // NOI18N

        removeButton1.setAction(actionMap.get("remove")); // NOI18N
        removeButton1.setText(resourceMap.getString("removeButton1.text")); // NOI18N
        removeButton1.setName("removeButton1"); // NOI18N

        javax.swing.GroupLayout jPanel3Layout = new javax.swing.GroupLayout(jPanel3);
        jPanel3.setLayout(jPanel3Layout);
        jPanel3Layout.setHorizontalGroup(
            jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel3Layout.createSequentialGroup()
                .addContainerGap(691, Short.MAX_VALUE)
                .addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(authAddButton, javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(authEditButton, javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(removeButton1, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.PREFERRED_SIZE, 99, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap())
            .addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addGroup(jPanel3Layout.createSequentialGroup()
                    .addGap(6, 6, 6)
                    .addComponent(jScrollPane7, javax.swing.GroupLayout.DEFAULT_SIZE, 672, Short.MAX_VALUE)
                    .addGap(124, 124, 124)))
        );

        jPanel3Layout.linkSize(javax.swing.SwingConstants.HORIZONTAL, new java.awt.Component[] {authAddButton, authEditButton, removeButton1});

        jPanel3Layout.setVerticalGroup(
            jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel3Layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(authAddButton)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(authEditButton)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(removeButton1)
                .addContainerGap(620, Short.MAX_VALUE))
            .addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addGroup(jPanel3Layout.createSequentialGroup()
                    .addContainerGap()
                    .addComponent(jScrollPane7, javax.swing.GroupLayout.DEFAULT_SIZE, 707, Short.MAX_VALUE)
                    .addContainerGap()))
        );

        jTabbedPane1.addTab(resourceMap.getString("jPanel3.TabConstraints.tabTitle"), jPanel3); // NOI18N

        javax.swing.GroupLayout jPanel1Layout = new javax.swing.GroupLayout(jPanel1);
        jPanel1.setLayout(jPanel1Layout);
        jPanel1Layout.setHorizontalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel1Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(jTabbedPane1, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, 814, Short.MAX_VALUE)
                    .addComponent(jList2, javax.swing.GroupLayout.Alignment.LEADING, 0, 814, Short.MAX_VALUE))
                .addContainerGap())
        );
        jPanel1Layout.setVerticalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jList2, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addComponent(jTabbedPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 772, Short.MAX_VALUE))
        );

        jSplitPane1.setRightComponent(jPanel1);

        javax.swing.GroupLayout mainPanelLayout = new javax.swing.GroupLayout(mainPanel);
        mainPanel.setLayout(mainPanelLayout);
        mainPanelLayout.setHorizontalGroup(
            mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(mainPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jSplitPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 1094, Short.MAX_VALUE)
                .addContainerGap())
        );
        mainPanelLayout.setVerticalGroup(
            mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(mainPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jSplitPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 827, Short.MAX_VALUE)
                .addContainerGap())
        );

        menuBar.setName("menuBar"); // NOI18N

        fileMenu.setMnemonic('F');
        fileMenu.setText(resourceMap.getString("fileMenu.text")); // NOI18N
        fileMenu.setName("fileMenu"); // NOI18N

        exitMenuItem.setAction(actionMap.get("quit")); // NOI18N
        exitMenuItem.setName("exitMenuItem"); // NOI18N
        fileMenu.add(exitMenuItem);

        menuBar.add(fileMenu);

        editMenu.setAction(actionMap.get("installCertificates")); // NOI18N
        editMenu.setText(resourceMap.getString("editMenu.text")); // NOI18N
        editMenu.setName("editMenu"); // NOI18N

        activateMenu.setAction(actionMap.get("activateWorkers")); // NOI18N
        activateMenu.setText(resourceMap.getString("activateMenu.text")); // NOI18N
        activateMenu.setName("activateMenu"); // NOI18N
        editMenu.add(activateMenu);

        deactivateMenu.setAction(actionMap.get("deactivateWorkers")); // NOI18N
        deactivateMenu.setText(resourceMap.getString("deactivateMenu.text")); // NOI18N
        deactivateMenu.setName("deactivateMenu"); // NOI18N
        editMenu.add(deactivateMenu);

        generateRequestMenu.setAction(actionMap.get("generateRequests")); // NOI18N
        generateRequestMenu.setText(resourceMap.getString("generateRequestMenu.text")); // NOI18N
        generateRequestMenu.setName("generateRequestMenu"); // NOI18N
        editMenu.add(generateRequestMenu);

        installCertificatesMenu.setAction(actionMap.get("installCertificates")); // NOI18N
        installCertificatesMenu.setText(resourceMap.getString("installCertificatesMenu.text")); // NOI18N
        installCertificatesMenu.setName("installCertificatesMenu"); // NOI18N
        editMenu.add(installCertificatesMenu);

        menuBar.add(editMenu);

        viewMenu.setAction(actionMap.get("showConfiguration")); // NOI18N
        viewMenu.setText(resourceMap.getString("viewMenu.text")); // NOI18N
        viewMenu.setName("viewMenu"); // NOI18N

        refreshMenu.setAction(actionMap.get("refreshWorkers")); // NOI18N
        refreshMenu.setText(resourceMap.getString("refreshMenu.text")); // NOI18N
        refreshMenu.setName("refreshMenu"); // NOI18N
        viewMenu.add(refreshMenu);

        statusMenu.setAction(actionMap.get("showStatuses")); // NOI18N
        statusMenu.setText(resourceMap.getString("statusMenu.text")); // NOI18N
        statusMenu.setName("statusMenu"); // NOI18N
        viewMenu.add(statusMenu);

        configurationMenu.setAction(actionMap.get("showConfiguration")); // NOI18N
        configurationMenu.setText(resourceMap.getString("configurationMenu.text")); // NOI18N
        configurationMenu.setName("configurationMenu"); // NOI18N
        viewMenu.add(configurationMenu);

        authorizationsMenu.setAction(actionMap.get("viewAuthorizations")); // NOI18N
        authorizationsMenu.setText(resourceMap.getString("authorizationsMenu.text")); // NOI18N
        authorizationsMenu.setName("authorizationsMenu"); // NOI18N
        viewMenu.add(authorizationsMenu);

        menuBar.add(viewMenu);

        helpMenu.setMnemonic('H');
        helpMenu.setText(resourceMap.getString("helpMenu.text")); // NOI18N
        helpMenu.setName("helpMenu"); // NOI18N

        aboutMenuItem.setAction(actionMap.get("showAboutBox")); // NOI18N
        aboutMenuItem.setName("aboutMenuItem"); // NOI18N
        helpMenu.add(aboutMenuItem);

        menuBar.add(helpMenu);

        jToolBar1.setRollover(true);
        jToolBar1.setName("jToolBar1"); // NOI18N

        refreshButton.setAction(actionMap.get("refreshWorkers")); // NOI18N
        refreshButton.setText(resourceMap.getString("refreshButton.text")); // NOI18N
        refreshButton.setFocusable(false);
        refreshButton.setHorizontalTextPosition(javax.swing.SwingConstants.CENTER);
        refreshButton.setName("refreshButton"); // NOI18N
        refreshButton.setVerticalTextPosition(javax.swing.SwingConstants.BOTTOM);
        jToolBar1.add(refreshButton);

        jSeparator1.setName("jSeparator1"); // NOI18N
        jToolBar1.add(jSeparator1);

        activateButton.setAction(actionMap.get("activateWorkers")); // NOI18N
        activateButton.setText(resourceMap.getString("activateButton.text")); // NOI18N
        activateButton.setFocusable(false);
        activateButton.setHorizontalTextPosition(javax.swing.SwingConstants.CENTER);
        activateButton.setName("activateButton"); // NOI18N
        activateButton.setVerticalTextPosition(javax.swing.SwingConstants.BOTTOM);
        jToolBar1.add(activateButton);

        deactivateButton.setAction(actionMap.get("deactivateWorkers")); // NOI18N
        deactivateButton.setText(resourceMap.getString("deactivateButton.text")); // NOI18N
        deactivateButton.setFocusable(false);
        deactivateButton.setHorizontalTextPosition(javax.swing.SwingConstants.CENTER);
        deactivateButton.setName("deactivateButton"); // NOI18N
        deactivateButton.setVerticalTextPosition(javax.swing.SwingConstants.BOTTOM);
        jToolBar1.add(deactivateButton);

        jSeparator2.setName("jSeparator2"); // NOI18N
        jToolBar1.add(jSeparator2);

        generateRequestsButton.setAction(actionMap.get("generateRequests")); // NOI18N
        generateRequestsButton.setText(resourceMap.getString("generateRequestsButton.text")); // NOI18N
        generateRequestsButton.setFocusable(false);
        generateRequestsButton.setHorizontalTextPosition(javax.swing.SwingConstants.CENTER);
        generateRequestsButton.setName("generateRequestsButton"); // NOI18N
        generateRequestsButton.setVerticalTextPosition(javax.swing.SwingConstants.BOTTOM);
        jToolBar1.add(generateRequestsButton);

        installCertificatesButton.setAction(actionMap.get("installCertificates")); // NOI18N
        installCertificatesButton.setText(resourceMap.getString("installCertificatesButton.text")); // NOI18N
        installCertificatesButton.setFocusable(false);
        installCertificatesButton.setHorizontalTextPosition(javax.swing.SwingConstants.CENTER);
        installCertificatesButton.setName("installCertificatesButton"); // NOI18N
        installCertificatesButton.setVerticalTextPosition(javax.swing.SwingConstants.BOTTOM);
        jToolBar1.add(installCertificatesButton);

        statusPanel.setName("statusPanel"); // NOI18N

        statusMessageLabel.setName("statusMessageLabel"); // NOI18N

        statusAnimationLabel.setHorizontalAlignment(javax.swing.SwingConstants.LEFT);
        statusAnimationLabel.setName("statusAnimationLabel"); // NOI18N

        progressBar.setName("progressBar"); // NOI18N

        javax.swing.GroupLayout statusPanelLayout = new javax.swing.GroupLayout(statusPanel);
        statusPanel.setLayout(statusPanelLayout);
        statusPanelLayout.setHorizontalGroup(
            statusPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, statusPanelLayout.createSequentialGroup()
                .addContainerGap(919, Short.MAX_VALUE)
                .addComponent(progressBar, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(statusAnimationLabel, javax.swing.GroupLayout.PREFERRED_SIZE, 37, javax.swing.GroupLayout.PREFERRED_SIZE))
            .addGroup(statusPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addGroup(statusPanelLayout.createSequentialGroup()
                    .addGap(135, 135, 135)
                    .addComponent(statusMessageLabel)
                    .addContainerGap(983, Short.MAX_VALUE)))
        );
        statusPanelLayout.setVerticalGroup(
            statusPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(statusPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING, false)
                .addComponent(statusAnimationLabel, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addComponent(progressBar, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
            .addGroup(statusPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addGroup(statusPanelLayout.createSequentialGroup()
                    .addContainerGap()
                    .addComponent(statusMessageLabel)
                    .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)))
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

        listItemPanel.setName("listItemPanel"); // NOI18N

        jLabel3.setText(resourceMap.getString("jLabel3.text")); // NOI18N
        jLabel3.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(0, 0, 0)));
        jLabel3.setName("jLabel3"); // NOI18N

        listItemLabel1.setFont(resourceMap.getFont("listItemLabel1.font")); // NOI18N
        listItemLabel1.setText(resourceMap.getString("listItemLabel1.text")); // NOI18N
        listItemLabel1.setName("listItemLabel1"); // NOI18N

        listItemLabel2.setText(resourceMap.getString("listItemLabel2.text")); // NOI18N
        listItemLabel2.setName("listItemLabel2"); // NOI18N

        javax.swing.GroupLayout listItemPanelLayout = new javax.swing.GroupLayout(listItemPanel);
        listItemPanel.setLayout(listItemPanelLayout);
        listItemPanelLayout.setHorizontalGroup(
            listItemPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(listItemPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jLabel3)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(listItemPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(listItemLabel1, javax.swing.GroupLayout.DEFAULT_SIZE, 254, Short.MAX_VALUE)
                    .addComponent(listItemLabel2, javax.swing.GroupLayout.DEFAULT_SIZE, 254, Short.MAX_VALUE))
                .addContainerGap())
        );
        listItemPanelLayout.setVerticalGroup(
            listItemPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(listItemPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(listItemPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(listItemPanelLayout.createSequentialGroup()
                        .addComponent(listItemLabel1)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 7, Short.MAX_VALUE)
                        .addComponent(listItemLabel2))
                    .addComponent(jLabel3, javax.swing.GroupLayout.DEFAULT_SIZE, 37, Short.MAX_VALUE))
                .addContainerGap())
        );

        setComponent(mainPanel);
        setMenuBar(menuBar);
        setStatusBar(statusPanel);
        setToolBar(jToolBar1);
    }// </editor-fold>//GEN-END:initComponents

    private void addButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_addButtonActionPerformed

        editPropertyTextField.setText("");
        editPropertyTextField.setEditable(true);
        editPropertyValueTextArea.setText("");

        final int res = JOptionPane.showConfirmDialog(getFrame(), editPanel,
                "Add property", JOptionPane.OK_CANCEL_OPTION,
                JOptionPane.PLAIN_MESSAGE);
        if (res == JOptionPane.OK_OPTION) {
            int workerId = selectedWorker.getWorkerId();


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

        final int row = configurationTable.getSelectedRow();

        if (row != -1) {

            final String oldPropertyName =
                    (String) configurationTable.getValueAt(row, 0);

            editPropertyTextField.setText(oldPropertyName);
            editPropertyTextField.setEditable(true);
            editPropertyValueTextArea.setText(
                    (String) configurationTable.getValueAt(row, 1));

            final int res = JOptionPane.showConfirmDialog(getFrame(), editPanel,
                    "Edit property", JOptionPane.OK_CANCEL_OPTION,
                    JOptionPane.PLAIN_MESSAGE);
            if (res == JOptionPane.OK_OPTION) {
                final int workerId = selectedWorker.getWorkerId();
                final String newPropertyName = editPropertyTextField.getText();

                if (!oldPropertyName.equals(newPropertyName)) {
                    SignServerAdminGUIApplication.getWorkerSession()
                            .removeWorkerProperty(workerId, oldPropertyName);
                }
                
                SignServerAdminGUIApplication.getWorkerSession()
                        .setWorkerProperty(workerId,
                        newPropertyName,
                        editPropertyValueTextArea.getText());
                SignServerAdminGUIApplication.getWorkerSession()
                        .reloadConfiguration(workerId);

                refreshButton.doClick();
            }
        }
}//GEN-LAST:event_editButtonActionPerformed

    private void removeButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_removeButtonActionPerformed
        final int row = configurationTable.getSelectedRow();

        if (row != -1) {
            final int res = JOptionPane.showConfirmDialog(getFrame(),
                    "Are you sure you want to remove the property?",
                    "Remove property", JOptionPane.YES_NO_CANCEL_OPTION,
                    JOptionPane.QUESTION_MESSAGE);
            if (res == JOptionPane.YES_OPTION) {
                int workerId = selectedWorker.getWorkerId();
                SignServerAdminGUIApplication.getWorkerSession()
                        .removeWorkerProperty(workerId,
                        editPropertyTextField.getText());
                SignServerAdminGUIApplication.getWorkerSession()
                        .reloadConfiguration(workerId);

                refreshButton.doClick();
            }
        }
}//GEN-LAST:event_removeButtonActionPerformed


    private void displayWorker(final Worker worker) {
        System.out.println("Display worker: " + worker);
        selectedWorker = worker;
        
        jList2.setEnabled(worker != null);
        statusSummaryTextPane.setEnabled(worker != null);
        propertiesTable.setEnabled(worker != null);

        if (worker == null) {
            statusSummaryTextPane.setText("");
            propertiesTable.setModel(new DefaultTableModel(
                new Object[][]{}, statusColumns) {

                @Override
                public boolean isCellEditable(int row, int column) {
                    return false;
                }

            });
        } else {
            statusSummaryTextPane.setText(worker.getStatusSummary());
            statusSummaryTextPane.setCaretPosition(0);

            propertiesTable.setModel(new DefaultTableModel(
                worker.getStatusProperties(), statusColumns) {

                @Override
                public boolean isCellEditable(int row, int column) {
                    return false;
                }

            });

             configurationTable.setModel(new DefaultTableModel(
                worker.getConfigurationProperties(), statusColumns) {

                @Override
                public boolean isCellEditable(int row, int column) {
                    return false;
                }

            });
        }

    }

    @Action(block = Task.BlockingScope.WINDOW)
    public Task refreshWorkers() {
        return new RefreshWorkersTask(getApplication());
    }

    private class RefreshWorkersTask extends org.jdesktop.application.Task<Object, Void> {
        RefreshWorkersTask(org.jdesktop.application.Application app) {
            // Runs on the EDT.  Copy GUI state that
            // doInBackground() depends on from parameters
            // to RefreshWorkersTask fields, here.
            super(app);

//            workersList.clear();
//
//            List<Integer> workerIds = SignServerAdminGUIApplication
//                .getGlobalConfigurationSession()
//                .getWorkers(GlobalConfiguration.WORKERTYPE_ALL);
//            for (Integer workerId : workerIds) {
//
//                final Vector<Object> workerInfo = new Vector<Object>();
//                final WorkerConfig config = SignServerAdminGUIApplication
//                        .getWorkerSession().getCurrentWorkerConfig(workerId);
//                final String name = config.getProperty("NAME");
//
//                try {
//                    final WorkerStatus status = SignServerAdminGUIApplication
//                    .getWorkerSession()
//                    .getStatus(workerId);
//
//                    workerInfo.add(status.isOK() == null ? "OK" : status.isOK());
//                } catch(InvalidWorkerIdException ex) {
//                    workerInfo.add("Invalid");
//                }
//
//                workerInfo.add(workerId);
//                workerInfo.add(name);
//
//                System.out.println("workerId: " + workerId);
//                System.out.println("name: " + name);
//
//                workersList.add(workerInfo);
//
//                jTable1.revalidate();
//
//                workersModel.fireTableDataChanged();

            selectedWorkerBeforeRefresh = (Worker) jList2.getSelectedItem();

//            }
        }
        @Override protected Object doInBackground() {
            // Your Task's code here.  This method runs
            // on a background thread, so don't reference
            // the Swing GUI from here.

            List<Worker> newSigners = new ArrayList<Worker>();

             List<Integer> workerIds = SignServerAdminGUIApplication
                .getGlobalConfigurationSession()
                .getWorkers(GlobalConfiguration.WORKERTYPE_ALL);
            for (Integer workerId : workerIds) {

                final Vector<Object> workerInfo = new Vector<Object>();
                final WorkerConfig config = SignServerAdminGUIApplication
                        .getWorkerSession().getCurrentWorkerConfig(workerId);
                final String name = config.getProperty("NAME");

                try {
                    final WorkerStatus status = SignServerAdminGUIApplication
                    .getWorkerSession()
                    .getStatus(workerId);

                    workerInfo.add(status.isOK() == null ? "OK" : status.isOK());
                } catch(InvalidWorkerIdException ex) {
                    workerInfo.add("Invalid");
                }

                workerInfo.add(workerId);
                workerInfo.add(name);

                System.out.println("workerId: " + workerId);
                System.out.println("name: " + name);

                // Configuration
                Set<Entry<Object, Object>> entries
                        = config.getProperties().entrySet();
                Object[][] configProperties = new Object[entries.size()][];
                int j = 0;
                for (Entry<Object, Object> entry : entries) {
                    configProperties[j] = new String[2];
                    configProperties[j][0] = (String) entry.getKey();
                    configProperties[j][1] = (String) entry.getValue();
//                    System.out.println("Value: \"" + entry.getValue() + "\"");
                    j++;
                }

                // Status
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                String statusSummary;

                String tokenStatus;
                WorkerStatus status = null;
                boolean active = false;
                try {
                    status = SignServerAdminGUIApplication.getWorkerSession()
                            .getStatus(workerId);
                    status.displayStatus(workerId,
                            new PrintStream(out), true);
                    statusSummary = out.toString();
                    tokenStatus = status.isOK() == null ? "ACTIVE" : "OFFLINE";
                    active = status.isOK() == null;
                } catch (InvalidWorkerIdException ex) {
                    statusSummary = "No such worker";
                    tokenStatus = "Unknown";
                }

                Date notBefore = null;
                Date notAfter = null;
                Certificate certificate = null;
                Collection<Certificate> certificateChain = null;

                Object[][] statusProperties = new Object[][] {
                    {"ID", workerId},
                    {"Name", name},
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
                    try {
                        certificateChain = SignServerAdminGUIApplication
                            .getWorkerSession()
                            .getSignerCertificateChain(workerId);
                    } catch (EJBException ex) {
                        // Handle problem caused by bug in server
                        LOG.error("Error getting signer certificate chain",
                                ex);
                        certificateChain = Collections.emptyList();
                    }

                    statusProperties[3] = new Object[] {
                        "Validity not before:", notBefore
                    };
                    statusProperties[4] = new Object[] {
                        "Validity not after:", notAfter
                    };
                    statusProperties[5] = new Object[] {
                        "Signer certificate", certificate
                    };
                    statusProperties[6] = new Object[] {
                        "Certificate chain:", certificateChain
                    };

                } catch (CryptoTokenOfflineException ex) {
                    System.out.println("offline: " + workerId);
                }


                newSigners.add(new Worker(workerId, name, statusSummary,
                        statusProperties, configProperties, active));
            }

            return newSigners;  // return your result
        }
        @Override protected void succeeded(final Object result) {
            // Runs on the EDT.  Update the GUI based on
            // the result computed by doInBackground().
            final List<Worker> newWorkers = (List) result;

            // Save selection
            ArrayList<Integer> indices = new ArrayList<Integer>();
            System.out.println("Selected signers: " + selectedSigners);
            for (Worker w : selectedSigners) {
                int index = newWorkers.indexOf(w);
                if (index != -1) {
                    indices.add(index);
                } else {
                    System.out.println(w + " is not in " + selectedSigners);
                }
            }
            int[] ints = new int[indices.size()];
            for (int i = 0; i < indices.size(); i++) {
                ints[i] = indices.get(i);
            }

            jList1.revalidate();
            jList2.revalidate();
            System.out.println("signers size: " + signers.size());
            jList1.setModel(new AbstractListModel() {

                @Override
                public int getSize() {
                    return newWorkers.size();
                }

                @Override
                public Object getElementAt(int index) {
                    return newWorkers.get(index);
                }
            });

            // New selection
            jList1.setSelectedIndices(ints);
            System.out.println("Selecting: " + Arrays.toString(ints));

            signers = newWorkers;
        }
    }

    @Action
    public void showStatuses() {
//        final int[] selected = jTable1.getSelectedRows();
//
//        final int[] workerIds = new int[selected.length];
//
//        for (int i = 0; i < selected.length; i++) {
//            workerIds[i] = (Integer) workersList.get(selected[i]).get(1);
//        }
//
//        if (selected.length > 0) {
//            getApplication().show(new WorkerStatusesView((SingleFrameApplication) this.getApplication(), workerIds));
//        }
    }

        @Action()
    public void activateWorkers() {
        final int[] selected = jList1.getSelectedIndices();

        for (int row : selected) {
            final String workerName = signers.get(row).getName();
            final int workerId = signers.get(row).getWorkerId();
            try {
                SignServerAdminGUIApplication.getWorkerSession()
                        .activateSigner(workerId, "");
            } catch (CryptoTokenAuthenticationFailureException ex) {
                final String error =
                        "Authentication failure activating worker "
                        + workerId;
                JOptionPane.showMessageDialog(getFrame(), 
                        error + ":\n" + ex.getMessage(),
                        "Activate workers", JOptionPane.ERROR_MESSAGE);
                LOG.error(error, ex);
            } catch (CryptoTokenOfflineException ex) {
                final String error =
                        "Crypto token offline failure activating worker "
                        + workerId;
                JOptionPane.showMessageDialog(getFrame(),
                        error + ":\n" + ex.getMessage(),
                        "Activate workers", JOptionPane.ERROR_MESSAGE);
                LOG.error(error, ex);
            } catch (InvalidWorkerIdException ex) {
                final String error =
                        "Invalid worker activating worker "
                        + workerId;
                JOptionPane.showMessageDialog(getFrame(),
                        error + ":\n" + ex.getMessage(),
                        "Activate workers", JOptionPane.ERROR_MESSAGE);
                LOG.error(error, ex);
            }
        }
        getContext().getTaskService().execute(refreshWorkers());
    }

    @Action
    public void deactivateWorkers() {
        final int[] selected = jList1.getSelectedIndices();

        for (int row : selected) {
            final int workerId = signers.get(row).getWorkerId();
            try {
                SignServerAdminGUIApplication.getWorkerSession()
                        .deactivateSigner(workerId);
            } catch (CryptoTokenOfflineException ex) {
                LOG.error("Error deactivating worker " + workerId, ex);
            } catch (InvalidWorkerIdException ex) {
                LOG.error("Error deactivating worker " + workerId, ex);
            }
        }
        getContext().getTaskService().execute(refreshWorkers());
    }

    @Action
    public void generateRequests() {
        final int[] selected = jList1.getSelectedIndices();
        final List<Integer> signerIds = new ArrayList<Integer>();
        final List<String> signerNames = new ArrayList<String>();

        for (int row : selected) {
            // TODO: check that the worker is a signer

            signerIds.add((Integer) signers.get(row).getWorkerId());
            signerNames.add(signers.get(row).getName());
        }

        if (selected.length > 0) {
            getApplication().show(new GenerateRequestsView((SingleFrameApplication) this.getApplication(), signerIds.toArray(new Integer[0]), signerNames.toArray(new String[0])));
        }
    }

    private boolean isWorkersSelected = false;
    public boolean isIsWorkersSelected() {
        return isWorkersSelected;
    }

    public void setIsWorkersSelected(boolean b) {
        boolean old = isIsWorkersSelected();
        this.isWorkersSelected = b;
        firePropertyChange("isWorkersSelected", old, isIsWorkersSelected());
    }

    @Action
    public void installCertificates() {
        final int[] selected = jList1.getSelectedIndices();
        final List<Integer> signerIds = new ArrayList<Integer>();
        final List<String> signerNames = new ArrayList<String>();

        for (int row : selected) {
            final String workerName = signers.get(row).getName();
            final Integer workerId = signers.get(row).getWorkerId();

            // TODO: check that the worker is a signer

            signerIds.add((Integer) workerId);
            signerNames.add((String) workerName);
        }

        if (selected.length > 0) {
            getApplication().show(new InstallCertificatesView(
                    (SingleFrameApplication) this.getApplication(), this,
                    signerIds.toArray(new Integer[0]),
                    signerNames.toArray(new String[0])));
        }
    }

    @Action
    public void viewAuthorizations() {
//        final int[] selected = jTable1.getSelectedRows();
//
//        final int[] workerIds = new int[selected.length];
//
//        for (int i = 0; i < selected.length; i++) {
//            workerIds[i] = (Integer) workersList.get(selected[i]).get(1);
//        }
//
//        if (selected.length > 0) {
//            getApplication().show(new WorkerAuthorizationView((SingleFrameApplication) this.getApplication(), workerIds));
//        }
    }

    @Action
    public void showConfiguration() {
//        final int[] selected = jTable1.getSelectedRows();
//
//        final int[] workerIds = new int[selected.length];
//
//        for (int i = 0; i < selected.length; i++) {
//            workerIds[i] = (Integer) workersList.get(selected[i]).get(1);
//        }
//
//        if (selected.length > 0) {
//            getApplication().show(new WorkerConfigurationView((SingleFrameApplication) this.getApplication(), workerIds));
//        }
    }

    private static class MyComboBoxModel extends AbstractListModel implements ComboBoxModel {

        private List<Worker> signers;
        private Worker selected;

        private MyComboBoxModel(List<Worker> signers) {
            this.signers = signers;
        }

        @Override
        public int getSize() {
            return signers.size();
        }

        @Override
        public Object getElementAt(int index) {
            return signers.get(index);
        }

        @Override
        public void setSelectedItem(Object anItem) {
            if (anItem instanceof Worker) {
                selected = (Worker) anItem;
            } else {
                selected = null;
            }
        }

        @Override
        public Object getSelectedItem() {
            return selected;
        }

    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton activateButton;
    private javax.swing.JMenuItem activateMenu;
    private javax.swing.JButton addButton;
    private javax.swing.JButton authAddButton;
    private javax.swing.JButton authEditButton;
    private javax.swing.JTable authTable;
    private javax.swing.JMenuItem authorizationsMenu;
    private javax.swing.JMenuItem configurationMenu;
    private javax.swing.JTable configurationTable;
    private javax.swing.JButton deactivateButton;
    private javax.swing.JMenuItem deactivateMenu;
    private javax.swing.JButton editButton;
    private javax.swing.JMenu editMenu;
    private javax.swing.JPanel editPanel;
    private javax.swing.JTextField editPropertyTextField;
    private javax.swing.JTextArea editPropertyValueTextArea;
    private javax.swing.JMenuItem generateRequestMenu;
    private javax.swing.JButton generateRequestsButton;
    private javax.swing.JButton installCertificatesButton;
    private javax.swing.JMenuItem installCertificatesMenu;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JList jList1;
    private javax.swing.JComboBox jList2;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JPanel jPanel2;
    private javax.swing.JPanel jPanel3;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JScrollPane jScrollPane4;
    private javax.swing.JScrollPane jScrollPane5;
    private javax.swing.JScrollPane jScrollPane6;
    private javax.swing.JScrollPane jScrollPane7;
    private javax.swing.JToolBar.Separator jSeparator1;
    private javax.swing.JToolBar.Separator jSeparator2;
    private javax.swing.JSplitPane jSplitPane1;
    private javax.swing.JTabbedPane jTabbedPane1;
    private javax.swing.JToolBar jToolBar1;
    private javax.swing.JLabel listItemLabel1;
    private javax.swing.JLabel listItemLabel2;
    private javax.swing.JPanel listItemPanel;
    private javax.swing.JPanel mainPanel;
    private javax.swing.JMenuBar menuBar;
    private javax.swing.JProgressBar progressBar;
    private javax.swing.JTable propertiesTable;
    private javax.swing.JButton refreshButton;
    private javax.swing.JMenuItem refreshMenu;
    private javax.swing.JButton removeButton;
    private javax.swing.JButton removeButton1;
    private javax.swing.JLabel statusAnimationLabel;
    private javax.swing.JMenuItem statusMenu;
    private javax.swing.JLabel statusMessageLabel;
    private javax.swing.JPanel statusPanel;
    private javax.swing.JTextPane statusSummaryTextPane;
    private javax.swing.JMenu viewMenu;
    // End of variables declaration//GEN-END:variables

    private final Timer messageTimer;
    private final Timer busyIconTimer;
    private final Icon idleIcon;
    private final Icon[] busyIcons = new Icon[15];
    private int busyIconIndex = 0;

    private JDialog aboutBox;
}
