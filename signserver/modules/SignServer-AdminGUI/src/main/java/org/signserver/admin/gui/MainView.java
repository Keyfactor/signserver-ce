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

import java.awt.CardLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Map.Entry;
import java.util.Properties;
import java.util.ResourceBundle;
import java.util.Set;
import java.util.Vector;
import javax.ejb.EJBException;
import javax.swing.AbstractListModel;
import javax.swing.ComboBoxModel;
import javax.swing.Icon;
import javax.swing.JDialog;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.SwingUtilities;
import javax.swing.Timer;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.DefaultTableModel;
import javax.xml.datatype.XMLGregorianCalendar;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.audit.impl.integrityprotected.AuditRecordData;
import org.ejbca.util.CertTools;
import org.jdesktop.application.Action;
import org.jdesktop.application.Application;
import org.jdesktop.application.FrameView;
import org.jdesktop.application.ResourceMap;
import org.jdesktop.application.SingleFrameApplication;
import org.jdesktop.application.Task;
import org.jdesktop.application.TaskMonitor;
import org.signserver.admin.gui.adminws.gen.AdminNotAuthorizedException_Exception;
import org.signserver.admin.gui.adminws.gen.AuthorizedClient;
import org.signserver.admin.gui.adminws.gen.CryptoTokenAuthenticationFailureException_Exception;
import org.signserver.admin.gui.adminws.gen.CryptoTokenOfflineException_Exception;
import org.signserver.admin.gui.adminws.gen.InvalidWorkerIdException_Exception;
import org.signserver.admin.gui.adminws.gen.KeyStoreException_Exception;
import org.signserver.admin.gui.adminws.gen.LogEntry;
import org.signserver.admin.gui.adminws.gen.Order;
import org.signserver.admin.gui.adminws.gen.QueryCondition;
import org.signserver.admin.gui.adminws.gen.QueryOrdering;
import org.signserver.admin.gui.adminws.gen.RelationalOperator;
import org.signserver.admin.gui.adminws.gen.SignServerException_Exception;
import org.signserver.admin.gui.adminws.gen.WsGlobalConfiguration;
import org.signserver.admin.gui.adminws.gen.WsWorkerConfig;
import org.signserver.admin.gui.adminws.gen.WsWorkerStatus;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.util.PropertiesDumper;

/**
 * The application's main frame.
 *
 * @author Markus Kilås
 * @version $Id$
 */
@SuppressWarnings("PMD.UnusedFormalParameter")
public class MainView extends FrameView {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(MainView.class);

    private ResourceBundle texts = ResourceBundle.getBundle("org/signserver/admin/gui/resources/SignServerAdminGUIApplication");
    
    private List<Worker> allWorkers = new ArrayList<Worker>();
    private List<Worker> selectedWorkers = new ArrayList<Worker>();
    private Worker selectedWorker;
    private Worker selectedWorkerBeforeRefresh;
    
    // holds a list of modified workers after running the add worker wizard
    // is used by the refresh background task to select these workers
    private List<Integer> modifiedWorkers = null;
    
    private AuditlogTableModel auditlogModel = new AuditlogTableModel();
    private ConditionsTableModel conditionsModel = new ConditionsTableModel();
    
    /**
     * The value of exportAllUnrelatedCheckbox before user selects "No workers"
     * and it is automagically selected. Stored so we can go back to the 
     * previous value.
     */
    private boolean exportAllUnrelatedPreviousValue;
    
    private static String[] statusColumns = {
        "Property", "Value"
    };

    private static String[] authColumns = new String[] {
        "Certificate serial number",
        "Issuer DN"
    };

    public MainView(SingleFrameApplication app) {
        super(app);

        initComponents();
        
        conditionsModel.addCondition(AuditRecordData.FIELD_EVENTTYPE, RelationalOperator.NEQ, "ACCESS_CONTROL");
        auditLogTable.setModel(auditlogModel);
        conditionsTable.setModel(conditionsModel);
        conditionsTable.getSelectionModel().addListSelectionListener(new ListSelectionListener() {

            @Override
            public void valueChanged(ListSelectionEvent e) {
                if (!e.getValueIsAdjusting()) {
                    jButtonAuditConditionRemove.setEnabled(conditionsTable.getSelectedRowCount() > 0);
                }
            }
        });
        jTabbedPane1.setSelectedComponent(mainPanel);

        workersList.setCellRenderer(new MyListCellRenderer());

        workersList.getSelectionModel().addListSelectionListener(
                new ListSelectionListener() {

            @Override
            public void valueChanged(final ListSelectionEvent evt) {
                if (!evt.getValueIsAdjusting()) {
                    selectedWorkers = new ArrayList<Worker>();

                    for(Object o : workersList.getSelectedValues()) {
                        if (o instanceof Worker) {
                            selectedWorkers.add((Worker) o);
                        }
                    }

                    workerComboBox.setModel(new MyComboBoxModel(selectedWorkers));
                    
                    // removeKey should only be enabled iff one selected
                    removeKeyMenu.setEnabled(selectedWorkers.size() == 1);
                    
                    if (selectedWorkers.size() > 0) {

                        if (LOG.isDebugEnabled()) {
                            LOG.debug("Previously selected: "
                                + selectedWorkerBeforeRefresh);
                        }

                        int comboBoxSelection = 0;

                        // Try to set the previously selected
                        if (selectedWorkerBeforeRefresh != null) {
                            comboBoxSelection = selectedWorkers
                                .indexOf(selectedWorkerBeforeRefresh);
                            if (comboBoxSelection == -1) {
                                comboBoxSelection = 0;
                            }
                        }
                        workerComboBox.setSelectedIndex(comboBoxSelection);
                    } else {
                        displayWorker(null);
                    }
                }
            }
        });

        workerComboBox.setRenderer(new SmallWorkerListCellRenderer(
                getResourceMap().getIcon("worker.smallIcon")));

        workerComboBox.addActionListener(new ActionListener() {

            @Override
            public void actionPerformed(final ActionEvent e) {
                if (workerComboBox.getSelectedItem() instanceof Worker) {
                    displayWorker((Worker) workerComboBox.getSelectedItem());
                }
            }
        });

        propertiesTable.getSelectionModel().addListSelectionListener(
                new ListSelectionListener() {

            @Override
            public void valueChanged(final ListSelectionEvent e) {
                if (!e.getValueIsAdjusting()) {

                    final int row = propertiesTable.getSelectedRow();
                    final boolean enable;

                    if (row == -1) {
                        enable = false;
                    } else {
                        final Object o = propertiesTable.getValueAt(row, 1);
                        enable = o instanceof X509Certificate
                                || o instanceof Collection; // TODO: Too weak
                    }
                    statusPropertiesDetailsButton.setEnabled(enable);
                }
            }
        });

        configurationTable.getSelectionModel().addListSelectionListener(
                new ListSelectionListener() {

            @Override
            public void valueChanged(final ListSelectionEvent e) {
                if (!e.getValueIsAdjusting()) {
                    final boolean enable
                            = configurationTable.getSelectedRowCount() == 1;
                    editButton.setEnabled(enable);
                    removeButton.setEnabled(enable);
                }
            }
        });

        authTable.getSelectionModel().addListSelectionListener(
                new ListSelectionListener() {

            @Override
            public void valueChanged(final ListSelectionEvent e) {
                if (!e.getValueIsAdjusting()) {
                    final boolean enable
                            = authTable.getSelectedRowCount() == 1;
                    authEditButton.setEnabled(enable);
                    authRemoveButton.setEnabled(enable);
                }
            }
        });

        displayWorker(null);

        // status bar initialization - message timeout, idle icon and busy
        // animation, etc
        ResourceMap resourceMap = getResourceMap();
        int messageTimeout = resourceMap.getInteger("StatusBar.messageTimeout");
        messageTimer = new Timer(messageTimeout, new ActionListener() {
            
            @Override
            public void actionPerformed(ActionEvent e) {
                statusMessageLabel.setText("");
            }
        });
        messageTimer.setRepeats(false);
        int busyAnimationRate = resourceMap.getInteger(
                "StatusBar.busyAnimationRate");
        for (int i = 0; i < busyIcons.length; i++) {
            busyIcons[i] = resourceMap.getIcon(
                    "StatusBar.busyIcons[" + i + "]");
        }
        busyIconTimer = new Timer(busyAnimationRate, new ActionListener() {
            
            @Override
            public void actionPerformed(ActionEvent e) {
                busyIconIndex = (busyIconIndex + 1) % busyIcons.length;
                statusAnimationLabel.setIcon(busyIcons[busyIconIndex]);
            }
        });
        idleIcon = resourceMap.getIcon("StatusBar.idleIcon");
        statusAnimationLabel.setIcon(idleIcon);
        progressBar.setVisible(false);

        // connecting action tasks to status bar via TaskMonitor
        TaskMonitor taskMonitor = new TaskMonitor(
                getApplication().getContext());
        taskMonitor.addPropertyChangeListener(new PropertyChangeListener() {
            
            @Override
            public void propertyChange(PropertyChangeEvent evt) {
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
                    String text = (String) evt.getNewValue();
                    statusMessageLabel.setText((text == null) ? "" : text);
                    messageTimer.restart();
                } else if ("progress".equals(propertyName)) {
                    int value = (Integer) evt.getNewValue();
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
            final JFrame mainFrame = SignServerAdminGUIApplication
                    .getApplication().getMainFrame();
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

        menuBar = new javax.swing.JMenuBar();
        javax.swing.JMenu fileMenu = new javax.swing.JMenu();
        addWorkerItem = new javax.swing.JMenuItem();
        exportMenuItem = new javax.swing.JMenuItem();
        javax.swing.JMenuItem exitMenuItem = new javax.swing.JMenuItem();
        editMenu = new javax.swing.JMenu();
        activateMenu = new javax.swing.JMenuItem();
        deactivateMenu = new javax.swing.JMenuItem();
        jSeparator7 = new javax.swing.JPopupMenu.Separator();
        renewKeyMenu = new javax.swing.JMenuItem();
        testKeyMenu = new javax.swing.JMenuItem();
        generateRequestMenu = new javax.swing.JMenuItem();
        installCertificatesMenu = new javax.swing.JMenuItem();
        jSeparator5 = new javax.swing.JPopupMenu.Separator();
        renewSignerMenu = new javax.swing.JMenuItem();
        removeKeyMenu = new javax.swing.JMenuItem();
        jSeparator8 = new javax.swing.JPopupMenu.Separator();
        removeWorkerMenu = new javax.swing.JMenuItem();
        jSeparator9 = new javax.swing.JPopupMenu.Separator();
        reloadMenu = new javax.swing.JMenuItem();
        globalConfigurationMenu = new javax.swing.JMenuItem();
        administratorsMenu = new javax.swing.JMenuItem();
        viewMenu = new javax.swing.JMenu();
        refreshMenu = new javax.swing.JMenuItem();
        jSeparator4 = new javax.swing.JPopupMenu.Separator();
        statusSummaryMenu = new javax.swing.JMenuItem();
        statusPropertiesMenu = new javax.swing.JMenuItem();
        configurationMenu = new javax.swing.JMenuItem();
        authorizationsMenu = new javax.swing.JMenuItem();
        jSeparator3 = new javax.swing.JPopupMenu.Separator();
        javax.swing.JMenu helpMenu = new javax.swing.JMenu();
        javax.swing.JMenuItem aboutMenuItem = new javax.swing.JMenuItem();
        jToolBar1 = new javax.swing.JToolBar();
        refreshButton = new javax.swing.JButton();
        jSeparator1 = new javax.swing.JToolBar.Separator();
        activateButton = new javax.swing.JButton();
        deactivateButton = new javax.swing.JButton();
        jSeparator2 = new javax.swing.JToolBar.Separator();
        renewKeyButton = new javax.swing.JButton();
        testKeyButton = new javax.swing.JButton();
        generateRequestsButton = new javax.swing.JButton();
        installCertificatesButton = new javax.swing.JButton();
        jSeparator6 = new javax.swing.JToolBar.Separator();
        renewSignerButton = new javax.swing.JButton();
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
        authEditPanel = new javax.swing.JPanel();
        jLabel4 = new javax.swing.JLabel();
        editSerialNumberTextfield = new javax.swing.JTextField();
        jLabel5 = new javax.swing.JLabel();
        editIssuerDNTextfield = new javax.swing.JTextField();
        editUpdateAllCheckbox = new javax.swing.JCheckBox();
        loadCertButton = new javax.swing.JButton();
        passwordPanel = new javax.swing.JPanel();
        passwordPanelLabel = new javax.swing.JLabel();
        passwordPanelField = new javax.swing.JPasswordField();
        jTabbedPane1 = new javax.swing.JTabbedPane();
        mainPanel = new javax.swing.JPanel();
        jSplitPane1 = new javax.swing.JSplitPane();
        jScrollPane2 = new javax.swing.JScrollPane();
        workersList = new javax.swing.JList();
        jPanel1 = new javax.swing.JPanel();
        workerComboBox = new javax.swing.JComboBox();
        workerTabbedPane = new javax.swing.JTabbedPane();
        statusSummaryTab = new javax.swing.JScrollPane();
        statusSummaryTextPane = new javax.swing.JTextPane();
        statusPropertiesTab = new javax.swing.JPanel();
        statusPropertiesScrollPane = new javax.swing.JScrollPane();
        propertiesTable = new javax.swing.JTable();
        statusPropertiesDetailsButton = new javax.swing.JButton();
        configurationTab = new javax.swing.JPanel();
        jScrollPane6 = new javax.swing.JScrollPane();
        configurationTable = new javax.swing.JTable();
        addButton = new javax.swing.JButton();
        editButton = new javax.swing.JButton();
        removeButton = new javax.swing.JButton();
        authorizationTab = new javax.swing.JPanel();
        jScrollPane7 = new javax.swing.JScrollPane();
        authTable = new javax.swing.JTable();
        authAddButton = new javax.swing.JButton();
        authEditButton = new javax.swing.JButton();
        authRemoveButton = new javax.swing.JButton();
        auditPanel = new javax.swing.JPanel();
        jSplitPane2 = new javax.swing.JSplitPane();
        jPanel2 = new javax.swing.JPanel();
        jLabel3 = new javax.swing.JLabel();
        jScrollPane3 = new javax.swing.JScrollPane();
        conditionsTable = new javax.swing.JTable();
        jButtonAuditConditionAdd = new javax.swing.JButton();
        jButtonAuditConditionRemove = new javax.swing.JButton();
        jPanel3 = new javax.swing.JPanel();
        auditlogFirstButton = new javax.swing.JButton();
        auditlogPreviousButton = new javax.swing.JButton();
        auditlogReloadButton = new javax.swing.JButton();
        auditlogNextButton = new javax.swing.JButton();
        jLabel6 = new javax.swing.JLabel();
        auditlogStartIndexTextfield = new javax.swing.JTextField();
        auditlogDisplayingToIndex = new javax.swing.JLabel();
        jLabel8 = new javax.swing.JLabel();
        auditlogMaxEntriesTextfield = new javax.swing.JTextField();
        auditlogPanel = new javax.swing.JPanel();
        auditlogTablePanel = new javax.swing.JPanel();
        auditlogTableScrollPane = new javax.swing.JScrollPane();
        auditLogTable = new javax.swing.JTable();
        auditlogErrorPanel = new javax.swing.JPanel();
        jScrollPane5 = new javax.swing.JScrollPane();
        auditlogErrorEditor = new javax.swing.JEditorPane();
        removeKeyPanel = new javax.swing.JPanel();
        jLabel7 = new javax.swing.JLabel();
        aliasTextField = new javax.swing.JTextField();
        reloadPanel = new javax.swing.JPanel();
        jEditorPane1 = new javax.swing.JEditorPane();
        reloadAllWorkersRadioButton = new javax.swing.JRadioButton();
        reloadSelectedWorkersRadioButton = new javax.swing.JRadioButton();
        jLabel9 = new javax.swing.JLabel();
        reloadPanelButtonGroup = new javax.swing.ButtonGroup();
        exportPanel = new javax.swing.JPanel();
        jLabel10 = new javax.swing.JLabel();
        exportAllRadioButton = new javax.swing.JRadioButton();
        exportSelectedRadioButton = new javax.swing.JRadioButton();
        exportNoRadioButton = new javax.swing.JRadioButton();
        exportAllUnrelatedGlobalCheckbox = new javax.swing.JCheckBox();
        exportPanelButtonGroup = new javax.swing.ButtonGroup();

        menuBar.setName("menuBar"); // NOI18N

        fileMenu.setMnemonic('F');
        org.jdesktop.application.ResourceMap resourceMap = org.jdesktop.application.Application.getInstance(org.signserver.admin.gui.SignServerAdminGUIApplication.class).getContext().getResourceMap(MainView.class);
        fileMenu.setText(resourceMap.getString("fileMenu.text")); // NOI18N
        fileMenu.setName("fileMenu"); // NOI18N

        addWorkerItem.setText(resourceMap.getString("addWorkerItem.text")); // NOI18N
        addWorkerItem.setName("addWorkerItem"); // NOI18N
        addWorkerItem.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                addWorkerItemActionPerformed(evt);
            }
        });
        fileMenu.add(addWorkerItem);

        javax.swing.ActionMap actionMap = org.jdesktop.application.Application.getInstance(org.signserver.admin.gui.SignServerAdminGUIApplication.class).getContext().getActionMap(MainView.class, this);
        exportMenuItem.setAction(actionMap.get("exportConfig")); // NOI18N
        exportMenuItem.setText(resourceMap.getString("exportMenuItem.text")); // NOI18N
        exportMenuItem.setName("exportMenuItem"); // NOI18N
        fileMenu.add(exportMenuItem);

        exitMenuItem.setAction(actionMap.get("quit")); // NOI18N
        exitMenuItem.setName("exitMenuItem"); // NOI18N
        fileMenu.add(exitMenuItem);

        menuBar.add(fileMenu);

        editMenu.setAction(actionMap.get("testKeys")); // NOI18N
        editMenu.setText(resourceMap.getString("editMenu.text")); // NOI18N
        editMenu.setName("editMenu"); // NOI18N

        activateMenu.setAction(actionMap.get("removeWorkers")); // NOI18N
        activateMenu.setText(resourceMap.getString("activateMenu.text")); // NOI18N
        activateMenu.setName("activateMenu"); // NOI18N
        editMenu.add(activateMenu);

        deactivateMenu.setAction(actionMap.get("deactivateWorkers")); // NOI18N
        deactivateMenu.setText(resourceMap.getString("deactivateMenu.text")); // NOI18N
        deactivateMenu.setName("deactivateMenu"); // NOI18N
        editMenu.add(deactivateMenu);

        jSeparator7.setName("jSeparator7"); // NOI18N
        editMenu.add(jSeparator7);

        renewKeyMenu.setAction(actionMap.get("renewKeys")); // NOI18N
        renewKeyMenu.setText(resourceMap.getString("renewKeyMenu.text")); // NOI18N
        renewKeyMenu.setName("renewKeyMenu"); // NOI18N
        editMenu.add(renewKeyMenu);

        testKeyMenu.setAction(actionMap.get("testKeys")); // NOI18N
        testKeyMenu.setText(resourceMap.getString("testKeyMenu.text")); // NOI18N
        testKeyMenu.setName("testKeyMenu"); // NOI18N
        editMenu.add(testKeyMenu);

        generateRequestMenu.setAction(actionMap.get("generateRequests")); // NOI18N
        generateRequestMenu.setText(resourceMap.getString("generateRequestMenu.text")); // NOI18N
        generateRequestMenu.setName("generateRequestMenu"); // NOI18N
        editMenu.add(generateRequestMenu);

        installCertificatesMenu.setAction(actionMap.get("installCertificates")); // NOI18N
        installCertificatesMenu.setText(resourceMap.getString("installCertificatesMenu.text")); // NOI18N
        installCertificatesMenu.setName("installCertificatesMenu"); // NOI18N
        editMenu.add(installCertificatesMenu);

        jSeparator5.setName("jSeparator5"); // NOI18N
        editMenu.add(jSeparator5);

        renewSignerMenu.setAction(actionMap.get("renewSigner")); // NOI18N
        renewSignerMenu.setText(resourceMap.getString("renewSignerMenu.text")); // NOI18N
        renewSignerMenu.setName("renewSignerMenu"); // NOI18N
        editMenu.add(renewSignerMenu);

        removeKeyMenu.setAction(actionMap.get("removeKey")); // NOI18N
        removeKeyMenu.setText(resourceMap.getString("removeKeyMenu.text")); // NOI18N
        removeKeyMenu.setName("removeKeyMenu"); // NOI18N
        editMenu.add(removeKeyMenu);

        jSeparator8.setName("jSeparator8"); // NOI18N
        editMenu.add(jSeparator8);

        removeWorkerMenu.setAction(actionMap.get("removeWorkers")); // NOI18N
        removeWorkerMenu.setText(resourceMap.getString("removeWorkerMenu.text")); // NOI18N
        removeWorkerMenu.setName("removeWorkerMenu"); // NOI18N
        editMenu.add(removeWorkerMenu);

        jSeparator9.setName("jSeparator9"); // NOI18N
        editMenu.add(jSeparator9);

        reloadMenu.setAction(actionMap.get("reloadFromDatabase")); // NOI18N
        reloadMenu.setText(resourceMap.getString("reloadMenu.text")); // NOI18N
        reloadMenu.setName("reloadMenu"); // NOI18N
        editMenu.add(reloadMenu);

        globalConfigurationMenu.setMnemonic('G');
        globalConfigurationMenu.setText(resourceMap.getString("globalConfigurationMenu.text")); // NOI18N
        globalConfigurationMenu.setName("globalConfigurationMenu"); // NOI18N
        globalConfigurationMenu.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                globalConfigurationMenuActionPerformed(evt);
            }
        });
        editMenu.add(globalConfigurationMenu);

        administratorsMenu.setMnemonic('m');
        administratorsMenu.setText(resourceMap.getString("administratorsMenu.text")); // NOI18N
        administratorsMenu.setName("administratorsMenu"); // NOI18N
        administratorsMenu.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                administratorsMenuActionPerformed(evt);
            }
        });
        editMenu.add(administratorsMenu);

        menuBar.add(editMenu);

        viewMenu.setMnemonic('V');
        viewMenu.setText(resourceMap.getString("viewMenu.text")); // NOI18N
        viewMenu.setName("viewMenu"); // NOI18N

        refreshMenu.setAction(actionMap.get("refreshWorkers")); // NOI18N
        refreshMenu.setText(resourceMap.getString("refreshMenu.text")); // NOI18N
        refreshMenu.setName("refreshMenu"); // NOI18N
        viewMenu.add(refreshMenu);

        jSeparator4.setName("jSeparator4"); // NOI18N
        viewMenu.add(jSeparator4);

        statusSummaryMenu.setText(resourceMap.getString("statusSummaryMenu.text")); // NOI18N
        statusSummaryMenu.setName("statusSummaryMenu"); // NOI18N
        statusSummaryMenu.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                statusSummaryMenuActionPerformed(evt);
            }
        });
        viewMenu.add(statusSummaryMenu);

        statusPropertiesMenu.setText(resourceMap.getString("statusPropertiesMenu.text")); // NOI18N
        statusPropertiesMenu.setName("statusPropertiesMenu"); // NOI18N
        statusPropertiesMenu.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                statusPropertiesMenuActionPerformed(evt);
            }
        });
        viewMenu.add(statusPropertiesMenu);

        configurationMenu.setText(resourceMap.getString("configurationMenu.text")); // NOI18N
        configurationMenu.setName("configurationMenu"); // NOI18N
        configurationMenu.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                configurationMenuActionPerformed(evt);
            }
        });
        viewMenu.add(configurationMenu);

        authorizationsMenu.setText(resourceMap.getString("authorizationsMenu.text")); // NOI18N
        authorizationsMenu.setName("authorizationsMenu"); // NOI18N
        authorizationsMenu.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                authorizationsMenuActionPerformed(evt);
            }
        });
        viewMenu.add(authorizationsMenu);

        jSeparator3.setName("jSeparator3"); // NOI18N
        viewMenu.add(jSeparator3);

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

        renewKeyButton.setAction(actionMap.get("renewKeys")); // NOI18N
        renewKeyButton.setText(resourceMap.getString("renewKeyButton.text")); // NOI18N
        renewKeyButton.setFocusable(false);
        renewKeyButton.setHorizontalTextPosition(javax.swing.SwingConstants.CENTER);
        renewKeyButton.setName("renewKeyButton"); // NOI18N
        renewKeyButton.setVerticalTextPosition(javax.swing.SwingConstants.BOTTOM);
        jToolBar1.add(renewKeyButton);

        testKeyButton.setAction(actionMap.get("testKeys")); // NOI18N
        testKeyButton.setText(resourceMap.getString("testKeyButton.text")); // NOI18N
        testKeyButton.setFocusable(false);
        testKeyButton.setHorizontalTextPosition(javax.swing.SwingConstants.CENTER);
        testKeyButton.setName("testKeyButton"); // NOI18N
        testKeyButton.setVerticalTextPosition(javax.swing.SwingConstants.BOTTOM);
        jToolBar1.add(testKeyButton);

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

        jSeparator6.setName("jSeparator6"); // NOI18N
        jToolBar1.add(jSeparator6);

        renewSignerButton.setAction(actionMap.get("renewSigner")); // NOI18N
        renewSignerButton.setText(resourceMap.getString("renewSignerButton.text")); // NOI18N
        renewSignerButton.setFocusable(false);
        renewSignerButton.setHorizontalTextPosition(javax.swing.SwingConstants.CENTER);
        renewSignerButton.setName("renewSignerButton"); // NOI18N
        renewSignerButton.setVerticalTextPosition(javax.swing.SwingConstants.BOTTOM);
        jToolBar1.add(renewSignerButton);

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
                .addContainerGap(1018, Short.MAX_VALUE)
                .addComponent(progressBar, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(statusAnimationLabel, javax.swing.GroupLayout.PREFERRED_SIZE, 37, javax.swing.GroupLayout.PREFERRED_SIZE))
            .addGroup(statusPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addGroup(statusPanelLayout.createSequentialGroup()
                    .addGap(135, 135, 135)
                    .addComponent(statusMessageLabel)
                    .addContainerGap(1082, Short.MAX_VALUE)))
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

        authEditPanel.setName("authEditPanel"); // NOI18N

        jLabel4.setText(resourceMap.getString("jLabel4.text")); // NOI18N
        jLabel4.setName("jLabel4"); // NOI18N

        editSerialNumberTextfield.setName("editSerialNumberTextfield"); // NOI18N

        jLabel5.setText(resourceMap.getString("jLabel5.text")); // NOI18N
        jLabel5.setName("jLabel5"); // NOI18N

        editIssuerDNTextfield.setName("editIssuerDNTextfield"); // NOI18N

        editUpdateAllCheckbox.setText(resourceMap.getString("editUpdateAllCheckbox.text")); // NOI18N
        editUpdateAllCheckbox.setName("editUpdateAllCheckbox"); // NOI18N

        loadCertButton.setText(resourceMap.getString("loadCertButton.text")); // NOI18N
        loadCertButton.setName("loadCertButton"); // NOI18N
        loadCertButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                loadFromCertificateButtonPerformed(evt);
            }
        });

        javax.swing.GroupLayout authEditPanelLayout = new javax.swing.GroupLayout(authEditPanel);
        authEditPanel.setLayout(authEditPanelLayout);
        authEditPanelLayout.setHorizontalGroup(
            authEditPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(authEditPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(authEditPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(editSerialNumberTextfield, javax.swing.GroupLayout.DEFAULT_SIZE, 331, Short.MAX_VALUE)
                    .addComponent(jLabel4, javax.swing.GroupLayout.DEFAULT_SIZE, 331, Short.MAX_VALUE)
                    .addComponent(editIssuerDNTextfield, javax.swing.GroupLayout.DEFAULT_SIZE, 331, Short.MAX_VALUE)
                    .addComponent(jLabel5, javax.swing.GroupLayout.DEFAULT_SIZE, 331, Short.MAX_VALUE)
                    .addComponent(editUpdateAllCheckbox, javax.swing.GroupLayout.DEFAULT_SIZE, 331, Short.MAX_VALUE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(loadCertButton, javax.swing.GroupLayout.PREFERRED_SIZE, 45, javax.swing.GroupLayout.PREFERRED_SIZE))
        );
        authEditPanelLayout.setVerticalGroup(
            authEditPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(authEditPanelLayout.createSequentialGroup()
                .addGap(51, 51, 51)
                .addComponent(jLabel4)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(authEditPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(editSerialNumberTextfield, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(loadCertButton))
                .addGap(18, 18, 18)
                .addComponent(jLabel5)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(editIssuerDNTextfield, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(45, 45, 45)
                .addComponent(editUpdateAllCheckbox)
                .addContainerGap(60, Short.MAX_VALUE))
        );

        passwordPanel.setName("passwordPanel"); // NOI18N

        passwordPanelLabel.setText(resourceMap.getString("passwordPanelLabel.text")); // NOI18N
        passwordPanelLabel.setName("passwordPanelLabel"); // NOI18N

        passwordPanelField.setText(resourceMap.getString("passwordPanelField.text")); // NOI18N
        passwordPanelField.setName("passwordPanelField"); // NOI18N

        javax.swing.GroupLayout passwordPanelLayout = new javax.swing.GroupLayout(passwordPanel);
        passwordPanel.setLayout(passwordPanelLayout);
        passwordPanelLayout.setHorizontalGroup(
            passwordPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, passwordPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(passwordPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(passwordPanelField, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, 391, Short.MAX_VALUE)
                    .addComponent(passwordPanelLabel, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, 391, Short.MAX_VALUE))
                .addContainerGap())
        );
        passwordPanelLayout.setVerticalGroup(
            passwordPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(passwordPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(passwordPanelLabel)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(passwordPanelField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        jTabbedPane1.setName("jTabbedPane1"); // NOI18N

        mainPanel.setName("mainPanel"); // NOI18N

        jSplitPane1.setName("jSplitPane1"); // NOI18N

        jScrollPane2.setMinimumSize(new java.awt.Dimension(250, 26));
        jScrollPane2.setName("jScrollPane2"); // NOI18N
        jScrollPane2.setPreferredSize(new java.awt.Dimension(550, 202));

        workersList.setName("workersList"); // NOI18N
        jScrollPane2.setViewportView(workersList);

        jSplitPane1.setLeftComponent(jScrollPane2);

        jPanel1.setName("jPanel1"); // NOI18N

        workerComboBox.setMinimumSize(new java.awt.Dimension(39, 60));
        workerComboBox.setName("workerComboBox"); // NOI18N

        workerTabbedPane.setName("workerTabbedPane"); // NOI18N

        statusSummaryTab.setBorder(javax.swing.BorderFactory.createEmptyBorder(1, 1, 1, 1));
        statusSummaryTab.setVerticalScrollBarPolicy(javax.swing.ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS);
        statusSummaryTab.setName("statusSummaryTab"); // NOI18N

        statusSummaryTextPane.setEditable(false);
        statusSummaryTextPane.setText(resourceMap.getString("statusSummaryTextPane.text")); // NOI18N
        statusSummaryTextPane.setName("statusSummaryTextPane"); // NOI18N
        statusSummaryTab.setViewportView(statusSummaryTextPane);

        workerTabbedPane.addTab(resourceMap.getString("statusSummaryTab.TabConstraints.tabTitle"), statusSummaryTab); // NOI18N

        statusPropertiesTab.setName("statusPropertiesTab"); // NOI18N

        statusPropertiesScrollPane.setVerticalScrollBarPolicy(javax.swing.ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS);
        statusPropertiesScrollPane.setName("statusPropertiesScrollPane"); // NOI18N

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
        statusPropertiesScrollPane.setViewportView(propertiesTable);

        statusPropertiesDetailsButton.setText(resourceMap.getString("statusPropertiesDetailsButton.text")); // NOI18N
        statusPropertiesDetailsButton.setEnabled(false);
        statusPropertiesDetailsButton.setName("statusPropertiesDetailsButton"); // NOI18N
        statusPropertiesDetailsButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                statusPropertiesDetailsButtonActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout statusPropertiesTabLayout = new javax.swing.GroupLayout(statusPropertiesTab);
        statusPropertiesTab.setLayout(statusPropertiesTabLayout);
        statusPropertiesTabLayout.setHorizontalGroup(
            statusPropertiesTabLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, statusPropertiesTabLayout.createSequentialGroup()
                .addContainerGap(501, Short.MAX_VALUE)
                .addComponent(statusPropertiesDetailsButton, javax.swing.GroupLayout.PREFERRED_SIZE, 84, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap())
            .addGroup(statusPropertiesTabLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addGroup(statusPropertiesTabLayout.createSequentialGroup()
                    .addContainerGap()
                    .addComponent(statusPropertiesScrollPane, javax.swing.GroupLayout.DEFAULT_SIZE, 473, Short.MAX_VALUE)
                    .addGap(112, 112, 112)))
        );
        statusPropertiesTabLayout.setVerticalGroup(
            statusPropertiesTabLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(statusPropertiesTabLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(statusPropertiesDetailsButton)
                .addContainerGap(492, Short.MAX_VALUE))
            .addGroup(statusPropertiesTabLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addGroup(statusPropertiesTabLayout.createSequentialGroup()
                    .addContainerGap()
                    .addComponent(statusPropertiesScrollPane, javax.swing.GroupLayout.DEFAULT_SIZE, 510, Short.MAX_VALUE)
                    .addContainerGap()))
        );

        workerTabbedPane.addTab(resourceMap.getString("statusPropertiesTab.TabConstraints.tabTitle"), statusPropertiesTab); // NOI18N

        configurationTab.setName("configurationTab"); // NOI18N

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

        javax.swing.GroupLayout configurationTabLayout = new javax.swing.GroupLayout(configurationTab);
        configurationTab.setLayout(configurationTabLayout);
        configurationTabLayout.setHorizontalGroup(
            configurationTabLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, configurationTabLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jScrollPane6, javax.swing.GroupLayout.DEFAULT_SIZE, 463, Short.MAX_VALUE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(configurationTabLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(addButton)
                    .addComponent(editButton)
                    .addComponent(removeButton, javax.swing.GroupLayout.PREFERRED_SIZE, 98, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap())
        );

        configurationTabLayout.linkSize(javax.swing.SwingConstants.HORIZONTAL, new java.awt.Component[] {addButton, editButton, removeButton});

        configurationTabLayout.setVerticalGroup(
            configurationTabLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(configurationTabLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(configurationTabLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jScrollPane6, javax.swing.GroupLayout.DEFAULT_SIZE, 510, Short.MAX_VALUE)
                    .addGroup(configurationTabLayout.createSequentialGroup()
                        .addComponent(addButton)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(editButton)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(removeButton)))
                .addContainerGap())
        );

        workerTabbedPane.addTab("Configuration", configurationTab);

        authorizationTab.setName("authorizationTab"); // NOI18N

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

        authAddButton.setText(resourceMap.getString("authAddButton.text")); // NOI18N
        authAddButton.setName("authAddButton"); // NOI18N
        authAddButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                authAddButtonActionPerformed(evt);
            }
        });

        authEditButton.setText(resourceMap.getString("authEditButton.text")); // NOI18N
        authEditButton.setEnabled(false);
        authEditButton.setName("authEditButton"); // NOI18N
        authEditButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                authEditButtonActionPerformed(evt);
            }
        });

        authRemoveButton.setText(resourceMap.getString("authRemoveButton.text")); // NOI18N
        authRemoveButton.setEnabled(false);
        authRemoveButton.setName("authRemoveButton"); // NOI18N
        authRemoveButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                authRemoveButtonActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout authorizationTabLayout = new javax.swing.GroupLayout(authorizationTab);
        authorizationTab.setLayout(authorizationTabLayout);
        authorizationTabLayout.setHorizontalGroup(
            authorizationTabLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(authorizationTabLayout.createSequentialGroup()
                .addContainerGap(486, Short.MAX_VALUE)
                .addGroup(authorizationTabLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(authAddButton, javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(authEditButton, javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(authRemoveButton, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.PREFERRED_SIZE, 99, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap())
            .addGroup(authorizationTabLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addGroup(authorizationTabLayout.createSequentialGroup()
                    .addGap(6, 6, 6)
                    .addComponent(jScrollPane7, javax.swing.GroupLayout.DEFAULT_SIZE, 467, Short.MAX_VALUE)
                    .addGap(124, 124, 124)))
        );

        authorizationTabLayout.linkSize(javax.swing.SwingConstants.HORIZONTAL, new java.awt.Component[] {authAddButton, authEditButton, authRemoveButton});

        authorizationTabLayout.setVerticalGroup(
            authorizationTabLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(authorizationTabLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(authAddButton)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(authEditButton)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(authRemoveButton)
                .addContainerGap(414, Short.MAX_VALUE))
            .addGroup(authorizationTabLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addGroup(authorizationTabLayout.createSequentialGroup()
                    .addContainerGap()
                    .addComponent(jScrollPane7, javax.swing.GroupLayout.DEFAULT_SIZE, 510, Short.MAX_VALUE)
                    .addContainerGap()))
        );

        workerTabbedPane.addTab(resourceMap.getString("authorizationTab.TabConstraints.tabTitle"), authorizationTab); // NOI18N

        javax.swing.GroupLayout jPanel1Layout = new javax.swing.GroupLayout(jPanel1);
        jPanel1.setLayout(jPanel1Layout);
        jPanel1Layout.setHorizontalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel1Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(workerTabbedPane, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, 605, Short.MAX_VALUE)
                    .addComponent(workerComboBox, javax.swing.GroupLayout.Alignment.LEADING, 0, 605, Short.MAX_VALUE))
                .addContainerGap())
        );
        jPanel1Layout.setVerticalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(workerComboBox, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addComponent(workerTabbedPane, javax.swing.GroupLayout.DEFAULT_SIZE, 572, Short.MAX_VALUE))
        );

        jSplitPane1.setRightComponent(jPanel1);

        javax.swing.GroupLayout mainPanelLayout = new javax.swing.GroupLayout(mainPanel);
        mainPanel.setLayout(mainPanelLayout);
        mainPanelLayout.setHorizontalGroup(
            mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(mainPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jSplitPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 1185, Short.MAX_VALUE)
                .addContainerGap())
        );
        mainPanelLayout.setVerticalGroup(
            mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(mainPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jSplitPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 630, Short.MAX_VALUE)
                .addContainerGap())
        );

        jTabbedPane1.addTab(resourceMap.getString("mainPanel.TabConstraints.tabTitle"), mainPanel); // NOI18N

        auditPanel.setName("auditPanel"); // NOI18N

        jSplitPane2.setOrientation(javax.swing.JSplitPane.VERTICAL_SPLIT);
        jSplitPane2.setName("jSplitPane2"); // NOI18N

        jPanel2.setMinimumSize(new java.awt.Dimension(0, 123));
        jPanel2.setName("jPanel2"); // NOI18N
        jPanel2.setPreferredSize(new java.awt.Dimension(1086, 423));

        jLabel3.setFont(resourceMap.getFont("jLabel3.font")); // NOI18N
        jLabel3.setText(resourceMap.getString("jLabel3.text")); // NOI18N
        jLabel3.setName("jLabel3"); // NOI18N

        jScrollPane3.setName("jScrollPane3"); // NOI18N

        conditionsTable.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {
                {"Event", "Not equals", "Access Control"}
            },
            new String [] {
                "Column", "Condition", "Value"
            }
        ) {
            boolean[] canEdit = new boolean [] {
                false, true, true
            };

            public boolean isCellEditable(int rowIndex, int columnIndex) {
                return canEdit [columnIndex];
            }
        });
        conditionsTable.setName("conditionsTable"); // NOI18N
        conditionsTable.setSelectionMode(javax.swing.ListSelectionModel.SINGLE_SELECTION);
        jScrollPane3.setViewportView(conditionsTable);

        jButtonAuditConditionAdd.setText(resourceMap.getString("jButtonAuditConditionAdd.text")); // NOI18N
        jButtonAuditConditionAdd.setName("jButtonAuditConditionAdd"); // NOI18N
        jButtonAuditConditionAdd.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonAuditConditionAddActionPerformed(evt);
            }
        });

        jButtonAuditConditionRemove.setText(resourceMap.getString("jButtonAuditConditionRemove.text")); // NOI18N
        jButtonAuditConditionRemove.setEnabled(false);
        jButtonAuditConditionRemove.setName("jButtonAuditConditionRemove"); // NOI18N
        jButtonAuditConditionRemove.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonAuditConditionRemoveActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout jPanel2Layout = new javax.swing.GroupLayout(jPanel2);
        jPanel2.setLayout(jPanel2Layout);
        jPanel2Layout.setHorizontalGroup(
            jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel2Layout.createSequentialGroup()
                .addGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(jLabel3, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, 787, Short.MAX_VALUE)
                    .addComponent(jScrollPane3, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, 787, Short.MAX_VALUE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addComponent(jButtonAuditConditionRemove, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(jButtonAuditConditionAdd, javax.swing.GroupLayout.DEFAULT_SIZE, 114, Short.MAX_VALUE))
                .addGap(272, 272, 272))
        );
        jPanel2Layout.setVerticalGroup(
            jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel2Layout.createSequentialGroup()
                .addComponent(jLabel3)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel2Layout.createSequentialGroup()
                        .addComponent(jButtonAuditConditionAdd)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jButtonAuditConditionRemove))
                    .addComponent(jScrollPane3, javax.swing.GroupLayout.DEFAULT_SIZE, 387, Short.MAX_VALUE))
                .addContainerGap())
        );

        jSplitPane2.setLeftComponent(jPanel2);

        jPanel3.setName("jPanel3"); // NOI18N

        auditlogFirstButton.setText(resourceMap.getString("auditlogFirstButton.text")); // NOI18N
        auditlogFirstButton.setEnabled(false);
        auditlogFirstButton.setHorizontalTextPosition(javax.swing.SwingConstants.CENTER);
        auditlogFirstButton.setName("auditlogFirstButton"); // NOI18N
        auditlogFirstButton.setVerticalTextPosition(javax.swing.SwingConstants.BOTTOM);
        auditlogFirstButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                auditlogFirstButtonActionPerformed(evt);
            }
        });

        auditlogPreviousButton.setText(resourceMap.getString("auditlogPreviousButton.text")); // NOI18N
        auditlogPreviousButton.setEnabled(false);
        auditlogPreviousButton.setHorizontalTextPosition(javax.swing.SwingConstants.CENTER);
        auditlogPreviousButton.setName("auditlogPreviousButton"); // NOI18N
        auditlogPreviousButton.setVerticalTextPosition(javax.swing.SwingConstants.BOTTOM);
        auditlogPreviousButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                auditlogPreviousButtonActionPerformed(evt);
            }
        });

        auditlogReloadButton.setAction(actionMap.get("auditlogReload")); // NOI18N
        auditlogReloadButton.setText(resourceMap.getString("auditlogReloadButton.text")); // NOI18N
        auditlogReloadButton.setHorizontalTextPosition(javax.swing.SwingConstants.CENTER);
        auditlogReloadButton.setName("auditlogReloadButton"); // NOI18N
        auditlogReloadButton.setVerticalTextPosition(javax.swing.SwingConstants.BOTTOM);

        auditlogNextButton.setText(resourceMap.getString("auditlogNextButton.text")); // NOI18N
        auditlogNextButton.setEnabled(false);
        auditlogNextButton.setHorizontalTextPosition(javax.swing.SwingConstants.CENTER);
        auditlogNextButton.setName("auditlogNextButton"); // NOI18N
        auditlogNextButton.setVerticalTextPosition(javax.swing.SwingConstants.BOTTOM);
        auditlogNextButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                auditlogNextButtonActionPerformed(evt);
            }
        });

        jLabel6.setHorizontalAlignment(javax.swing.SwingConstants.RIGHT);
        jLabel6.setText(resourceMap.getString("jLabel6.text")); // NOI18N
        jLabel6.setName("jLabel6"); // NOI18N

        auditlogStartIndexTextfield.setText(resourceMap.getString("auditlogStartIndexTextfield.text")); // NOI18N
        auditlogStartIndexTextfield.setName("auditlogStartIndexTextfield"); // NOI18N

        auditlogDisplayingToIndex.setHorizontalAlignment(javax.swing.SwingConstants.LEFT);
        auditlogDisplayingToIndex.setText(resourceMap.getString("auditlogDisplayingToIndex.text")); // NOI18N
        auditlogDisplayingToIndex.setName("auditlogDisplayingToIndex"); // NOI18N

        jLabel8.setHorizontalAlignment(javax.swing.SwingConstants.RIGHT);
        jLabel8.setText(resourceMap.getString("jLabel8.text")); // NOI18N
        jLabel8.setName("jLabel8"); // NOI18N

        auditlogMaxEntriesTextfield.setText(resourceMap.getString("auditlogMaxEntriesTextfield.text")); // NOI18N
        auditlogMaxEntriesTextfield.setName("auditlogMaxEntriesTextfield"); // NOI18N

        auditlogPanel.setName("auditlogPanel"); // NOI18N
        auditlogPanel.setLayout(new java.awt.CardLayout());

        auditlogTablePanel.setName("auditlogTablePanel"); // NOI18N

        auditlogTableScrollPane.setEnabled(false);
        auditlogTableScrollPane.setName("auditlogTableScrollPane"); // NOI18N

        auditLogTable.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {
                {"2013-01-19 11:47:52+0100", "EJBCA Node Start", "Success", "StartServicesServlet.init", "Service", null, null, null, "atitudem", "Init, EJBCA 5.0.5 (r14787) startup."}
            },
            new String [] {
                "Time", "Event", "Outcome", "Administrator", "Module", "Certificate Authority", "Certificate", "Username", "Node", "Details"
            }
        ));
        auditLogTable.setEnabled(false);
        auditLogTable.setName("auditLogTable"); // NOI18N
        auditLogTable.setSelectionMode(javax.swing.ListSelectionModel.SINGLE_SELECTION);
        auditLogTable.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                auditLogTableMouseClicked(evt);
            }
        });
        auditLogTable.addKeyListener(new java.awt.event.KeyAdapter() {
            public void keyReleased(java.awt.event.KeyEvent evt) {
                auditLogTableKeyReleased(evt);
            }
        });
        auditlogTableScrollPane.setViewportView(auditLogTable);

        javax.swing.GroupLayout auditlogTablePanelLayout = new javax.swing.GroupLayout(auditlogTablePanel);
        auditlogTablePanel.setLayout(auditlogTablePanelLayout);
        auditlogTablePanelLayout.setHorizontalGroup(
            auditlogTablePanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGap(0, 1161, Short.MAX_VALUE)
            .addGroup(auditlogTablePanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addComponent(auditlogTableScrollPane, javax.swing.GroupLayout.DEFAULT_SIZE, 1161, Short.MAX_VALUE))
        );
        auditlogTablePanelLayout.setVerticalGroup(
            auditlogTablePanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGap(0, 130, Short.MAX_VALUE)
            .addGroup(auditlogTablePanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addComponent(auditlogTableScrollPane, javax.swing.GroupLayout.DEFAULT_SIZE, 130, Short.MAX_VALUE))
        );

        auditlogPanel.add(auditlogTablePanel, "auditlogTableCard");

        auditlogErrorPanel.setName("auditlogErrorPanel"); // NOI18N

        jScrollPane5.setName("jScrollPane5"); // NOI18N

        auditlogErrorEditor.setEditable(false);
        auditlogErrorEditor.setName("auditlogErrorEditor"); // NOI18N
        jScrollPane5.setViewportView(auditlogErrorEditor);

        javax.swing.GroupLayout auditlogErrorPanelLayout = new javax.swing.GroupLayout(auditlogErrorPanel);
        auditlogErrorPanel.setLayout(auditlogErrorPanelLayout);
        auditlogErrorPanelLayout.setHorizontalGroup(
            auditlogErrorPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jScrollPane5, javax.swing.GroupLayout.Alignment.TRAILING)
        );
        auditlogErrorPanelLayout.setVerticalGroup(
            auditlogErrorPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jScrollPane5, javax.swing.GroupLayout.DEFAULT_SIZE, 130, Short.MAX_VALUE)
        );

        auditlogPanel.add(auditlogErrorPanel, "auditlogErrorCard");

        javax.swing.GroupLayout jPanel3Layout = new javax.swing.GroupLayout(jPanel3);
        jPanel3.setLayout(jPanel3Layout);
        jPanel3Layout.setHorizontalGroup(
            jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel3Layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(auditlogFirstButton, javax.swing.GroupLayout.PREFERRED_SIZE, 83, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(auditlogPreviousButton)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(auditlogReloadButton)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(auditlogNextButton)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jLabel6, javax.swing.GroupLayout.PREFERRED_SIZE, 156, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(auditlogStartIndexTextfield, javax.swing.GroupLayout.PREFERRED_SIZE, 63, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(auditlogDisplayingToIndex, javax.swing.GroupLayout.PREFERRED_SIZE, 63, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jLabel8, javax.swing.GroupLayout.PREFERRED_SIZE, 156, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(auditlogMaxEntriesTextfield, javax.swing.GroupLayout.PREFERRED_SIZE, 56, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(275, Short.MAX_VALUE))
            .addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addGroup(jPanel3Layout.createSequentialGroup()
                    .addContainerGap()
                    .addComponent(auditlogPanel, javax.swing.GroupLayout.DEFAULT_SIZE, 1161, Short.MAX_VALUE)
                    .addContainerGap()))
        );

        jPanel3Layout.linkSize(javax.swing.SwingConstants.HORIZONTAL, new java.awt.Component[] {auditlogFirstButton, auditlogNextButton, auditlogPreviousButton, auditlogReloadButton});

        jPanel3Layout.setVerticalGroup(
            jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel3Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(auditlogFirstButton)
                    .addComponent(auditlogPreviousButton, javax.swing.GroupLayout.PREFERRED_SIZE, 23, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(auditlogReloadButton, javax.swing.GroupLayout.PREFERRED_SIZE, 23, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(auditlogNextButton, javax.swing.GroupLayout.PREFERRED_SIZE, 23, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                        .addComponent(jLabel6)
                        .addComponent(auditlogStartIndexTextfield, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addComponent(auditlogDisplayingToIndex)
                        .addComponent(jLabel8)
                        .addComponent(auditlogMaxEntriesTextfield, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addContainerGap(159, Short.MAX_VALUE))
            .addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel3Layout.createSequentialGroup()
                    .addGap(59, 59, 59)
                    .addComponent(auditlogPanel, javax.swing.GroupLayout.DEFAULT_SIZE, 130, Short.MAX_VALUE)
                    .addContainerGap()))
        );

        jPanel3Layout.linkSize(javax.swing.SwingConstants.VERTICAL, new java.awt.Component[] {auditlogFirstButton, auditlogNextButton, auditlogPreviousButton, auditlogReloadButton, jLabel6});

        jSplitPane2.setRightComponent(jPanel3);

        javax.swing.GroupLayout auditPanelLayout = new javax.swing.GroupLayout(auditPanel);
        auditPanel.setLayout(auditPanelLayout);
        auditPanelLayout.setHorizontalGroup(
            auditPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(auditPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jSplitPane2, javax.swing.GroupLayout.DEFAULT_SIZE, 1185, Short.MAX_VALUE)
                .addContainerGap())
        );
        auditPanelLayout.setVerticalGroup(
            auditPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(auditPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jSplitPane2, javax.swing.GroupLayout.DEFAULT_SIZE, 630, Short.MAX_VALUE)
                .addContainerGap())
        );

        jTabbedPane1.addTab(resourceMap.getString("auditPanel.TabConstraints.tabTitle"), auditPanel); // NOI18N

        removeKeyPanel.setName("removeKeyPanel"); // NOI18N

        jLabel7.setText(resourceMap.getString("jLabel7.text")); // NOI18N
        jLabel7.setName("jLabel7"); // NOI18N

        aliasTextField.setName("aliasTextField"); // NOI18N

        javax.swing.GroupLayout removeKeyPanelLayout = new javax.swing.GroupLayout(removeKeyPanel);
        removeKeyPanel.setLayout(removeKeyPanelLayout);
        removeKeyPanelLayout.setHorizontalGroup(
            removeKeyPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jLabel7, javax.swing.GroupLayout.DEFAULT_SIZE, 394, Short.MAX_VALUE)
            .addComponent(aliasTextField, javax.swing.GroupLayout.DEFAULT_SIZE, 394, Short.MAX_VALUE)
        );
        removeKeyPanelLayout.setVerticalGroup(
            removeKeyPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(removeKeyPanelLayout.createSequentialGroup()
                .addComponent(jLabel7)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(aliasTextField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
        );

        reloadPanel.setName("reloadPanel"); // NOI18N

        jEditorPane1.setBackground(resourceMap.getColor("jEditorPane1.background")); // NOI18N
        jEditorPane1.setContentType(resourceMap.getString("jEditorPane1.contentType")); // NOI18N
        jEditorPane1.setEditable(false);
        jEditorPane1.setText(resourceMap.getString("jEditorPane1.text")); // NOI18N
        jEditorPane1.setName("jEditorPane1"); // NOI18N

        reloadPanelButtonGroup.add(reloadAllWorkersRadioButton);
        reloadAllWorkersRadioButton.setText(resourceMap.getString("reloadAllWorkersRadioButton.text")); // NOI18N
        reloadAllWorkersRadioButton.setName("reloadAllWorkersRadioButton"); // NOI18N

        reloadPanelButtonGroup.add(reloadSelectedWorkersRadioButton);
        reloadSelectedWorkersRadioButton.setText(resourceMap.getString("reloadSelectedWorkersRadioButton.text")); // NOI18N
        reloadSelectedWorkersRadioButton.setName("reloadSelectedWorkersRadioButton"); // NOI18N

        jLabel9.setText(resourceMap.getString("jLabel9.text")); // NOI18N
        jLabel9.setName("jLabel9"); // NOI18N

        javax.swing.GroupLayout reloadPanelLayout = new javax.swing.GroupLayout(reloadPanel);
        reloadPanel.setLayout(reloadPanelLayout);
        reloadPanelLayout.setHorizontalGroup(
            reloadPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jEditorPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 396, Short.MAX_VALUE)
            .addGroup(reloadPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jLabel9, javax.swing.GroupLayout.DEFAULT_SIZE, 372, Short.MAX_VALUE)
                .addContainerGap())
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, reloadPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(reloadAllWorkersRadioButton, javax.swing.GroupLayout.DEFAULT_SIZE, 372, Short.MAX_VALUE)
                .addContainerGap())
            .addGroup(reloadPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(reloadSelectedWorkersRadioButton, javax.swing.GroupLayout.DEFAULT_SIZE, 372, Short.MAX_VALUE)
                .addContainerGap())
        );
        reloadPanelLayout.setVerticalGroup(
            reloadPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(reloadPanelLayout.createSequentialGroup()
                .addComponent(jEditorPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 96, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jLabel9)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(reloadAllWorkersRadioButton)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(reloadSelectedWorkersRadioButton)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        exportPanel.setName("exportPanel"); // NOI18N

        jLabel10.setText(resourceMap.getString("jLabel10.text")); // NOI18N
        jLabel10.setName("jLabel10"); // NOI18N

        exportPanelButtonGroup.add(exportAllRadioButton);
        exportAllRadioButton.setText(resourceMap.getString("exportAllRadioButton.text")); // NOI18N
        exportAllRadioButton.setName("exportAllRadioButton"); // NOI18N
        exportAllRadioButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                exportRadioButtonActionPerformed(evt);
            }
        });

        exportPanelButtonGroup.add(exportSelectedRadioButton);
        exportSelectedRadioButton.setText(resourceMap.getString("exportSelectedRadioButton.text")); // NOI18N
        exportSelectedRadioButton.setName("exportSelectedRadioButton"); // NOI18N
        exportSelectedRadioButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                exportRadioButtonActionPerformed(evt);
            }
        });

        exportPanelButtonGroup.add(exportNoRadioButton);
        exportNoRadioButton.setText(resourceMap.getString("exportNoRadioButton.text")); // NOI18N
        exportNoRadioButton.setName("exportNoRadioButton"); // NOI18N
        exportNoRadioButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                exportRadioButtonActionPerformed(evt);
            }
        });

        exportAllUnrelatedGlobalCheckbox.setText(resourceMap.getString("exportAllUnrelatedGlobalCheckbox.text")); // NOI18N
        exportAllUnrelatedGlobalCheckbox.setName("exportAllUnrelatedGlobalCheckbox"); // NOI18N

        javax.swing.GroupLayout exportPanelLayout = new javax.swing.GroupLayout(exportPanel);
        exportPanel.setLayout(exportPanelLayout);
        exportPanelLayout.setHorizontalGroup(
            exportPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jLabel10, javax.swing.GroupLayout.DEFAULT_SIZE, 475, Short.MAX_VALUE)
            .addGroup(exportPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(exportSelectedRadioButton, javax.swing.GroupLayout.DEFAULT_SIZE, 451, Short.MAX_VALUE)
                .addContainerGap())
            .addGroup(exportPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(exportNoRadioButton, javax.swing.GroupLayout.DEFAULT_SIZE, 451, Short.MAX_VALUE)
                .addContainerGap())
            .addGroup(exportPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(exportAllUnrelatedGlobalCheckbox, javax.swing.GroupLayout.DEFAULT_SIZE, 451, Short.MAX_VALUE)
                .addContainerGap())
            .addGroup(exportPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(exportAllRadioButton, javax.swing.GroupLayout.DEFAULT_SIZE, 451, Short.MAX_VALUE)
                .addContainerGap())
        );
        exportPanelLayout.setVerticalGroup(
            exportPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(exportPanelLayout.createSequentialGroup()
                .addComponent(jLabel10)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(exportAllRadioButton)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(exportSelectedRadioButton)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(exportNoRadioButton)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(exportAllUnrelatedGlobalCheckbox))
        );

        setComponent(jTabbedPane1);
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

            try {
                SignServerAdminGUIApplication.getAdminWS()
                        .setWorkerProperty(workerId,
                        editPropertyTextField.getText(),
                        editPropertyValueTextArea.getText());
                SignServerAdminGUIApplication.getAdminWS()
                        .reloadConfiguration(workerId);

                refreshButton.doClick();
            } catch (AdminNotAuthorizedException_Exception ex) {
                postAdminNotAuthorized(ex);
            }
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
                try {
                    final int workerId = selectedWorker.getWorkerId();
                    final String newPropertyName = editPropertyTextField.getText();

                    if (!oldPropertyName.equals(newPropertyName)) {
                        SignServerAdminGUIApplication.getAdminWS()
                                .removeWorkerProperty(workerId, oldPropertyName);
                    }

                    SignServerAdminGUIApplication.getAdminWS()
                            .setWorkerProperty(workerId,
                            newPropertyName,
                            editPropertyValueTextArea.getText());
                    SignServerAdminGUIApplication.getAdminWS()
                            .reloadConfiguration(workerId);

                    refreshButton.doClick();
                } catch (final AdminNotAuthorizedException_Exception ex) {
                    postAdminNotAuthorized(ex);
                }
            }
        }
}//GEN-LAST:event_editButtonActionPerformed

    private void removeButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_removeButtonActionPerformed
        try {
            final int row = configurationTable.getSelectedRow();

            if (row != -1) {
                final int res = JOptionPane.showConfirmDialog(getFrame(),
                        "Are you sure you want to remove the property?",
                        "Remove property", JOptionPane.YES_NO_CANCEL_OPTION,
                        JOptionPane.QUESTION_MESSAGE);
                if (res == JOptionPane.YES_OPTION) {
                    int workerId = selectedWorker.getWorkerId();
                    SignServerAdminGUIApplication.getAdminWS()
                            .removeWorkerProperty(workerId,
                            (String) configurationTable.getValueAt(row, 0));
                    SignServerAdminGUIApplication.getAdminWS()
                            .reloadConfiguration(workerId);

                    refreshButton.doClick();
                }
            }
        } catch (AdminNotAuthorizedException_Exception ex) {
            postAdminNotAuthorized(ex);
        }
}//GEN-LAST:event_removeButtonActionPerformed

    private void authAddButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_authAddButtonActionPerformed
        editSerialNumberTextfield.setText("");
        editSerialNumberTextfield.setEditable(true);
        editIssuerDNTextfield.setText("");
        editIssuerDNTextfield.setEditable(true);
        editUpdateAllCheckbox.setSelected(false);

        final int res = JOptionPane.showConfirmDialog(getFrame(), authEditPanel,
                "Add authorized client", JOptionPane.OK_CANCEL_OPTION,
                JOptionPane.PLAIN_MESSAGE);
        if (res == JOptionPane.OK_OPTION) {
            List<Worker> workers;
            if (editUpdateAllCheckbox.isSelected()) {
                workers = selectedWorkers;
            } else {
                workers = Collections.singletonList(selectedWorker);
            }

            if (LOG.isDebugEnabled()) {
                LOG.debug("Selected workers: " + workers);
            }

            for (Worker worker : workers) {
                try {
                    org.signserver.admin.gui.adminws.gen.AuthorizedClient client = new org.signserver.admin.gui.adminws.gen.AuthorizedClient();
                    client.setCertSN(editSerialNumberTextfield.getText());
                    client.setIssuerDN(editIssuerDNTextfield.getText());
                    SignServerAdminGUIApplication.getAdminWS()
                            .addAuthorizedClient(worker.getWorkerId(), client);
                    SignServerAdminGUIApplication.getAdminWS()
                            .reloadConfiguration(worker.getWorkerId());
                } catch (AdminNotAuthorizedException_Exception ex) {
                    postAdminNotAuthorized(ex);
                }
            }
            refreshButton.doClick();
        }
    }//GEN-LAST:event_authAddButtonActionPerformed

    private void authEditButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_authEditButtonActionPerformed
        final int row = authTable.getSelectedRow();
        if (row != -1) {

            final String serialNumberBefore =
                   (String) authTable.getValueAt(row, 0);
            final String issuerDNBefore =
                    (String) authTable.getValueAt(row, 1);

            editSerialNumberTextfield.setText(serialNumberBefore);
            editSerialNumberTextfield.setEditable(true);
            editIssuerDNTextfield.setText(issuerDNBefore);
            editIssuerDNTextfield.setEditable(true);
            editUpdateAllCheckbox.setSelected(false);

            final int res = JOptionPane.showConfirmDialog(getFrame(),
                    authEditPanel, "Edit authorized client",
                    JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
            if (res == JOptionPane.OK_OPTION) {
                List<Worker> workers;
                if (editUpdateAllCheckbox.isSelected()) {
                    workers = selectedWorkers;
                } else {
                    workers = Collections.singletonList(selectedWorker);
                }

                if (LOG.isDebugEnabled()) {
                    LOG.debug("Selected workers: " + workers);
                }

                final AuthorizedClient oldAuthorizedClient =
                    new AuthorizedClient();
                oldAuthorizedClient.setCertSN(serialNumberBefore);
                oldAuthorizedClient.setIssuerDN(issuerDNBefore);

                final AuthorizedClient client = new AuthorizedClient();
                client.setCertSN(editSerialNumberTextfield.getText());
                client.setIssuerDN(editIssuerDNTextfield.getText());

                for (Worker worker : workers) {
                    try {
                        boolean removed =
                                SignServerAdminGUIApplication.getAdminWS()
                                .removeAuthorizedClient(worker.getWorkerId(),
                                oldAuthorizedClient);
                        if (removed) {
                            SignServerAdminGUIApplication.getAdminWS()
                                .addAuthorizedClient(worker.getWorkerId(),
                                    client);
                            SignServerAdminGUIApplication.getAdminWS()
                                .reloadConfiguration(worker.getWorkerId());
                        }
                    } catch (AdminNotAuthorizedException_Exception ex) {
                        postAdminNotAuthorized(ex);
                    }
                }
                refreshButton.doClick();
            }
        }
    }//GEN-LAST:event_authEditButtonActionPerformed

    private void authRemoveButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_authRemoveButtonActionPerformed
        final int row = authTable.getSelectedRow();
        if (row != -1) {

            final String serialNumberBefore =
                    (String) authTable.getValueAt(row, 0);
            final String issuerDNBefore =
                    (String) authTable.getValueAt(row, 1);

            editSerialNumberTextfield.setText(serialNumberBefore);
            editSerialNumberTextfield.setEditable(false);
            editIssuerDNTextfield.setText(issuerDNBefore);
            editIssuerDNTextfield.setEditable(false);
            editUpdateAllCheckbox.setSelected(false);

            final int res = JOptionPane.showConfirmDialog(getFrame(), 
                    authEditPanel, "Remove authorized client",
                    JOptionPane.YES_NO_CANCEL_OPTION,
                    JOptionPane.QUESTION_MESSAGE);
            if (res == JOptionPane.YES_OPTION) {
                List<Worker> workers;
                if (editUpdateAllCheckbox.isSelected()) {
                    workers = selectedWorkers;
                } else {
                    workers = Collections.singletonList(selectedWorker);
                }

                if (LOG.isDebugEnabled()) {
                    LOG.debug("Selected workers: " + workers);
                }

                final AuthorizedClient oldAuthorizedClient =
                    new AuthorizedClient();
                oldAuthorizedClient.setCertSN(serialNumberBefore);
                oldAuthorizedClient.setIssuerDN(issuerDNBefore);

                final AuthorizedClient client = new AuthorizedClient();
                client.setCertSN(editSerialNumberTextfield.getText());
                client.setIssuerDN(editIssuerDNTextfield.getText());

                for (Worker worker : workers) {
                    try {
                        SignServerAdminGUIApplication.getAdminWS()
                            .removeAuthorizedClient(worker.getWorkerId(),
                            oldAuthorizedClient);
                        SignServerAdminGUIApplication.getAdminWS()
                            .reloadConfiguration(worker.getWorkerId());
                    } catch (AdminNotAuthorizedException_Exception ex) {
                        postAdminNotAuthorized(ex);
                    }
                }
                refreshButton.doClick();
            }
        }
    }//GEN-LAST:event_authRemoveButtonActionPerformed

    private void statusSummaryMenuActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_statusSummaryMenuActionPerformed
        workerTabbedPane.setSelectedComponent(statusSummaryTab);
    }//GEN-LAST:event_statusSummaryMenuActionPerformed

    private void statusPropertiesMenuActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_statusPropertiesMenuActionPerformed
        workerTabbedPane.setSelectedComponent(statusPropertiesTab);
    }//GEN-LAST:event_statusPropertiesMenuActionPerformed

    private void configurationMenuActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_configurationMenuActionPerformed
        workerTabbedPane.setSelectedComponent(configurationTab);
    }//GEN-LAST:event_configurationMenuActionPerformed

    private void authorizationsMenuActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_authorizationsMenuActionPerformed
        workerTabbedPane.setSelectedComponent(authorizationTab);
    }//GEN-LAST:event_authorizationsMenuActionPerformed

    private void statusPropertiesDetailsButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_statusPropertiesDetailsButtonActionPerformed
        final int row = propertiesTable.getSelectedRow();
        if (row != -1) {
            final Object o = propertiesTable.getValueAt(row, 1);
            List<X509Certificate> certificates = null;
            if (o instanceof X509Certificate) {
                certificates = Collections.singletonList((X509Certificate) o);
            } else if (o instanceof Collection) {
                certificates = new LinkedList<X509Certificate>();
                for (Object c : (Collection) o) {
                    if (c instanceof X509Certificate) {
                        certificates.add((X509Certificate) c);
                    }
                }
            }
            if (certificates != null) {
                final ViewCertificateFrame frame =
                        new ViewCertificateFrame(certificates);
                frame.setVisible(true);
            }
        }
    }//GEN-LAST:event_statusPropertiesDetailsButtonActionPerformed

    private void globalConfigurationMenuActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_globalConfigurationMenuActionPerformed
        GlobalConfigurationFrame frame = new GlobalConfigurationFrame();
        frame.setVisible(true);
    }//GEN-LAST:event_globalConfigurationMenuActionPerformed

    private void administratorsMenuActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_administratorsMenuActionPerformed
        final AdministratorsFrame frame = new AdministratorsFrame();
        frame.setVisible(true);
    }//GEN-LAST:event_administratorsMenuActionPerformed

private void auditlogNextButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_auditlogNextButtonActionPerformed
    // Step forward
    final int maxEntries = Integer.valueOf(auditlogMaxEntriesTextfield.getText());
    final int index = Integer.valueOf(auditlogStartIndexTextfield.getText()) + maxEntries;
    auditlogStartIndexTextfield.setText(String.valueOf(index));
    
    // Reload
    getContext().getTaskService().execute(auditlogReload());
}//GEN-LAST:event_auditlogNextButtonActionPerformed

private void auditlogPreviousButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_auditlogPreviousButtonActionPerformed
    // Step backwards
    final int maxEntries = Integer.valueOf(auditlogMaxEntriesTextfield.getText());
    int index = Integer.valueOf(auditlogStartIndexTextfield.getText()) - maxEntries;
    if (index < 1) {
        index = 1;
    }
    auditlogStartIndexTextfield.setText(String.valueOf(index));
    
    // Reload
    getContext().getTaskService().execute(auditlogReload());
}//GEN-LAST:event_auditlogPreviousButtonActionPerformed

private void auditlogFirstButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_auditlogFirstButtonActionPerformed
    auditlogStartIndexTextfield.setText(String.valueOf(1));
    
    // Reload
    getContext().getTaskService().execute(auditlogReload());
}//GEN-LAST:event_auditlogFirstButtonActionPerformed

private void jButtonAuditConditionAddActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButtonAuditConditionAddActionPerformed
    AddConditionDialog dlg = new AddConditionDialog(getFrame(), true);
    dlg.setVisible(true);
    if (dlg.isOkPressed()) {
        conditionsModel.addCondition(dlg.getColumn().getName(), dlg.getCondition().getOperator(), dlg.getValue());
    }
}//GEN-LAST:event_jButtonAuditConditionAddActionPerformed

private void jButtonAuditConditionRemoveActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButtonAuditConditionRemoveActionPerformed
    int selected = conditionsTable.getSelectedRow();
    if (selected > -1) {
        conditionsModel.removeCondition(selected);
    }
}//GEN-LAST:event_jButtonAuditConditionRemoveActionPerformed

private void auditLogTableMouseClicked(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_auditLogTableMouseClicked
    if (evt.getClickCount() > 1) {
        displayLogEntryAction();
    }
}//GEN-LAST:event_auditLogTableMouseClicked

private void auditLogTableKeyReleased(java.awt.event.KeyEvent evt) {//GEN-FIRST:event_auditLogTableKeyReleased
    if (evt.getKeyCode() == KeyEvent.VK_ENTER) {
        displayLogEntryAction();
    }
}//GEN-LAST:event_auditLogTableKeyReleased

private void loadFromCertificateButtonPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_loadFromCertificateButtonPerformed
    LOG.debug("Load from certificate file");
    
    Utils.selectAndLoadFromCert(authEditPanel, editSerialNumberTextfield, editIssuerDNTextfield);
}//GEN-LAST:event_loadFromCertificateButtonPerformed

private void addWorkerItemActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_addWorkerItemActionPerformed
    final AddWorkerDialog addWorkerDialog = new AddWorkerDialog(getFrame(), true);
    
    addWorkerDialog.setVisible(true);
    
    modifiedWorkers = addWorkerDialog.getModifiedWorkers();
    
    if (modifiedWorkers != null) {
        JOptionPane.showMessageDialog(getFrame(),
                "Added/modified workers with the following IDs: \n" +
                StringUtils.join(modifiedWorkers.toArray(), ","), "Loaded",
                JOptionPane.INFORMATION_MESSAGE);
    
        
        getContext().getTaskService().execute(refreshWorkers());
    }
    
    
}//GEN-LAST:event_addWorkerItemActionPerformed

    private void selectWorkers(final List<Integer> workerIds) {
        final int numSelected = workerIds.size();
        final int[] indices = new int[numSelected];
        
        for (int i = 0; i < numSelected; i++) {
            for (int j = 0; j < allWorkers.size(); j++) {
                final Worker worker = allWorkers.get(j);
                
                if (worker.getWorkerId() == workerIds.get(i)) {
                    indices[i] = j;
                    break;
                }
            }
        }
        
        workersList.setSelectedIndices(indices);
    }

    private void exportRadioButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_exportRadioButtonActionPerformed

        if (evt.getSource() == exportNoRadioButton) {
            exportAllUnrelatedGlobalCheckbox.setEnabled(false);
            exportAllUnrelatedPreviousValue = exportAllUnrelatedGlobalCheckbox.isSelected();
            exportAllUnrelatedGlobalCheckbox.setSelected(true);
        } else {
            exportAllUnrelatedGlobalCheckbox.setEnabled(true);
            exportAllUnrelatedGlobalCheckbox.setSelected(exportAllUnrelatedPreviousValue);
        }
    }//GEN-LAST:event_exportRadioButtonActionPerformed

private void displayLogEntryAction() {
    final int sel = auditLogTable.getSelectedRow();
    if (sel >= 0) {
        DisplayAuditlogEntryFrame frame = new DisplayAuditlogEntryFrame(auditlogModel.getRow(sel));
        frame.setVisible(true);
    }
}

    private void displayWorker(final Worker worker) {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Display worker: " + worker);
        }
        selectedWorker = worker;
        
        final boolean active = worker != null;

        workerComboBox.setEnabled(worker != null);
        workerTabbedPane.setEnabled(worker != null);
        statusSummaryTextPane.setEnabled(worker != null);
        propertiesTable.setEnabled(worker != null);
        configurationTable.setEnabled(worker != null);
        authTable.setEnabled(worker != null);

        addButton.setEnabled(active);
        authAddButton.setEnabled(active);

        authorizationsMenu.setEnabled(active);
        statusSummaryMenu.setEnabled(active);
        statusPropertiesMenu.setEnabled(active);
        configurationMenu.setEnabled(active);
        activateButton.setEnabled(active);
        activateMenu.setEnabled(active);
        deactivateButton.setEnabled(active);
        deactivateMenu.setEnabled(active);
        renewKeyButton.setEnabled(active);
        renewKeyMenu.setEnabled(active);
        testKeyButton.setEnabled(active);
        testKeyMenu.setEnabled(active);
        generateRequestsButton.setEnabled(active);
        generateRequestMenu.setEnabled(active);
        installCertificatesButton.setEnabled(active);
        installCertificatesMenu.setEnabled(active);
        renewSignerButton.setEnabled(active);
        renewSignerMenu.setEnabled(active);
        removeWorkerMenu.setEnabled(active);

        if (worker == null) {
            statusSummaryTextPane.setText("");
            propertiesTable.setModel(new DefaultTableModel(
                new Object[][]{}, statusColumns) {

                @Override
                public boolean isCellEditable(int row, int column) {
                    return false;
                }

            });
            configurationTable.setModel(new DefaultTableModel(
                new Object[][]{}, statusColumns) {

                @Override
                public boolean isCellEditable(int row, int column) {
                    return false;
                }

            });
            authTable.setModel(new DefaultTableModel(
                new Object[][]{}, authColumns) {

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

            String[][] authData = new String[worker.getAuthClients().size()][];

            int i = 0;
            for (AuthorizedClient client : worker.getAuthClients()) {
                authData[i] = new String[2];
                authData[i][0] = client.getCertSN();
                authData[i][1] = client.getIssuerDN();
                i++;
            }

            authTable.setModel(new DefaultTableModel(
                authData, authColumns) {

                @Override
                public boolean isCellEditable(final int row, final int column) {
                    return false;
                }

            });
        }

    }

    @Action(block = Task.BlockingScope.WINDOW)
    public Task refreshWorkers() {
        return new RefreshWorkersTask(getApplication());
    }

    private class RefreshWorkersTask extends org.jdesktop.application.Task<List<Worker>, Void> {
        RefreshWorkersTask(org.jdesktop.application.Application app) {
            // Runs on the EDT.  Copy GUI state that
            // doInBackground() depends on from parameters
            // to RefreshWorkersTask fields, here.
            super(app);

            selectedWorkerBeforeRefresh = (Worker) workerComboBox.getSelectedItem();
        }
        @Override protected List<Worker> doInBackground() {
            // Your Task's code here.  This method runs
            // on a background thread, so don't reference
            // the Swing GUI from here.

            setProgress(0);

            List<Worker> newSigners = new ArrayList<Worker>();

            try {
                List<Integer> workerIds = SignServerAdminGUIApplication
                        .getAdminWS()
                        .getWorkers(GlobalConfiguration.WORKERTYPE_ALL);
                int workers = 0;
                for (Integer workerId : workerIds) {
                    setProgress(workers, 0, workerIds.size());
                    final Vector<Object> workerInfo = new Vector<Object>();
                    final WsWorkerConfig config = SignServerAdminGUIApplication.getAdminWS().getCurrentWorkerConfig(workerId);
                    final Properties properties = asProperties(config);
                    final String name = properties.getProperty("NAME");
                    try {
                        final WsWorkerStatus status = SignServerAdminGUIApplication.getAdminWS().getStatus(workerId);
                        workerInfo.add(status.getOk() == null ? "OK" : status.getOk());
                    } catch (InvalidWorkerIdException_Exception ex) {
                        workerInfo.add("Invalid");
                    } catch (Exception ex) {
                        workerInfo.add("Error");
                        LOG.error("Error getting status for worker " + workerId, ex);
                    }
                    workerInfo.add(workerId);
                    workerInfo.add(name);
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("workerId: " + workerId + ", name: " + name);
                    }
                    // Configuration
                    Set<Entry<Object, Object>> entries = properties.entrySet();
                    Object[][] configProperties = new Object[entries.size()][];
                    int j = 0;
                    for (Entry<Object, Object> entry : entries) {
                        configProperties[j] = new String[2];
                        configProperties[j][0] = (String) entry.getKey();
                        configProperties[j][1] = (String) entry.getValue();
                        j++;
                    }
                    // Status
                    String statusSummary;
                    String tokenStatus;
                    WsWorkerStatus status = null;
                    boolean active = false;
                    try {
                        status = SignServerAdminGUIApplication.getAdminWS().getStatus(workerId);
                        statusSummary = status.getCompleteStatusText();
                        tokenStatus = status.getOk() == null ? "ACTIVE" : "OFFLINE";
                        active = status.getOk() == null;
                    } catch (InvalidWorkerIdException_Exception ex) {
                        statusSummary = "No such worker";
                        tokenStatus = "Unknown";
                    } catch (Exception ex) {
                        statusSummary = "Error getting status";
                        tokenStatus = "Unknown";
                        LOG.error("Error getting status for worker " + workerId, ex);
                    }
                    XMLGregorianCalendar notBefore = null;
                    XMLGregorianCalendar notAfter = null;
                    Certificate certificate = null;
                    Collection<? extends Certificate> certificateChain = null;
                    Object[][] statusProperties = new Object[][]{{"ID", workerId}, {"Name", name}, {"Token status", tokenStatus}, {}, {}, {}, {}};
                    try {
                        notBefore = SignServerAdminGUIApplication.getAdminWS().getSigningValidityNotBefore(workerId);
                        notAfter = SignServerAdminGUIApplication.getAdminWS().getSigningValidityNotAfter(workerId);
                        certificate = asCertificate(SignServerAdminGUIApplication.getAdminWS().getSignerCertificate(workerId));
                        try {
                            certificateChain = asCertificates(SignServerAdminGUIApplication.getAdminWS().getSignerCertificateChain(workerId));
                        } catch (EJBException ex) {
                            // Handle problem caused by bug in server
                            LOG.error("Error getting signer certificate chain", ex);
                            certificateChain = Collections.emptyList();
                        }
                        statusProperties[3] = new Object[]{"Validity not before:", notBefore};
                        statusProperties[4] = new Object[]{"Validity not after:", notAfter};
                        statusProperties[5] = new Object[]{"Signer certificate", certificate};
                        statusProperties[6] = new Object[]{"Certificate chain:", certificateChain};
                    } catch (CryptoTokenOfflineException_Exception ex) {
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("offline: " + workerId);
                        }
                    } catch (RuntimeException ex) {
                        LOG.warn("Methods not supported by server", ex);
                    } catch (CertificateException ex) {
                        LOG.error("Error in certificate", ex);
                    }
                    final Collection<AuthorizedClient> authClients = SignServerAdminGUIApplication.getAdminWS().getAuthorizedClients(workerId);
                    newSigners.add(new Worker(workerId, name, statusSummary, statusProperties, configProperties, properties, active, authClients));
                    workers++;
                }

            } catch (AdminNotAuthorizedException_Exception ex) {
                postAdminNotAuthorized(ex);
            }

            return newSigners;  // return your result
        }
        @Override protected void succeeded(final List<Worker> result) {
            // Runs on the EDT.  Update the GUI based on
            // the result computed by doInBackground().
            
            // Set title
            final StringBuilder title = new StringBuilder();
            X509Certificate adminCertificate = SignServerAdminGUIApplication.getAdminCertificate();
            if (adminCertificate != null) {
                String cn = CertTools.getPartFromDN(adminCertificate.getSubjectDN().getName(), "CN");
                title.append(cn).append(" @ ");
            }
            title.append(SignServerAdminGUIApplication.getServerHost());
            title.append(" - ");
            title.append(texts.getString("Application.title"));
            SignServerAdminGUIApplication.getApplication().getMainFrame().setTitle(title.toString());
            
            final List<Worker> newWorkers = result;

            
            int[] ints;
            
            if (modifiedWorkers != null) {
                // select added/modified workers from the add worker wizard
                final int numModified = modifiedWorkers.size();
                ints = new int[numModified];
                
                for (int i = 0; i < numModified; i++) {
                    for (int j = 0; j < newWorkers.size(); j++) {
                        final Worker worker = newWorkers.get(j);
                        
                        if (worker.getWorkerId() == modifiedWorkers.get(i)) {
                            ints[i] = j;
                            break;
                        }
                    }
                }
                modifiedWorkers = null;
                
            } else {
                // Save selection
                ArrayList<Integer> indices = new ArrayList<Integer>();
                
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Selected signers: " + selectedWorkers);
                }
                for (Worker w : selectedWorkers) {
                    int index = newWorkers.indexOf(w);
                    if (index != -1) {
                        indices.add(index);
                    } else {
                        if (LOG.isDebugEnabled()) {
                            LOG.debug(w + " is not in " + selectedWorkers);
                        }
                    }
                }
                ints = new int[indices.size()];
                for (int i = 0; i < indices.size(); i++) {
                    ints[i] = indices.get(i);
                }
            }

            workersList.revalidate();
            workerComboBox.revalidate();
            workersList.setModel(new AbstractListModel() {

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
            workersList.setSelectedIndices(ints);
            if (LOG.isDebugEnabled()) {
                LOG.debug("Selecting: " + Arrays.toString(ints));
            }

            allWorkers = newWorkers;
        }
    }

    @Action(block = Task.BlockingScope.WINDOW)
    public Task activateWorkers() {
        return new ActivateWorkersTask(getApplication());
    }

    private class ActivateWorkersTask extends Task<String, Void> {

        private char[] authCode;
        private int[] selected;

        ActivateWorkersTask(org.jdesktop.application.Application app) {
            // Runs on the EDT.  Copy GUI state that
            // doInBackground() depends on from parameters
            // to ActivateWorkersTask fields, here.
            super(app);
            selected = workersList.getSelectedIndices();

            passwordPanelLabel.setText(
                    "Enter authentication code for all workers or leave empty:");
            passwordPanelField.setText("");
            passwordPanelField.grabFocus();

            int res = JOptionPane.showConfirmDialog(getFrame(), passwordPanel,
                    "Activate worker(s)", JOptionPane.OK_CANCEL_OPTION);


            if (res == JOptionPane.OK_OPTION) {
                authCode = passwordPanelField.getPassword();
            } else {
                authCode = null;
            }
        }
        @Override protected String doInBackground() {
            // Your Task's code here.  This method runs
            // on a background thread, so don't reference
            // the Swing GUI from here.
            String errors = null;
            if (authCode != null) {
                StringBuilder sb = new StringBuilder();
                int workers = 0;
                for (int row : selected) {
                    setProgress(workers, 0, selected.length);
                    final int workerId = allWorkers.get(row).getWorkerId();
                    try {
                        SignServerAdminGUIApplication.getAdminWS()
                                .activateSigner(workerId, new String(authCode));
                    } catch (final AdminNotAuthorizedException_Exception ex) {
                        final String error =
                                "Authorization denied activating worker "
                                + workerId;
                        sb.append(error);
                        sb.append("\n");
                        LOG.error(error, ex);
                    } catch (CryptoTokenAuthenticationFailureException_Exception ex) {
                        final String error =
                                "Authentication failure activating worker "
                                + workerId;
                        sb.append(error);
                        sb.append("\n");
                        LOG.error(error, ex);
                    } catch (CryptoTokenOfflineException_Exception ex) {
                        final String error =
                            "Crypto token offline failure activating worker "
                            + workerId;
                        sb.append(error);
                        sb.append("\n");
                        LOG.error(error, ex);
                    } catch (InvalidWorkerIdException_Exception ex) {
                        final String error =
                                "Invalid worker activating worker "
                                + workerId;
                        sb.append(error);
                        sb.append("\n");
                        LOG.error(error, ex);
                    } catch (EJBException ex) {
                        final String error =
                                "Error activating worker "
                                + workerId;
                        sb.append(error).append(": ").append(ex.getMessage());
                        sb.append("\n");
                        LOG.error(error, ex);
                    }
                    workers++;
                }
                errors = sb.toString();
            }
            return errors;  // return your result
        }
        @Override protected void succeeded(final String result) {
            // Runs on the EDT.  Update the GUI based on
            // the result computed by doInBackground().
            if (result != null) {
                if (result.length() > 0) {
                    JOptionPane.showMessageDialog(getFrame(), result,
                            "Activate workers", JOptionPane.ERROR_MESSAGE);
                }
                getContext().getTaskService().execute(refreshWorkers());
            }
            if (authCode != null) {
                for (int i = 0; i < authCode.length; i++) {
                    authCode[i] = 0;
                }
            }
        }
    }

    @Action(block = Task.BlockingScope.WINDOW)
    public Task deactivateWorkers() {
        return new DeactivateWorkersTask(getApplication());
    }

    private class DeactivateWorkersTask extends org.jdesktop.application.Task<String, Void> {

        private int[] selected;

        DeactivateWorkersTask(final Application app) {
            // Runs on the EDT.  Copy GUI state that
            // doInBackground() depends on from parameters
            // to DeactivateWorkersTask fields, here.
            super(app);
            selected = workersList.getSelectedIndices();
        }
        @Override protected String doInBackground() {
            // Your Task's code here.  This method runs
            // on a background thread, so don't reference
            // the Swing GUI from here.
            final StringBuilder sb = new StringBuilder();
            int workers = 0;
            setProgress(workers++, 0, selected.length);
            for (int row : selected) {
                final int workerId = allWorkers.get(row).getWorkerId();
                try {
                    SignServerAdminGUIApplication.getAdminWS()
                            .deactivateSigner(workerId);
                } catch (final AdminNotAuthorizedException_Exception ex) {
                        final String error =
                                "Authorization denied deactivating worker "
                                + workerId;
                        sb.append(error);
                        sb.append("\n");
                        LOG.error(error, ex);
                } catch (CryptoTokenOfflineException_Exception ex) {
                    final String error = "Error deactivating worker "
                            + workerId;
                    LOG.error(error, ex);
                    sb.append(error).append(": ").append(ex.getMessage());
                    sb.append("\n");
                } catch (InvalidWorkerIdException_Exception ex) {
                    final String error = "Error deactivating worker "
                            + workerId;
                    LOG.error(error, ex);
                    LOG.error(error, ex);
                    sb.append(error).append(": ").append(ex.getMessage());
                    sb.append("\n");
                } catch (EJBException ex) {
                    final String error = "Error deactivating worker "
                            + workerId;
                    LOG.error(error, ex);
                    sb.append(error).append(": ").append(ex.getMessage());
                    sb.append(error);
                    sb.append("\n");
                }
                setProgress(workers++, 0, selected.length);
            }
            return sb.toString();  // return your result
        }
        @Override protected void succeeded(final String result) {
            // Runs on the EDT.  Update the GUI based on
            // the result computed by doInBackground().
            if (result.length() > 0) {
                JOptionPane.showMessageDialog(getFrame(), result,
                            "Deactivate workers", JOptionPane.ERROR_MESSAGE);
            }
            getContext().getTaskService().execute(refreshWorkers());
        }
    }

    @Action
    public void renewKeys() {
        if (selectedWorkers.size() > 0) {
            RenewKeysDialog dlg = new RenewKeysDialog(getFrame(),
                    true, selectedWorkers);
            if (dlg.showRequestsDialog() == RenewKeysDialog.OK) {
                getContext().getTaskService().execute(refreshWorkers());
            }
        }
    }

    @Action
    public void testKeys() {
        if (selectedWorkers.size() > 0) {
            TestKeysDialog dlg = new TestKeysDialog(getFrame(),
                    true, selectedWorkers);
            dlg.showRequestsDialog();
        }
    }

    @Action
    public void generateRequests() {

        if (selectedWorkers.size() > 0) {
            GenerateRequestsDialog dlg = new GenerateRequestsDialog(getFrame(),
                    true, selectedWorkers, allWorkers, getResourceMap());
            if (dlg.showRequestsDialog() == GenerateRequestsDialog.OK) {
                getContext().getTaskService().execute(refreshWorkers());
            }
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
        if (selectedWorkers.size() > 0) {
            InstallCertificatesDialog dlg = new InstallCertificatesDialog(
                    getFrame(), true, selectedWorkers);
            if (dlg.showDialog() == InstallCertificatesDialog.OK) {
                getContext().getTaskService().execute(refreshWorkers());
            }
        }
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

    private Properties asProperties(WsWorkerConfig config) {
        final Properties result = new Properties();
        for(WsWorkerConfig.Properties.Entry entry
                : config.getProperties().getEntry()) {
            result.setProperty((String) entry.getKey(),
                    (String) entry.getValue());
        }
        return result;
    }

    private X509Certificate asCertificate(final byte[] certbytes)
            throws CertificateException {
        final X509Certificate result;
        if (certbytes == null || certbytes.length == 0) {
            result = null;
        } else {
            result = (X509Certificate) CertTools.getCertfromByteArray(certbytes);
        }
        return result;
    }

    private Collection<X509Certificate> asCertificates(
            final Collection<byte[]> certs) throws CertificateException {
        final LinkedList<X509Certificate> results;
        if (certs == null || certs.size() < 1) {
            results = null;
        } else {
            results = new LinkedList<X509Certificate>();
            for (byte[] certbytes : certs) {
                X509Certificate cert = null;
                if (certbytes != null && certbytes.length > 0) {
                    cert = asCertificate(certbytes);
                }
                results.add(cert);
            }
        }
        return results;
    }

    private void postAdminNotAuthorized(
            final AdminNotAuthorizedException_Exception ex) {
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                JOptionPane.showMessageDialog(
                        MainView.this.getFrame(), ex.getMessage(),
                "Authorization denied", JOptionPane.ERROR_MESSAGE);
            }
        });
    }

    @Action
    public void renewSigner() {
        if (selectedWorkers.size() > 0) {
            RenewSignerDialog dlg = new RenewSignerDialog(
                    getFrame(), true, allWorkers, selectedWorkers);
            if (dlg.showDialog() == RenewSignerDialog.OK) {
                getContext().getTaskService().execute(refreshWorkers());
            }
        }
    }

    @Action(block = Task.BlockingScope.COMPONENT)
    public Task auditlogReload() {
        return new AuditlogReloadTask(getApplication());
    }

    private class AuditlogReloadTask extends org.jdesktop.application.Task<List<LogEntry>, Void> {
        
        private int startIndex;
        private int maxEntries;
        private Exception exception;
        
        AuditlogReloadTask(org.jdesktop.application.Application app) {
            // Runs on the EDT.  Copy GUI state that
            // doInBackground() depends on from parameters
            // to AuditlogReloadTask fields, here.
            super(app);
            
            startIndex = Integer.parseInt(auditlogStartIndexTextfield.getText()) - 1;
            maxEntries = Integer.parseInt(auditlogMaxEntriesTextfield.getText());
            
        }
        @Override protected List<LogEntry> doInBackground() {
            try {
                // Your Task's code here.  This method runs
                // on a background thread, so don't reference
                // the Swing GUI from here.
                final ArrayList<QueryCondition> conditions = new ArrayList<QueryCondition>(conditionsModel.getEntries());
                final QueryOrdering order = new QueryOrdering();
                order.setColumn(AuditRecordData.FIELD_TIMESTAMP);
                order.setOrder(Order.DESC);
                return SignServerAdminGUIApplication.getAdminWS().queryAuditLog(startIndex, maxEntries, conditions, Collections.singletonList(order));
            } catch (AdminNotAuthorizedException_Exception ex) {
                exception = ex;
            } catch (SignServerException_Exception ex) {
                exception = ex;
            } catch (Exception ex) {
                LOG.error("Reload failed", ex);
                exception = ex;
            }
            return null;
        }
        @Override protected void succeeded(List<LogEntry> result) {
            // Runs on the EDT.  Update the GUI based on
            // the result computed by doInBackground().
            final CardLayout layout = (CardLayout) auditlogPanel.getLayout();
            if (result == null) {
                result = Collections.emptyList();
                auditlogDisplayingToIndex.setText("to " + (startIndex + maxEntries)); // We pretend we got all entries
                auditlogNextButton.setEnabled(true);
                layout.show(auditlogPanel, "auditlogErrorCard");
                auditLogTable.setEnabled(false);
                auditlogTableScrollPane.setEnabled(false);
            } else {
                auditlogDisplayingToIndex.setText("to " + (startIndex + result.size()));
                auditlogNextButton.setEnabled(result.size() >= maxEntries);
                layout.show(auditlogPanel, "auditlogTableCard");
                auditLogTable.setEnabled(true);
                auditlogTableScrollPane.setEnabled(false);
            }
            auditlogModel.setEntries(result);
            
            auditlogFirstButton.setEnabled(startIndex > 0);
            auditlogPreviousButton.setEnabled(startIndex > 0);
            
            if (exception != null) {
                auditlogErrorEditor.setText(new StringBuilder().append("Reload failed within the selected interval:\n\n").append(exception.getMessage()).toString());
            }
        }
    }

    @Action(block = Task.BlockingScope.WINDOW)
    public Task removeWorkers() {
        return new RemoveWorkersTask(getApplication());
    }

    private class RemoveWorkersTask extends org.jdesktop.application.Task<Integer, Void> {
        
        final List<Worker> workers;
        final StringBuilder errors = new StringBuilder();
        
        RemoveWorkersTask(org.jdesktop.application.Application app) {
            // Runs on the EDT.  Copy GUI state that
            // doInBackground() depends on from parameters
            // to RemoveWorkersTask fields, here.
            super(app);
            if (!selectedWorkers.isEmpty() && JOptionPane.showConfirmDialog(getFrame(), 
                    "Are you sure you want to remove " + selectedWorkers.size() + " worker(s)?",
                    "Remove worker(s)", JOptionPane.YES_NO_CANCEL_OPTION,
                    JOptionPane.QUESTION_MESSAGE) == JOptionPane.YES_OPTION) {
                workers = selectedWorkers;
            } else {
                workers = Collections.emptyList();
            }
        }
        @Override protected Integer doInBackground() {
            // Your Task's code here.  This method runs
            // on a background thread, so don't reference
            // the Swing GUI from here.
            Integer result = null;
            WsGlobalConfiguration globalConfiguration;
            try {
                setProgress(0);
                globalConfiguration = SignServerAdminGUIApplication.getAdminWS().getGlobalConfiguration();
                setProgress(50);
                
                if (!workers.isEmpty()) {
                    int removed = 0;
                    int i = 0;
                    for (Worker worker : workers) {
                        setProgress(i, 0, workers.size());
                        try {
                            removeWorker(worker, globalConfiguration);
                            removed++;
                        } catch (AdminNotAuthorizedException_Exception ex) {
                            errors.append("Removing worker ").append(worker.getName()).append(": ").append(ex.getMessage()).append("\n");
                        }
                        i++;
                    }
                    result = removed;
                }
            } catch (final AdminNotAuthorizedException_Exception ex) {
                SwingUtilities.invokeLater(new Runnable() {
                    @Override
                    public void run() {
                        JOptionPane.showMessageDialog(getFrame(), 
                                "Could not get global configuration:\n" + ex.getMessage(),
                                "Authorization denied", JOptionPane.ERROR_MESSAGE);
                    }
                });
            }
            return result;  // return your result
        }
        @Override protected void succeeded(Integer result) {
            // Runs on the EDT.  Update the GUI based on
            // the result computed by doInBackground().
            if (result != null && result > 0) {
                errors.append("Removed ").append(result).append(" worker(s)");
                JOptionPane.showMessageDialog(getFrame(), errors.toString());
                getContext().getTaskService().execute(refreshWorkers());
            }
        }

        private void removeWorker(Worker worker, WsGlobalConfiguration gc) throws AdminNotAuthorizedException_Exception {
            // Remove global properties
            for (WsGlobalConfiguration.Config.Entry entry : gc.getConfig().getEntry()) {
                if (entry.getKey() instanceof String) {
                    String key = (String) entry.getKey();
                    if (key.toUpperCase().startsWith("GLOB.WORKER" + worker.getWorkerId())) {
                        key = key.substring("GLOB.".length());
                        if (SignServerAdminGUIApplication.getAdminWS().removeGlobalProperty(GlobalConfiguration.SCOPE_GLOBAL, key)) {
                            if (LOG.isDebugEnabled()) {
                                LOG.debug("  Global property '" + key + "' removed successfully.");
                            }
                        } else {
                            if (LOG.isDebugEnabled()) {
                                LOG.debug("  Failed removing global property '" + key + "'.");
                            }
                        }
                    }
                }
            }
            // Remove worker properties
            for (final String property : worker.getConfiguration().stringPropertyNames()) {
                if (SignServerAdminGUIApplication.getAdminWS().removeWorkerProperty(worker.getWorkerId(), property)) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("  Property '" + property + "' removed.");
                    }
                } else {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("  Error, the property '" + property + "' couldn't be removed.");
                    }
                }
            }
        }
    }

    @Action(block = Task.BlockingScope.WINDOW)
    public Task removeKey() {
        return new RemoveKeyTask(getApplication());
    }
    
    private class RemoveKeyTask extends Task<Boolean, Void> {
        private final String alias;
        private final boolean proceed;
        private final int workerId;
        private String errorMessage;
        
        public RemoveKeyTask(Application application) {
            super(application);
            Object selected = workersList.getSelectedValue();
            if (selected instanceof Worker) {
                workerId = ((Worker) selected).getWorkerId();

                aliasTextField.setText("");
                int res = JOptionPane.showConfirmDialog(getFrame(), removeKeyPanel,
                        "Remove key", JOptionPane.OK_CANCEL_OPTION);
                alias = aliasTextField.getText();
                if (res == JOptionPane.OK_OPTION && !alias.isEmpty()) {
                    res = JOptionPane.showConfirmDialog(getFrame(), 
                            "WARNING: Will attempt to permantently remove the following key:\n" +
                            alias + "\n" +
                            "\n" +
                            "Note: the key might be used by multiple workers.\n" +
                            "Are you sure you want to try to destroy the key?",
                        "Confirm key destruction", JOptionPane.YES_NO_CANCEL_OPTION);

                    proceed = res == JOptionPane.YES_OPTION;
                } else {
                    proceed = false;
                }
            } else {
                alias = null;
                proceed = false;
                workerId = 0;
            }
        }
        
        @Override
        protected Boolean doInBackground() throws Exception {
            if (!proceed) {
                return null;
            }
            setMessage("Requesting key to be deleted");
            boolean success = false;
            try {
                success = SignServerAdminGUIApplication.getAdminWS().removeKey(workerId, alias);
            } catch (AdminNotAuthorizedException_Exception ex) {
                errorMessage = "Authorization denied:\n" + ex.getLocalizedMessage();
            } catch (CryptoTokenOfflineException_Exception ex) {
                errorMessage = "Unable to remove key because token was not active:\n" + ex.getLocalizedMessage();
            } catch (InvalidWorkerIdException_Exception ex) {
                errorMessage = "Unable to remove key:\n" + ex.getLocalizedMessage();
            } catch (KeyStoreException_Exception ex) {
                errorMessage = "Unable to remove key:\n" + ex.getLocalizedMessage();
            } catch (SignServerException_Exception ex) {
                errorMessage = "Unable to remove key:\n" + ex.getLocalizedMessage();
            }
            return success;
        }

        @Override
        protected void succeeded(Boolean success) {
            if (success != null) {
                if (errorMessage == null) {
                    JOptionPane.showMessageDialog(MainView.this.getFrame(), 
                            success ? "Removal succeeded" : "Removal failed", "Removal result", success ? JOptionPane.INFORMATION_MESSAGE : JOptionPane.ERROR_MESSAGE);
                } else {
                    JOptionPane.showMessageDialog(MainView.this.getFrame(), 
                            errorMessage, "Removal failed", JOptionPane.ERROR_MESSAGE);
                }
            }
        }
    }

    @Action(block = Task.BlockingScope.APPLICATION)
    public Task reloadFromDatabase() {
        return new ReloadFromDatabaseTask(getApplication());
    }

    private class ReloadFromDatabaseTask extends org.jdesktop.application.Task<String, Void> {
        
        private final int[] selected;
        private final boolean confirmed;
        private final boolean reloadAll;
        
        ReloadFromDatabaseTask(org.jdesktop.application.Application app) {
            // Runs on the EDT.  Copy GUI state that
            // doInBackground() depends on from parameters
            // to ReloadFromDatabaseTask fields, here.
            super(app);
            selected = workersList.getSelectedIndices();
            
            reloadSelectedWorkersRadioButton.setEnabled(selected.length > 0);
            reloadSelectedWorkersRadioButton.setSelected(selected.length > 0);
            reloadAllWorkersRadioButton.setSelected(selected.length == 0);
            confirmed = JOptionPane.showConfirmDialog(MainView.this.getFrame(), reloadPanel, "Reload from database", JOptionPane.OK_CANCEL_OPTION) == JOptionPane.OK_OPTION;
            reloadAll = reloadAllWorkersRadioButton.isSelected();
        }
        @Override protected String doInBackground() {
            // Your Task's code here.  This method runs
            // on a background thread, so don't reference
            // the Swing GUI from here.
            try {
                if (confirmed) {
                    if (reloadAll) {
                        setMessage("Reloading global configuration...");
                        SignServerAdminGUIApplication.getAdminWS().reloadConfiguration(0);
                    } else {
                        int current = 0;
                        for (int row : selected) {
                            setMessage("Reloading worker " + (current + 1) + " of " + selected.length + "...");
                            setProgress(current, 0, selected.length);
                            final int workerId = allWorkers.get(row).getWorkerId();
                            SignServerAdminGUIApplication.getAdminWS().reloadConfiguration(workerId);
                            current++;
                        }
                    }
                    return "Configuration reloaded";
                }
            } catch (AdminNotAuthorizedException_Exception ex) {
                postAdminNotAuthorized(ex);
            }
            
            return null;  // return your result
        }
        @Override protected void succeeded(String result) {
            // Runs on the EDT.  Update the GUI based on
            // the result computed by doInBackground().
            if (result != null) {
                JOptionPane.showMessageDialog(MainView.this.getFrame(), result, "Reload from database", JOptionPane.INFORMATION_MESSAGE);
            }
            if (confirmed) {
                refreshButton.doClick();
            }
        }
    }

    @Action(block = Task.BlockingScope.WINDOW)
    public Task exportConfig() {
        return new ExportConfigTask(getApplication());
    }

    private class ExportConfigTask extends org.jdesktop.application.Task<String, Void> {
        
        private final int[] selected;
        private final boolean confirmed;
        private final boolean exportAllUnrelatedGlobal;
        private final boolean exportAll;
        private final boolean exportSelected;
        private final boolean exportNone;
        
        private final File file;
        
        private boolean success;
        
        ExportConfigTask(org.jdesktop.application.Application app) {
            // Runs on the EDT.  Copy GUI state that
            // doInBackground() depends on from parameters
            // to ExportConfigTask fields, here.
            super(app);
            selected = workersList.getSelectedIndices();
            
            exportSelectedRadioButton.setEnabled(selected.length > 0);
            exportSelectedRadioButton.setSelected(selected.length > 0);
            exportAllRadioButton.setSelected(selected.length == 0);
            exportAllUnrelatedGlobalCheckbox.setSelected(false);
            exportAllUnrelatedGlobalCheckbox.setEnabled(true);
            exportAllUnrelatedPreviousValue = false;
            final boolean firstConfirm = JOptionPane.showConfirmDialog(MainView.this.getFrame(), exportPanel, "Export configuration", JOptionPane.OK_CANCEL_OPTION) == JOptionPane.OK_OPTION;
            exportAll = exportAllRadioButton.isSelected();
            exportSelected = exportSelectedRadioButton.isSelected();
            exportNone = exportNoRadioButton.isSelected();
            exportAllUnrelatedGlobal = exportAllUnrelatedGlobalCheckbox.isSelected();
            
            if (firstConfirm) {
                final JFileChooser chooser = new JFileChooser();
                final File baseDir = SignServerAdminGUIApplication.getBaseDir();
                final String basedirPath = baseDir.getAbsolutePath();
                final File sampleDir =
                        new File(basedirPath + File.separator + "doc" + File.separator +
                                 "sample-configs");

                chooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
                chooser.setCurrentDirectory(sampleDir.isDirectory() ? sampleDir : baseDir);
                chooser.setMultiSelectionEnabled(false);
                chooser.setFileFilter(new FileNameExtensionFilter("Properties files", "properties"));
                
                confirmed = chooser.showSaveDialog(MainView.this.getFrame()) == JFileChooser.APPROVE_OPTION;
                file = chooser.getSelectedFile();
            } else {
                confirmed = false;
                file = null;
            }
        }
        @Override protected String doInBackground() {
            // Your Task's code here.  This method runs
            // on a background thread, so don't reference
            // the Swing GUI from here.
            if (!confirmed) {
                return null;
            }
            
            OutputStream out = null;
            try {
                Properties globalConfig = toProperties(SignServerAdminGUIApplication.getAdminWS().getGlobalConfiguration());
                Properties outProperties = new Properties();
                
                if (exportAllUnrelatedGlobal) {
                    setMessage("Global configuration...");
                    PropertiesDumper.dumpNonWorkerSpecificGlobalConfiguration(globalConfig, outProperties);
                }
                
                final List<Worker> workers;
                if (exportAll) {
                    workers = allWorkers;
                } else if (exportSelected) {
                    workers = new ArrayList<Worker>();
                    for (int row : selected) {
                        workers.add(allWorkers.get(row));
                    }
                } else {
                    workers = Collections.emptyList();
                }
                
                int current = 0;
                for (Worker worker : workers) {
                    setMessage("Worker " + (current + 1) + " of " + workers.size() + "...");
                    setProgress(current, 0, workers.size());
                    PropertiesDumper.dumpWorkerProperties(worker.getWorkerId(), globalConfig, worker.getConfiguration(), outProperties);
                    current++;
                }
                
                // Write the properties
                out = new FileOutputStream(file);
                outProperties.store(out, null);
                success = true;
                final StringBuilder result = new StringBuilder();
                result.append("Exported ").append(outProperties.size()).append(" properties from ").append(workers.size()).append( " workers.");
                return result.toString();
            } catch (AdminNotAuthorizedException_Exception ex) {
                return "Authorization denied:\n" + ex.getLocalizedMessage();
            } catch (CertificateEncodingException ex) {
                return "Failed to encode certificate:\n" + ex.getLocalizedMessage();
            } catch (FileNotFoundException ex) {
                return "The selected file could not be written:\n" + ex.getLocalizedMessage();
            } catch (IOException ex) {
                return "Failed to write the properties to file:\n" + ex.getLocalizedMessage();
            } finally {
                IOUtils.closeQuietly(out);
            }
        }
        @Override protected void succeeded(String result) {
            // Runs on the EDT.  Update the GUI based on
            // the result computed by doInBackground().
            if (confirmed) {
                JOptionPane.showMessageDialog(MainView.this.getFrame(), result, "Export configuration", success ? JOptionPane.INFORMATION_MESSAGE : JOptionPane.ERROR_MESSAGE);
            }
        }

        private Properties toProperties(WsGlobalConfiguration wsgc) {
            final Properties result = new Properties();
            for (WsGlobalConfiguration.Config.Entry entry : wsgc.getConfig().getEntry()) {
                result.put(entry.getKey(), entry.getValue());
            }
            return result;
        }
    }




    // Variables declaration - do not modify//GEN-BEGIN:variables
    javax.swing.JButton activateButton;
    javax.swing.JMenuItem activateMenu;
    javax.swing.JButton addButton;
    javax.swing.JMenuItem addWorkerItem;
    javax.swing.JMenuItem administratorsMenu;
    javax.swing.JTextField aliasTextField;
    javax.swing.JTable auditLogTable;
    javax.swing.JPanel auditPanel;
    javax.swing.JLabel auditlogDisplayingToIndex;
    javax.swing.JEditorPane auditlogErrorEditor;
    javax.swing.JPanel auditlogErrorPanel;
    javax.swing.JButton auditlogFirstButton;
    javax.swing.JTextField auditlogMaxEntriesTextfield;
    javax.swing.JButton auditlogNextButton;
    javax.swing.JPanel auditlogPanel;
    javax.swing.JButton auditlogPreviousButton;
    javax.swing.JButton auditlogReloadButton;
    javax.swing.JTextField auditlogStartIndexTextfield;
    javax.swing.JPanel auditlogTablePanel;
    javax.swing.JScrollPane auditlogTableScrollPane;
    javax.swing.JButton authAddButton;
    javax.swing.JButton authEditButton;
    javax.swing.JPanel authEditPanel;
    javax.swing.JButton authRemoveButton;
    javax.swing.JTable authTable;
    javax.swing.JPanel authorizationTab;
    javax.swing.JMenuItem authorizationsMenu;
    javax.swing.JTable conditionsTable;
    javax.swing.JMenuItem configurationMenu;
    javax.swing.JPanel configurationTab;
    javax.swing.JTable configurationTable;
    javax.swing.JButton deactivateButton;
    javax.swing.JMenuItem deactivateMenu;
    javax.swing.JButton editButton;
    javax.swing.JTextField editIssuerDNTextfield;
    javax.swing.JMenu editMenu;
    javax.swing.JPanel editPanel;
    javax.swing.JTextField editPropertyTextField;
    javax.swing.JTextArea editPropertyValueTextArea;
    javax.swing.JTextField editSerialNumberTextfield;
    javax.swing.JCheckBox editUpdateAllCheckbox;
    javax.swing.JRadioButton exportAllRadioButton;
    javax.swing.JCheckBox exportAllUnrelatedGlobalCheckbox;
    javax.swing.JMenuItem exportMenuItem;
    javax.swing.JRadioButton exportNoRadioButton;
    javax.swing.JPanel exportPanel;
    javax.swing.ButtonGroup exportPanelButtonGroup;
    javax.swing.JRadioButton exportSelectedRadioButton;
    javax.swing.JMenuItem generateRequestMenu;
    javax.swing.JButton generateRequestsButton;
    javax.swing.JMenuItem globalConfigurationMenu;
    javax.swing.JButton installCertificatesButton;
    javax.swing.JMenuItem installCertificatesMenu;
    javax.swing.JButton jButtonAuditConditionAdd;
    javax.swing.JButton jButtonAuditConditionRemove;
    javax.swing.JEditorPane jEditorPane1;
    javax.swing.JLabel jLabel1;
    javax.swing.JLabel jLabel10;
    javax.swing.JLabel jLabel2;
    javax.swing.JLabel jLabel3;
    javax.swing.JLabel jLabel4;
    javax.swing.JLabel jLabel5;
    javax.swing.JLabel jLabel6;
    javax.swing.JLabel jLabel7;
    javax.swing.JLabel jLabel8;
    javax.swing.JLabel jLabel9;
    javax.swing.JPanel jPanel1;
    javax.swing.JPanel jPanel2;
    javax.swing.JPanel jPanel3;
    javax.swing.JScrollPane jScrollPane1;
    javax.swing.JScrollPane jScrollPane2;
    javax.swing.JScrollPane jScrollPane3;
    javax.swing.JScrollPane jScrollPane5;
    javax.swing.JScrollPane jScrollPane6;
    javax.swing.JScrollPane jScrollPane7;
    javax.swing.JToolBar.Separator jSeparator1;
    javax.swing.JToolBar.Separator jSeparator2;
    javax.swing.JPopupMenu.Separator jSeparator3;
    javax.swing.JPopupMenu.Separator jSeparator4;
    javax.swing.JPopupMenu.Separator jSeparator5;
    javax.swing.JToolBar.Separator jSeparator6;
    javax.swing.JPopupMenu.Separator jSeparator7;
    javax.swing.JPopupMenu.Separator jSeparator8;
    javax.swing.JPopupMenu.Separator jSeparator9;
    javax.swing.JSplitPane jSplitPane1;
    javax.swing.JSplitPane jSplitPane2;
    javax.swing.JTabbedPane jTabbedPane1;
    javax.swing.JToolBar jToolBar1;
    javax.swing.JButton loadCertButton;
    javax.swing.JPanel mainPanel;
    javax.swing.JMenuBar menuBar;
    javax.swing.JPanel passwordPanel;
    javax.swing.JPasswordField passwordPanelField;
    javax.swing.JLabel passwordPanelLabel;
    private javax.swing.JProgressBar progressBar;
    javax.swing.JTable propertiesTable;
    javax.swing.JButton refreshButton;
    javax.swing.JMenuItem refreshMenu;
    javax.swing.JRadioButton reloadAllWorkersRadioButton;
    javax.swing.JMenuItem reloadMenu;
    javax.swing.JPanel reloadPanel;
    javax.swing.ButtonGroup reloadPanelButtonGroup;
    javax.swing.JRadioButton reloadSelectedWorkersRadioButton;
    javax.swing.JButton removeButton;
    javax.swing.JMenuItem removeKeyMenu;
    javax.swing.JPanel removeKeyPanel;
    javax.swing.JMenuItem removeWorkerMenu;
    javax.swing.JButton renewKeyButton;
    javax.swing.JMenuItem renewKeyMenu;
    javax.swing.JButton renewSignerButton;
    javax.swing.JMenuItem renewSignerMenu;
    private javax.swing.JLabel statusAnimationLabel;
    private javax.swing.JLabel statusMessageLabel;
    javax.swing.JPanel statusPanel;
    javax.swing.JButton statusPropertiesDetailsButton;
    javax.swing.JMenuItem statusPropertiesMenu;
    javax.swing.JScrollPane statusPropertiesScrollPane;
    javax.swing.JPanel statusPropertiesTab;
    javax.swing.JMenuItem statusSummaryMenu;
    javax.swing.JScrollPane statusSummaryTab;
    javax.swing.JTextPane statusSummaryTextPane;
    javax.swing.JButton testKeyButton;
    javax.swing.JMenuItem testKeyMenu;
    javax.swing.JMenu viewMenu;
    javax.swing.JComboBox workerComboBox;
    javax.swing.JTabbedPane workerTabbedPane;
    javax.swing.JList workersList;
    // End of variables declaration//GEN-END:variables

    private final Timer messageTimer;
    private final Timer busyIconTimer;
    private final Icon idleIcon;
    private final Icon[] busyIcons = new Icon[15];
    private int busyIconIndex = 0;

    private JDialog aboutBox;
}
