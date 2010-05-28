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
import org.jdesktop.application.SingleFrameApplication;
import org.jdesktop.application.FrameView;
import org.jdesktop.application.Task;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.List;
import java.util.Vector;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.Icon;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.Timer;
import javax.swing.event.ListSelectionListener;
import javax.swing.table.DefaultTableModel;
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

    private Vector<Vector<Object>> workersList
            = new Vector<Vector<Object>>();

    private Vector<String> columnNames = new Vector<String>();

    private DefaultTableModel workersModel;
    

    public MainView(SingleFrameApplication app) {
        super(app);

        columnNames.add("Status");
        columnNames.add("Id");
        columnNames.add("Name");

        initComponents();

        jTable1.getSelectionModel().addListSelectionListener(new ListSelectionListener() {

            public void valueChanged(ListSelectionEvent e) {
                if (!e.getValueIsAdjusting()) {
                    final boolean active = jTable1.getSelectedRowCount() > 0;
                    autorizationsButton.setEnabled(active);
                    authorizationsMenu.setEnabled(active);
                    statusButton.setEnabled(active);
                    statusMenu.setEnabled(active);
                    activateButton.setEnabled(active);
                    activateMenu.setEnabled(active);
                    deactivateButton.setEnabled(active);
                    deactivateMenu.setEnabled(active);
                    generateRequestsButton.setEnabled(active);
                    generateRequestMenu.setEnabled(active);
                    installCertificatesButton.setEnabled(active);
                    installCertificatesMenu.setEnabled(active);
                }
            }
        });

        workersModel = new DefaultTableModel(workersList, columnNames) {

            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }

        };

        jTable1.setModel(workersModel);


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
        jScrollPane1 = new javax.swing.JScrollPane();
        jTable1 = new javax.swing.JTable();
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
        authorizationsMenu = new javax.swing.JMenuItem();
        javax.swing.JMenu helpMenu = new javax.swing.JMenu();
        javax.swing.JMenuItem aboutMenuItem = new javax.swing.JMenuItem();
        jToolBar1 = new javax.swing.JToolBar();
        jButtonRefresh1 = new javax.swing.JButton();
        jSeparator1 = new javax.swing.JToolBar.Separator();
        statusPanel = new javax.swing.JPanel();
        statusMessageLabel = new javax.swing.JLabel();
        statusAnimationLabel = new javax.swing.JLabel();
        progressBar = new javax.swing.JProgressBar();
        activateButton = new javax.swing.JButton();
        deactivateButton = new javax.swing.JButton();
        statusButton = new javax.swing.JButton();
        generateRequestsButton = new javax.swing.JButton();
        installCertificatesButton = new javax.swing.JButton();
        autorizationsButton = new javax.swing.JButton();

        mainPanel.setName("mainPanel"); // NOI18N

        jScrollPane1.setName("jScrollPane1"); // NOI18N

        jTable1.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {
                {"ACTIVE", "SODSigner", "70"},
                {"OFFLINE", "Sod1", "71"},
                {"OFFLINE", "Sod2", "72"},
                {"OFFLINE", "Sod3", "73"},
                {"OFFLINE", "Sod4", "74"},
                {"OFFLINE", "Sod5", "75"}
            },
            new String [] {
                "Status", "Name", "ID"
            }
        ) {
            boolean[] canEdit = new boolean [] {
                false, false, false
            };

            public boolean isCellEditable(int rowIndex, int columnIndex) {
                return canEdit [columnIndex];
            }
        });
        jTable1.setAutoResizeMode(javax.swing.JTable.AUTO_RESIZE_LAST_COLUMN);
        jTable1.setName("jTable1"); // NOI18N
        jScrollPane1.setViewportView(jTable1);

        javax.swing.GroupLayout mainPanelLayout = new javax.swing.GroupLayout(mainPanel);
        mainPanel.setLayout(mainPanelLayout);
        mainPanelLayout.setHorizontalGroup(
            mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(mainPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 824, Short.MAX_VALUE)
                .addContainerGap())
        );
        mainPanelLayout.setVerticalGroup(
            mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(mainPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 468, Short.MAX_VALUE))
        );

        menuBar.setName("menuBar"); // NOI18N

        fileMenu.setMnemonic('F');
        org.jdesktop.application.ResourceMap resourceMap = org.jdesktop.application.Application.getInstance(org.signserver.admin.gui.SignServerAdminGUIApplication.class).getContext().getResourceMap(MainView.class);
        fileMenu.setText(resourceMap.getString("fileMenu.text")); // NOI18N
        fileMenu.setName("fileMenu"); // NOI18N

        javax.swing.ActionMap actionMap = org.jdesktop.application.Application.getInstance(org.signserver.admin.gui.SignServerAdminGUIApplication.class).getContext().getActionMap(MainView.class, this);
        exitMenuItem.setAction(actionMap.get("quit")); // NOI18N
        exitMenuItem.setName("exitMenuItem"); // NOI18N
        fileMenu.add(exitMenuItem);

        menuBar.add(fileMenu);

        editMenu.setAction(actionMap.get("installCertificates")); // NOI18N
        editMenu.setMnemonic('E');
        editMenu.setText(resourceMap.getString("editMenu.text")); // NOI18N
        editMenu.setName("editMenu"); // NOI18N

        activateMenu.setAction(actionMap.get("activateWorkers")); // NOI18N
        activateMenu.setText(resourceMap.getString("activateMenu.text")); // NOI18N
        activateMenu.setEnabled(false);
        activateMenu.setName("activateMenu"); // NOI18N
        editMenu.add(activateMenu);

        deactivateMenu.setAction(actionMap.get("deactivateWorkers")); // NOI18N
        deactivateMenu.setText(resourceMap.getString("deactivateMenu.text")); // NOI18N
        deactivateMenu.setEnabled(false);
        deactivateMenu.setName("deactivateMenu"); // NOI18N
        editMenu.add(deactivateMenu);

        generateRequestMenu.setAction(actionMap.get("generateRequests")); // NOI18N
        generateRequestMenu.setText(resourceMap.getString("generateRequestMenu.text")); // NOI18N
        generateRequestMenu.setEnabled(false);
        generateRequestMenu.setName("generateRequestMenu"); // NOI18N
        editMenu.add(generateRequestMenu);

        installCertificatesMenu.setAction(actionMap.get("installCertificates")); // NOI18N
        installCertificatesMenu.setText(resourceMap.getString("installCertificatesMenu.text")); // NOI18N
        installCertificatesMenu.setEnabled(false);
        installCertificatesMenu.setName("installCertificatesMenu"); // NOI18N
        editMenu.add(installCertificatesMenu);

        menuBar.add(editMenu);

        viewMenu.setAction(actionMap.get("viewAuthorizations")); // NOI18N
        viewMenu.setMnemonic('V');
        viewMenu.setText(resourceMap.getString("viewMenu.text")); // NOI18N
        viewMenu.setName("viewMenu"); // NOI18N

        refreshMenu.setAction(actionMap.get("refreshWorkers")); // NOI18N
        refreshMenu.setText(resourceMap.getString("refreshMenu.text")); // NOI18N
        refreshMenu.setName("refreshMenu"); // NOI18N
        viewMenu.add(refreshMenu);

        statusMenu.setAction(actionMap.get("showStatuses")); // NOI18N
        statusMenu.setText(resourceMap.getString("statusMenu.text")); // NOI18N
        statusMenu.setEnabled(false);
        statusMenu.setName("statusMenu"); // NOI18N
        viewMenu.add(statusMenu);

        authorizationsMenu.setAction(actionMap.get("viewAuthorizations")); // NOI18N
        authorizationsMenu.setText(resourceMap.getString("authorizationsMenu.text")); // NOI18N
        authorizationsMenu.setEnabled(false);
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

        jButtonRefresh1.setAction(actionMap.get("refreshWorkers")); // NOI18N
        jButtonRefresh1.setText(resourceMap.getString("jButtonRefresh1.text")); // NOI18N
        jButtonRefresh1.setFocusable(false);
        jButtonRefresh1.setHorizontalTextPosition(javax.swing.SwingConstants.CENTER);
        jButtonRefresh1.setName("jButtonRefresh1"); // NOI18N
        jButtonRefresh1.setVerticalTextPosition(javax.swing.SwingConstants.BOTTOM);
        jToolBar1.add(jButtonRefresh1);

        jSeparator1.setName("jSeparator1"); // NOI18N
        jToolBar1.add(jSeparator1);

        statusPanel.setName("statusPanel"); // NOI18N
        statusPanel.setPreferredSize(new java.awt.Dimension(588, 68));

        statusMessageLabel.setName("statusMessageLabel"); // NOI18N

        statusAnimationLabel.setHorizontalAlignment(javax.swing.SwingConstants.LEFT);
        statusAnimationLabel.setName("statusAnimationLabel"); // NOI18N

        progressBar.setName("progressBar"); // NOI18N

        activateButton.setAction(actionMap.get("activateWorkers")); // NOI18N
        activateButton.setText(resourceMap.getString("activateButton.text")); // NOI18N
        activateButton.setEnabled(false);
        activateButton.setName("activateButton"); // NOI18N

        deactivateButton.setAction(actionMap.get("deactivateWorkers")); // NOI18N
        deactivateButton.setText(resourceMap.getString("deactivateButton.text")); // NOI18N
        deactivateButton.setEnabled(false);
        deactivateButton.setName("deactivateButton"); // NOI18N

        statusButton.setAction(actionMap.get("showStatuses")); // NOI18N
        statusButton.setText(resourceMap.getString("statusButton.text")); // NOI18N
        statusButton.setEnabled(false);
        statusButton.setName("statusButton"); // NOI18N

        generateRequestsButton.setAction(actionMap.get("generateRequests")); // NOI18N
        generateRequestsButton.setText(resourceMap.getString("generateRequestsButton.text")); // NOI18N
        generateRequestsButton.setEnabled(false);
        generateRequestsButton.setName("generateRequestsButton"); // NOI18N

        installCertificatesButton.setAction(actionMap.get("installCertificates")); // NOI18N
        installCertificatesButton.setText(resourceMap.getString("installCertificatesButton.text")); // NOI18N
        installCertificatesButton.setEnabled(false);
        installCertificatesButton.setName("installCertificatesButton"); // NOI18N

        autorizationsButton.setAction(actionMap.get("viewAuthorizations")); // NOI18N
        autorizationsButton.setText(resourceMap.getString("autorizationsButton.text")); // NOI18N
        autorizationsButton.setEnabled(false);
        autorizationsButton.setName("autorizationsButton"); // NOI18N

        javax.swing.GroupLayout statusPanelLayout = new javax.swing.GroupLayout(statusPanel);
        statusPanel.setLayout(statusPanelLayout);
        statusPanelLayout.setHorizontalGroup(
            statusPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(statusPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(statusPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(statusPanelLayout.createSequentialGroup()
                        .addComponent(activateButton)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(deactivateButton)
                        .addGap(18, 18, 18)
                        .addComponent(statusButton)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(autorizationsButton)
                        .addGap(18, 18, 18)
                        .addComponent(generateRequestsButton)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(installCertificatesButton))
                    .addGroup(statusPanelLayout.createSequentialGroup()
                        .addComponent(statusMessageLabel)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 664, Short.MAX_VALUE)
                        .addComponent(progressBar, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(statusAnimationLabel)))
                .addContainerGap())
        );

        statusPanelLayout.linkSize(javax.swing.SwingConstants.HORIZONTAL, new java.awt.Component[] {activateButton, deactivateButton});

        statusPanelLayout.setVerticalGroup(
            statusPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(statusPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(statusPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(activateButton)
                    .addComponent(deactivateButton)
                    .addComponent(statusButton)
                    .addComponent(installCertificatesButton)
                    .addComponent(autorizationsButton)
                    .addComponent(generateRequestsButton))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addGroup(statusPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(statusMessageLabel)
                    .addComponent(statusAnimationLabel)
                    .addComponent(progressBar, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(3, 3, 3))
        );

        statusPanelLayout.linkSize(javax.swing.SwingConstants.VERTICAL, new java.awt.Component[] {activateButton, deactivateButton});

        setComponent(mainPanel);
        setMenuBar(menuBar);
        setStatusBar(statusPanel);
        setToolBar(jToolBar1);
    }// </editor-fold>//GEN-END:initComponents


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

            workersList.clear();

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

                workersList.add(workerInfo);

                jTable1.revalidate();

                workersModel.fireTableDataChanged();
            }
        }
        @Override protected Object doInBackground() {
            // Your Task's code here.  This method runs
            // on a background thread, so don't reference
            // the Swing GUI from here.
            return null;  // return your result
        }
        @Override protected void succeeded(Object result) {
            // Runs on the EDT.  Update the GUI based on
            // the result computed by doInBackground().
        }
    }

    @Action
    public void showStatuses() {
        final int[] selected = jTable1.getSelectedRows();

        final int[] workerIds = new int[selected.length];

        for (int i = 0; i < selected.length; i++) {
            workerIds[i] = (Integer) workersList.get(selected[i]).get(1);
        }

        if (selected.length > 0) {
            getApplication().show(new WorkerStatusesView((SingleFrameApplication) this.getApplication(), workerIds));
        }
    }

    @Action(enabledProperty = "isWorkersSelected")
    public void activateWorkers() {
        final int[] selected = jTable1.getSelectedRows();

        for (int row : selected) {
            try {
                SignServerAdminGUIApplication.getWorkerSession()
                        .activateSigner(
                            (Integer) workersList.get(row).get(1), "");
            } catch (CryptoTokenAuthenticationFailureException ex) {
                JOptionPane.showMessageDialog(getFrame(),
                        "Authentication failure activating worker "
                        + workersList.get(row).get(1) + ":\n" + ex.getMessage(),
                        "Activate workers", JOptionPane.ERROR_MESSAGE);
                Logger.getLogger(MainView
                        .class.getName()).log(Level.SEVERE, null, ex);
            } catch (CryptoTokenOfflineException ex) {
                JOptionPane.showMessageDialog(getFrame(),
                        "Crypto token offline failure activating worker "
                        + workersList.get(row).get(1) + ":\n" + ex.getMessage(),
                        "Activate workers", JOptionPane.ERROR_MESSAGE);
                Logger.getLogger(MainView
                        .class.getName()).log(Level.SEVERE, null, ex);
            } catch (InvalidWorkerIdException ex) {
                JOptionPane.showMessageDialog(getFrame(),
                        "Invalid worker activating worker "
                        + workersList.get(row).get(1) + ":\n" + ex.getMessage(),
                        "Activate workers", JOptionPane.ERROR_MESSAGE);
                Logger.getLogger(MainView
                        .class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        refreshWorkers();
    }

    @Action
    public void deactivateWorkers() {
        final int[] selected = jTable1.getSelectedRows();

        for (int row : selected) {
            try {
                SignServerAdminGUIApplication.getWorkerSession()
                        .deactivateSigner((Integer) workersList.get(row)
                        .get(1));
            } catch (CryptoTokenOfflineException ex) {
                Logger.getLogger(MainView
                        .class.getName()).log(Level.SEVERE, null, ex);
            } catch (InvalidWorkerIdException ex) {
                Logger.getLogger(MainView
                        .class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        refreshWorkers();
    }

    @Action
    public void generateRequests() {
        final int[] selected = jTable1.getSelectedRows();
        final List<Integer> signerIds = new ArrayList<Integer>();
        final List<String> signerNames = new ArrayList<String>();

        for (int row : selected) {
            // TODO: check that the worker is a signer

            signerIds.add((Integer) workersList.get(row).get(1));
            signerNames.add((String) workersList.get(row).get(2));
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
        final int[] selected = jTable1.getSelectedRows();
        final List<Integer> signerIds = new ArrayList<Integer>();
        final List<String> signerNames = new ArrayList<String>();

        for (int row : selected) {
            // TODO: check that the worker is a signer

            signerIds.add((Integer) workersList.get(row).get(1));
            signerNames.add((String) workersList.get(row).get(2));
        }

        if (selected.length > 0) {
            getApplication().show(new InstallCertificatesView((SingleFrameApplication) this.getApplication(), signerIds.toArray(new Integer[0]), signerNames.toArray(new String[0])));
        }
    }

    @Action
    public void viewAuthorizations() {
        final int[] selected = jTable1.getSelectedRows();

        final int[] workerIds = new int[selected.length];

        for (int i = 0; i < selected.length; i++) {
            workerIds[i] = (Integer) workersList.get(selected[i]).get(1);
        }

        if (selected.length > 0) {
            getApplication().show(new WorkerAuthorizationView((SingleFrameApplication) this.getApplication(), workerIds));
        }
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton activateButton;
    private javax.swing.JMenuItem activateMenu;
    private javax.swing.JMenuItem authorizationsMenu;
    private javax.swing.JButton autorizationsButton;
    private javax.swing.JButton deactivateButton;
    private javax.swing.JMenuItem deactivateMenu;
    private javax.swing.JMenu editMenu;
    private javax.swing.JMenuItem generateRequestMenu;
    private javax.swing.JButton generateRequestsButton;
    private javax.swing.JButton installCertificatesButton;
    private javax.swing.JMenuItem installCertificatesMenu;
    private javax.swing.JButton jButtonRefresh1;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JToolBar.Separator jSeparator1;
    private javax.swing.JTable jTable1;
    private javax.swing.JToolBar jToolBar1;
    private javax.swing.JPanel mainPanel;
    private javax.swing.JMenuBar menuBar;
    private javax.swing.JProgressBar progressBar;
    private javax.swing.JMenuItem refreshMenu;
    private javax.swing.JLabel statusAnimationLabel;
    private javax.swing.JButton statusButton;
    private javax.swing.JMenuItem statusMenu;
    private javax.swing.JLabel statusMessageLabel;
    private javax.swing.JPanel statusPanel;
    private javax.swing.JMenu viewMenu;
    // End of variables declaration//GEN-END:variables

    private final Timer messageTimer;
    private final Timer busyIconTimer;
    private final Icon idleIcon;
    private final Icon[] busyIcons = new Icon[15];
    private int busyIconIndex = 0;

    private JDialog aboutBox;
}
