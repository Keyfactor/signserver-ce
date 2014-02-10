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

/*
 * AddWorkerDialog.java
 *
 * Created on 2014-jan-15, 09:48:28
 */
package org.signserver.admin.gui;

import java.awt.CardLayout;
import java.awt.Component;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.rmi.RemoteException;
import java.util.List;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.filechooser.FileFilter;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.plaf.basic.BasicTabbedPaneUI;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.util.Arrays;
import org.signserver.admin.gui.adminws.gen.AdminNotAuthorizedException_Exception;
import org.signserver.common.util.PropertiesApplier;
import org.signserver.common.util.PropertiesConstants;
import org.signserver.common.util.PropertiesParser;

/**
 * Dialog for adding worker(s) from a properties file, or by editing
 * properties manually.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public class AddWorkerDialog extends javax.swing.JDialog {

    /**
     * Enum holding state in the config dialog.
     * 
     */
    private enum Stage {

        /**
         * The initial state, choosing a file or entering preset configuration.
         */
        INITIAL_CONFIG,
        /**
         * The final state, with the possibility to hand-edit properties.
         */
        EDIT_PROPERTIES
    }

    /**
     * Enum holding the add worker mode.
     */
    private enum Mode {

        /**
         * Load worker properties from a property file.
         */
        LOAD_FROM_FILE,
        /**
         * Edit worker properties in the UI.
         */
        EDIT_MANUALLY
    }
    private Stage stage;
    private Mode mode;
    // raw data of the config
    private String config;
    // keep track of raw configuration editing
    private boolean configurationEdited = false;
    // keep track of newly selected file
    private boolean fileSelected = false;
    
    private List<Integer> modifiedWorkers;

    private WorkerPropertyEditor workerPropertyEditor = new WorkerPropertyEditor();

    /** Creates new form AddWorkerDialog */
    public AddWorkerDialog(java.awt.Frame parent, boolean modal) {
        super(parent, modal);
        initComponents();

        stage = Stage.INITIAL_CONFIG;
        mode = Mode.LOAD_FROM_FILE;
        loadFromFileRadioButton.setSelected(true);
        updateControls();

        // initially set the Next button to be greyed-out, so that it can be
        // enabled based on the state
        nextApplyButton.setEnabled(false);
        
        propertiesTable.setDefaultRenderer(String.class,
            new DefaultTableCellRenderer() {
                @Override
                public Component getTableCellRendererComponent(JTable table,
                                                               Object value,
                                                               boolean selected,
                                                               boolean focused,
                                                               int row, int column) {
                    setEnabled(table == null || table.isEnabled());
                    super.getTableCellRendererComponent(table, value, selected, focused, row, column);

                    return this;
                }
            });
        
        propertiesTable.getSelectionModel().addListSelectionListener(
                new ListSelectionListener() {

            @Override
            public void valueChanged(final ListSelectionEvent e) {
                if (!e.getValueIsAdjusting()) {
                    final boolean enable
                            = propertiesTable.getSelectedRowCount() == 1;
                    editPropertyButton.setEnabled(enable);
                    removePropertyButton.setEnabled(enable);
                }
            }
        });
    }

    /**
     * Update the UI according to the stage, changing button visibility 
     */
    private void updateControls() {
        // the reload button is only visible in the edit properties stage
        reloadButton.setVisible(stage == Stage.EDIT_PROPERTIES);
        // enable the reload button when there is changes done in the
        // free text configuration editor
        reloadButton.setEnabled(configurationEdited);

        // only enable the back button in the last step...
        backButton.setEnabled(stage == Stage.EDIT_PROPERTIES);
        // similarily, set the appropriate text for the "Next"/"Apply" button
        nextApplyButton.setText(stage == Stage.INITIAL_CONFIG ? "Next" : "Apply");

        // update controls depending on mode (load from file or edit manually)

        // file controls
        filePathTextField.setEnabled(mode == Mode.LOAD_FROM_FILE);
        filePathBrowseButton.setEnabled(mode == Mode.LOAD_FROM_FILE);

        // edit controls
        workerIdLabel.setEnabled(mode == Mode.EDIT_MANUALLY);
        workerIdComboBox.setEnabled(mode == Mode.EDIT_MANUALLY);
        workerNameLabel.setEnabled(mode == Mode.EDIT_MANUALLY);
        workerNameField.setEnabled(mode == Mode.EDIT_MANUALLY);
        workerImplementationLabel.setEnabled(mode == Mode.EDIT_MANUALLY);
        workerImplementationField.setEnabled(mode == Mode.EDIT_MANUALLY);
        tokenImplementationLabel.setEnabled(mode == Mode.EDIT_MANUALLY);
        tokenImplementationField.setEnabled(mode == Mode.EDIT_MANUALLY);
        propertiesLabel.setEnabled(mode == Mode.EDIT_MANUALLY);
        propertiesScrollPanel.setEnabled(mode == Mode.EDIT_MANUALLY);
        propertiesTable.setEnabled(mode == Mode.EDIT_MANUALLY);
        
        final int selectedRows = propertiesTable.getSelectedRowCount();
        
        addPropertyButton.setEnabled(mode == Mode.EDIT_MANUALLY);
        removePropertyButton.setEnabled(mode == Mode.EDIT_MANUALLY && selectedRows == 1);
        editPropertyButton.setEnabled(mode == Mode.EDIT_MANUALLY && selectedRows == 1);

        // update state of Next/Apply button
        switch (mode) {
            case LOAD_FROM_FILE:
                final String filePath = filePathTextField.getText();
                nextApplyButton.setEnabled(filePath != null && !filePath.isEmpty());
                break;
            case EDIT_MANUALLY:
                final String workerId =
                        ((JTextField) workerIdComboBox.getEditor().getEditorComponent())
                        .getText();
                final String workerName = workerNameField.getText();
                final String classPath = workerImplementationField.getText();
                
                // enable next button if all required fields have been set
                nextApplyButton.setEnabled(!workerId.isEmpty()
                                           && !workerName.isEmpty()
                                           && !classPath.isEmpty());
                break;
            default:
                // should not happen
                break;
        }
    }

    /** This method is called from within the constructor to
     * initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is
     * always regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        modeSelectButtonGroup = new javax.swing.ButtonGroup();
        nextApplyButton = new javax.swing.JButton();
        backButton = new javax.swing.JButton();
        reloadButton = new javax.swing.JButton();
        cancelButton = new javax.swing.JButton();
        wizardPanel = new javax.swing.JPanel();
        initialSetupPanel = new javax.swing.JPanel();
        removePropertyButton = new javax.swing.JButton();
        propertiesScrollPanel = new javax.swing.JScrollPane();
        propertiesTable = new javax.swing.JTable();
        addPropertyButton = new javax.swing.JButton();
        editPropertyButton = new javax.swing.JButton();
        tokenImplementationLabel = new javax.swing.JLabel();
        tokenImplementationField = new javax.swing.JTextField();
        workerImplementationLabel = new javax.swing.JLabel();
        workerImplementationField = new javax.swing.JTextField();
        filePathTextField = new javax.swing.JTextField();
        propertiesLabel = new javax.swing.JLabel();
        workerNameField = new javax.swing.JTextField();
        workerIdLabel = new javax.swing.JLabel();
        filePathBrowseButton = new javax.swing.JButton();
        loadFromFileRadioButton = new javax.swing.JRadioButton();
        editWorkerPropertiesRadioButton = new javax.swing.JRadioButton();
        workerNameLabel = new javax.swing.JLabel();
        workerIdComboBox = new javax.swing.JComboBox();
        configurationPanel = new javax.swing.JPanel();
        configurationLabel = new javax.swing.JLabel();
        configurationScrollPane = new javax.swing.JScrollPane();
        configurationTextArea = new javax.swing.JTextArea();

        setDefaultCloseOperation(javax.swing.WindowConstants.DISPOSE_ON_CLOSE);
        setName("Form"); // NOI18N

        org.jdesktop.application.ResourceMap resourceMap = org.jdesktop.application.Application.getInstance(org.signserver.admin.gui.SignServerAdminGUIApplication.class).getContext().getResourceMap(AddWorkerDialog.class);
        nextApplyButton.setText(resourceMap.getString("nextApplyButton.text")); // NOI18N
        nextApplyButton.setName("nextApplyButton"); // NOI18N
        nextApplyButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                nextApplyButtonActionPerformed(evt);
            }
        });

        backButton.setText(resourceMap.getString("backButton.text")); // NOI18N
        backButton.setName("backButton"); // NOI18N
        backButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                backButtonActionPerformed(evt);
            }
        });

        reloadButton.setText(resourceMap.getString("reloadButton.text")); // NOI18N
        reloadButton.setName("reloadButton"); // NOI18N
        reloadButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                reloadButtonActionPerformed(evt);
            }
        });

        cancelButton.setText(resourceMap.getString("cancelButton.text")); // NOI18N
        cancelButton.setName("cancelButton"); // NOI18N
        cancelButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                cancelButtonActionPerformed(evt);
            }
        });

        wizardPanel.setName("wizardPanel"); // NOI18N
        wizardPanel.setLayout(new java.awt.CardLayout());

        initialSetupPanel.setName("initialSetupPanel"); // NOI18N

        removePropertyButton.setText(resourceMap.getString("removePropertyButton.text")); // NOI18N
        removePropertyButton.setName("removePropertyButton"); // NOI18N
        removePropertyButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                removePropertyButtonActionPerformed(evt);
            }
        });

        propertiesScrollPanel.setName("propertiesScrollPanel"); // NOI18N

        propertiesTable.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {

            },
            new String [] {
                "Property", "Value"
            }
        ));
        propertiesTable.setName("propertiesTable"); // NOI18N
        propertiesScrollPanel.setViewportView(propertiesTable);

        addPropertyButton.setText(resourceMap.getString("addPropertyButton.text")); // NOI18N
        addPropertyButton.setName("addPropertyButton"); // NOI18N
        addPropertyButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                addPropertyButtonActionPerformed(evt);
            }
        });

        editPropertyButton.setText(resourceMap.getString("editPropertyButton.text")); // NOI18N
        editPropertyButton.setName("editPropertyButton"); // NOI18N
        editPropertyButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                editPropertyButtonActionPerformed(evt);
            }
        });

        tokenImplementationLabel.setText(resourceMap.getString("tokenImplementationLabel.text")); // NOI18N
        tokenImplementationLabel.setName("tokenImplementationLabel"); // NOI18N

        tokenImplementationField.setText(resourceMap.getString("tokenImplementationField.text")); // NOI18N
        tokenImplementationField.setName("tokenImplementationField"); // NOI18N

        workerImplementationLabel.setText(resourceMap.getString("workerImplementationLabel.text")); // NOI18N
        workerImplementationLabel.setName("workerImplementationLabel"); // NOI18N

        workerImplementationField.setText(resourceMap.getString("workerImplementationField.text")); // NOI18N
        workerImplementationField.setName("workerImplementationField"); // NOI18N
        workerImplementationField.addKeyListener(new java.awt.event.KeyAdapter() {
            public void keyTyped(java.awt.event.KeyEvent evt) {
                workerImplementationFieldKeyTyped(evt);
            }
        });

        filePathTextField.setText(resourceMap.getString("filePathTextField.text")); // NOI18N
        filePathTextField.setName("filePathTextField"); // NOI18N
        filePathTextField.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                filePathTextFieldActionPerformed(evt);
            }
        });
        filePathTextField.addKeyListener(new java.awt.event.KeyAdapter() {
            public void keyTyped(java.awt.event.KeyEvent evt) {
                filePathTextFieldKeyTyped(evt);
            }
        });

        propertiesLabel.setFont(resourceMap.getFont("propertiesLabel.font")); // NOI18N
        propertiesLabel.setText(resourceMap.getString("propertiesLabel.text")); // NOI18N
        propertiesLabel.setName("propertiesLabel"); // NOI18N

        workerNameField.setText(resourceMap.getString("workerNameField.text")); // NOI18N
        workerNameField.setName("workerNameField"); // NOI18N
        workerNameField.addKeyListener(new java.awt.event.KeyAdapter() {
            public void keyTyped(java.awt.event.KeyEvent evt) {
                workerNameFieldKeyTyped(evt);
            }
        });

        workerIdLabel.setText(resourceMap.getString("workerIdLabel.text")); // NOI18N
        workerIdLabel.setName("workerIdLabel"); // NOI18N

        filePathBrowseButton.setText(resourceMap.getString("filePathBrowseButton.text")); // NOI18N
        filePathBrowseButton.setName("filePathBrowseButton"); // NOI18N
        filePathBrowseButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                filePathBrowseButtonActionPerformed(evt);
            }
        });

        modeSelectButtonGroup.add(loadFromFileRadioButton);
        loadFromFileRadioButton.setFont(resourceMap.getFont("loadFromFileRadioButton.font")); // NOI18N
        loadFromFileRadioButton.setText(resourceMap.getString("loadFromFileRadioButton.text")); // NOI18N
        loadFromFileRadioButton.setName("loadFromFileRadioButton"); // NOI18N
        loadFromFileRadioButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                loadFromFileRadioButtonActionPerformed(evt);
            }
        });

        modeSelectButtonGroup.add(editWorkerPropertiesRadioButton);
        editWorkerPropertiesRadioButton.setFont(resourceMap.getFont("editWorkerPropertiesRadioButton.font")); // NOI18N
        editWorkerPropertiesRadioButton.setText(resourceMap.getString("editWorkerPropertiesRadioButton.text")); // NOI18N
        editWorkerPropertiesRadioButton.setName("editWorkerPropertiesRadioButton"); // NOI18N
        editWorkerPropertiesRadioButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                editWorkerPropertiesRadioButtonActionPerformed(evt);
            }
        });

        workerNameLabel.setText(resourceMap.getString("workerNameLabel.text")); // NOI18N
        workerNameLabel.setName("workerNameLabel"); // NOI18N

        workerIdComboBox.setEditable(true);
        workerIdComboBox.setModel(new javax.swing.DefaultComboBoxModel(new String[] { "GENID1" }));
        workerIdComboBox.setName("workerIdComboBox"); // NOI18N
        workerIdComboBox.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                workerIdComboBoxActionPerformed(evt);
            }
        });
        workerIdComboBox.addKeyListener(new java.awt.event.KeyAdapter() {
            public void keyTyped(java.awt.event.KeyEvent evt) {
                workerIdComboBoxKeyTyped(evt);
            }
        });

        javax.swing.GroupLayout initialSetupPanelLayout = new javax.swing.GroupLayout(initialSetupPanel);
        initialSetupPanel.setLayout(initialSetupPanelLayout);
        initialSetupPanelLayout.setHorizontalGroup(
            initialSetupPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(initialSetupPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(initialSetupPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(initialSetupPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(initialSetupPanelLayout.createSequentialGroup()
                            .addComponent(workerNameLabel, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addGap(748, 748, 748))
                        .addGroup(initialSetupPanelLayout.createSequentialGroup()
                            .addComponent(workerImplementationLabel, javax.swing.GroupLayout.PREFERRED_SIZE, 486, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addContainerGap(303, Short.MAX_VALUE)))
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, initialSetupPanelLayout.createSequentialGroup()
                        .addComponent(workerIdComboBox, javax.swing.GroupLayout.PREFERRED_SIZE, 163, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(123, 123, 123))))
            .addGroup(initialSetupPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addGroup(initialSetupPanelLayout.createSequentialGroup()
                    .addGap(11, 11, 11)
                    .addGroup(initialSetupPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(initialSetupPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(editWorkerPropertiesRadioButton)
                            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, initialSetupPanelLayout.createSequentialGroup()
                                .addComponent(filePathTextField, javax.swing.GroupLayout.PREFERRED_SIZE, 717, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 35, Short.MAX_VALUE)
                                .addComponent(filePathBrowseButton))
                            .addComponent(loadFromFileRadioButton, javax.swing.GroupLayout.PREFERRED_SIZE, 133, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, initialSetupPanelLayout.createSequentialGroup()
                                .addGroup(initialSetupPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addComponent(workerIdLabel, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, 492, Short.MAX_VALUE)
                                    .addComponent(tokenImplementationLabel, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, 492, Short.MAX_VALUE))
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addGroup(initialSetupPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addComponent(workerNameField, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, 274, Short.MAX_VALUE)
                                    .addComponent(workerImplementationField, javax.swing.GroupLayout.DEFAULT_SIZE, 274, Short.MAX_VALUE)
                                    .addComponent(tokenImplementationField, javax.swing.GroupLayout.DEFAULT_SIZE, 274, Short.MAX_VALUE)))
                            .addGroup(initialSetupPanelLayout.createSequentialGroup()
                                .addComponent(propertiesScrollPanel, javax.swing.GroupLayout.PREFERRED_SIZE, 684, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addGroup(initialSetupPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addComponent(addPropertyButton, javax.swing.GroupLayout.DEFAULT_SIZE, 88, Short.MAX_VALUE)
                                    .addComponent(editPropertyButton, javax.swing.GroupLayout.DEFAULT_SIZE, 88, Short.MAX_VALUE)
                                    .addComponent(removePropertyButton, javax.swing.GroupLayout.DEFAULT_SIZE, 88, Short.MAX_VALUE))))
                        .addGroup(initialSetupPanelLayout.createSequentialGroup()
                            .addComponent(propertiesLabel, javax.swing.GroupLayout.PREFERRED_SIZE, 745, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 33, javax.swing.GroupLayout.PREFERRED_SIZE)))
                    .addGap(12, 12, 12)))
        );
        initialSetupPanelLayout.setVerticalGroup(
            initialSetupPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(initialSetupPanelLayout.createSequentialGroup()
                .addGap(139, 139, 139)
                .addComponent(workerIdComboBox, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addComponent(workerNameLabel)
                .addGap(27, 27, 27)
                .addComponent(workerImplementationLabel)
                .addContainerGap(231, Short.MAX_VALUE))
            .addGroup(initialSetupPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, initialSetupPanelLayout.createSequentialGroup()
                    .addContainerGap(28, Short.MAX_VALUE)
                    .addComponent(loadFromFileRadioButton)
                    .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                    .addGroup(initialSetupPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                        .addComponent(filePathBrowseButton)
                        .addComponent(filePathTextField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGap(16, 16, 16)
                    .addComponent(editWorkerPropertiesRadioButton)
                    .addGap(18, 18, 18)
                    .addComponent(workerIdLabel, javax.swing.GroupLayout.PREFERRED_SIZE, 31, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addGap(8, 8, 8)
                    .addComponent(workerNameField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                    .addComponent(workerImplementationField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                    .addGroup(initialSetupPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                        .addComponent(tokenImplementationField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addComponent(tokenImplementationLabel))
                    .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                    .addComponent(propertiesLabel)
                    .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                    .addGroup(initialSetupPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                        .addComponent(propertiesScrollPanel, javax.swing.GroupLayout.PREFERRED_SIZE, 148, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, initialSetupPanelLayout.createSequentialGroup()
                            .addComponent(addPropertyButton)
                            .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                            .addComponent(editPropertyButton)
                            .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                            .addComponent(removePropertyButton)
                            .addGap(14, 14, 14)))
                    .addContainerGap()))
        );

        wizardPanel.add(initialSetupPanel, "initial");

        configurationPanel.setName("configurationPanel"); // NOI18N

        configurationLabel.setFont(resourceMap.getFont("configurationLabel.font")); // NOI18N
        configurationLabel.setText(resourceMap.getString("configurationLabel.text")); // NOI18N
        configurationLabel.setName("configurationLabel"); // NOI18N

        configurationScrollPane.setName("configurationScrollPane"); // NOI18N

        configurationTextArea.setColumns(20);
        configurationTextArea.setRows(5);
        configurationTextArea.setName("configurationTextArea"); // NOI18N
        configurationTextArea.addKeyListener(new java.awt.event.KeyAdapter() {
            public void keyTyped(java.awt.event.KeyEvent evt) {
                configurationTextAreaKeyTyped(evt);
            }
        });
        configurationScrollPane.setViewportView(configurationTextArea);

        javax.swing.GroupLayout configurationPanelLayout = new javax.swing.GroupLayout(configurationPanel);
        configurationPanel.setLayout(configurationPanelLayout);
        configurationPanelLayout.setHorizontalGroup(
            configurationPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGap(0, 801, Short.MAX_VALUE)
            .addGroup(configurationPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addGroup(configurationPanelLayout.createSequentialGroup()
                    .addGap(32, 32, 32)
                    .addGroup(configurationPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                        .addComponent(configurationScrollPane, javax.swing.GroupLayout.DEFAULT_SIZE, 737, Short.MAX_VALUE)
                        .addComponent(configurationLabel, javax.swing.GroupLayout.PREFERRED_SIZE, 720, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGap(32, 32, 32)))
        );
        configurationPanelLayout.setVerticalGroup(
            configurationPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGap(0, 490, Short.MAX_VALUE)
            .addGroup(configurationPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addGroup(configurationPanelLayout.createSequentialGroup()
                    .addContainerGap()
                    .addComponent(configurationLabel)
                    .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                    .addComponent(configurationScrollPane, javax.swing.GroupLayout.PREFERRED_SIZE, 422, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addContainerGap(29, Short.MAX_VALUE)))
        );

        wizardPanel.add(configurationPanel, "editing");

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(reloadButton)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 470, Short.MAX_VALUE)
                .addComponent(cancelButton, javax.swing.GroupLayout.PREFERRED_SIZE, 86, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(backButton, javax.swing.GroupLayout.PREFERRED_SIZE, 74, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(nextApplyButton, javax.swing.GroupLayout.PREFERRED_SIZE, 110, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(24, 24, 24))
            .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addGroup(layout.createSequentialGroup()
                    .addGap(0, 22, Short.MAX_VALUE)
                    .addComponent(wizardPanel, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addGap(0, 22, Short.MAX_VALUE)))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addContainerGap(554, Short.MAX_VALUE)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(reloadButton)
                    .addComponent(nextApplyButton)
                    .addComponent(backButton)
                    .addComponent(cancelButton))
                .addContainerGap())
            .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addGroup(layout.createSequentialGroup()
                    .addGap(0, 54, Short.MAX_VALUE)
                    .addComponent(wizardPanel, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addGap(0, 55, Short.MAX_VALUE)))
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void filePathBrowseButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_filePathBrowseButtonActionPerformed
        final JFileChooser chooser = new JFileChooser();
        final File baseDir = SignServerAdminGUIApplication.getBaseDir();
        final String basedirPath = baseDir.getAbsolutePath();
        final File sampleDir =
                new File(basedirPath + File.separator + "doc" + File.separator +
                         "sample-configs");

        chooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
        chooser.setCurrentDirectory(sampleDir.isDirectory() ? sampleDir : baseDir);
        chooser.setFileFilter(new FileNameExtensionFilter("Properties files", "properties"));
        
        final int res = chooser.showOpenDialog(this);

        if (res == JFileChooser.APPROVE_OPTION) {
            final File file = chooser.getSelectedFile();
            filePathTextField.setText(file.getAbsolutePath());
            fileSelected = true;
        }

        updateControls();
    }//GEN-LAST:event_filePathBrowseButtonActionPerformed

    private void filePathTextFieldActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_filePathTextFieldActionPerformed
        // update UI controls
        updateControls();
    }//GEN-LAST:event_filePathTextFieldActionPerformed

    private void filePathTextFieldKeyTyped(java.awt.event.KeyEvent evt) {//GEN-FIRST:event_filePathTextFieldKeyTyped
        // update UI controls
        updateControls();
        fileSelected = true;
    }//GEN-LAST:event_filePathTextFieldKeyTyped

    private void nextApplyButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_nextApplyButtonActionPerformed
        switch (stage) {
            case INITIAL_CONFIG:
                // in the initial config pane, go to the next step
                gotoPropertiesEditing();

                break;
            case EDIT_PROPERTIES:
                final boolean sucess = applyConfiguration();
                
                if (sucess) {
                    dispose();
                }
                break;
            default:
                // should not happen...
                break;
        }
    }//GEN-LAST:event_nextApplyButtonActionPerformed

    // TODO: run this as a background task
    private boolean applyConfiguration() {
        config = configurationTextArea.getText();

        final Properties props = new Properties();

        try {
            props.load(new ByteArrayInputStream(config.getBytes()));
        } catch (IOException e) {
            JOptionPane.showMessageDialog(this,
                    "Error loading properties: " + e.getMessage(), "Error",
                    JOptionPane.ERROR_MESSAGE);
            return false;
        }
            
        final PropertiesParser parser = new PropertiesParser();

        parser.process(props);

        if (parser.hasErrors()) {
            final List<String> errors = parser.getErrors();
            
            // show the first error message from the parser, to avoid overflowing
            // TODO: maybe add a "more errors..." view later...
            JOptionPane.showMessageDialog(this,
                    "Error parsing properties: " + errors.get(0),
                    "Error", JOptionPane.ERROR_MESSAGE);
            return false;
        } else {
            final PropertiesApplier applier = new AdminGUIPropertiesApplier();

            applier.apply(parser);
            
            if (applier.hasError()) {
                JOptionPane.showMessageDialog(this,
                        "Error applying properties: " + applier.getError(),
                        "Error", JOptionPane.ERROR_MESSAGE);
                return false;
            }
            
            modifiedWorkers = applier.getWorkerIds();
            
            try {
                for (final int workerId : modifiedWorkers) {
                    SignServerAdminGUIApplication.getAdminWS().reloadConfiguration(workerId);
                }
            } catch (AdminNotAuthorizedException_Exception e) {
                JOptionPane.showMessageDialog(this,
                        "Error reloading workers: " + e.getMessage(),
                        "Error reloading", JOptionPane.ERROR_MESSAGE);
            }
        }

        return true;
    }

    private void configurationTextAreaKeyTyped(java.awt.event.KeyEvent evt) {//GEN-FIRST:event_configurationTextAreaKeyTyped
        configurationEdited = true;
        updateControls();
    }//GEN-LAST:event_configurationTextAreaKeyTyped

    private void reloadButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_reloadButtonActionPerformed
        loadConfigurationEditor();
        updateControls();
    }//GEN-LAST:event_reloadButtonActionPerformed

    private void backButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_backButtonActionPerformed
        goBackToInitialConfig();
    }//GEN-LAST:event_backButtonActionPerformed

    private void cancelButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_cancelButtonActionPerformed
        dispose();
    }//GEN-LAST:event_cancelButtonActionPerformed

    private void loadFromFileRadioButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_loadFromFileRadioButtonActionPerformed
        setMode(Mode.LOAD_FROM_FILE);
    }//GEN-LAST:event_loadFromFileRadioButtonActionPerformed

    private void editWorkerPropertiesRadioButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_editWorkerPropertiesRadioButtonActionPerformed
        setMode(Mode.EDIT_MANUALLY);
    }//GEN-LAST:event_editWorkerPropertiesRadioButtonActionPerformed

    private void workerIdComboBoxActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_workerIdComboBoxActionPerformed
        updateControls();
    }//GEN-LAST:event_workerIdComboBoxActionPerformed

    private void workerIdComboBoxKeyTyped(java.awt.event.KeyEvent evt) {//GEN-FIRST:event_workerIdComboBoxKeyTyped
        updateControls();
    }//GEN-LAST:event_workerIdComboBoxKeyTyped

    private void workerNameFieldKeyTyped(java.awt.event.KeyEvent evt) {//GEN-FIRST:event_workerNameFieldKeyTyped
        updateControls();
    }//GEN-LAST:event_workerNameFieldKeyTyped

    private void workerImplementationFieldKeyTyped(java.awt.event.KeyEvent evt) {//GEN-FIRST:event_workerImplementationFieldKeyTyped
        updateControls();
    }//GEN-LAST:event_workerImplementationFieldKeyTyped

    private void addOrEditProperty(final String key, final String value) {
        if (PropertiesConstants.NAME.equals(key)) {
            JOptionPane.showMessageDialog(this, 
                        "Use the Name text field to edit the worker name",
                        "Set worker name", JOptionPane.ERROR_MESSAGE);
        } else {
            final DefaultTableModel model =
                    (DefaultTableModel) propertiesTable.getModel();
            boolean existing = false;

            for (int i = 0; i < model.getRowCount(); i++) {
                final String foundKey = (String) model.getValueAt(i, 0);

                if (key.equals(foundKey)) {
                    // update existing row
                    model.setValueAt(key, i, 0);
                    model.setValueAt(value, i, 1);
                    existing = true;
                    break;
                }
            }

            if (!existing) {
                model.addRow(new Object[] {key, value});
            }
        }
    }
    
    private void removeProperty(final String key) {
        final DefaultTableModel model =
                    (DefaultTableModel) propertiesTable.getModel();
        
        for (int i = 0; i < model.getRowCount(); i++) {
            if (key.equals(model.getValueAt(i, 0))) {
                model.removeRow(i);
                break;
            }
        }
    }
    
    private void addPropertyButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_addPropertyButtonActionPerformed
        workerPropertyEditor.setKey("");
        workerPropertyEditor.setValue("");
        
        final int res = workerPropertyEditor.showDialog(this);
        
        if (res == JOptionPane.OK_OPTION) {
            final String key = workerPropertyEditor.getKey();
            final String value = workerPropertyEditor.getValue();
            
            addOrEditProperty(key, value);
        }
    }//GEN-LAST:event_addPropertyButtonActionPerformed
    
    private void editPropertyButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_editPropertyButtonActionPerformed
        final int row = propertiesTable.getSelectedRow();
        
        if (row != -1) {
            final String oldKey = (String) propertiesTable.getValueAt(row, 0);
            final String oldValue = (String) propertiesTable.getValueAt(row, 1);
            
            workerPropertyEditor.setKey(oldKey);
            workerPropertyEditor.setValue(oldValue);
            
            final int res = workerPropertyEditor.showDialog(this);
            
            if (res == JOptionPane.OK_OPTION) {
                final String key = workerPropertyEditor.getKey();
                final String value = workerPropertyEditor.getValue();
                
                if (!oldKey.equals(key)) {
                    removeProperty(oldKey);
                }
                
                addOrEditProperty(key, value);
            }
        }
    }//GEN-LAST:event_editPropertyButtonActionPerformed

    private void removePropertyButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_removePropertyButtonActionPerformed
        final int row = propertiesTable.getSelectedRow();
        
        if (row != -1) {
            final DefaultTableModel model =
                    (DefaultTableModel) propertiesTable.getModel();
            
            model.removeRow(row);
        }
    }//GEN-LAST:event_removePropertyButtonActionPerformed

    private void setMode(final Mode mode) {
        this.mode = mode;
        updateControls();
        
        // forget about selected file when going to edit properties mode
        if (mode == Mode.EDIT_MANUALLY) {
            fileSelected = false;
        }
    }
    
    private void goBackToInitialConfig() {       
        ((CardLayout) wizardPanel.getLayout()).show(wizardPanel, "initial");
        stage = Stage.INITIAL_CONFIG;

        updateControls();
    }

    private void gotoPropertiesEditing() {
        ((CardLayout) wizardPanel.getLayout()).show(wizardPanel, "editing");
        stage = Stage.EDIT_PROPERTIES;

        // TODO: should later on handle merging manual properties to the
        // properties editor and so on...

        // reload configuration if a new file has been selected or if
        // a worker was add using the form
        if (mode == Mode.EDIT_MANUALLY || fileSelected) {
            loadConfigurationEditor();
        }
        updateControls();
    }

    private void loadConfigurationEditor() {
        switch (mode) {
            case LOAD_FROM_FILE:
                final File file = new File(filePathTextField.getText());

                try {
                    config = FileUtils.readFileToString(file);
                    configurationTextArea.setText(config);
                    configurationTextArea.setCaretPosition(0);
                    configurationEdited = false;
                    // reset file selected status
                    fileSelected = false;
                } catch (IOException e) {
                    JOptionPane.showMessageDialog(this, e.getMessage(),
                            "Failed to read file", JOptionPane.ERROR_MESSAGE);
                }
                break;
            case EDIT_MANUALLY:
                configurationTextArea.setText(generateProperties());
                configurationTextArea.setCaretPosition(0);
                break;
            default:
                // should not happen
                break;
        }
    }
    
    /**
     * Generate properties based on filled-in values the add form.
     * 
     * @return Properties file content to fill the editor
     */
    private String generateProperties() {
        // TODO: merge in previous content from the text editor in the case
        // when the user goes back and changes some values in the form and then
        // back to the editor
        
        final StringBuffer sb = new StringBuffer();
        final String workerId =
                ((JTextField) workerIdComboBox.getEditor().getEditorComponent())
                .getText();
        final String classPath = workerImplementationField.getText();
        final String tokenClassPath = tokenImplementationField.getText();
        final String workerName = workerNameField.getText();
        
        // insert CLASSPATH global property
        sb.append(PropertiesConstants.GLOBAL_PREFIX_DOT);
        sb.append(PropertiesConstants.WORKER_PREFIX);
        sb.append(workerId);
        sb.append(".CLASSPATH");
        sb.append(" = ");
        sb.append(classPath);
        sb.append("\n");
        
        if (tokenClassPath != null && !tokenClassPath.isEmpty()) {
            // insert SIGNERTOKEN.CLASSPATH global property
            sb.append(PropertiesConstants.GLOBAL_PREFIX_DOT);
            sb.append(workerId);
            sb.append(".SIGNERTOKEN.CLASSPATH");
            sb.append(" = ");
            sb.append(tokenClassPath);
            sb.append("\n");
        }
        
        // insert NAME worker property
        sb.append(PropertiesConstants.WORKER_PREFIX);
        sb.append(workerId);
        sb.append(".NAME");
        sb.append(" = ");
        sb.append(workerName);
        sb.append("\n");
        
        // TODO: handle additional properties
        
        return sb.toString();
    }

    /**
     * Get a list of worker IDs added and modified by the apply operation.
     * 
     * @return List of worker IDs
     */
    public List<Integer> getModifiedWorkers() {
        return modifiedWorkers;
    }
    
    
    /**
     * @param args the command line arguments
     */
    public static void main(String args[]) {
        java.awt.EventQueue.invokeLater(new Runnable() {

            public void run() {
                AddWorkerDialog dialog = new AddWorkerDialog(new javax.swing.JFrame(), true);
                dialog.addWindowListener(new java.awt.event.WindowAdapter() {

                    public void windowClosing(java.awt.event.WindowEvent e) {
                        System.exit(0);
                    }
                });
                dialog.setVisible(true);
            }
        });
    }
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton addPropertyButton;
    private javax.swing.JButton backButton;
    private javax.swing.JButton cancelButton;
    private javax.swing.JLabel configurationLabel;
    private javax.swing.JPanel configurationPanel;
    private javax.swing.JScrollPane configurationScrollPane;
    private javax.swing.JTextArea configurationTextArea;
    private javax.swing.JButton editPropertyButton;
    private javax.swing.JRadioButton editWorkerPropertiesRadioButton;
    private javax.swing.JButton filePathBrowseButton;
    private javax.swing.JTextField filePathTextField;
    private javax.swing.JPanel initialSetupPanel;
    private javax.swing.JRadioButton loadFromFileRadioButton;
    private javax.swing.ButtonGroup modeSelectButtonGroup;
    private javax.swing.JButton nextApplyButton;
    private javax.swing.JLabel propertiesLabel;
    private javax.swing.JScrollPane propertiesScrollPanel;
    private javax.swing.JTable propertiesTable;
    private javax.swing.JButton reloadButton;
    private javax.swing.JButton removePropertyButton;
    private javax.swing.JTextField tokenImplementationField;
    private javax.swing.JLabel tokenImplementationLabel;
    private javax.swing.JPanel wizardPanel;
    private javax.swing.JComboBox workerIdComboBox;
    private javax.swing.JLabel workerIdLabel;
    private javax.swing.JTextField workerImplementationField;
    private javax.swing.JLabel workerImplementationLabel;
    private javax.swing.JTextField workerNameField;
    private javax.swing.JLabel workerNameLabel;
    // End of variables declaration//GEN-END:variables
}
