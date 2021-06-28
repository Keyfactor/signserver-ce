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
import java.awt.Component;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Properties;
import javax.ejb.EJBException;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.text.JTextComponent;
import javax.xml.ws.soap.SOAPFaultException;
import org.apache.commons.io.FileUtils;
import org.apache.log4j.Logger;
import org.jdesktop.application.Action;
import org.jdesktop.application.Task;
import org.signserver.admin.gui.adminws.gen.AdminNotAuthorizedException_Exception;
import org.signserver.common.WorkerConfig;
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
    
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(AddWorkerDialog.class);

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
        
        invalidWorkerIdStatusLabel.setVisible(false);
        
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
        
        // add a document listner to update the UI when the content of the ID
        // combobox changes
        final JTextComponent component =
                (JTextComponent) workerIdComboBox.getEditor().getEditorComponent();
        component.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent ev) {
                updateControls();
            }

            @Override
            public void removeUpdate(DocumentEvent ev) {
                updateControls();
            }

            @Override
            public void changedUpdate(DocumentEvent ev) {
                updateControls();
            }
        });

        // add a document listner to update the UI on updates of the configuration text
        configurationTextArea.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent ev) {
                configurationEdited = true;
                updateControls();
            }

            @Override
            public void removeUpdate(DocumentEvent ev) {
                configurationEdited = true;
                updateControls();
            }

            @Override
            public void changedUpdate(DocumentEvent ev) {
                configurationEdited = true;
                updateControls();
            }
        });
        
        workerNameField.getDocument().addDocumentListener(new DocumentListener() {
           @Override
           public void insertUpdate(DocumentEvent ev) {
               configurationEdited = true;
               updateControls();
           }
           
           @Override
            public void removeUpdate(DocumentEvent ev) {
                configurationEdited = true;
                updateControls();
            }

            @Override
            public void changedUpdate(DocumentEvent ev) {
                configurationEdited = true;
                updateControls();
            }
        });
        
        workerImplementationField.getDocument().addDocumentListener(new DocumentListener() {
           @Override
           public void insertUpdate(DocumentEvent ev) {
               configurationEdited = true;
               updateControls();
           }
           
           @Override
            public void removeUpdate(DocumentEvent ev) {
                configurationEdited = true;
                updateControls();
            }

            @Override
            public void changedUpdate(DocumentEvent ev) {
                configurationEdited = true;
                updateControls();
            }
        });
    }
    
    /**
     * Update the UI according to the stage, changing button visibility 
     */
    private void updateControls() {
        // the reload button is only visible in the edit properties stage
        resetButton.setVisible(stage == Stage.EDIT_PROPERTIES);
        // enable the reload button when there is changes done in the
        // free text configuration editor
        resetButton.setEnabled(configurationEdited);

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
        typeLabel.setEnabled(mode == Mode.EDIT_MANUALLY);
        typeComboBox.setEnabled(mode == Mode.EDIT_MANUALLY);
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
                invalidWorkerIdStatusLabel.setVisible(false);
                break;
            case EDIT_MANUALLY:
                final String workerId =
                        ((JTextField) workerIdComboBox.getEditor().getEditorComponent())
                        .getText();
                final String workerName = workerNameField.getText();
                final String classPath = workerImplementationField.getText();
                final boolean workerIdValid = isWorkerIdValid(workerId);
                
                // enable next button if all required fields have been set
                nextApplyButton.setEnabled(!workerId.isEmpty()
                                           && workerIdValid
                                           && !workerName.isEmpty()
                                           && !classPath.isEmpty());
                invalidWorkerIdStatusLabel.setVisible(!workerIdValid);
                
                break;
            default:
                // should not happen
                break;
        }
    }
    
    /**
     * Determine if a string qualifies as a worker ID prefix, either a positive
     * integer or a string of the form GENIDx, where x is a positive integer
     * for generated worker IDs.
     * 
     * @param workerId
     * @return True if the given string represents a valid worker ID or generated ID
     */
    private boolean isWorkerIdValid(final String workerId) {
        try {
            final int id = Integer.parseInt(workerId);
            
            return id > 0;
        } catch (NumberFormatException e) {
            if (workerId.length() > PropertiesConstants.GENID.length() &&
                PropertiesConstants.GENID.equals(workerId.substring(0, PropertiesConstants.GENID.length()))) {
                try {
                    final int index =
                            Integer.parseInt(workerId.substring(PropertiesConstants.GENID.length()));
                    
                    return index >= 1;
                } catch (NumberFormatException ex) {
                    return false;
                }
            } else {
                return false;
            }
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
        resetButton = new javax.swing.JButton();
        cancelButton = new javax.swing.JButton();
        wizardPanel = new javax.swing.JPanel();
        initialSetupPanel = new javax.swing.JPanel();
        removePropertyButton = new javax.swing.JButton();
        propertiesScrollPanel = new javax.swing.JScrollPane();
        propertiesTable = new javax.swing.JTable();
        addPropertyButton = new javax.swing.JButton();
        editPropertyButton = new javax.swing.JButton();
        filePathTextField = new javax.swing.JTextField();
        propertiesLabel = new javax.swing.JLabel();
        filePathBrowseButton = new javax.swing.JButton();
        loadFromFileRadioButton = new javax.swing.JRadioButton();
        editWorkerPropertiesRadioButton = new javax.swing.JRadioButton();
        workerIdLabel = new javax.swing.JLabel();
        workerIdComboBox = new javax.swing.JComboBox();
        workerNameLabel = new javax.swing.JLabel();
        workerNameField = new javax.swing.JTextField();
        workerImplementationLabel = new javax.swing.JLabel();
        workerImplementationField = new javax.swing.JTextField();
        tokenImplementationLabel = new javax.swing.JLabel();
        tokenImplementationField = new javax.swing.JTextField();
        invalidWorkerIdStatusLabel = new javax.swing.JLabel();
        typeComboBox = new javax.swing.JComboBox();
        typeLabel = new javax.swing.JLabel();
        configurationPanel = new javax.swing.JPanel();
        configurationLabel = new javax.swing.JLabel();
        configurationScrollPane = new javax.swing.JScrollPane();
        configurationTextArea = new javax.swing.JTextArea();

        setDefaultCloseOperation(javax.swing.WindowConstants.DISPOSE_ON_CLOSE);
        org.jdesktop.application.ResourceMap resourceMap = org.jdesktop.application.Application.getInstance().getContext().getResourceMap(AddWorkerDialog.class);
        setTitle(resourceMap.getString("Form.title")); // NOI18N
        setName("Form"); // NOI18N

        javax.swing.ActionMap actionMap = org.jdesktop.application.Application.getInstance().getContext().getActionMap(AddWorkerDialog.class, this);
        nextApplyButton.setAction(actionMap.get("nextAction")); // NOI18N
        nextApplyButton.setText(resourceMap.getString("nextApplyButton.text")); // NOI18N
        nextApplyButton.setName("nextApplyButton"); // NOI18N

        backButton.setText(resourceMap.getString("backButton.text")); // NOI18N
        backButton.setName("backButton"); // NOI18N
        backButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                backButtonActionPerformed(evt);
            }
        });

        resetButton.setAction(actionMap.get("reloadAction")); // NOI18N
        resetButton.setText(resourceMap.getString("resetButton.text")); // NOI18N
        resetButton.setName("resetButton"); // NOI18N

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

        workerIdLabel.setText(resourceMap.getString("workerIdLabel.text")); // NOI18N
        workerIdLabel.setName("workerIdLabel"); // NOI18N

        workerIdComboBox.setEditable(true);
        workerIdComboBox.setModel(new javax.swing.DefaultComboBoxModel(new String[] { "GENID1" }));
        workerIdComboBox.setName("workerIdComboBox"); // NOI18N

        workerNameLabel.setText(resourceMap.getString("workerNameLabel.text")); // NOI18N
        workerNameLabel.setName("workerNameLabel"); // NOI18N

        workerNameField.setName("workerNameField"); // NOI18N
        workerNameField.addKeyListener(new java.awt.event.KeyAdapter() {
            public void keyTyped(java.awt.event.KeyEvent evt) {
                workerNameFieldKeyTyped(evt);
            }
        });

        workerImplementationLabel.setText(resourceMap.getString("workerImplementationLabel.text")); // NOI18N
        workerImplementationLabel.setName("workerImplementationLabel"); // NOI18N

        workerImplementationField.setName("workerImplementationField"); // NOI18N
        workerImplementationField.addKeyListener(new java.awt.event.KeyAdapter() {
            public void keyTyped(java.awt.event.KeyEvent evt) {
                workerImplementationFieldKeyTyped(evt);
            }
        });

        tokenImplementationLabel.setText(resourceMap.getString("tokenImplementationLabel.text")); // NOI18N
        tokenImplementationLabel.setName("tokenImplementationLabel"); // NOI18N

        tokenImplementationField.setName("tokenImplementationField"); // NOI18N

        invalidWorkerIdStatusLabel.setForeground(resourceMap.getColor("invalidWorkerIdStatusLabel.foreground")); // NOI18N
        invalidWorkerIdStatusLabel.setText(resourceMap.getString("invalidWorkerIdStatusLabel.text")); // NOI18N
        invalidWorkerIdStatusLabel.setName("invalidWorkerIdStatusLabel"); // NOI18N

        typeComboBox.setEditable(true);
        typeComboBox.setModel(new javax.swing.DefaultComboBoxModel(new String[] { "PROCESSABLE", "CRYPTO_WORKER", "TIMED_SERVICE", "SPECIAL" }));
        typeComboBox.setName("typeComboBox"); // NOI18N

        typeLabel.setText(resourceMap.getString("typeLabel.text")); // NOI18N
        typeLabel.setName("typeLabel"); // NOI18N

        javax.swing.GroupLayout initialSetupPanelLayout = new javax.swing.GroupLayout(initialSetupPanel);
        initialSetupPanel.setLayout(initialSetupPanelLayout);
        initialSetupPanelLayout.setHorizontalGroup(
            initialSetupPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(initialSetupPanelLayout.createSequentialGroup()
                .addGroup(initialSetupPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, initialSetupPanelLayout.createSequentialGroup()
                        .addComponent(filePathTextField, javax.swing.GroupLayout.DEFAULT_SIZE, 903, Short.MAX_VALUE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(filePathBrowseButton))
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, initialSetupPanelLayout.createSequentialGroup()
                        .addGroup(initialSetupPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(propertiesScrollPanel, javax.swing.GroupLayout.DEFAULT_SIZE, 817, Short.MAX_VALUE)
                            .addComponent(propertiesLabel, javax.swing.GroupLayout.PREFERRED_SIZE, 745, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(initialSetupPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                            .addComponent(editPropertyButton, javax.swing.GroupLayout.DEFAULT_SIZE, 107, Short.MAX_VALUE)
                            .addComponent(removePropertyButton, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, 107, Short.MAX_VALUE)
                            .addComponent(addPropertyButton, javax.swing.GroupLayout.DEFAULT_SIZE, 107, Short.MAX_VALUE)))
                    .addGroup(initialSetupPanelLayout.createSequentialGroup()
                        .addComponent(loadFromFileRadioButton, javax.swing.GroupLayout.PREFERRED_SIZE, 133, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 797, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(initialSetupPanelLayout.createSequentialGroup()
                        .addComponent(editWorkerPropertiesRadioButton)
                        .addGap(195, 195, 195))
                    .addGroup(initialSetupPanelLayout.createSequentialGroup()
                        .addGroup(initialSetupPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(initialSetupPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING, false)
                                .addComponent(tokenImplementationLabel, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                .addComponent(workerImplementationLabel, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                .addComponent(workerNameLabel, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                .addComponent(workerIdLabel, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.PREFERRED_SIZE, 253, javax.swing.GroupLayout.PREFERRED_SIZE))
                            .addComponent(typeLabel))
                        .addGap(18, 18, 18)
                        .addGroup(initialSetupPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(workerNameField, javax.swing.GroupLayout.DEFAULT_SIZE, 659, Short.MAX_VALUE)
                            .addComponent(workerImplementationField, javax.swing.GroupLayout.DEFAULT_SIZE, 659, Short.MAX_VALUE)
                            .addComponent(tokenImplementationField, javax.swing.GroupLayout.DEFAULT_SIZE, 659, Short.MAX_VALUE)
                            .addComponent(typeComboBox, javax.swing.GroupLayout.PREFERRED_SIZE, 286, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(workerIdComboBox, javax.swing.GroupLayout.PREFERRED_SIZE, 281, javax.swing.GroupLayout.PREFERRED_SIZE))))
                .addGap(0, 0, 0))
            .addGroup(initialSetupPanelLayout.createSequentialGroup()
                .addComponent(invalidWorkerIdStatusLabel, javax.swing.GroupLayout.DEFAULT_SIZE, 918, Short.MAX_VALUE)
                .addContainerGap())
        );

        initialSetupPanelLayout.linkSize(javax.swing.SwingConstants.HORIZONTAL, new java.awt.Component[] {typeComboBox, workerIdComboBox});

        initialSetupPanelLayout.setVerticalGroup(
            initialSetupPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(initialSetupPanelLayout.createSequentialGroup()
                .addComponent(loadFromFileRadioButton)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(initialSetupPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(filePathTextField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(filePathBrowseButton))
                .addGap(18, 18, 18)
                .addComponent(editWorkerPropertiesRadioButton)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(initialSetupPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(workerIdLabel, javax.swing.GroupLayout.PREFERRED_SIZE, 31, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(workerIdComboBox, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(initialSetupPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(workerNameLabel)
                    .addComponent(workerNameField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(initialSetupPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(workerImplementationLabel)
                    .addComponent(workerImplementationField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(initialSetupPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(tokenImplementationLabel)
                    .addComponent(tokenImplementationField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(initialSetupPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(typeComboBox, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(typeLabel))
                .addGap(24, 24, 24)
                .addComponent(propertiesLabel)
                .addGap(20, 20, 20)
                .addGroup(initialSetupPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(initialSetupPanelLayout.createSequentialGroup()
                        .addGap(6, 6, 6)
                        .addComponent(addPropertyButton)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(editPropertyButton)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(removePropertyButton))
                    .addComponent(propertiesScrollPanel, javax.swing.GroupLayout.PREFERRED_SIZE, 189, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(invalidWorkerIdStatusLabel)
                .addContainerGap())
        );

        wizardPanel.add(initialSetupPanel, "initial");

        configurationPanel.setName("configurationPanel"); // NOI18N

        configurationLabel.setFont(resourceMap.getFont("configurationLabel.font")); // NOI18N
        configurationLabel.setText(resourceMap.getString("configurationLabel.text")); // NOI18N
        configurationLabel.setName("configurationLabel"); // NOI18N

        configurationScrollPane.setName("configurationScrollPane"); // NOI18N

        configurationTextArea.setColumns(20);
        configurationTextArea.setName("configurationTextArea"); // NOI18N
        configurationScrollPane.setViewportView(configurationTextArea);

        javax.swing.GroupLayout configurationPanelLayout = new javax.swing.GroupLayout(configurationPanel);
        configurationPanel.setLayout(configurationPanelLayout);
        configurationPanelLayout.setHorizontalGroup(
            configurationPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(configurationPanelLayout.createSequentialGroup()
                .addGroup(configurationPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(configurationLabel)
                    .addGroup(configurationPanelLayout.createSequentialGroup()
                        .addGap(12, 12, 12)
                        .addComponent(configurationScrollPane, javax.swing.GroupLayout.DEFAULT_SIZE, 906, Short.MAX_VALUE)))
                .addContainerGap())
        );
        configurationPanelLayout.setVerticalGroup(
            configurationPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(configurationPanelLayout.createSequentialGroup()
                .addComponent(configurationLabel)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(configurationScrollPane, javax.swing.GroupLayout.DEFAULT_SIZE, 615, Short.MAX_VALUE)
                .addContainerGap())
        );

        wizardPanel.add(configurationPanel, "editing");

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(resetButton)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 540, Short.MAX_VALUE)
                .addComponent(cancelButton, javax.swing.GroupLayout.PREFERRED_SIZE, 86, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(backButton, javax.swing.GroupLayout.PREFERRED_SIZE, 74, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(nextApplyButton, javax.swing.GroupLayout.PREFERRED_SIZE, 110, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap())
            .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addGroup(layout.createSequentialGroup()
                    .addContainerGap()
                    .addComponent(wizardPanel, javax.swing.GroupLayout.DEFAULT_SIZE, 930, Short.MAX_VALUE)
                    .addContainerGap()))
        );

        layout.linkSize(javax.swing.SwingConstants.HORIZONTAL, new java.awt.Component[] {backButton, cancelButton, nextApplyButton});

        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addContainerGap(708, Short.MAX_VALUE)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(resetButton)
                    .addComponent(nextApplyButton)
                    .addComponent(backButton)
                    .addComponent(cancelButton))
                .addContainerGap())
            .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addGroup(layout.createSequentialGroup()
                    .addGap(37, 37, 37)
                    .addComponent(wizardPanel, javax.swing.GroupLayout.DEFAULT_SIZE, 649, Short.MAX_VALUE)
                    .addGap(59, 59, 59)))
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

    private void backButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_backButtonActionPerformed
        if (configurationEdited) {
            final int confirm = JOptionPane.showConfirmDialog(this,
                    "Configuration has been edited, going back to the initial setup will discard changes.\n Proceed?",
                    "Changes have been made", JOptionPane.YES_NO_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);
        
            if (confirm == JOptionPane.YES_OPTION) {
                goBackToInitialConfig();
            }
        } else {
            // no changes made
            goBackToInitialConfig();
        }
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
            final String key = workerPropertyEditor.getKey().toUpperCase();
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
                final String key = workerPropertyEditor.getKey().toUpperCase();
                final String value = workerPropertyEditor.getValue();
                
                if (!oldKey.equals(key) && !key.equals(PropertiesConstants.NAME)) {
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

    private void workerNameFieldKeyTyped(java.awt.event.KeyEvent evt) {//GEN-FIRST:event_workerNameFieldKeyTyped
        updateControls();
    }//GEN-LAST:event_workerNameFieldKeyTyped

    private void workerImplementationFieldKeyTyped(java.awt.event.KeyEvent evt) {//GEN-FIRST:event_workerImplementationFieldKeyTyped
        updateControls();
    }//GEN-LAST:event_workerImplementationFieldKeyTyped

    private void setMode(final Mode mode) {
        this.mode = mode;
        updateControls();
        
        // forget about selected file when going to edit properties mode
        if (mode == Mode.EDIT_MANUALLY) {
            fileSelected = false;
        } else if (filePathTextField.getText().length() > 0) {
            // if going from edit manually back to select file, and a file was already
            // selected, consider that to be selected
            fileSelected = true;
        }
    }
    
    private void goBackToInitialConfig() {       
        ((CardLayout) wizardPanel.getLayout()).show(wizardPanel, "initial");
        stage = Stage.INITIAL_CONFIG;

        updateControls();
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
        
        final Properties properties = new Properties();

        final String workerId =
                ((JTextField) workerIdComboBox.getEditor().getEditorComponent())
                .getText();
        final String workerClassName = workerImplementationField.getText();
        final String tokenClassName = tokenImplementationField.getText();
        final String workerName = workerNameField.getText();
        final String workerPrefix =
                PropertiesConstants.WORKER_PREFIX + workerId;
        final String workerType =
                ((JTextField) typeComboBox.getEditor().getEditorComponent()).getText();

        // insert IMPLEMENTATION_CLASS property
        properties.setProperty(workerPrefix + "." + PropertiesConstants.IMPLEMENTATION_CLASS,
                workerClassName);
        
        if (tokenClassName != null && !tokenClassName.isEmpty()) {
            // insert CRYPTOTOKEN_IMPLEMENTATION_CLASS property
            properties.setProperty(workerPrefix + "."
                    + PropertiesConstants.CRYPTOTOKEN_IMPLEMENTATION_CLASS,
                    tokenClassName);
        }
        
        // insert NAME worker property   
        properties.setProperty(workerPrefix + "." + PropertiesConstants.NAME,
                workerName);
        
        properties.setProperty(workerPrefix + "." + WorkerConfig.TYPE,
                workerType);
        
        // generate additional properties
        final DefaultTableModel model =
                (DefaultTableModel) propertiesTable.getModel();
        
        for (int i = 0; i < model.getRowCount(); i++) {
            final String key = (String) model.getValueAt(i, 0);
            final String value = (String) model.getValueAt(i, 1);
            
            properties.setProperty(workerPrefix + "." + key, value);
        }
        
        final StringWriter writer = new StringWriter();
        
        try {
            properties.store(writer, null);
        } catch (IOException e) {
            // ignore
        }
            
        return writer.getBuffer().toString();
    }

    /**
     * Get a list of worker IDs added and modified by the apply operation.
     * 
     * @return List of worker IDs
     */
    public List<Integer> getModifiedWorkers() {
        return modifiedWorkers;
    }

    @Action(block = Task.BlockingScope.APPLICATION)
    public Task nextAction() {
        final Task result;
        switch (stage) {
            case INITIAL_CONFIG:
                result = createLoadTask(false);
                break;
            case EDIT_PROPERTIES:
                result = createApplyTask();
                break;
            default:
                throw new IllegalArgumentException("Unknown state: " + stage);
        }
        return result;
    }
    
    private Task createApplyTask() {
        return new ApplyTask(org.jdesktop.application.Application.getInstance(org.signserver.admin.gui.SignServerAdminGUIApplication.class));
    }
    
    private Task createLoadTask(final boolean forceReload) {
        return new LoadTask(org.jdesktop.application.Application.getInstance(org.signserver.admin.gui.SignServerAdminGUIApplication.class), forceReload);
    }
    
    @Action(block = Task.BlockingScope.APPLICATION)
    public Task reloadAction() {
        return createLoadTask(true);
    }

    /** 
     * Task for loading configuration from file or putting together a new 
     * configuration and if successful switching to the next stage.
     */
    private class LoadTask extends org.jdesktop.application.Task<String, Void> {
        private final String filePath;
        private final boolean reload;
        private String conf;
        LoadTask(org.jdesktop.application.Application app, boolean forceReload) {
            // Runs on the EDT.  Copy GUI state that
            // doInBackground() depends on from parameters
            // to NextActionTask fields, here.
            super(app);
            filePath = filePathTextField.getText();
            this.reload = forceReload || mode == Mode.EDIT_MANUALLY || fileSelected;
        }
        @Override protected String doInBackground() {
            // Your Task's code here.  This method runs
            // on a background thread, so don't reference
            // the Swing GUI from here.

            // TODO: should later on handle merging manual properties to the
            // properties editor and so on...

            // reload configuration if a new file has been selected or if
            // a worker was add using the form
            if (reload) {
                switch (mode) {
                    case LOAD_FROM_FILE:
                        final File file = new File(filePath);

                        try {
                            conf = FileUtils.readFileToString(file, StandardCharsets.ISO_8859_1.name());
                        } catch (IOException e) {
                            return "Failed to read file: " + e.getLocalizedMessage();
                        }
                        break;
                    case EDIT_MANUALLY:
                        conf = generateProperties();
                        break;
                    default:
                        throw new IllegalArgumentException("Unknown mode: " + mode);
                }
            }
            
            return null;
        }
        @Override protected void succeeded(String error) {
            // Runs on the EDT.  Update the GUI based on
            // the result computed by doInBackground().
            
            if (error == null) {
                stage = Stage.EDIT_PROPERTIES;
                // in the initial config pane, go to the next step
                ((CardLayout) wizardPanel.getLayout()).show(wizardPanel, "editing");

                if (reload) {
                    configurationTextArea.setText(conf);
                    configurationTextArea.setCaretPosition(0);
                    configurationEdited = false;
                    // reset file selected status
                    fileSelected = false;
                }
                updateControls();
            } else {
                JOptionPane.showMessageDialog(AddWorkerDialog.this, error,
                        "Failed to load properties", JOptionPane.ERROR_MESSAGE);
            }
        }
    }
    
    private class ApplyTask extends org.jdesktop.application.Task<String, Void> {
        private final String conf;
        ApplyTask(org.jdesktop.application.Application app) {
            // Runs on the EDT.  Copy GUI state that
            // doInBackground() depends on from parameters
            // to NextActionTask fields, here.
            super(app);
            conf = configurationTextArea.getText();
            
        }
        @Override protected String doInBackground() {
            // Your Task's code here.  This method runs
            // on a background thread, so don't reference
            // the Swing GUI from here.
            final Properties props = new Properties();
            try {
                props.load(new StringReader(conf));
            } catch (IOException e) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Error loading properties", e);
                }
                return "Error loading properties: " + e.getMessage();
            }

            final PropertiesParser parser = new PropertiesParser();

            parser.process(props);

            if (parser.hasErrors()) {
                final List<String> errors = parser.getErrors();

                // show the first error message from the parser, to avoid overflowing
                // TODO: maybe add a "more errors..." view later...
                return "Error parsing properties: " + errors.get(0);
            } else {
                final PropertiesApplier applier = new AdminGUIPropertiesApplier();

                applier.apply(parser);

                if (applier.hasError()) {
                    return "Error applying properties: " + applier.getError();
                }

                modifiedWorkers = applier.getWorkerIds();

                try {
                    for (final int workerId : modifiedWorkers) {
                        SignServerAdminGUIApplication.getAdminWS().reloadConfiguration(workerId);
                    }
                } catch (AdminNotAuthorizedException_Exception | SOAPFaultException | EJBException e) {
                    return "Error reloading workers: " + e.getMessage();
                }
            }

            return null;
        }
        @Override protected void succeeded(String error) {
            // Runs on the EDT.  Update the GUI based on
            // the result computed by doInBackground().
            if (error == null) {
                dispose();
            } else {
                JOptionPane.showMessageDialog(AddWorkerDialog.this, error,
                        "Failed apply properties", JOptionPane.ERROR_MESSAGE);
            }
        }
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
    private javax.swing.JLabel invalidWorkerIdStatusLabel;
    private javax.swing.JRadioButton loadFromFileRadioButton;
    private javax.swing.ButtonGroup modeSelectButtonGroup;
    private javax.swing.JButton nextApplyButton;
    private javax.swing.JLabel propertiesLabel;
    private javax.swing.JScrollPane propertiesScrollPanel;
    private javax.swing.JTable propertiesTable;
    private javax.swing.JButton removePropertyButton;
    private javax.swing.JButton resetButton;
    private javax.swing.JTextField tokenImplementationField;
    private javax.swing.JLabel tokenImplementationLabel;
    private javax.swing.JComboBox typeComboBox;
    private javax.swing.JLabel typeLabel;
    private javax.swing.JPanel wizardPanel;
    private javax.swing.JComboBox workerIdComboBox;
    private javax.swing.JLabel workerIdLabel;
    private javax.swing.JTextField workerImplementationField;
    private javax.swing.JLabel workerImplementationLabel;
    private javax.swing.JTextField workerNameField;
    private javax.swing.JLabel workerNameLabel;
    // End of variables declaration//GEN-END:variables
}
