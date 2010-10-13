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
import java.awt.Frame;
import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Vector;
import javax.ejb.EJBException;
import javax.swing.AbstractListModel;
import javax.swing.ComboBoxModel;
import javax.swing.DefaultCellEditor;
import javax.swing.DefaultListCellRenderer;
import javax.swing.JComboBox;
import javax.swing.JDialog;
import javax.swing.JFileChooser;
import javax.swing.JList;
import javax.swing.JOptionPane;
import javax.swing.JTextField;
import javax.swing.event.TableModelEvent;
import javax.swing.event.TableModelListener;
import javax.swing.table.DefaultTableModel;
import org.apache.log4j.Logger;
import org.jdesktop.application.Action;
import org.jdesktop.application.Application;
import org.jdesktop.application.Task;
import org.signserver.admin.gui.adminws.gen.Base64SignerCertReqData;
import org.signserver.admin.gui.adminws.gen.InvalidWorkerIdException_Exception;
import org.signserver.admin.gui.adminws.gen.Pkcs10CertReqInfo;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.GenericSignResponse;

/**
 * Dialog for generating certificate requests.
 * @author markus
 * @version $Id$
 */
public class GenerateRequestsDialog extends JDialog {

    /** Logger for this class. */
    private static final Logger LOG
            = Logger.getLogger(GenerateRequestsDialog.class);

    public static final int CANCEL = 0;
    public static final int OK = 1;

    private static final Vector<String> COLUMN_NAMES = new Vector(Arrays.asList(
            new String[] {
        "Signer",
        "Key",
        "Signature algorithm",
        "DN",
        "Filename"
    }));
    private static final String NEXT_KEY = "Next key";
    private static final String DEFAULT_KEY = "Default key";

    private int resultCode = CANCEL;

    private Vector<Vector<String>> data;
    
    private JComboBox sigAlgComboBox = new JComboBox(new String[] {
        "SHA1WithRSA",
        "SHA256WithRSA",
        "MD5WithRSA",
        "SHA256WithRSAAndMGF1",
        "SHA1withECDSA",
        "SHA224withECDSA",
        "SHA256withECDSA",
        "SHA384withECDSA",
        "SHA1WithDSA"
    });

    private JComboBox aliasComboBox = new JComboBox(new String[] {
         NEXT_KEY, DEFAULT_KEY});

    private List<Worker> workers;

    private List<Worker> signers;
   
    /** Creates new form GenerateRequestsDialog. */
    public GenerateRequestsDialog(final Frame parent, final boolean modal,
            final List<Worker> workers, final List<Worker> signers) {
        super(parent, modal);
        this.workers = new ArrayList<Worker>(workers);
        this.signers = signers;
        sigAlgComboBox.setEditable(true);
        initComponents();
        setTitle("Generate CSRs for " + workers.size() + " signers");

        data = new Vector<Vector<String>>();
        for (Worker worker : workers) {
            Vector<String> cols = new Vector<String>();
            cols.add(worker.getName() + " (" + worker.getWorkerId() + ")");
            if (worker.getConfiguration().getProperty("NEXTCERTSIGNKEY") != null) {
                cols.add(NEXT_KEY);
            } else {
                cols.add(DEFAULT_KEY);
            }
            cols.add(worker.getConfiguration().getProperty("SIGNATUREALGORITHM",
                    ""));
            cols.add(worker.getConfiguration().getProperty("REQUESTDN", ""));
            data.add(cols);
        }
        jTable1.setModel(new DefaultTableModel(data, COLUMN_NAMES) {

            @Override
            public boolean isCellEditable(int row, int column) {
                return column > 0;
            }

            @Override
            public void setValueAt(Object aValue, int row, int column) {
                data.get(row).set(column, (String) aValue);
                super.setValueAt(aValue, row, column);
            }

        });
         jTable1.getModel().addTableModelListener(new TableModelListener() {

            @Override
            public void tableChanged(final TableModelEvent e) {
                boolean enable = true;
                for (int row = 0; row < jTable1.getRowCount(); row++) {
                    if ("".equals(jTable1.getValueAt(row, 2))
                            || "".equals(jTable1.getValueAt(row, 3))
                            || "".equals(jTable1.getValueAt(row, 4))) {
                        enable = false;
                        break;
                    }
                }
                jButtonGenerate.setEnabled(enable);
            }
        });

        final BrowseCellEditor editor = new BrowseCellEditor(new JTextField(),
                JFileChooser.SAVE_DIALOG);
        editor.setClickCountToStart(1);
        final DefaultCellEditor textFieldEditor
                = new DefaultCellEditor(new JTextField());
        final DefaultCellEditor comboBoxFieldEditor
                = new DefaultCellEditor(sigAlgComboBox);
        comboBoxFieldEditor.setClickCountToStart(1);
        jTable1.getColumn("Filename").setCellEditor(editor);
        textFieldEditor.setClickCountToStart(1);
        jTable1.getColumn("Signature algorithm").setCellEditor(
                comboBoxFieldEditor);
        jTable1.getColumn("DN").setCellEditor(textFieldEditor);

        final DefaultCellEditor aliasComboBoxFieldEditor
                = new DefaultCellEditor(aliasComboBox);
        aliasComboBoxFieldEditor.setClickCountToStart(1);
        jTable1.getColumn("Key").setCellEditor(aliasComboBoxFieldEditor);
        
        signersComboBox.setRenderer(new DefaultListCellRenderer() {

            @Override
            public Component getListCellRendererComponent(final JList list,
                    Object value, final int index, final boolean isSelected,
                    final boolean cellHasFocus) {
                if (value instanceof Worker) {
                    final Worker worker = (Worker) value;
                    value = worker.getName()
                            + " (" + worker.getWorkerId() + ")";
                }
                return super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
            }

        });
        signersComboBox.setModel(new SignersComboBoxModel(signers));

        // Find and select first matching REQUESTSIGNER
        Worker selectedSigner = null;
        loop1: for (Worker worker : workers) {
            final String requestSigner = (String) worker.getConfiguration()
                    .get("REQUESTSIGNER");
            for (Worker signer : signers) {
                if (signer.getName().equals(requestSigner)) {
                    selectedSigner = signer;
                    break loop1;
                }
            }
        }
        if (selectedSigner == null) {
            standardFormatRadioButton.setSelected(true);
        } else {
            signersComboBox.setSelectedItem(selectedSigner);
            signedFormatRadioButton.setSelected(true);
        }
        radioButtonsStateChanged(null);
    }

    /** This method is called from within the constructor to
     * initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is
     * always regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        buttonGroup1 = new javax.swing.ButtonGroup();
        jButton2 = new javax.swing.JButton();
        jButtonGenerate = new javax.swing.JButton();
        jScrollPane1 = new javax.swing.JScrollPane();
        jTable1 = new javax.swing.JTable();
        jPanel1 = new javax.swing.JPanel();
        standardFormatRadioButton = new javax.swing.JRadioButton();
        signedFormatRadioButton = new javax.swing.JRadioButton();
        signersComboBox = new javax.swing.JComboBox();

        setDefaultCloseOperation(javax.swing.WindowConstants.DISPOSE_ON_CLOSE);
        setLocationByPlatform(true);
        setName("Form"); // NOI18N

        org.jdesktop.application.ResourceMap resourceMap = org.jdesktop.application.Application.getInstance(org.signserver.admin.gui.SignServerAdminGUIApplication.class).getContext().getResourceMap(GenerateRequestsDialog.class);
        jButton2.setText(resourceMap.getString("jButton2.text")); // NOI18N
        jButton2.setName("jButton2"); // NOI18N
        jButton2.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton2ActionPerformed(evt);
            }
        });

        javax.swing.ActionMap actionMap = org.jdesktop.application.Application.getInstance(org.signserver.admin.gui.SignServerAdminGUIApplication.class).getContext().getActionMap(GenerateRequestsDialog.class, this);
        jButtonGenerate.setAction(actionMap.get("generateRequests")); // NOI18N
        jButtonGenerate.setText(resourceMap.getString("jButtonGenerate.text")); // NOI18N
        jButtonGenerate.setName("jButtonGenerate"); // NOI18N
        jButtonGenerate.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonGenerateActionPerformed(evt);
            }
        });

        jScrollPane1.setName("jScrollPane1"); // NOI18N

        jTable1.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {
                {null, null, null, null},
                {null, null, null, null},
                {null, null, null, null},
                {null, null, null, null}
            },
            new String [] {
                "Signer ID", "Signer Name", "DN", "Filename"
            }
        ) {
            Class[] types = new Class [] {
                java.lang.Object.class, java.lang.Object.class, java.lang.String.class, java.lang.Object.class
            };
            boolean[] canEdit = new boolean [] {
                true, false, true, true
            };

            public Class getColumnClass(int columnIndex) {
                return types [columnIndex];
            }

            public boolean isCellEditable(int rowIndex, int columnIndex) {
                return canEdit [columnIndex];
            }
        });
        jTable1.setName("jTable1"); // NOI18N
        jScrollPane1.setViewportView(jTable1);

        jPanel1.setBorder(javax.swing.BorderFactory.createTitledBorder(resourceMap.getString("jPanel1.border.title"))); // NOI18N
        jPanel1.setName("jPanel1"); // NOI18N

        buttonGroup1.add(standardFormatRadioButton);
        standardFormatRadioButton.setSelected(true);
        standardFormatRadioButton.setText(resourceMap.getString("standardFormatRadioButton.text")); // NOI18N
        standardFormatRadioButton.setName("standardFormatRadioButton"); // NOI18N
        standardFormatRadioButton.addChangeListener(new javax.swing.event.ChangeListener() {
            public void stateChanged(javax.swing.event.ChangeEvent evt) {
                radioButtonsStateChanged(evt);
            }
        });

        buttonGroup1.add(signedFormatRadioButton);
        signedFormatRadioButton.setText(resourceMap.getString("signedFormatRadioButton.text")); // NOI18N
        signedFormatRadioButton.setName("signedFormatRadioButton"); // NOI18N
        signedFormatRadioButton.addChangeListener(new javax.swing.event.ChangeListener() {
            public void stateChanged(javax.swing.event.ChangeEvent evt) {
                radioButtonsStateChanged(evt);
            }
        });

        signersComboBox.setModel(new javax.swing.DefaultComboBoxModel(new String[] { "Item 1", "Item 2", "Item 3", "Item 4" }));
        signersComboBox.setName("signersComboBox"); // NOI18N

        javax.swing.GroupLayout jPanel1Layout = new javax.swing.GroupLayout(jPanel1);
        jPanel1.setLayout(jPanel1Layout);
        jPanel1Layout.setHorizontalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(standardFormatRadioButton, javax.swing.GroupLayout.PREFERRED_SIZE, 404, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(signedFormatRadioButton, javax.swing.GroupLayout.PREFERRED_SIZE, 209, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(signersComboBox, 0, 194, Short.MAX_VALUE)
                .addContainerGap())
        );
        jPanel1Layout.setVerticalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(standardFormatRadioButton)
                    .addComponent(signedFormatRadioButton)
                    .addComponent(signersComboBox, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(jScrollPane1, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, 855, Short.MAX_VALUE)
                    .addComponent(jPanel1, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(jButton2)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jButtonGenerate)))
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 212, Short.MAX_VALUE)
                .addGap(18, 18, 18)
                .addComponent(jPanel1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jButtonGenerate)
                    .addComponent(jButton2))
                .addContainerGap())
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    public Vector<Vector<String>> getData() {
        return data;
    }

    public int getResultCode() {
        return resultCode;
    }

    private void jButton2ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton2ActionPerformed
        dispose();
}//GEN-LAST:event_jButton2ActionPerformed

    private void jButtonGenerateActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButtonGenerateActionPerformed
        
    }//GEN-LAST:event_jButtonGenerateActionPerformed

    private void radioButtonsStateChanged(javax.swing.event.ChangeEvent evt) {//GEN-FIRST:event_radioButtonsStateChanged
        signersComboBox.setEnabled(signedFormatRadioButton.isSelected());
    }//GEN-LAST:event_radioButtonsStateChanged

    public int showRequestsDialog() {
        setVisible(true);
        return resultCode;
    }

    @Action
    public Task generateRequests() {
        return new GenerateRequestsTask(Application.getInstance(
                SignServerAdminGUIApplication.class));
    }

    private class GenerateRequestsTask extends Task<String, Void> {
        
        private Worker signer;

        GenerateRequestsTask(final Application app) {
            // Runs on the EDT.  Copy GUI state that
            // doInBackground() depends on from parameters
            // to GenerateRequestsTask fields, here.
            super(app);
            if (signedFormatRadioButton.isSelected()) {
                final Object o = signersComboBox.getSelectedItem();
                if (o instanceof Worker) {
                    signer = (Worker) o;
                } else {
                    cancel(false);
                }
            }
        }
        @Override protected String doInBackground() {
            // Your Task's code here.  This method runs
            // on a background thread, so don't reference
            // the Swing GUI from here.
            resultCode = OK;

            final StringBuilder sb = new StringBuilder();
            for (int row = 0; row < data.size(); row++) {
                final Worker worker = workers.get(row);
                final int workerid = worker.getWorkerId();
                final String key = (String) data.get(row).get(1);
                final String sigAlg =  (String) data.get(row).get(2);
                final String dn = (String) data.get(row).get(3);
                final String filename = (String) data.get(row).get(4);

                final boolean defaultKey= DEFAULT_KEY.equals(key);

                if (LOG.isDebugEnabled()) {
                    LOG.debug("worker=" + workerid + ", key=" + key
                            + ", dn=" + dn + ", sigAlg=" + sigAlg
                            + ", filename=" + filename
                            + ", defaultKey=" + defaultKey);
                }

                FileOutputStream fos = null;
                try {
                    final Pkcs10CertReqInfo certReqInfo
                            = new Pkcs10CertReqInfo();
                    certReqInfo.setSignatureAlgorithm(sigAlg);
                    certReqInfo.setSubjectDN(dn);
                    certReqInfo.setAttributes(null);
                    final Base64SignerCertReqData reqData =
                        (Base64SignerCertReqData) SignServerAdminGUIApplication
                            .getAdminWS()
                            .getPKCS10CertificateRequestForKey(workerid, certReqInfo,
                                defaultKey);
                    if (reqData == null) {
                        final String error =
                            "Unable to generate certificate request for signer "
                            + workerid;
                        LOG.error(error);
                        sb.append(error);
                        sb.append("\n");
                    } else {

                        final ByteArrayOutputStream bout
                                = new ByteArrayOutputStream();
                        bout.write("-----BEGIN CERTIFICATE REQUEST-----\n"
                                .getBytes());
                        bout.write(reqData.getBase64CertReq());
                        bout.write("\n-----END CERTIFICATE REQUEST-----\n"
                                .getBytes());

                        byte[] fileContent;
                        if (signer == null) {
                            fileContent = bout.toByteArray();
                        } else {
                            final GenericSignResponse response =
                                    (GenericSignResponse)
                                    SignServerAdminGUIApplication
                            .getClientWS().sign(
                                    String.valueOf(signer.getWorkerId()),
                                    bout.toByteArray());
                            fileContent = response.getProcessedData();
                        }

                        fos = new FileOutputStream(filename);
                        fos.write(fileContent);

                        workers.remove(worker);
                        data.remove(row);
                        row--;
                        jTable1.revalidate();
                    }
                } catch (EJBException ejbException) {
                    final Exception ex = ejbException.getCausedByException();
                    final String error = "Error generating request for signer "
                        + workerid;
                    LOG.error(error, ex);
                    sb.append(error);
                    sb.append(":\n" + ex.getMessage());
                    sb.append("\n");
                } catch (CryptoTokenOfflineException ex) {
                    final String error = "Error generating request for signer "
                        + workerid + ":\n" + ex.getMessage();
                    LOG.error(error, ex);
                    sb.append(error);
                    sb.append("\n");
                } catch (InvalidWorkerIdException_Exception ex) {
                    final String error = "Error generating request for signer "
                        + workerid + ":\n" + ex.getMessage();
                    LOG.error(error, ex);
                    sb.append(error);
                    sb.append("\n");
                } catch (FileNotFoundException ex) {
                    final String error = "Error generating request for signer "
                        + workerid + ":\n" + ex.getMessage();
                    LOG.error(error, ex);
                    sb.append(error);
                    sb.append("\n");
                } catch (IOException ex) {
                    final String error = "Error generating request for signer "
                        + workerid + ":\n" + ex.getMessage();
                    LOG.error(error, ex);
                    sb.append(error);
                    sb.append("\n");
                } catch (Exception ex) {
                    final String error = "Error generating request for signer "
                        + workerid + ":\n" + ex.getMessage();
                    LOG.error(error, ex);
                    sb.append(error);
                    sb.append("\n");
                } finally {
                    if (fos != null) {
                        try {
                            fos.close();
                        } catch (IOException ex2) {
                            LOG.error("Error closing file: " + filename, ex2);
                        }
                    }
                }
            }

            return sb.toString();  // return your result
        }
        @Override protected void succeeded(final String result) {
            // Runs on the EDT.  Update the GUI based on
            // the result computed by doInBackground().
            if (result.length() > 0) {
                JOptionPane.showMessageDialog(GenerateRequestsDialog.this,
                        result, "Error", JOptionPane.ERROR_MESSAGE);
            }
            if (data.size() == 0) {
                JOptionPane.showMessageDialog(GenerateRequestsDialog.this,
                        "Generated requests for all choosen signers.");
                dispose();
            }
        }
    }


    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.ButtonGroup buttonGroup1;
    private javax.swing.JButton jButton2;
    private javax.swing.JButton jButtonGenerate;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JTable jTable1;
    private javax.swing.JRadioButton signedFormatRadioButton;
    private javax.swing.JComboBox signersComboBox;
    private javax.swing.JRadioButton standardFormatRadioButton;
    // End of variables declaration//GEN-END:variables

    private static class SignersComboBoxModel extends AbstractListModel 
            implements ComboBoxModel {

        private List<Worker> items;
        private Object selectedItem;

        public SignersComboBoxModel(List<Worker> items) {
            this.items = items;
        }

        @Override
        public int getSize() {
            return items.size();
        }

        @Override
        public Object getElementAt(int index) {
            return items.get(index);
        }

        @Override
        public void setSelectedItem(Object anItem) {
            if ((selectedItem != null && !selectedItem.equals(anItem)) ||
                selectedItem == null && anItem != null) {
                selectedItem = anItem;
                fireContentsChanged(this, -1, -1);
            }
        }

        @Override
        public Object getSelectedItem() {
            return selectedItem;
        }
        
    }

}
