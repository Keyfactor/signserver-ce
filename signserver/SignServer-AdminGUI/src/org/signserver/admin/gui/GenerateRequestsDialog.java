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

import java.awt.Frame;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Vector;
import javax.ejb.EJBException;
import javax.swing.DefaultCellEditor;
import javax.swing.JComboBox;
import javax.swing.JDialog;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.JTextField;
import javax.swing.event.TableModelEvent;
import javax.swing.event.TableModelListener;
import javax.swing.table.DefaultTableModel;
import org.apache.log4j.Logger;
import org.signserver.common.Base64SignerCertReqData;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.PKCS10CertReqInfo;

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
        "Signature algorithm",
        "DN",
        "Filename"
    }));

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

    private List<Worker> workers;

    /** Creates new form GenerateRequestsDialog */
    public GenerateRequestsDialog(final Frame parent, final boolean modal,
            final List<Worker> workers) {
        super(parent, modal);
        this.workers = new ArrayList<Worker>(workers);
        sigAlgComboBox.setEditable(true);
        initComponents();
        setTitle("Generate CSRs for " + workers.size() + " signers");

        data = new Vector<Vector<String>>();
        for (Worker worker : workers) {
            Vector<String> cols = new Vector<String>();
            cols.add(worker.getName() + " (" + worker.getWorkerId() + ")");
            cols.add("");
            cols.add("");
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
                    if ("".equals(jTable1.getValueAt(row, 1))
                            || "".equals(jTable1.getValueAt(row, 2))
                            || "".equals(jTable1.getValueAt(row, 3))) {
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
    }

    /** This method is called from within the constructor to
     * initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is
     * always regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jButton2 = new javax.swing.JButton();
        jButtonGenerate = new javax.swing.JButton();
        jScrollPane1 = new javax.swing.JScrollPane();
        jTable1 = new javax.swing.JTable();

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

        jButtonGenerate.setText(resourceMap.getString("jButtonGenerate.text")); // NOI18N
        jButtonGenerate.setEnabled(false);
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

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(jScrollPane1, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, 855, Short.MAX_VALUE)
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
                .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 308, Short.MAX_VALUE)
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
        resultCode = OK;
        final String hostname = null;

        for (int row = 0; row < data.size(); row++) {
            final Worker worker = workers.get(row);
            final int workerid = worker.getWorkerId();
            final String sigAlg =  (String) jTable1.getValueAt(row, 1);
            final String dn = (String) jTable1.getValueAt(row, 2);
            final String filename = (String) jTable1.getValueAt(row, 3);
            final String error = "Error generating request for signer "
                    + workerid;

            LOG.debug("worker=" + workerid + ", dn=" + dn
                    + ", sigAlg=" + sigAlg + ", filename=" + filename);

            FileOutputStream fos = null;
            try {
                final PKCS10CertReqInfo certReqInfo
                        = new PKCS10CertReqInfo(sigAlg, dn, null);
                final Base64SignerCertReqData reqData =
                        (Base64SignerCertReqData) SignServerAdminGUIApplication
                        .getWorkerSession()
                        .getCertificateRequest(workerid, certReqInfo);
                if (reqData == null) {
                    LOG.error(error
                            + ": Unable to generate certificate request.");
                    JOptionPane.showMessageDialog(this, error + ":\n"
                            + "Unable to generate certificate request.",
                            "Error", JOptionPane.ERROR_MESSAGE);
                } else {
                    fos = new FileOutputStream(filename);
                    fos.write("-----BEGIN CERTIFICATE REQUEST-----\n"
                            .getBytes());
                    fos.write(reqData.getBase64CertReq());
                    fos.write("\n-----END CERTIFICATE REQUEST-----\n"
                            .getBytes());

                    workers.remove(worker);
                    data.remove(row);
                    row--;
                    jTable1.revalidate();
                }
            } catch (EJBException ejbException) {
                final Exception ex = ejbException.getCausedByException();
                LOG.error(error, ex);
                JOptionPane.showMessageDialog(this, error + ":\n"
                        + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            } catch (CryptoTokenOfflineException ex) {
                LOG.error("Error", ex);
                JOptionPane.showMessageDialog(this, error + ":\n"
                        + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            } catch (InvalidWorkerIdException ex) {
                LOG.error("Error", ex);
                JOptionPane.showMessageDialog(this, error + ":\n"
                        + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            } catch (FileNotFoundException ex) {
                LOG.error("Error", ex);
                JOptionPane.showMessageDialog(this, error + ":\n"
                        + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            } catch (IOException ex) {
                LOG.error("Error", ex);
                JOptionPane.showMessageDialog(this, error + ":\n"
                        + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            } catch (Exception ex) {
                System.out.println("Ex: " + ex);
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

        if (jTable1.getRowCount() == 0) {
            JOptionPane.showMessageDialog(this,
                    "Generated requests for all choosen signers.");
            dispose();
        }
    }//GEN-LAST:event_jButtonGenerateActionPerformed

    public int showRequestsDialog() {
        setVisible(true);
        return resultCode;
    }


    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton jButton2;
    private javax.swing.JButton jButtonGenerate;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JTable jTable1;
    // End of variables declaration//GEN-END:variables

}
