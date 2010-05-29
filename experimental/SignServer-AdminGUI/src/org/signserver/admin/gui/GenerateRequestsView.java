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
import org.jdesktop.application.SingleFrameApplication;
import org.jdesktop.application.FrameView;
import org.jdesktop.application.Task;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.Vector;
import javax.ejb.EJBException;
import javax.swing.DefaultCellEditor;
import javax.swing.JComboBox;
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
 * Frame for generating certificate requests.
 * @author markus
 * @version $Id$
 */
public class GenerateRequestsView extends FrameView {

    private static final Logger LOG
            = Logger.getLogger(GenerateRequestsView.class);

    private Vector<Integer> signerIds;
    private Vector<String> signerNames;
    private Vector<Vector<String>> data;
    private static Vector<String> columnNames = new Vector(Arrays.asList(
            new String[] {
        "Signer",
        "Signature algorithm",
        "DN",
        "Filename"
    }));

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

    public GenerateRequestsView(SingleFrameApplication app, Integer[] signerIds,
            String[] signerNames) {
        super(app);

        this.signerIds = new Vector<Integer>(Arrays.asList(signerIds));
        this.signerNames = new Vector<String>(Arrays.asList(signerNames));
        sigAlgComboBox.setEditable(true);
        initComponents();
        getFrame().setTitle("Generate CSRs for " + signerIds.length
                + " signers");
        data = new Vector<Vector<String>>();
        for (int row = 0; row < signerIds.length; row++) {
            Vector<String> cols = new Vector<String>();
            cols.add(SignServerAdminGUIApplication.getWorkerSession()
                    .getCurrentWorkerConfig(signerIds[row]).getProperty("NAME")
                    + " (" + signerIds[row] + ")");
            cols.add("");
            cols.add("");
            data.add(cols);
        }
        jTable1.setModel(new DefaultTableModel(data, columnNames) {

            @Override
            public boolean isCellEditable(int row, int column) {
                return column > 0;
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
        final DefaultCellEditor textFieldEditor = new DefaultCellEditor(new JTextField());
        final DefaultCellEditor comboBoxFieldEditor = new DefaultCellEditor(sigAlgComboBox);
        comboBoxFieldEditor.setClickCountToStart(1);
        jTable1.getColumn("Filename").setCellEditor(editor);
        textFieldEditor.setClickCountToStart(1);
        jTable1.getColumn("Signature algorithm").setCellEditor(comboBoxFieldEditor);
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

        mainPanel = new javax.swing.JPanel();
        jButton2 = new javax.swing.JButton();
        jButtonGenerate = new javax.swing.JButton();
        jScrollPane1 = new javax.swing.JScrollPane();
        jTable1 = new javax.swing.JTable();

        mainPanel.setName("mainPanel"); // NOI18N

        org.jdesktop.application.ResourceMap resourceMap = org.jdesktop.application.Application.getInstance(org.signserver.admin.gui.SignServerAdminGUIApplication.class).getContext().getResourceMap(GenerateRequestsView.class);
        jButton2.setText(resourceMap.getString("jButton2.text")); // NOI18N
        jButton2.setName("jButton2"); // NOI18N
        jButton2.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton2ActionPerformed(evt);
            }
        });

        javax.swing.ActionMap actionMap = org.jdesktop.application.Application.getInstance(org.signserver.admin.gui.SignServerAdminGUIApplication.class).getContext().getActionMap(GenerateRequestsView.class, this);
        jButtonGenerate.setAction(actionMap.get("generateRequests")); // NOI18N
        jButtonGenerate.setText(resourceMap.getString("jButtonGenerate.text")); // NOI18N
        jButtonGenerate.setName("jButtonGenerate"); // NOI18N

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

        javax.swing.GroupLayout mainPanelLayout = new javax.swing.GroupLayout(mainPanel);
        mainPanel.setLayout(mainPanelLayout);
        mainPanelLayout.setHorizontalGroup(
            mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, mainPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(jScrollPane1, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, 817, Short.MAX_VALUE)
                    .addGroup(mainPanelLayout.createSequentialGroup()
                        .addComponent(jButton2)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jButtonGenerate)))
                .addContainerGap())
        );
        mainPanelLayout.setVerticalGroup(
            mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, mainPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 368, Short.MAX_VALUE)
                .addGap(18, 18, 18)
                .addGroup(mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jButtonGenerate)
                    .addComponent(jButton2))
                .addContainerGap())
        );

        setComponent(mainPanel);
    }// </editor-fold>//GEN-END:initComponents

    private void jButton2ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton2ActionPerformed
        getFrame().setVisible(false);
}//GEN-LAST:event_jButton2ActionPerformed

    @Action(block = Task.BlockingScope.WINDOW)
    public void generateRequests() {
        final String hostname = null;

        for (int row = 0; row < data.size(); row++) {
            final int workerid = signerIds.get(row);
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
                    JOptionPane.showMessageDialog(getFrame(), error + ":\n"
                            + "Unable to generate certificate request.",
                            "Error", JOptionPane.ERROR_MESSAGE);
                } else {
                    fos = new FileOutputStream(filename);
                    fos.write("-----BEGIN CERTIFICATE REQUEST-----\n"
                            .getBytes());
                    fos.write(reqData.getBase64CertReq());
                    fos.write("\n-----END CERTIFICATE REQUEST-----\n"
                            .getBytes());
                    
                    signerIds.remove(row);
                    signerNames.remove(row);
                    data.remove(row);
                    row--;
                    jTable1.revalidate();
                }
            } catch (EJBException ejbException) {
                final Exception ex = ejbException.getCausedByException();
                LOG.error(error, ex);
                JOptionPane.showMessageDialog(getFrame(), error + ":\n"
                        + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            } catch (CryptoTokenOfflineException ex) {
                LOG.error("Error", ex);
                JOptionPane.showMessageDialog(getFrame(), error + ":\n"
                        + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            } catch (InvalidWorkerIdException ex) {
                LOG.error("Error", ex);
                JOptionPane.showMessageDialog(getFrame(), error + ":\n"
                        + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            } catch (FileNotFoundException ex) {
                LOG.error("Error", ex);
                JOptionPane.showMessageDialog(getFrame(), error + ":\n"
                        + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            } catch (IOException ex) {
                LOG.error("Error", ex);
                JOptionPane.showMessageDialog(getFrame(), error + ":\n"
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
            JOptionPane.showMessageDialog(getFrame(),
                    "Generated requests for all choosen signers.");
            getFrame().dispose();
        }
    }


    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton jButton2;
    private javax.swing.JButton jButtonGenerate;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JTable jTable1;
    private javax.swing.JPanel mainPanel;
    // End of variables declaration//GEN-END:variables

}
