/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

/*
 * GenerateRequestsDialog.java
 *
 * Created on May 23, 2010, 9:58:27 PM
 */

package org.signserver.admin.gui;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.EventObject;
import javax.swing.DefaultCellEditor;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.table.DefaultTableModel;
import org.signserver.common.Base64SignerCertReqData;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.PKCS10CertReqInfo;

/**
 *
 * @author markus
 */
public class GenerateRequestsDialog extends javax.swing.JDialog {

    private Integer[] signerIds;
    private String[] signerNames;
    private Object[][] data;
    private String[] columnNames = {
        "Signer",
        "Signature algorithm",
        "DN",
        "Filename"
    };

    /** Creates new form GenerateRequestsDialog */
    public GenerateRequestsDialog(java.awt.Frame parent, boolean modal,
            Integer[] signerIds, String[] signerNames) {
        super(parent, modal);
        this.signerIds = signerIds;
        this.signerNames = signerNames;
        initComponents();
        data = new Object[signerIds.length][];
        for (int row = 0; row < signerIds.length; row++) {
            data[row] = new Object[] {
                SignServerAdminGUIApplication.getWorkerSession()
                    .getCurrentWorkerConfig(signerIds[row]).getProperty("NAME")
                    + " (" + signerIds[row] + ")",
                "",
                ""
            };
        }
        jTable1.setModel(new DefaultTableModel(data, columnNames) {

            @Override
            public boolean isCellEditable(int row, int column) {
                return column > 0;
            }

        });

//        jTable1.getColumn("Filename").setCellEditor(new DefaultCellEditor(new JTextField()) {
//
//            JButton customEditorButton = new JButton("...");
//
//            {
//                customEditorButton.addActionListener(new ActionListener() {
//
//                    public void actionPerformed(ActionEvent e) {
//                        String text = JOptionPane.showInputDialog(null);
//                        if (text != null) {
//                            table.
//                        }
//                    }
//                });
//            }
//
//            @Override
//            public Component getTableCellEditorComponent(JTable table, Object value, boolean isSelected, int row, int column){
//                JPanel panel = new JPanel(new BorderLayout());
//                panel.add(super.getTableCellEditorComponent(table, value, isSelected, row, column));
//                panel.add(customEditorButton, BorderLayout.EAST);
////                this.table = table;
////                this.row = row;
////                this.column = column;
//                return panel;
//            }
//
//
//        });
        final BrowseCellEditor editor = new BrowseCellEditor(new JTextField());
        editor.setClickCountToStart(1);
        final DefaultCellEditor textFieldEditor = new DefaultCellEditor(new JTextField());
        jTable1.getColumn("Filename").setCellEditor(editor);
        textFieldEditor.setClickCountToStart(1);
        jTable1.getColumn("Signature algorithm").setCellEditor(textFieldEditor);
        jTable1.getColumn("DN").setCellEditor(textFieldEditor);
    }

    private static class BrowseCellEditor extends DefaultCellEditor implements ActionListener {

        JButton customEditorButton = new JButton("...");
        JTable table;
        int row;
        int column;

        JFileChooser chooser = new JFileChooser();

        public BrowseCellEditor(JTextField textField) {
            super(textField);
            customEditorButton.addActionListener(this);
        }

        public void actionPerformed(ActionEvent e) {
            stopCellEditing();

            File currentFile = new File((String) table.getValueAt(row, column));

            chooser.setMultiSelectionEnabled(false);
            chooser.setDialogType(JFileChooser.SAVE_DIALOG);
            chooser.setSelectedFile(currentFile);

            chooser.showOpenDialog(null);
            
            if (chooser.getSelectedFile() != null) {
                table.setValueAt(chooser.getSelectedFile().getAbsolutePath(), row, column);
            }
        }

        @Override
        public Component getTableCellEditorComponent(JTable table, Object value, boolean isSelected, int row, int column) {
            JPanel panel = new JPanel(new BorderLayout());
            panel.add(super.getTableCellEditorComponent(table, value, isSelected, row, column));
            panel.add(customEditorButton, BorderLayout.EAST);
            this.table = table;
            this.row = row;
            this.column = column;
            return panel;
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

        jButton2 = new javax.swing.JButton();
        jButton3 = new javax.swing.JButton();
        jScrollPane1 = new javax.swing.JScrollPane();
        jTable1 = new javax.swing.JTable();

        setDefaultCloseOperation(javax.swing.WindowConstants.DISPOSE_ON_CLOSE);
        org.jdesktop.application.ResourceMap resourceMap = org.jdesktop.application.Application.getInstance(org.signserver.admin.gui.SignServerAdminGUIApplication.class).getContext().getResourceMap(GenerateRequestsDialog.class);
        setTitle(resourceMap.getString("Form.title")); // NOI18N
        setLocationByPlatform(true);
        setName("Form"); // NOI18N

        jButton2.setText(resourceMap.getString("jButton2.text")); // NOI18N
        jButton2.setName("jButton2"); // NOI18N
        jButton2.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton2ActionPerformed(evt);
            }
        });

        jButton3.setText(resourceMap.getString("jButton3.text")); // NOI18N
        jButton3.setName("jButton3"); // NOI18N
        jButton3.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton3ActionPerformed(evt);
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
                    .addComponent(jScrollPane1, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, 676, Short.MAX_VALUE)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(jButton2)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jButton3)))
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 301, Short.MAX_VALUE)
                .addGap(18, 18, 18)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jButton3)
                    .addComponent(jButton2))
                .addContainerGap())
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void jButton2ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton2ActionPerformed
        dispose();
    }//GEN-LAST:event_jButton2ActionPerformed

    private void jButton3ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton3ActionPerformed

        final String hostname = null;

        for (int row = 0; row < data.length; row++) {
            final int workerid = (Integer) data[row][0];
            final String sigAlg =  (String) jTable1.getValueAt(row, 2);
            final String dn = (String) jTable1.getValueAt(row, 3);
            final String filename = (String) jTable1.getValueAt(row, 4);

            System.out.println("worker=" + workerid +", dn=" +  dn + ", sigAlg=" + sigAlg + ", filename=" + filename);

            
            try {
                PKCS10CertReqInfo certReqInfo = new PKCS10CertReqInfo(sigAlg,dn,null);
                Base64SignerCertReqData reqData = (Base64SignerCertReqData) SignServerAdminGUIApplication.getWorkerSession().getCertificateRequest(workerid, certReqInfo);
                if (reqData == null) {
                    JOptionPane.showMessageDialog(this, "Base64SignerCertReqData returned was null. Unable to generate certificate request.", "Error", JOptionPane.ERROR_MESSAGE);
                    return;
                }
                FileOutputStream fos = new FileOutputStream(filename);
                fos.write("-----BEGIN CERTIFICATE REQUEST-----\n".getBytes());
                fos.write(reqData.getBase64CertReq());
                fos.write("\n-----END CERTIFICATE REQUEST-----\n".getBytes());
                fos.close();

//                getOutputStream().println(resources[SUCCESS] + filename);

            } catch (CryptoTokenOfflineException ex) {
                JOptionPane.showMessageDialog(this, ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            } catch (InvalidWorkerIdException ex) {
                JOptionPane.showMessageDialog(this, ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            } catch (IOException ex) {
                JOptionPane.showMessageDialog(this, ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
        
        
    }//GEN-LAST:event_jButton3ActionPerformed


    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton jButton2;
    private javax.swing.JButton jButton3;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JTable jTable1;
    // End of variables declaration//GEN-END:variables

}
