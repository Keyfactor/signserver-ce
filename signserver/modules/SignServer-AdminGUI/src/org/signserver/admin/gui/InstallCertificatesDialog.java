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

import java.io.File;
import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.Vector;
import javax.swing.DefaultCellEditor;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.JTextField;
import javax.swing.event.TableModelEvent;
import javax.swing.event.TableModelListener;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableColumn;
import org.apache.log4j.Logger;
import org.ejbca.util.CertTools;
import org.jdesktop.application.Action;
import org.jdesktop.application.Application;
import org.jdesktop.application.Task;
import org.signserver.admin.gui.adminws.gen
        .AdminNotAuthorizedException_Exception;
import org.signserver.admin.gui.adminws.gen.IllegalRequestException_Exception;
import org.signserver.common.GlobalConfiguration;

/**
 * Dialog for installing certificates to signers.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class InstallCertificatesDialog extends javax.swing.JDialog {

    /** Logger for this class. */
    private static final Logger LOG
            = Logger.getLogger(InstallCertificatesDialog.class);

    public static final int CANCEL = 0;
    public static final int OK = 1;

    private static final String NEXT_KEY = "Next key";
    private static final String DEFAULT_KEY = "Default key";

    @SuppressWarnings("UseOfObsoleteCollectionType")
    private static final Vector<String> COLUMN_NAMES = new Vector<String>();
    static {
        COLUMN_NAMES.add("Signer");
        COLUMN_NAMES.add("Key");
        COLUMN_NAMES.add("Signer certificate");
        COLUMN_NAMES.add("Certificate chain");
    };

    private int resultCode = CANCEL;

    private List<Worker> signers;
    private Vector<Vector<String>> data;

    private JComboBox aliasComboBox = new JComboBox(new String[] {
         NEXT_KEY, DEFAULT_KEY});

    /** Creates new form InstallCertificatesDialog. */
    public InstallCertificatesDialog(java.awt.Frame parent, boolean modal,
            List<Worker> signers) {
        super(parent, modal);
        this.signers = new ArrayList<Worker>(signers);
        initComponents();
        setTitle("Install certificates for " + signers.size() + " signers");
        data = new Vector<Vector<String>>();
        for (int row = 0; row < signers.size(); row++) {
            Worker signer = signers.get(row);
            Vector<String> cols = new Vector<String>();
            cols.add(signer.getName() + " (" + signer.getWorkerId() + ")");
            if (signer.getConfiguration().getProperty("NEXTCERTSIGNKEY") != null) {
                cols.add(NEXT_KEY);
            } else {
                cols.add(DEFAULT_KEY);
            }
            cols.add("");
            cols.add("");
            data.add(cols);
        }
        jTable1.setModel(new DefaultTableModel(data, COLUMN_NAMES) {

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
                    if ("".equals(jTable1.getValueAt(row, 2))
                            || "".equals(jTable1.getValueAt(row, 3))) {
                        enable = false;
                        break;
                    }
                }
                jButtonInstall.setEnabled(enable);
            }
        });

        final BrowseCellEditor editor = new BrowseCellEditor(new JTextField(),
                JFileChooser.OPEN_DIALOG);
        editor.setClickCountToStart(1);
        final TableColumn columnSignerCert = jTable1.getColumn("Signer certificate");
        final TableColumn columnCertChain = jTable1.getColumn("Certificate chain");
        columnSignerCert.setCellEditor(editor);
        columnCertChain.setCellEditor(editor);
        columnSignerCert.setCellRenderer(new BrowseCellRenderer());
        columnCertChain.setCellRenderer(new BrowseCellRenderer());
        final DefaultCellEditor aliasComboBoxFieldEditor
                = new DefaultCellEditor(aliasComboBox);
        aliasComboBoxFieldEditor.setClickCountToStart(1);
        jTable1.getColumn("Key").setCellEditor(aliasComboBoxFieldEditor);
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
        jButtonInstall = new javax.swing.JButton();
        jScrollPane1 = new javax.swing.JScrollPane();
        jTable1 = new javax.swing.JTable();

        setDefaultCloseOperation(javax.swing.WindowConstants.DISPOSE_ON_CLOSE);
        setLocationByPlatform(true);
        setName("Form"); // NOI18N

        org.jdesktop.application.ResourceMap resourceMap = org.jdesktop.application.Application.getInstance(org.signserver.admin.gui.SignServerAdminGUIApplication.class).getContext().getResourceMap(InstallCertificatesDialog.class);
        jButton2.setText(resourceMap.getString("jButton2.text")); // NOI18N
        jButton2.setName("jButton2"); // NOI18N
        jButton2.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton2ActionPerformed(evt);
            }
        });

        javax.swing.ActionMap actionMap = org.jdesktop.application.Application.getInstance(org.signserver.admin.gui.SignServerAdminGUIApplication.class).getContext().getActionMap(InstallCertificatesDialog.class, this);
        jButtonInstall.setAction(actionMap.get("installCertificates")); // NOI18N
        jButtonInstall.setText(resourceMap.getString("jButtonInstall.text")); // NOI18N
        jButtonInstall.setEnabled(false);
        jButtonInstall.setName("jButtonInstall"); // NOI18N
        jButtonInstall.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonInstallActionPerformed(evt);
            }
        });

        jScrollPane1.setName("jScrollPane1"); // NOI18N

        jTable1.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {
                {null, null, null},
                {null, null, null},
                {null, null, null}
            },
            new String [] {
                "Signer", "Signer certificate", "Certificate chain"
            }
        ) {
            Class[] types = new Class [] {
                java.lang.Object.class, java.lang.Object.class, java.lang.String.class
            };
            boolean[] canEdit = new boolean [] {
                false, true, true
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
                    .addComponent(jScrollPane1, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, 803, Short.MAX_VALUE)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(jButton2)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jButtonInstall)))
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 321, Short.MAX_VALUE)
                .addGap(18, 18, 18)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jButtonInstall)
                    .addComponent(jButton2))
                .addContainerGap())
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void jButton2ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton2ActionPerformed
        dispose();
}//GEN-LAST:event_jButton2ActionPerformed

    private void jButtonInstallActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButtonInstallActionPerformed
        
    }//GEN-LAST:event_jButtonInstallActionPerformed

    public int getResultCode() {
        return resultCode;
    }

    public int showDialog() {
        setVisible(true);
        return resultCode;
    }

    @Action(block = Task.BlockingScope.WINDOW)
    public Task installCertificates() {
        return new InstallCertificatesTask(org.jdesktop.application.Application.getInstance(org.signserver.admin.gui.SignServerAdminGUIApplication.class));
    }

    private class InstallCertificatesTask extends Task<Result, Void> {
        InstallCertificatesTask(Application app) {
            // Runs on the EDT.  Copy GUI state that
            // doInBackground() depends on from parameters
            // to InstallCertificatesTask fields, here.
            super(app);
        }
        @Override protected Result doInBackground() {
            // Your Task's code here.  This method runs
            // on a background thread, so don't reference
            // the Swing GUI from here.
            final StringBuilder errors = new StringBuilder();
            final StringBuilder warnings = new StringBuilder();
            for (int row = 0; row < data.size(); row++) {
                final Worker signer = signers.get(row);
                final int workerid = signer.getWorkerId();
                final String key = (String) data.get(row).get(1);
                final File signerCertFile = new File(data.get(row).get(2));
                final File signerChainFile = new File(data.get(row).get(3));

                final boolean defaultKey= DEFAULT_KEY.equals(key);

                if (LOG.isDebugEnabled()) {
                    LOG.debug("signer=" + workerid + "cert=\"" + signerCertFile
                        + "\", signerChainFile=\"" + signerChainFile + "\""
                        + ", defaultKey=" + defaultKey);
                }

                try {
                    final String scope = GlobalConfiguration.SCOPE_GLOBAL;

                    final Collection<Certificate> signerCerts =
                            CertTools.getCertsFromPEM(
                            signerCertFile.getAbsolutePath());
                    if (signerCerts.isEmpty()) {
                        final String error =
                            "Problem with signer certificate file for signer "
                            + workerid + ":\n" + "No certificate in file";
                        LOG.error(error);
                        errors.append(error);
                        errors.append("\n");
                    } else {
                        if (signerCerts.size() != 1) {
                            final String warning =
                                    "Warning: More than one certificate "
                                    + "found in signer certificate file for signer "
                                    + workerid;
                            LOG.warn(warning);
                            warnings.append(warning);
                            warnings.append("\n");
                        }
                        final X509Certificate signerCert
                                = (X509Certificate) signerCerts.iterator().next();

                        List<Certificate> signerChain;

                        try {
                            signerChain = (List) CertTools.getCertsFromPEM(
                                    signerChainFile.getAbsolutePath());
                            if (signerChain.isEmpty()) {
                                final String error =
                                    "Problem with certificate chain file for signer "
                                    + workerid + ":\n" + "No certificates in file";
                                LOG.error(error);
                                errors.append(error);
                                errors.append("\n");
                            }

                            if (signerChain.contains(signerCert)) {
                                LOG.debug("Chain contains signercert");
                            } else {
                                LOG.debug("Adding signercert to chain");
                                signerChain.add(0, signerCert);
                            }

                            SignServerAdminGUIApplication.getAdminWS()
                                    .uploadSignerCertificateChain(workerid,
                                        asByteArrayList(signerChain), scope);
                            SignServerAdminGUIApplication.getAdminWS()
                                    .uploadSignerCertificate(workerid, 
                                    asByteArray(signerCert), scope);
                            // Set DEFAULTKEY to NEXTCERTSIGNKEY
                            if (defaultKey) {
                                LOG.debug("Uploaded was for DEFAULTKEY");
                            } else if (!defaultKey) {
                                LOG.debug("Uploaded was for NEXTCERTSIGNKEY");
                                final String nextCertSignKey
                                        = signer.getConfiguration()
                                            .getProperty("NEXTCERTSIGNKEY");
                               SignServerAdminGUIApplication.getAdminWS()
                                       .setWorkerProperty(workerid, "DEFAULTKEY",
                                       nextCertSignKey);
                               SignServerAdminGUIApplication.getAdminWS()
                                       .removeWorkerProperty(workerid,
                                       "NEXTCERTSIGNKEY");
                            }
                            SignServerAdminGUIApplication.getAdminWS()
                                    .reloadConfiguration(workerid);

                            signers.remove(signer);
                            data.remove(row);
                            row--;
                            jTable1.revalidate();
                        } catch (AdminNotAuthorizedException_Exception ex) {
                            final String error =
                                "Authorization denied for worker "
                                + workerid;
                            LOG.error(error, ex);
                            errors.append(error).append(":\n").append(ex.getMessage());
                            errors.append("\n");
                        } catch (IOException ex) {
                            final String error =
                                "Problem with certificate chain file for signer "
                                + workerid;
                            LOG.error(error, ex);
                            errors.append(error).append(":\n").append(ex.getMessage());
                            errors.append("\n");
                        } catch (CertificateException ex) {
                            final String error =
                                "Problem with certificate chain file for signer "
                                + workerid;
                            LOG.error(error, ex);
                            errors.append(error).append(":\n").append(ex.getMessage());
                            errors.append("\n");
                        }
                    }

                } catch (IOException ex) {
                    final String error =
                            "Problem with signer certificate file for signer "
                            + workerid;
                    LOG.error(error, ex);
                    errors.append(error).append(":\n").append(ex.getMessage());
                    errors.append("\n");
                } catch (CertificateException ex) {
                    final String error =
                            "Problem with signer certificate file for signer "
                            + workerid;
                    LOG.error(error, ex);
                    errors.append(error).append(":\n").append(ex.getMessage());
                    errors.append("\n");
                } catch (IllegalRequestException_Exception ex) {
                    final String error =
                            "Problem with certificates for signer "
                            + workerid;
                    LOG.error(error, ex);
                    errors.append(error).append(":\n").append(ex.getMessage());
                    errors.append("\n");
                }
            }
            return new Result(errors.toString(), warnings.toString());
        }
        @Override protected void succeeded(final Result result) {
            // Runs on the EDT.  Update the GUI based on
            // the result computed by doInBackground().
            if (result.getErrors().length() > 0) {
                JOptionPane.showMessageDialog(InstallCertificatesDialog.this,
                            result.getErrors(),
                            "Install certificates", JOptionPane.ERROR_MESSAGE);
            }
            if (result.getWarnings().length() > 0) {
                JOptionPane.showMessageDialog(InstallCertificatesDialog.this,
                            result.getWarnings(),
                            "Install certificates",
                            JOptionPane.WARNING_MESSAGE);
            }
            if (jTable1.getRowCount() == 0) {
                JOptionPane.showMessageDialog(InstallCertificatesDialog.this,
                        "All certificates installed. Please verify the installed ceritifcates before activating the signers.");
                resultCode = OK;
                dispose();
            }
        }

        private List<byte[]> asByteArrayList(
                final List<Certificate> signerChain)
                throws CertificateEncodingException {
            final List<byte[]> result = new LinkedList<byte[]>();
            for (final Certificate cert : signerChain) {
                result.add(cert.getEncoded());
            }
            return result;
        }

        private byte[] asByteArray(final X509Certificate signerCert)
                throws CertificateEncodingException {
            return signerCert.getEncoded();
        }
    }

    private static final class Result {
        private final String errors;
        private final String warnings;

        public Result(final String errors, final String warnings) {
            this.errors = errors;
            this.warnings = warnings;
        }

        public String getErrors() {
            return errors;
        }

        public String getWarnings() {
            return warnings;
        }
    }


    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton jButton2;
    private javax.swing.JButton jButtonInstall;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JTable jTable1;
    // End of variables declaration//GEN-END:variables

}
