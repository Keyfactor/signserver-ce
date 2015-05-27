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
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Vector;
import java.util.logging.Level;
import javax.ejb.EJBException;
import javax.swing.DefaultCellEditor;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.event.TableModelEvent;
import javax.swing.event.TableModelListener;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableColumn;
import javax.xml.ws.soap.SOAPFaultException;
import org.apache.log4j.Logger;
import org.ejbca.util.CertTools;
import org.jdesktop.application.Action;
import org.jdesktop.application.Application;
import org.jdesktop.application.Task;
import org.signserver.admin.gui.adminws.gen
        .AdminNotAuthorizedException_Exception;
import org.signserver.admin.gui.adminws.gen.CertificateException_Exception;
import org.signserver.admin.gui.adminws.gen.CryptoTokenOfflineException_Exception;
import org.signserver.admin.gui.adminws.gen.IllegalRequestException_Exception;
import org.signserver.admin.gui.adminws.gen.OperationUnsupportedException_Exception;
import org.signserver.common.GlobalConfiguration;

/**
 * Dialog for installing certificates to signers.
 *
 * @author Markus Kilås
 * @version $Id$
 */
@SuppressWarnings("PMD.UnusedFormalParameter")
public class InstallCertificatesDialog extends javax.swing.JDialog {

    /** Logger for this class. */
    private static final Logger LOG
            = Logger.getLogger(InstallCertificatesDialog.class);

    public static final int CANCEL = 0;
    public static final int OK = 1;

    @SuppressWarnings("UseOfObsoleteCollectionType")
    private static final Vector<String> COLUMN_NAMES = new Vector<String>();
    static {
        COLUMN_NAMES.add("Signer");
        COLUMN_NAMES.add("Key");
        COLUMN_NAMES.add("Signer certificate");
        COLUMN_NAMES.add("Certificate chain");
        COLUMN_NAMES.add("Install in token");
    };

    private int resultCode = CANCEL;

    private List<Worker> signers;
    private Vector<Vector<Object>> data;
    private JCheckBox installInTokenCheckbox = new JCheckBox();
    
    private Map<Integer, Utils.HardCodedAliasValue> savedAliases =
            new HashMap<Integer, Utils.HardCodedAliasValue>();

    /** Creates new form InstallCertificatesDialog. */
    public InstallCertificatesDialog(java.awt.Frame parent, boolean modal,
            List<Worker> signers, boolean tokenOnly) {
        this(parent, modal, signers, null, null, tokenOnly);
    }
    
    public InstallCertificatesDialog(java.awt.Frame parent, boolean modal,
            Worker worker, List<String> aliases, boolean tokenOnly) {
        this(parent, modal, null, worker, aliases, tokenOnly);
    }
    
    private InstallCertificatesDialog(java.awt.Frame parent, boolean modal,
            List<Worker> signers, Worker worker, final List<String> aliases, final boolean tokenOnly) {
        super(parent, modal);
        if (signers != null && worker != null) {
            throw new IllegalArgumentException("Specify only one of signers and worker");
        }
        if (worker != null && aliases == null) {
            throw new IllegalArgumentException("Missing list of aliases");
        }
        
        initComponents();

        data = new Vector<Vector<Object>>();

        if (worker != null) {
            setTitle("Install certificates for " + aliases.size() + " token entries");
            Worker[] workersArray = new Worker[aliases.size()];
            Arrays.fill(workersArray, worker);
            this.signers = new ArrayList<Worker>(Arrays.asList(workersArray));
            
            for (String a : aliases) {
                Vector<Object> cols = new Vector<Object>();
                cols.add(worker.getName() + " (" + worker.getWorkerId() + ")");
                cols.add(a);
                cols.add("");
                cols.add("");
                cols.add(tokenOnly);
                data.add(cols);
            }
        } else {
            setTitle("Install certificates for " + signers.size() + " signers");
            this.signers = new ArrayList<Worker>(signers);
            
            for (int row = 0; row < signers.size(); row++) {
                Worker signer = signers.get(row);
                Vector<Object> cols = new Vector<Object>();
                cols.add(signer.getName() + " (" + signer.getWorkerId() + ")");
                if (signer.getConfiguration().getProperty("NEXTCERTSIGNKEY") != null) {
                    cols.add(new Utils.HardCodedAliasValue(Utils.HardCodedAlias.NEXT_KEY,
                                                           signer));
                } else {
                    cols.add(new Utils.HardCodedAliasValue(Utils.HardCodedAlias.DEFAULT_KEY,
                                                           signer));
                }
                cols.add("");
                cols.add("");
                cols.add(tokenOnly);
                data.add(cols);
            }
        }

        jTable1.setModel(new DefaultTableModel(data, COLUMN_NAMES) {

            @Override
            public boolean isCellEditable(int row, int column) {
                return column > 0
                        && (!tokenOnly || column != 4) // Don't change from token if it is fixed
                        && (aliases == null || column != 1); // Don't change alias if alises specified
            }

        });

        final BrowseCellEditor editor = new BrowseCellEditor(new JTextField(),
                JFileChooser.OPEN_DIALOG);
        editor.setClickCountToStart(1);
        final TableColumn columnSignerCert = jTable1.getColumn("Signer certificate");
        final TableColumn columnCertChain = jTable1.getColumn("Certificate chain");
        final TableColumn installInToken = jTable1.getColumn("Install in token");
        final TableColumn keyColumn = jTable1.getColumn("Key");
        
        columnSignerCert.setCellEditor(editor);
        columnCertChain.setCellEditor(editor);
        columnSignerCert.setCellRenderer(new BrowseCellRenderer());
        columnCertChain.setCellRenderer(new BrowseCellRenderer());

        final JComboBox aliasCellEditorComboBox = new JComboBox();
        final AliasCellEditor aliasCellEditor =
                new AliasCellEditor(this.signers, aliasCellEditorComboBox, false);
        keyColumn.setCellEditor(aliasCellEditor);

        jTable1.getModel().addTableModelListener(new TableModelListener() {

            @Override
            public void tableChanged(final TableModelEvent e) {
                boolean enable = true;
                for (int row = 0; row < jTable1.getRowCount(); row++) {
                    final String cert = (String) jTable1.getValueAt(row, 2);
                    final String certChain = (String) jTable1.getValueAt(row, 3);
                    final boolean installInToken =
                            (Boolean) jTable1.getValueAt(row, 4);
                    
                    if (("".equals(cert) && !installInToken) || "".equals(certChain)) {
                        enable = false;
                        break;
                    }
                }
                jButtonInstall.setEnabled(enable);
                
                updateAliasCombobox();
            }
            
            
        });
        
        jTable1.getSelectionModel().addListSelectionListener(new ListSelectionListener() {

            @Override
            public void valueChanged(ListSelectionEvent e) {
                updateAliasCombobox();
            }
            
        });

        final DefaultCellEditor installInTokenCheckboxFieldEditor
                = new DefaultCellEditor(installInTokenCheckbox);
        installInToken.setCellEditor(installInTokenCheckboxFieldEditor);
        installInToken.setCellRenderer(new CheckboxCellRenderer());
        jTable1.setRowHeight(aliasCellEditorComboBox.getPreferredSize().height);
        
        jTable1.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
    }
    
    private void updateAliasCombobox() {
        final int selectedRow = jTable1.getSelectedRow();
        final boolean installInToken =
                (Boolean) jTable1.getValueAt(selectedRow, 4);
        final Object selectedAlias = jTable1.getValueAt(selectedRow, 1);
        final JComboBox comboBox =
                (JComboBox) jTable1.getCellEditor(selectedRow, 1)
                .getTableCellEditorComponent(jTable1, selectedAlias, true, selectedRow, 1);
        final boolean wasEditable = comboBox.isEditable();
        final Worker selectedSigner = signers.get(selectedRow); 

        // update editability of the alias key alias
        comboBox.setEditable(installInToken);

        if (selectedAlias instanceof Utils.HardCodedAliasValue) {
            // record the old (hard-coded) selection
            savedAliases.put(selectedRow,
                             (Utils.HardCodedAliasValue) jTable1.getValueAt(selectedRow, 1));
        } else if (!installInToken && selectedAlias instanceof String) {
            final int confirm =
                    JOptionPane.showConfirmDialog(this,
                                                  "Reset manually edited alias?",
                                                  "Reset alias",
                                                  JOptionPane.YES_NO_CANCEL_OPTION,
                                                  JOptionPane.INFORMATION_MESSAGE);            
            
            if (confirm == JOptionPane.OK_OPTION) {
                // restore the saved hard-coded alias
                final Utils.HardCodedAliasValue savedAlias =
                        savedAliases.get(selectedRow);
                
                jTable1.setValueAt(savedAlias != null ?
                                   savedAlias :
                                   new Utils.HardCodedAliasValue(Utils.HardCodedAlias.DEFAULT_KEY,
                                                                 selectedSigner),
                                   selectedRow, 1);
            } else {
                // restore the state for install to crypto token when
                // user wants to keep the manually entered alias
                jTable1.setValueAt(true, selectedRow, 4);
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
                final Object key = data.get(row).get(1);
                final String cert = data.get(row).get(2).toString();
                final String certChain = data.get(row).get(3).toString();
                final File signerCertFile =
                        "".equals(cert) ? null : new File(cert);
                final File signerChainFile = new File(certChain);

                final boolean defaultKey = 
                        key instanceof Utils.HardCodedAliasValue &&
                        ((Utils.HardCodedAliasValue) key).getHardCodedAlias()
                            .equals(Utils.HardCodedAlias.DEFAULT_KEY);
                final boolean editedAlias = key instanceof String;
                final boolean installInToken = (Boolean) data.get(row).get(4);

                if (LOG.isDebugEnabled()) {
                    LOG.debug("signer=" + workerid + "cert=\"" + signerCertFile
                        + "\", signerChainFile=\"" + signerChainFile + "\""
                        + ", defaultKey=" + defaultKey);
                }

                try {
                    final String scope = GlobalConfiguration.SCOPE_GLOBAL;

                    final Collection<Certificate> signerCerts =
                            signerCertFile != null ?
                            CertTools.getCertsFromPEM(signerCertFile.getAbsolutePath()) :
                            null;
                    
                    if (signerCerts != null && signerCerts.isEmpty()) {
                        final String error =
                            "Problem with signer certificate file for signer "
                            + workerid + ":\n" + "No certificate in file";
                        LOG.error(error);
                        errors.append(error);
                        errors.append("\n");
                    } else {
                        if (signerCerts != null && signerCerts.size() != 1) {
                            final String warning =
                                    "Warning: More than one certificate "
                                    + "found in signer certificate file for signer "
                                    + workerid;
                            LOG.warn(warning);
                            warnings.append(warning);
                            warnings.append("\n");
                        }
                        final X509Certificate signerCert =
                                signerCerts != null ?
                                (X509Certificate) signerCerts.iterator().next() :
                                null;

                        List<Certificate> signerChain;

                        try {
                            signerChain = (List<Certificate>) CertTools.getCertsFromPEM(
                                    signerChainFile.getAbsolutePath());
                            if (signerChain.isEmpty()) {
                                final String error =
                                    "Problem with certificate chain file for signer "
                                    + workerid + ":\n" + "No certificates in file";
                                LOG.error(error);
                                errors.append(error);
                                errors.append("\n");
                            }

                            if (signerCert != null) {
                                if (signerChain.contains(signerCert)) {
                                    LOG.debug("Chain contains signercert");
                                } else {
                                    LOG.debug("Adding signercert to chain");
                                    signerChain.add(0, signerCert);
                                }
                            }

                            if (installInToken) {
                                final String alias =
                                        editedAlias ?
                                        (String) key :
                                        defaultKey ?
                                        signer.getConfiguration().getProperty("DEFAULTKEY") :
                                        signer.getConfiguration().getProperty("NEXTCERTSIGNKEY");
                                
                                SignServerAdminGUIApplication.getAdminWS()
                                        .importCertificateChain(workerid,
                                                                asByteArrayList(signerChain),
                                                                alias, null);
                            } else {
                                SignServerAdminGUIApplication.getAdminWS()
                                        .uploadSignerCertificateChain(workerid,
                                            asByteArrayList(signerChain), scope);
                                SignServerAdminGUIApplication.getAdminWS()
                                        .uploadSignerCertificate(workerid, 
                                        asByteArray(signerCert), scope);
                            }
                               
                            if (!editedAlias) {
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
                            }

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
                        } catch (OperationUnsupportedException_Exception ex) {
                            final String error =
                                    "Importing certificate chain is not supported by crypto token for worker "
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
                        } catch (SOAPFaultException ex) {
                            final String error =
                                "Operation failed on server side for signer "
                                + workerid;
                            LOG.error(error, ex);
                            errors.append(error).append(":\n").append(ex.getMessage());
                            errors.append("\n");
                        } catch (EJBException ex) {
                            final String error =
                                "Operation failed on server side for signer "
                                + workerid;
                            LOG.error(error, ex);
                            errors.append(error).append(":\n").append(ex.getMessage());
                            errors.append("\n");
                        } catch (CertificateException_Exception ex) {
                            final String error =
                                "Problem with certificate chain file for signer "
                                + workerid;
                            LOG.error(error, ex);
                            errors.append(error).append(":\n").append(ex.getMessage());
                            errors.append("\n");
                        } catch (CryptoTokenOfflineException_Exception ex) {
                            final String error =
                                "Operation failed on server side for signer "
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
