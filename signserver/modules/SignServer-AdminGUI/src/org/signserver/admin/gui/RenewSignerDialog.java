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

import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import java.util.Properties;
import java.util.Vector;
import javax.swing.DefaultCellEditor;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JComboBox;
import javax.swing.JOptionPane;
import javax.swing.event.TableModelEvent;
import javax.swing.event.TableModelListener;
import javax.swing.table.AbstractTableModel;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.ws.soap.SOAPFaultException;
import org.apache.log4j.Logger;
import org.jdesktop.application.Action;
import org.jdesktop.application.Application;
import org.jdesktop.application.Task;
import org.signserver.admin.gui.adminws.gen
        .AdminNotAuthorizedException_Exception;
import org.signserver.admin.gui.adminws.gen
        .CryptoTokenOfflineException_Exception;
import org.signserver.admin.gui.adminws.gen.IllegalRequestException_Exception;
import org.signserver.admin.gui.adminws.gen.InvalidWorkerIdException_Exception;
import org.signserver.admin.gui.adminws.gen.SignServerException_Exception;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.GenericPropertiesRequest;
import org.signserver.common.GenericPropertiesResponse;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.RequestAndResponseManager;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.module.renewal.common.RenewalWorkerProperties;

/**
 * Dialog for installing certificates to signers.
 *
 * @author markus
 * @version $Id: InstallCertificatesDialog.java 1234 2010-10-13 13:51:55Z netmackan $
 */
public class RenewSignerDialog extends javax.swing.JDialog {

    /** Logger for this class. */
    private static final Logger LOG
            = Logger.getLogger(RenewSignerDialog.class);

    public static final int CANCEL = 0;
    public static final int OK = 1;

    private static final String[] COLUMN_NAMES = new String[] {
        "Renew", "Signer", "Not valid after", "Signings", "Renewal worker"
    };

    private List<Item> items = new ArrayList<Item>();

    private boolean renewButtonClicked;

    private int resultCode = CANCEL;

    private List<Worker> workers;

    private List<Worker> signers;
    private Vector<Vector<String>> data;

    private JComboBox signersComboBox = new JComboBox();



    /** Creates new form InstallCertificatesDialog. */
    public RenewSignerDialog(java.awt.Frame parent, boolean modal,
            final List<Worker> workers, final List<Worker> signers) {
        super(parent, modal);
        this.workers = new ArrayList<Worker>(workers);
        this.signers = new ArrayList<Worker>(signers);

        // All signers that should be renewed
        for (Worker signer : signers) {
            final String keyUsageLimit = signer.getConfiguration()
                    .getProperty("KEYUSAGELIMIT");
            final Long limit;
            if (keyUsageLimit == null || "-1".equals(keyUsageLimit)) {
                limit = null;
            } else {
                limit = Long.valueOf(keyUsageLimit);
            }
            items.add(new Item(true, signer, null, null, limit,
                    signer.getConfiguration().getProperty(
                    RenewalWorkerProperties.WORKERPROPERTY_RENEWWORKER)));
        }


        initComponents();
        setTitle("Renew " + signers.size() + " signers");

        jTable1.setModel(new AbstractTableModel() {

            @Override
            public int getRowCount() {
                return items.size();
            }

            @Override
            public int getColumnCount() {
                return COLUMN_NAMES.length;
            }

            @Override
            public Object getValueAt(int rowIndex, int columnIndex) {
                final Object result;
                final Item item = items.get(rowIndex);
                switch (columnIndex) {
                    case 0: {
                        result = item.isRenew();
                        break;
                    }
                    case 1: {
                        result = item.getSigner().getName();
                        break;
                    }
                    case 2: {
                        result = item.getNotAfter();
                        break;
                    }
                    case 3: {
                        final StringBuilder buff = new StringBuilder();
                        buff.append(item.getSignings());
                        if (item.getSigningsMax() != null) {
                            buff.append(" of ");
                            buff.append(item.getSigningsMax());
                        }
                        result = buff.toString();
                        break;
                    }
                    case 4: {
                        result = item.getRenewalWorker();
                        break;
                    }
                    default: {
                        result = "";
                    }
                }
                return result;
            }

            @Override
            public Class<?> getColumnClass(int columnIndex) {
                if (columnIndex == 0) {
                    return Boolean.class;
                }
                return super.getColumnClass(columnIndex);
            }

            @Override
            public String getColumnName(int column) {
                return COLUMN_NAMES[column];
            }

            @Override
            public boolean isCellEditable(int rowIndex, int columnIndex) {
                return columnIndex == 0 || columnIndex == 4;
            }

            @Override
            public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
                final Item item = items.get(rowIndex);
                if (columnIndex == 0) {
                    item.setRenew((Boolean) aValue);
                } else if (columnIndex == 4) {
                    item.setRenewalWorker((String) aValue);
                }
                fireTableCellUpdated(rowIndex, columnIndex);
            }


        });
        

        final Vector<String> workerNames = new Vector<String>();
        for (Worker worker : workers) {
            workerNames.add(worker.getName());
        }
        signersComboBox.setModel(new DefaultComboBoxModel(workerNames));


        data = new Vector<Vector<String>>();
        for (int row = 0; row < signers.size(); row++) {
            Worker signer = signers.get(row);
            Vector<String> cols = new Vector<String>();
            cols.add(signer.getName() + " (" + signer.getWorkerId() + ")");
            
            final String renewalWorker = signer.getConfiguration().getProperty(
                    RenewalWorkerProperties.WORKERPROPERTY_RENEWWORKER);

            if (renewalWorker == null) {
                buttonRenew.setEnabled(false);
            }

            cols.add(renewalWorker);

            data.add(cols);
        }
        
        jTable1.getModel().addTableModelListener(new TableModelListener() {

            @Override
            public void tableChanged(final TableModelEvent e) {
               table1Changed();
            }
        });

        final DefaultCellEditor renewalCellEditor
                = new DefaultCellEditor(signersComboBox);
        jTable1.getColumn("Renewal worker").setCellEditor(renewalCellEditor);

        refreshButton.doClick();
    }

    private void table1Changed() {
        boolean enable = true;
        boolean anySelected = false;
        for (Item item : items) {
            if (item.isRenew()) {
                anySelected = true;
                if (item.getRenewalWorker() == null
                    || "".equals(item.getRenewalWorker())) {
                    enable = false;
                    break;
                }
            }
        }
        buttonRenew.setEnabled(enable && anySelected);
    }

    /** This method is called from within the constructor to
     * initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is
     * always regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        passwordPanel = new javax.swing.JPanel();
        passwordPanelLabel = new javax.swing.JLabel();
        passwordPanelField = new javax.swing.JPasswordField();
        jButton2 = new javax.swing.JButton();
        buttonRenew = new javax.swing.JButton();
        jScrollPane1 = new javax.swing.JScrollPane();
        jTable1 = new javax.swing.JTable();
        jToolBar1 = new javax.swing.JToolBar();
        refreshButton = new javax.swing.JButton();

        passwordPanel.setName("passwordPanel"); // NOI18N

        org.jdesktop.application.ResourceMap resourceMap = org.jdesktop.application.Application.getInstance(org.signserver.admin.gui.SignServerAdminGUIApplication.class).getContext().getResourceMap(RenewSignerDialog.class);
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

        setDefaultCloseOperation(javax.swing.WindowConstants.DISPOSE_ON_CLOSE);
        setLocationByPlatform(true);
        setName("Form"); // NOI18N

        jButton2.setText(resourceMap.getString("jButton2.text")); // NOI18N
        jButton2.setName("jButton2"); // NOI18N
        jButton2.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton2ActionPerformed(evt);
            }
        });

        javax.swing.ActionMap actionMap = org.jdesktop.application.Application.getInstance(org.signserver.admin.gui.SignServerAdminGUIApplication.class).getContext().getActionMap(RenewSignerDialog.class, this);
        buttonRenew.setAction(actionMap.get("installCertificates")); // NOI18N
        buttonRenew.setText(resourceMap.getString("buttonRenew.text")); // NOI18N
        buttonRenew.setName("buttonRenew"); // NOI18N
        buttonRenew.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                buttonRenewActionPerformed(evt);
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

        jToolBar1.setRollover(true);
        jToolBar1.setName("jToolBar1"); // NOI18N

        refreshButton.setAction(actionMap.get("refresh")); // NOI18N
        refreshButton.setText(resourceMap.getString("refreshButton.text")); // NOI18N
        refreshButton.setFocusable(false);
        refreshButton.setHorizontalTextPosition(javax.swing.SwingConstants.CENTER);
        refreshButton.setName("refreshButton"); // NOI18N
        refreshButton.setVerticalTextPosition(javax.swing.SwingConstants.BOTTOM);
        jToolBar1.add(refreshButton);

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jToolBar1, javax.swing.GroupLayout.DEFAULT_SIZE, 827, Short.MAX_VALUE)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(jScrollPane1, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, 803, Short.MAX_VALUE)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(jButton2)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(buttonRenew)))
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addComponent(jToolBar1, javax.swing.GroupLayout.PREFERRED_SIZE, 25, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 290, Short.MAX_VALUE)
                .addGap(18, 18, 18)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(buttonRenew)
                    .addComponent(jButton2))
                .addContainerGap())
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void jButton2ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton2ActionPerformed
        if (renewButtonClicked) {
            resultCode = RenewSignerDialog.OK;
        }
        dispose();
}//GEN-LAST:event_jButton2ActionPerformed

    private void buttonRenewActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_buttonRenewActionPerformed
        
    }//GEN-LAST:event_buttonRenewActionPerformed

    public int getResultCode() {
        return resultCode;
    }

    public int showDialog() {
        setVisible(true);
        return resultCode;
    }

        @Action(block = Task.BlockingScope.WINDOW)
    public Task installCertificates() {
        return new RenewTask(org.jdesktop.application.Application.getInstance(org.signserver.admin.gui.SignServerAdminGUIApplication.class));
    }

    private class InstallCertificatesTask extends org.jdesktop.application.Task<Object, Void> {
        InstallCertificatesTask(org.jdesktop.application.Application app) {
            // Runs on the EDT.  Copy GUI state that
            // doInBackground() depends on from parameters
            // to InstallCertificatesTask fields, here.
            super(app);
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

    private class RenewTask extends Task<Result, Void> {

        private char[] authCode;

        RenewTask(Application app) {
            // Runs on the EDT.  Copy GUI state that
            // doInBackground() depends on from parameters
            // to InstallCertificatesTask fields, here.
            super(app);
            passwordPanelLabel.setText(
                    "Enter authentication code for all workers or leave empty:");
            passwordPanelField.setText("");
            passwordPanelField.grabFocus();

            int res = JOptionPane.showConfirmDialog(RenewSignerDialog.this,
                    passwordPanel, "Generate keys",
                    JOptionPane.OK_CANCEL_OPTION);

           if (res == JOptionPane.OK_OPTION) {
               authCode = passwordPanelField.getPassword();
           }
           renewButtonClicked = true;
        }
        @Override protected Result doInBackground() {
            // Your Task's code here.  This method runs
            // on a background thread, so don't reference
            // the Swing GUI from here.
            final StringBuilder errors = new StringBuilder();
            final StringBuilder warnings = new StringBuilder();
            int success = 0;
            int failure = 0;
            for (Item item : items) {
                if (!item.isRenew()) {
                    continue;
                }
                
                if (LOG.isDebugEnabled()) {
                    LOG.debug("signer=" + item.getSigner().getName());
                }

                try {
                    final Properties requestProperties = new Properties();
                    requestProperties.setProperty(
                            RenewalWorkerProperties.REQUEST_WORKER, 
                            item.getSigner().getName());
                    requestProperties.setProperty(
                            RenewalWorkerProperties.REQUEST_AUTHCODE,
                            String.valueOf(authCode));
//                    requestProperties.setProperty(
//                            RenewalWorkerProperties.REQUEST_RENEWKEY,
//                            RenewalWorkerProperties.REQUEST_RENEWKEY_TRUE);
                    final GenericPropertiesRequest request
                            = new GenericPropertiesRequest(requestProperties);

                    final List<byte[]> responses =
                                    SignServerAdminGUIApplication
                            .getAdminWS().process(item.getRenewalWorker(),
                                    Collections.singletonList(RequestAndResponseManager.serializeProcessRequest(request)));

                    final Properties responseProperties;

                    if (responses.size() > 0) {
                        final GenericPropertiesResponse response
                                = (GenericPropertiesResponse)
                                RequestAndResponseManager.parseProcessResponse(
                                    responses.get(0));
                        responseProperties  = response.getProperties();

                        if (RenewalWorkerProperties.RESPONSE_RESULT_OK.equals(
                                responseProperties.getProperty(
                                    RenewalWorkerProperties.RESPONSE_RESULT))) {

                            item.setRenew(false);
                            success++;
                            jTable1.revalidate(); // TODO Safe from this thread??
                        } else {
                            final String error =
                                "Problem renewing signer "
                                + item.getSigner().getName();
                            LOG.error(error + ": " + responseProperties.getProperty(
                                RenewalWorkerProperties.RESPONSE_MESSAGE));
                            errors.append(error);
                            errors.append(":\n");
                            errors.append(responseProperties.getProperty(
                                RenewalWorkerProperties.RESPONSE_MESSAGE));
                            errors.append("\n");
                            failure++;
                        }
                    } else {
                        final String error =
                            "Problem renewing signer "
                            + item.getSigner().getName();
                        LOG.error(error + ": " + "Got empty response");
                        errors.append(error);
                        errors.append(":\n");
                        errors.append("Got empty response");
                        errors.append("\n");
                        failure++;
                    }
                } catch (CryptoTokenOfflineException_Exception ex) {
                    final String error =
                            "Problem renewing signer "
                            + item.getSigner().getName();
                    LOG.error(error, ex);
                    errors.append(error + ":\n" + ex.getMessage());
                    errors.append("\n");
                    failure++;
                } catch (SignServerException_Exception ex) {
                    final String error =
                            "Problem renewing signer "
                            + item.getSigner().getName();
                    LOG.error(error, ex);
                    errors.append(error + ":\n" + ex.getMessage());
                    errors.append("\n");
                    failure++;
                } catch (IllegalRequestException_Exception ex) {
                    final String error =
                            "Problem renewing signer "
                            + item.getSigner().getName();
                    LOG.error(error, ex);
                    errors.append(error + ":\n" + ex.getMessage());
                    errors.append("\n");
                    failure++;
                } catch (IOException ex) {
                    final String error =
                            "Problem renewing signer "
                            + item.getSigner().getName();
                    LOG.error(error, ex);
                    errors.append(error + ":\n" + ex.getMessage());
                    errors.append("\n");
                    failure++;
                } catch (AdminNotAuthorizedException_Exception ex) {
                    final String error =
                            "Problem renewing signer "
                            + item.getSigner().getName();
                    LOG.error(error, ex);
                    errors.append(error + ":\n" + ex.getMessage());
                    errors.append("\n");
                    failure++;
                } catch (InvalidWorkerIdException_Exception ex) {
                    final String error =
                            "Problem renewing signer "
                            + item.getSigner().getName();
                    LOG.error(error, ex);
                    errors.append(error + ":\n" + ex.getMessage());
                    errors.append("\n");
                    failure++;
                } catch (SOAPFaultException ex) {
                    final String error =
                            "Problem renewing signer "
                            + item.getSigner().getName();
                    LOG.error(error, ex);
                    errors.append(error + ":\n" + ex.getMessage());
                    errors.append("\n");
                    failure++;
                }

                // Not update the status
                updateStatus(item);
            }
            return new Result(success, failure, errors.toString(), warnings.toString());
        }
        @Override protected void succeeded(final Result result) {
            // Runs on the EDT.  Update the GUI based on
            // the result computed by doInBackground().

            jTable1.revalidate();
            table1Changed();

            final StringBuilder buff = new StringBuilder();
            buff.append("Successfully renewed: ");
            buff.append(result.getSuccessful());
            buff.append("\n");
            buff.append("Failures: ");
            buff.append(result.getFailures());
            buff.append("\n");
            buff.append("\n");
            buff.append(result.getErrors());
            buff.append(result.getWarnings());

            int messageType;
            if (result.getErrors().length() > 0) {
                messageType = JOptionPane.ERROR_MESSAGE;
            } else if (result.getWarnings().length() > 0) {
                messageType = JOptionPane.WARNING_MESSAGE;
            } else {
                messageType = JOptionPane.INFORMATION_MESSAGE;
            }

            JOptionPane.showMessageDialog(RenewSignerDialog.this,
                    buff.toString(), "Renew signers", messageType);
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
        private final int successful;
        private final int failures;
        private final String errors;
        private final String warnings;

        public Result(final int successful, final int failures, 
                final String errors, final String warnings) {
            this.successful = successful;
            this.failures = failures;
            this.errors = errors;
            this.warnings = warnings;
        }

        public int getFailures() {
            return failures;
        }

        public int getSuccessful() {
            return successful;
        }

        public String getErrors() {
            return errors;
        }

        public String getWarnings() {
            return warnings;
        }
    }

    private void updateStatus(Item item) {
        Date newNotAfter;
        try {
            XMLGregorianCalendar notAfter =
                    SignServerAdminGUIApplication.getAdminWS()
                    .getSigningValidityNotAfter(item.getSigner()
                    .getWorkerId());
            if (notAfter == null) {
                newNotAfter = null;
            } else {
                newNotAfter = notAfter.toGregorianCalendar().getTime();
            }
        } catch (AdminNotAuthorizedException_Exception ex) {
            LOG.error(ex, ex);
            newNotAfter = null;
        } catch(CryptoTokenOfflineException_Exception ex) {
            LOG.error(ex, ex);
            newNotAfter = null;
        }
        item.setNotAfter(newNotAfter);

        Long newSignings = null;
        try {
            newSignings =
                    SignServerAdminGUIApplication.getAdminWS()
                    .getKeyUsageCounterValue(item.getSigner().getWorkerId());
        } catch (AdminNotAuthorizedException_Exception ex) {
            LOG.error(ex, ex);
        } catch(CryptoTokenOfflineException_Exception ex) {
            LOG.error(ex, ex);
        }
        item.setSignings(newSignings);
    }


    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton buttonRenew;
    private javax.swing.JButton jButton2;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JTable jTable1;
    private javax.swing.JToolBar jToolBar1;
    private javax.swing.JPanel passwordPanel;
    private javax.swing.JPasswordField passwordPanelField;
    private javax.swing.JLabel passwordPanelLabel;
    private javax.swing.JButton refreshButton;
    // End of variables declaration//GEN-END:variables

    /**
     * Represents an item in the renewals list.
     */
    private static class Item {

        private boolean renew;
        private Worker signer;
        private Date notAfter;
        private Long signings;
        private Long signingsMax;
        private String renewalWorker;

        public Item(final boolean renew, final Worker signer,
                final Date notAfter, final Long signings,
                final Long signingsMax, final String renewalWorker) {
            this.renew = renew;
            this.signer = signer;
            this.notAfter = notAfter;
            this.signings = signings;
            this.signingsMax = signingsMax;
            this.renewalWorker = renewalWorker;
        }

        public Date getNotAfter() {
            return notAfter;
        }

        public void setNotAfter(Date notAfter) {
            this.notAfter = notAfter;
        }

        public boolean isRenew() {
            return renew;
        }

        public void setRenew(boolean renew) {
            this.renew = renew;
        }

        public String getRenewalWorker() {
            return renewalWorker;
        }

        public void setRenewalWorker(String renewalWorker) {
            this.renewalWorker = renewalWorker;
        }

        public Worker getSigner() {
            return signer;
        }

        public void setSigner(Worker signer) {
            this.signer = signer;
        }

        public Long getSignings() {
            return signings;
        }

        public void setSignings(Long signings) {
            this.signings = signings;
        }

        public Long getSigningsMax() {
            return signingsMax;
        }

        public void setSigningsMax(Long signingsMax) {
            this.signingsMax = signingsMax;
        }


    }

    @Action(block = Task.BlockingScope.WINDOW)
    public Task refresh() {
        return new RefreshTask(org.jdesktop.application.Application.getInstance(org.signserver.admin.gui.SignServerAdminGUIApplication.class));
    }

    private class RefreshTask extends org.jdesktop.application.Task<Object, Void> {
        RefreshTask(org.jdesktop.application.Application app) {
            // Runs on the EDT.  Copy GUI state that
            // doInBackground() depends on from parameters
            // to RefreshTask fields, here.
            super(app);
        }
        @Override protected Object doInBackground() {
            // Your Task's code here.  This method runs
            // on a background thread, so don't reference
            // the Swing GUI from here.

            for (Item item : items) {
                updateStatus(item);
            }

            return null;  // return your result
        }
        @Override protected void succeeded(Object result) {
            // Runs on the EDT.  Update the GUI based on
            // the result computed by doInBackground().
            jTable1.revalidate();
        }
    }

}
