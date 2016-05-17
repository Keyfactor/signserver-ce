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

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Vector;
import javax.swing.DefaultCellEditor;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JPanel;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import org.apache.log4j.Logger;
import org.cesecore.util.CertTools;
import org.signserver.admin.gui.adminws.gen.TokenEntry;
import org.signserver.admin.gui.adminws.gen.TokenEntry.Info.Entry;

/**
 * Frame for displaying details about an entry in a token such as key alias,
 * type, certificate etc.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class TokenEntryDetailsFrame extends javax.swing.JFrame {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(TokenEntryDetailsFrame.class);
    
    private final SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ssZ");
    private static final String COLUMN_CERTIFICATE = "Certificate";
    private List<X509Certificate> chain;
    
    /**
     * Creates new form TokenEntryDetailsFrame.
     * @param entry to display details for
     */
    public TokenEntryDetailsFrame(TokenEntry entry) {
        initComponents();
        setTitle("Token entry " + entry.getAlias());
        
        X509Certificate signerCert = null;
        try {
            if (entry.getChain() != null && !entry.getChain().isEmpty()) {
                this.chain = new LinkedList<>();
                for (byte[] certBytes : entry.getChain()) {
                    Certificate cert = CertTools.getCertfromByteArray(certBytes, "BC");
                    if (cert instanceof X509Certificate) {
                        this.chain.add((X509Certificate) cert);
                    } else {
                        LOG.info("Not an X.509 certificate: " + cert);
                    }
                }
                signerCert = this.chain.get(0);
            } else if (entry.getTrustedCertificate() != null && entry.getTrustedCertificate().length > 0) {
                this.chain = new LinkedList<>();
                Certificate cert = CertTools.getCertfromByteArray(entry.getTrustedCertificate(), "BC");
                if (cert instanceof X509Certificate) {
                    this.chain.add((X509Certificate) cert);
                } else {
                    LOG.info("Not an X.509 certificate: " + cert);
                }
            }
        } catch (CertificateException ex) {
            LOG.error("Unable to parse certificate from token: " + ex.getMessage(), ex);
            this.chain = null;
        }
        
        
        final String alias = entry.getAlias();
        final String type = entry.getType();
        final String creationDate = entry.getCreationDate() == null ? "n/a" : sdf.format(entry.getCreationDate().toGregorianCalendar().getTime());
        
        final String certSubjectDN;
        if (signerCert != null) {
            certSubjectDN = CertTools.getSubjectDN(signerCert);
        } else if (chain != null) { // For trusted certificates
            certSubjectDN = CertTools.getSubjectDN(chain.get(0));
        } else {
            certSubjectDN = "n/a";
        }

        Vector<Vector<String>> data = new Vector<>();

        data.add(new Vector<>(Arrays.asList("Alias", alias)));
        data.add(new Vector<>(Arrays.asList("Type", type)));
        data.add(new Vector<>(Arrays.asList("Creation date", creationDate)));
        data.add(new Vector<>(Arrays.asList(COLUMN_CERTIFICATE, certSubjectDN)));

        if (entry.getInfo() != null && entry.getInfo().getEntry() != null) {
            for (Entry item : entry.getInfo().getEntry()) {
                data.add(new Vector<>(Arrays.asList(item.getKey(), item.getValue())));
            }
        }
        
        DefaultTableModel model = new DefaultTableModel(data, new Vector<>(Arrays.asList("Name", "Value"))) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return column == 1;
            }
        };
        infoTable.setModel(model);
        infoTable.setRowHeight(new JComboBox().getPreferredSize().height);

        final JButton viewButton = new JButton("View");
        if (chain != null && !chain.isEmpty()) {
            viewButton.addActionListener(new ActionListener() {

                @Override
                public void actionPerformed(ActionEvent e) {
                    viewButtonActionPerformed(e);
                }
            });
        } else {
            viewButton.setEnabled(false);
        }

        DefaultCellEditor editor = new DefaultCellEditor(new JTextField("")) {
            
            @Override
            public Component getTableCellEditorComponent(final JTable table,
                    final Object value, final boolean isSelected, final int row,
                    final int column) {
                
                final Component defaultComponent
                        = super.getTableCellEditorComponent(table, value, isSelected,
                        row, column);
                final JPanel panel = new JPanel(new BorderLayout());
                ((JTextField) defaultComponent).setEditable(false);
                panel.setBackground(isSelected ? table.getSelectionBackground() : table.getBackground());
                panel.add(defaultComponent, BorderLayout.CENTER);
                if (COLUMN_CERTIFICATE.equals(table.getValueAt(row, 0))) {
                    panel.add(viewButton, BorderLayout.EAST);
                }
                return panel;
            }   
        };
        editor.setClickCountToStart(1);        
        infoTable.getColumnModel().getColumn(1).setCellEditor(editor);

        infoTable.getColumnModel().getColumn(1).setCellRenderer(new DefaultTableCellRenderer() {
            private final JButton viewButton = new JButton("View");

            {
                if (chain == null || chain.isEmpty()) {
                    viewButton.setEnabled(false);
                }
            }
            
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value,
                    boolean isSelected, boolean hasFocus, int row, int column) {
                final Component defaultComponent
                    = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                
                JPanel viewPanel = new JPanel(new BorderLayout());
                viewPanel.add(defaultComponent, BorderLayout.CENTER);
                if (COLUMN_CERTIFICATE.equals(table.getValueAt(row, 0))) {
                    viewPanel.add(viewButton, BorderLayout.EAST);
                }
                viewPanel.setBackground(isSelected ? table.getSelectionBackground() : table.getBackground());
                return viewPanel;
            }
        });
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jScrollPane1 = new javax.swing.JScrollPane();
        infoTable = new javax.swing.JTable();
        closeButton = new javax.swing.JButton();

        setDefaultCloseOperation(javax.swing.WindowConstants.DISPOSE_ON_CLOSE);
        setTitle("Token entry");
        setLocationByPlatform(true);

        infoTable.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {
                {null, null, null, null},
                {null, null, null, null},
                {null, null, null, null},
                {null, null, null, null}
            },
            new String [] {
                "Title 1", "Title 2", "Title 3", "Title 4"
            }
        ));
        infoTable.setRowSelectionAllowed(false);
        jScrollPane1.setViewportView(infoTable);

        closeButton.setText("Close");
        closeButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                closeButtonActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 786, Short.MAX_VALUE)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(closeButton, javax.swing.GroupLayout.PREFERRED_SIZE, 107, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(0, 0, Short.MAX_VALUE)))
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 418, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(closeButton)
                .addContainerGap())
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void closeButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_closeButtonActionPerformed
        dispose();
    }//GEN-LAST:event_closeButtonActionPerformed

    private void viewButtonActionPerformed(ActionEvent e) {
        final ViewCertificateFrame frame = new ViewCertificateFrame(chain);
        frame.setVisible(true);
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton closeButton;
    private javax.swing.JTable infoTable;
    private javax.swing.JScrollPane jScrollPane1;
    // End of variables declaration//GEN-END:variables
}
