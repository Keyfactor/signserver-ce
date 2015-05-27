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
import java.util.LinkedList;
import java.util.List;
import javax.swing.DefaultCellEditor;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import org.apache.log4j.Logger;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.util.CertTools;
import org.signserver.admin.gui.adminws.gen.TokenEntry;

/**
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class TokenEntryDetailsFrame extends javax.swing.JFrame {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(TokenEntryDetailsFrame.class);
    
    private static final String COLUMN_CERTIFICATE = "Certificate";
    private List<X509Certificate> chain;
    
    /**
     * Creates new form TokenEntryDetailsFrame
     */
    public TokenEntryDetailsFrame(TokenEntry entry) {
        initComponents();
        
        X509Certificate signerCert = null;
        try {
            if (entry.getChain() != null && !entry.getChain().isEmpty()) {
                this.chain = new LinkedList<X509Certificate>();
                for (byte[] certBytes : entry.getChain()) {
                    Certificate cert = CertTools.getCertfromByteArray(certBytes, "BC");
                    if (cert instanceof X509Certificate) {
                        this.chain.add((X509Certificate) cert);
                    } else {
                        LOG.info("Not an X.509 certificate: " + cert);
                    }
                }
                signerCert = this.chain.get(0);
            } 
        } catch (CertificateException ex) {
            LOG.error("Unable to parse certificate from token: " + ex.getMessage(), ex);
            this.chain = null;
        }
        
        
        final String alias = entry.getAlias();
        final String type = entry.getType();
        final String creationDate = entry.getCreationDate() == null ? "n/a" : entry.getCreationDate().toString(); // TODO: SimpleDateFormat
        
        final String keyAlg = signerCert == null ? "n/a" : AlgorithmTools.getKeyAlgorithm(signerCert.getPublicKey());
        final String keySpec = signerCert == null ? "n/a" : AlgorithmTools.getKeySpecification(signerCert.getPublicKey());
        final String certSubjectDN = signerCert == null ? "n/a" : CertTools.getSubjectDN(signerCert);
        
        
        
        
        
        
        Object[][] data = new Object[][] {
            new Object[] { "Alias", alias},
            new Object[] { "Type", type},
            new Object[] { "Creation date", creationDate},
            new Object[] { "Key algorithm", keyAlg},
            new Object[] { "Key specification", keySpec},
            new Object[] { COLUMN_CERTIFICATE, certSubjectDN},
        };
                
        final StringBuilder sb = new StringBuilder();
        sb.append("<html><body><table border='1'>\n");
        
        sb.append("<tr><td>").append("Alias").append("</td><td>").append(alias).append("</td></tr>\n");
        sb.append("<tr><td>").append("Type").append("</td><td>").append(type).append("</td></tr>\n");
        sb.append("<tr><td>").append("Creation date").append("</td><td>").append(creationDate).append("</td></tr>\n");
        sb.append("<tr><td>").append("Key algorithm").append("</td><td>").append(keyAlg).append("</td></tr>\n");
        sb.append("<tr><td>").append("Key specification").append("</td><td>").append(keySpec).append("</td></tr>\n");
        
        sb.append("</table></body></html>\n");

        DefaultTableModel model = new DefaultTableModel(data, new String[] {"Name", "Value"}) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return column == 1;
            }
        };
        infoTable.setModel(model);
        infoTable.setRowHeight(new JComboBox().getPreferredSize().height);

        final JButton viewButton = new JButton("View");
        viewButton.addActionListener(new ActionListener() {

            @Override
            public void actionPerformed(ActionEvent e) {
                viewButtonActionPerformed(e);
            }
        });

        DefaultCellEditor editor = new DefaultCellEditor(new JTextField("")) {
            
            @Override
            public Component getTableCellEditorComponent(final JTable table,
                    final Object value, final boolean isSelected, final int row,
                    final int column) {
                
                final Component defaultComponent
                        = super.getTableCellEditorComponent(table, value, isSelected,
                        row, column);
                final JPanel panel = new JPanel(new BorderLayout());
                final JLabel label = new JLabel((((JTextField) defaultComponent)).getText());
                panel.setBackground(isSelected ? table.getSelectionBackground() : table.getBackground());

                panel.add(label, BorderLayout.CENTER);
                if (COLUMN_CERTIFICATE.equals(table.getValueAt(row, 0))) {
                    panel.add(viewButton, BorderLayout.EAST);
                }
                return panel;
            }   
        };
        editor.setClickCountToStart(1);        
        infoTable.getColumnModel().getColumn(1).setCellEditor(editor);

        infoTable.getColumnModel().getColumn(1).setCellRenderer(new DefaultTableCellRenderer() {
            final JButton viewButton = new JButton("View");
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

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);

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
        jScrollPane1.setViewportView(infoTable);

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 474, Short.MAX_VALUE)
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 537, Short.MAX_VALUE)
                .addContainerGap())
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void viewButtonActionPerformed(ActionEvent e) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }
    
    

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JTable infoTable;
    private javax.swing.JScrollPane jScrollPane1;
    // End of variables declaration//GEN-END:variables
}
