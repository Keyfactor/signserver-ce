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

import java.security.cert.X509Certificate;

import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTextField;
import org.cesecore.util.CertTools;

import org.signserver.common.SignServerUtil;

/**
 * Utility methods for the Admin GUI.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 *
 */
public class Utils {
    public static final String NEXT_KEY = "Next key";
    public static final String DEFAULT_KEY = "Default key";
    
    /**
     * Open a file selector that lets the user select a certificate file.
     * Fill the supplied serial number and issuer DN text fields with the values from the cert
     * or show an error message in associated with the supplied panel.
     * 
     * @param panel Panel requesting the action. Used to attach the open file dialog and a possible error message.
     * @param serialNumberTextfield field Text field to set the serial number in.
     * @param issuerDNTextfield Text fieald to set the issuer DN in.
     * @param forAdmins If true, format the DN as expected by WS admins, otherwise
     *                     use a format suitable for the ClientCertAuthorizer
     */
    public static void selectAndLoadFromCert(final JPanel panel,
            final JTextField serialNumberTextfield,
            final JTextField issuerDNTextfield,
            final boolean forAdmins) {
        
        final JFileChooser chooser = new JFileChooser();
        final int res = chooser.showOpenDialog(panel);
        
        if (res == JFileChooser.APPROVE_OPTION) {
            try {
                final X509Certificate cert =
                        SignServerUtil.getCertFromFile(chooser.getSelectedFile().getAbsolutePath());
                serialNumberTextfield.setText(cert.getSerialNumber().toString(16));
                if (forAdmins) {
                    issuerDNTextfield.setText(SignServerUtil.getTokenizedIssuerDNFromCert(cert));
                } else {
                    issuerDNTextfield.setText(CertTools.stringToBCDNString(cert.getIssuerX500Principal().getName()));
                }
            } catch (IllegalArgumentException e) {
                JOptionPane.showMessageDialog(panel, e.getMessage());
            }
        }
    }
    
    public static enum HardCodedAlias {
        NEXT_KEY {
            @Override
            public String toString() {
                return Utils.NEXT_KEY;
            }
        },
        DEFAULT_KEY {
            @Override
            public String toString() {
                return Utils.DEFAULT_KEY;
            }
        }
    }
    
    public static class HardCodedAliasValue {
        private final HardCodedAlias hardCodedAlias;
        private final Worker worker;
        
        public HardCodedAliasValue(final HardCodedAlias hardCodedAlias,
                                   final Worker worker) {
            this.hardCodedAlias = hardCodedAlias;
            this.worker = worker;
        }
        
        @Override
        public String toString() {
            final String alias;
            
            switch (hardCodedAlias) {
                case DEFAULT_KEY:
                    alias = worker.getConfiguration().getProperty("DEFAULTKEY");
                    break;
                case NEXT_KEY:
                    alias = worker.getConfiguration().getProperty("NEXTCERTSIGNKEY");
                    break;
                default:
                    throw new IllegalArgumentException("Unknown hard-coded alias");
            }
            
            return hardCodedAlias.toString() + " (" + alias + ")";
        }
        
        public HardCodedAlias getHardCodedAlias() {
            return hardCodedAlias;
        }
    }

}
