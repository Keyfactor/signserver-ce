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

import org.signserver.common.SignServerUtil;

/**
 * Utility methods for the Admin GUI.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 *
 */
public class Utils {

    /**
     * Open a file selector that lets the user select a certificate file.
     * Fill the supplied serial number and issuer DN text fields with the values from the cert
     * or show an error message in associated with the supplied panel.
     * 
     * @param panel Panel requesting the action. Used to attach the open file dialog and a possible error message.
     * @param serialNumberText field Text field to set the serial number in.
     * @param issuerDNTextfield Text fieald to set the issuer DN in.
     */
    public static void selectAndLoadFromCert(final JPanel panel,
            final JTextField serialNumberTextfield,
            final JTextField issuerDNTextfield) {
        
        final JFileChooser chooser = new JFileChooser();
        final int res = chooser.showOpenDialog(panel);
        
        if (res == JFileChooser.APPROVE_OPTION) {
            try {
                final X509Certificate cert =
                        SignServerUtil.getCertFromFile(chooser.getSelectedFile().getAbsolutePath());
                serialNumberTextfield.setText(cert.getSerialNumber().toString(16));
                issuerDNTextfield.setText(cert.getIssuerDN().getName());
            } catch (IllegalArgumentException e) {
                JOptionPane.showMessageDialog(panel, e.getMessage());
            }
        }
    }

}
