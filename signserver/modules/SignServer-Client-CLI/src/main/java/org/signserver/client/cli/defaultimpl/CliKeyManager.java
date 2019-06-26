/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.signserver.client.cli.defaultimpl;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.logging.Level;
import javax.net.ssl.X509KeyManager;
import org.apache.log4j.Logger;

/**
 * Key manager that prompts user for choosing which certificate to use.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class CliKeyManager implements X509KeyManager {
    
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(CliKeyManager.class);

    private final X509KeyManager base;

    private String lastSelectedAlias;
    private volatile X509Certificate selectedCertificate; // Note: Can be read/written by multiple threads
    private final PrintStream out;
    
    public CliKeyManager(final X509KeyManager base, final PrintStream out) {
        this.base = base;
        this.out = out;
    }

    @Override
    public String[] getClientAliases(String string, Principal[] prncpls) {
        return base.getClientAliases(string, prncpls);
    }

    @Override
    public synchronized String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) { // Note: synchronized to stop all but one thread from asking for alias

        if (lastSelectedAlias == null) {
            // For each keyType, call getClientAliases on the base KeyManager
            // to find valid aliases. If our requested alias is found, select it
            // for return.
            String selectedAlias = null;
            for (String keyType1 : keyType) {
                String[] validAliases = base.getClientAliases(keyType1, issuers);
                if (validAliases != null) {
                    Arrays.sort(validAliases);
                    out.println("Choose identity: ");
                    int i = 1;
                    for (String alias : validAliases) {
                        out.println("[" + i++ + "] " + alias);
                    }
                    out.flush();
                    final String format;
                    if (validAliases.length > 1) {
                        format = "Choose [1-%d]: ";
                    } else {
                        format = "Choose [%d]: ";
                    }

                    for (int j = 0; j < 3; j++) {
                        out.printf(format, i - 1);

                        final BufferedReader reader =
                                new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
                        
                        String answer = null;
                        try {
                            answer = reader.readLine();
                        } catch (IOException ex) {
                            LOG.error("Failed to read answer: " + ex);
                        }

                        if (answer == null) {
                            break;
                        }
                        answer = answer.trim();
                        try {
                            int choice = Integer.valueOf(answer);
                            
                            if (choice > 0 && choice < i) {
                                selectedAlias = validAliases[choice - 1];
                                break;
                            }
                            
                        } catch (NumberFormatException ex) {}
                    }

                    if (selectedAlias != null) {
                        break;
                    }
                } else {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("No matching client aliases for key type " + keyType1);
                    }
                }
            }
            lastSelectedAlias = selectedAlias;
            X509Certificate[] chain = base.getCertificateChain(selectedAlias);
            if (chain != null && chain.length > 0) {
                selectedCertificate = chain[0];
            }
        }
        return lastSelectedAlias;
    }

    @Override
    public String[] getServerAliases(String string, Principal[] prncpls) {
        return base.getClientAliases(string, prncpls);
    }

    @Override
    public String chooseServerAlias(String string, Principal[] prncpls, Socket socket) {
        return base.chooseServerAlias(string, prncpls, socket);
    }

    @Override
    public X509Certificate[] getCertificateChain(String string) {
        return base.getCertificateChain(string);
    }

    @Override
    public PrivateKey getPrivateKey(String string) {
        return base.getPrivateKey(string);
    }

    public X509Certificate getSelectedCertificate() {
        return selectedCertificate;
    }
}
