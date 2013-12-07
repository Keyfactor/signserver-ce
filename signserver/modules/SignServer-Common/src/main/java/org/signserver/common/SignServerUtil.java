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
package org.signserver.common;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;

import org.apache.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.ejbca.util.CertTools;

/**
 * Containing common util methods used for various reasons.
 * 
 * @author Philip Vendil 2007 jan 26
 * @version $Id$
 */
public class SignServerUtil {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(SignServerUtil.class);

    public static void installBCProvider() {
        if (Security.addProvider(new BouncyCastleProvider()) < 0) {
            Security.removeProvider("BC");
            if (Security.addProvider(new BouncyCastleProvider()) < 0) {
                LOG.error("Cannot even install BC provider again!");
            }

        }
    }

    /**
     * Method that takes a configuration, traverses trough it to find all properties beginning
     * with the propertyPrefix and a number between 0 and 255 and returns a list in the given
     * order where missing numbers have the value "". The list have the same lenght as the
     * maximum number in the configuration.
     * 
     * For example will a configuration of:
     * SOMEPOSTFIX.0 = "SOMEDATA0"
     * SOMEPOSTFIX.1 = "SOMEDATA1"
     * SOMEPOSTFIX.4 = "SOMEDATA4"
     * 
     * Return a list of {"SOMEDATA0","SOMEDATA1","","","SOMEDATA4"}
     * @param propertyPrefix must be a valid property key and end with a '.'
     * @return a list of values from the configuration, never null.
     */
    public static ArrayList<String> getCollectionOfValuesFromProperties(String propertyPrefix, WorkerConfig config) {
        ArrayList<String> list = new ArrayList<String>();
        int n = 255;
        while (n >= 0) {
            n--;
            String value = config.getProperty(propertyPrefix + n);
            if (value != null) {
                list.add(0, value);
                break;
            }
        }

        while (n > 0) {
            n--;
            String value = config.getProperty(propertyPrefix + n);
            if (value != null) {
                list.add(0, value);
            } else {
                list.add(0, "");
            }
        }

        return list;
    }

    /**
     * Help method that reads a key from a configuration file.
     * Example a file containing a row with SIGNSERVER_NODEID = NODE1 will return NODE1
     * @param key to look for
     * @param confFile configuration file to parse
     * @return the value after the '=' character, trimmed, or null if key wasn't found in file.
     * @throws IOException if something went wrong when reading the file.
     */
    public static String readValueFromConfigFile(String key, File confFile) throws IOException {
        String retval = null;
        FileReader fr = new FileReader(confFile);
        BufferedReader br = new BufferedReader(fr);
        String next;
        while ((next = br.readLine()) != null) {
            next = next.trim();
            if (next.startsWith(key) || next.startsWith(key.toUpperCase())) {
                int index = next.indexOf('=');
                if (index != -1) {
                    String nextkey = next.substring(0, index);
                    if (nextkey.trim().equalsIgnoreCase(key)) {
                        String value = next.substring(index + 1);
                        retval = value.trim();
                        break;
                    }
                }
            }
        }
        return retval;
    }
    
    /**
     * Get a certificate from a file (PEM or binary cert)
     * @param filename
     * @return Certificate
     * @throws IllegalCommandArgumentsException
     */
    public static X509Certificate getCertFromFile(final String filename)
                throws IllegalArgumentException {
        Collection<?> certs;
        X509Certificate cert = null;
        
        try {
                certs = CertTools.getCertsFromPEM(filename);
                        
                if (certs.isEmpty()) {
                        throw new IllegalArgumentException("Invalid PEM file, couldn't find any certificate");
                }
                
                cert = (X509Certificate) certs.iterator().next();
        } catch (CertificateException cex) {
                throw new IllegalArgumentException("Could not fetch certificate from PEM file: " + cex.getMessage());
        } catch (IOException ioex) {
                // try to treat the file as a binary certificate file
                        FileInputStream fis = null;

                try {
                        fis = new FileInputStream(filename);
                        byte[] content = new byte[fis.available()];
                        fis.read(content, 0, fis.available());
                        cert = (X509Certificate) CertTools.getCertfromByteArray(content);
                } catch (Exception ex) {
                        throw new IllegalArgumentException("Could not read certificate in DER format: " + ex.getMessage());
                } finally {
                        if (fis != null) {
                                try {
                                        fis.close();
                                } catch (IOException ioe) {
                                }
                        }
                }
        }
        
        return cert;
    }
}
