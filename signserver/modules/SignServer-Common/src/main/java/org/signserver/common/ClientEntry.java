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

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.apache.log4j.Logger;

/**
 * Class representing admin or client authorization.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public class ClientEntry {
    /** Logger for this class. */
    private static Logger LOG = Logger.getLogger(ClientEntry.class);

    private BigInteger serialNumber;
    private String issuerDN;

    public ClientEntry(final BigInteger serialNumber, final String issuerDN) {
        this.serialNumber = serialNumber;
        this.issuerDN = issuerDN;
    }

    public ClientEntry(final X509Certificate cert) {
        this.serialNumber = cert.getSerialNumber();
        this.issuerDN = cert.getIssuerDN().toString();
    }
    
    public BigInteger getSerialNumber() {
        return serialNumber;
    }
    
    public String getIssuerDN() {
        return issuerDN;
    }

    @Override
    public boolean equals(final Object other) {
        if (other instanceof ClientEntry) {
            final ClientEntry otherEntry = (ClientEntry) other;

            return serialNumber.equals(otherEntry.serialNumber)
                    && issuerDN.equals(otherEntry.issuerDN);
        } else {
            return false;
        }
    }

    @Override
    public int hashCode() {
        int hash = 3;
        hash = 67 * hash + (this.serialNumber != null ? this.serialNumber.hashCode() : 0);
        hash = 67 * hash + (this.issuerDN != null ? this.issuerDN.hashCode() : 0);
        return hash;
    }

    @Override
    public String toString() {
        return "(SN: " + serialNumber.toString(16) + ", Issuer: " + issuerDN + ")";
    }
    
    public static Set<ClientEntry> clientEntriesFromProperty(final String property) {
        final Set<ClientEntry> result = new HashSet<ClientEntry>();
        
        for (final String entry : property.split(";")) {
            final String[] splittedEntry = entry.split(",", 2);
            
            if (splittedEntry.length != 2) {
                LOG.warn("Malformed admin entry: " + entry);
            }
            
            try {
                result.add(new ClientEntry(new BigInteger(splittedEntry[0], 16),
                                        splittedEntry[1]));
            } catch (NumberFormatException e) {
                LOG.warn("Malformed serial number: " + splittedEntry[0]);
            }
        }
        
        return result;
    }
    
    public static String serializeClientEntries(final Collection<ClientEntry> entries) {
        final StringBuilder buff = new StringBuilder();
        for (final ClientEntry entry : entries) {
            buff.append(entry.getSerialNumber().toString(16));
            buff.append(",");
            buff.append(entry.getIssuerDN());
            buff.append(";");
        }
        return buff.toString();
    }
}
