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
import java.util.HashSet;
import java.util.Set;
import org.apache.log4j.Logger;

/**
 * Class representing admin or client authorization.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public class AdminEntry {
    /** Logger for this class. */
    private static Logger LOG = Logger.getLogger(AdminEntry.class);

    private BigInteger serialNumber;
    private String issuerDN;

    public AdminEntry(final BigInteger serialNumber, final String issuerDN) {
        this.serialNumber = serialNumber;
        this.issuerDN = issuerDN;
    }

    public AdminEntry(final X509Certificate cert) {
        this.serialNumber = cert.getSerialNumber();
        this.issuerDN = cert.getIssuerDN().toString();
    }

    @Override
    public boolean equals(final Object other) {
        if (other instanceof AdminEntry) {
            final AdminEntry otherEntry = (AdminEntry) other;

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
    
    public static Set<AdminEntry> adminEntriesFromProperty(final String property) {
        final Set<AdminEntry> result = new HashSet<AdminEntry>();
        
        for (final String entry : property.split(";")) {
            final String[] splittedEntry = entry.split(",", 2);
            
            if (splittedEntry.length != 2) {
                LOG.warn("Malformed admin entry: " + entry);
            }
            
            result.add(new AdminEntry(new BigInteger(splittedEntry[0], 16),
                                        splittedEntry[1]));
        }
        
        return result;
    }
}
