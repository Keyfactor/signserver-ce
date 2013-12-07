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

import java.io.Serializable;

import org.ejbca.util.CertTools;

/**
 * Class representing an authorized client containing the  serial number and 
 * issuerDN of trusted client certs.
 * 
 * @author Philip Vendil
 * @version $Id$
 */
public class AuthorizedClient implements Comparable<Object>, Serializable {

    private static final long serialVersionUID = 1L;

    private String certSN;
    private String issuerDN;

    public AuthorizedClient() {
    }

    public void setCertSN(String certSN) {
        this.certSN = certSN;
    }

    public void setIssuerDN(String issuerDN) {
        this.issuerDN = CertTools.stringToBCDNString(issuerDN);
    }

    public AuthorizedClient(String certSN, String issuerDN) {
        this.certSN = certSN;
        this.issuerDN = issuerDN;
    }

    /**
     * Sort by Cert SN
     * @param arg0 must be a AuthorizedClient
     */
    public int compareTo(Object arg0) {
        if (arg0 instanceof AuthorizedClient) {
            return certSN.compareTo(((AuthorizedClient) arg0).getCertSN());
        }
        return 0;
    }

    public String getCertSN() {
        return certSN;
    }

    public String getIssuerDN() {
        return issuerDN;
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 29 * hash + (this.certSN != null ? this.certSN.hashCode() : 0);
        hash = 29 * hash + (this.issuerDN != null ? this.issuerDN.hashCode() : 0);
        return hash;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final AuthorizedClient other = (AuthorizedClient) obj;
        if ((this.certSN == null) ? (other.certSN != null) : !this.certSN.equals(other.certSN)) {
            return false;
        }
        if ((this.issuerDN == null) ? (other.issuerDN != null) : !this.issuerDN.equals(other.issuerDN)) {
            return false;
        }
        return true;
    }
}