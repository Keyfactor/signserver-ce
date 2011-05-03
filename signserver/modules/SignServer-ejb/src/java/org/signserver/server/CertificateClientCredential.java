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

package org.signserver.server;

/**
 * Representation of a X509 client certificate for authentication use.
 * @version $Id$
 */
public class CertificateClientCredential implements IClientCredential {

    private String serialNumber;
    private String issuerDN;

    public CertificateClientCredential(String serialNumber, String issuerDN) {
        this.serialNumber = serialNumber;
        this.issuerDN = issuerDN;
    }

    public String getIssuerDN() {
        return issuerDN;
    }

    public String getSerialNumber() {
        return serialNumber;
    }
}
