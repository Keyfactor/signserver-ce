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
package org.signserver.test.utils.builders.crl;

import java.math.BigInteger;
import java.util.Date;
import org.bouncycastle.asn1.x509.Extensions;

/**
 * Holder for the data to use when creating an CRL entry.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class CRLEntry {
    
    private BigInteger userCertificateSerial;
    private Date date;
    private Integer reason;
    private Date invalidityDate;
    private Extensions extensions;
    
    public CRLEntry(BigInteger userCertificateSerial, Date date, int reason) {
        this.userCertificateSerial = userCertificateSerial;
        this.date = date;
        this.reason = reason;
    }

    public CRLEntry(BigInteger userCertificateSerial, Date revocationDate, int reason, Date invalidityDate) {
        this.userCertificateSerial = userCertificateSerial;
        this.date = revocationDate;
        this.reason = reason;
        this.invalidityDate = invalidityDate;
    }

    public CRLEntry(BigInteger userCertificateSerial, Date revocationDate, Extensions extensions) {
        this.userCertificateSerial = userCertificateSerial;
        this.date = revocationDate;
        this.extensions = extensions;
    }

    public BigInteger getUserCertificateSerial() {
        return userCertificateSerial;
    }

    public Date getDate() {
        return date;
    }

    public Integer getReason() {
        return reason;
    }

    public Date getInvalidityDate() {
        return invalidityDate;
    }

    public Extensions getExtensions() {
        return extensions;
    }

    @Override
    public String toString() {
        return "CRLEntry{" + "userCertificateSerial=" + userCertificateSerial + ", date=" + date + ", reason=" + reason + ", invalidityDate=" + invalidityDate + ", extensions=" + extensions + '}';
    }
    
}
