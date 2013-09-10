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
package org.signserver.test.utils.builders.ocsp;

import java.util.Date;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;

/**
 * Holder for OCSP response information.
 *
 *
 * XXX: This code is duplicated in EJBCA and SignServer. Consider breaking out as a separate JAR.
 * 
 * @version $Id$
 */
public class OcspRespObject {
    private CertificateID certId;
    private CertificateStatus certStatus;
    private Date thisUpdate;
    private Date nextUpdate;
    private Extensions extensions;

    public OcspRespObject(CertificateID certId, CertificateStatus certStatus, Date thisUpdate, Date nextUpdate, Extensions extensions) {
        this.certId = certId;
        this.certStatus = certStatus;
        this.thisUpdate = thisUpdate;
        this.nextUpdate = nextUpdate;
        this.extensions = extensions;
    }

    public OcspRespObject(CertificateID certId, CertificateStatus certStatus) {
        this(certId, certStatus, new Date(), null, null);
    }

    public OcspRespObject(CertificateID certId, CertificateStatus certStatus, Extensions extensions) {
        this(certId, certStatus, new Date(), null, extensions);
    }

    public CertificateID getCertId() {
        return certId;
    }

    public CertificateStatus getCertStatus() {
        return certStatus;
    }

    public Extensions getExtensions() {
        return extensions;
    }

    public Date getNextUpdate() {
        return nextUpdate;
    }

    public Date getThisUpdate() {
        return thisUpdate;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final OcspRespObject other = (OcspRespObject) obj;
        if (this.certId != other.certId && (this.certId == null || !this.certId.equals(other.certId))) {
            return false;
        }
        return true;
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 97 * hash + (this.certId != null ? this.certId.hashCode() : 0);
        return hash;
    }
    
}
