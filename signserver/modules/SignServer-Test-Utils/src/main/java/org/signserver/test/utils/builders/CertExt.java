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
package org.signserver.test.utils.builders;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;

/**
 * Holder for the data to use when creating an certificate extension.
 * 
 *
 * @version $Id$
 */
public class CertExt {
    private ASN1ObjectIdentifier oid;
    private boolean isCritical;
    private ASN1Encodable value;

    public CertExt(ASN1ObjectIdentifier oid, boolean isCritical, ASN1Encodable value) {
        this.oid = oid;
        this.isCritical = isCritical;
        this.value = value;
    }

    public boolean isIsCritical() {
        return isCritical;
    }

    public ASN1ObjectIdentifier getOid() {
        return oid;
    }

    public ASN1Encodable getValue() {
        return value;
    }

    /**
     * An CertExt equals an other CertExt iff it has the same OID.
     */
    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final CertExt other = (CertExt) obj;
        if (this.oid != other.oid && (this.oid == null || !this.oid.equals(other.oid))) {
            return false;
        }
        return true;
    }

    @Override
    public int hashCode() {
        int hash = 3;
        hash = 97 * hash + (this.oid != null ? this.oid.hashCode() : 0);
        return hash;
    }
    
}
