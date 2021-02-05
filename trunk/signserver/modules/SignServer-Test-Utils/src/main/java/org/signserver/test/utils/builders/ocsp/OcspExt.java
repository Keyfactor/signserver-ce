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

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;

/**
 * Holder for the data to use when creating an OCSP extension.
 * 
 * XXX: This code is duplicated in EJBCA and SignServer. Consider breaking out as a separate JAR.
 *
 * @version $Id$
 */
public class OcspExt {
    private ASN1ObjectIdentifier oid;
    private boolean isCritical;
    private ASN1OctetString value;

    public OcspExt(ASN1ObjectIdentifier oid, boolean isCritical, ASN1OctetString value) {
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

    public ASN1OctetString getValue() {
        return value;
    }

    /**
     * An OcspExt equals an other OcspExt iff it has the same OID.
     */
    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final OcspExt other = (OcspExt) obj;
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
