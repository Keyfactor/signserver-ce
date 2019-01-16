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
package org.signserver.utils.timestampers;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cms.CMSSignedData;
import org.signserver.ejb.interfaces.InternalProcessSessionLocal;

/**
 * Internal RFC3161 time-stamper standard style.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class RFCInternalRFC3161Timestamper extends InternalRFC3161Timestamper {

    public RFCInternalRFC3161Timestamper(String tsaWorkerNameOrId, final ASN1ObjectIdentifier policy, String username, String password, InternalProcessSessionLocal workerSession) {
        super(tsaWorkerNameOrId, policy, username, password, true, workerSession);
    }

    @Override
    protected AttributeTable getUnsignedAttributes(CMSSignedData token) {
        Attribute rfc3161CounterSignature = new Attribute(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken, new DERSet(token.toASN1Structure()));
        return new AttributeTable(rfc3161CounterSignature);
    }
    
}
