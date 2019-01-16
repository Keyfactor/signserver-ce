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

/**
 * External RFC3161 time-stamper standard style.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class RFCExternalRFC3161Timestamper extends ExternalRFC3161Timestamper {

    public RFCExternalRFC3161Timestamper(final ASN1ObjectIdentifier policy, String username, String password) {
        super(policy, username, password, true);
    }

    @Override
    protected AttributeTable getUnsignedAttributes(CMSSignedData token) {
        Attribute rfc3161CounterSignature = new Attribute(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken, new DERSet(token.toASN1Structure()));
        return new AttributeTable(rfc3161CounterSignature);
    }
}
