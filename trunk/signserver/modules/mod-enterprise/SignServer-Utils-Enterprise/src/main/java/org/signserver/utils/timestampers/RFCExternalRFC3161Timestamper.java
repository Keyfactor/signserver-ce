/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
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
