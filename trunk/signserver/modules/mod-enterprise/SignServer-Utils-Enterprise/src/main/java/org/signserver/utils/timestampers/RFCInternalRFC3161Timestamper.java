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
