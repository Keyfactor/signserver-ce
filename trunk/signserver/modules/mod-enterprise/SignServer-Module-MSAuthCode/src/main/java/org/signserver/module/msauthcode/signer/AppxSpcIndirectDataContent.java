/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.module.msauthcode.signer;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.BERSequence;
import org.bouncycastle.asn1.x509.DigestInfo;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import net.jsign.asn1.authenticode.SpcAttributeTypeAndOptionalValue;

/**
 * <pre>
 * AppxSpcIndirectDataContent ::= SEQUENCE {
 *     data                    SpcAttributeTypeAndOptionalValue,
 *     messageDigest           DigestInfo
 * }
 * </pre>
 *
 * @author Selwyn Oh
 * @version $Id$
 */
public class AppxSpcIndirectDataContent extends ASN1Object {

    private final SpcAttributeTypeAndOptionalValue data;
    private final DigestInfo messageDigest;

    public AppxSpcIndirectDataContent(SpcAttributeTypeAndOptionalValue data, DigestInfo messageDigest) {
        this.data = data;
        this.messageDigest = messageDigest;
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        try {

            ASN1EncodableVector v = new ASN1EncodableVector();
            v.add(data);
            byte[] byteArrDigest = messageDigest.getDigest();
            byte[] padding = new byte[] {(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00 };
            ByteArrayOutputStream digestBytes = new ByteArrayOutputStream();
            digestBytes.write(byteArrDigest);
            digestBytes.write(padding);

            v.add(messageDigest);
            return new BERSequence(v);
            
        }
        catch (IOException ioe) {
            return null;
        }
    }
}
