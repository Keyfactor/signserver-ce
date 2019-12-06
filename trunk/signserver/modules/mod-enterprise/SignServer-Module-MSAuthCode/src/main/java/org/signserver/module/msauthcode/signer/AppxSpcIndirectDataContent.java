/**
 * Copyright 2012 Emmanuel Bourg
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.signserver.module.msauthcode.signer;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.BERSequence;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.asn1.DEROctetString;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * <pre>
 * AppxSpcIndirectDataContent ::= SEQUENCE {
 *     data                    SpcAttributeTypeAndOptionalValue,
 *     messageDigest           DigestInfo
 * }
 * </pre>
 *
 * @author Emmanuel Bourg
 * @since 1.0
 */
public class AppxSpcIndirectDataContent extends ASN1Object {

    private SpcAttributeTypeAndOptionalValue data;
    private DigestInfo messageDigest;

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