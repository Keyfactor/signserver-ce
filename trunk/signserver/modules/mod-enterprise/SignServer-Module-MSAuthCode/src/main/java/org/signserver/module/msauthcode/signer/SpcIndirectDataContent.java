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

import java.util.Enumeration;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.BERSequence;
import org.bouncycastle.asn1.x509.DigestInfo;

/**
 * <pre>
 * SpcIndirectDataContent ::= SEQUENCE {
 *     data                    SpcAttributeTypeAndOptionalValue,
 *     messageDigest           DigestInfo
 * }
 * </pre>
 *
 * @author Emmanuel Bourg
 * @since 1.0
 */
public class SpcIndirectDataContent extends ASN1Object {
    
    SpcAttributeTypeAndOptionalValue data;
    DigestInfo messageDigest;

    public SpcIndirectDataContent(DigestInfo messageDigest) {
        this.data = new SpcAttributeTypeAndOptionalValue();
        this.messageDigest = messageDigest;
    }

    public SpcIndirectDataContent(SpcAttributeTypeAndOptionalValue data, DigestInfo messageDigest) {
        this.data = data;
        this.messageDigest = messageDigest;
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(data);
        v.add(messageDigest);
        return new BERSequence(v);
    }

    public static SpcIndirectDataContent getInstance(ASN1Sequence seq) {
        Enumeration objects = seq.getObjects();
        SpcAttributeTypeAndOptionalValue data = SpcAttributeTypeAndOptionalValue.getInstance((ASN1Sequence) objects.nextElement());
        DigestInfo messageDigest = DigestInfo.getInstance(objects.nextElement());
        return new SpcIndirectDataContent(data, messageDigest);
    }
}
