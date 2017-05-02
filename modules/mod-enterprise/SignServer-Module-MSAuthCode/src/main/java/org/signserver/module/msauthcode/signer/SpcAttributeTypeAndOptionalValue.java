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
import net.jsign.asn1.authenticode.AuthenticodeObjectIdentifiers;
import net.jsign.asn1.authenticode.SpcPeImageData;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.BERSequence;

/**
 * <pre>
 * SpcAttributeTypeAndOptionalValue ::= SEQUENCE {
 *     type                    OBJECT IDENTIFIER,
 *     value                   ANY DEFINED BY type OPTIONAL
 * }
 * </pre>
 * 
 * @author Emmanuel Bourg
 * @since 1.0
 */
public class SpcAttributeTypeAndOptionalValue extends ASN1Object {

    final ASN1ObjectIdentifier type;
    final ASN1Object value;

    public SpcAttributeTypeAndOptionalValue() {
        this.type = AuthenticodeObjectIdentifiers.SPC_PE_IMAGE_DATA_OBJID;
        this.value = new SpcPeImageData();
    }

    public SpcAttributeTypeAndOptionalValue(ASN1ObjectIdentifier type, ASN1Object value) {
        this.type = type;
        this.value = value;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(type);
        v.add(value);
        return new BERSequence(v);
    }

    public static SpcAttributeTypeAndOptionalValue getInstance(ASN1Sequence o) {
        Enumeration objects = o.getObjects();
        ASN1ObjectIdentifier type = (ASN1ObjectIdentifier) objects.nextElement();
        ASN1Object value = (ASN1Object) objects.nextElement();
        return new SpcAttributeTypeAndOptionalValue(type, value);
    }
    
}
