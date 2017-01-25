/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
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
