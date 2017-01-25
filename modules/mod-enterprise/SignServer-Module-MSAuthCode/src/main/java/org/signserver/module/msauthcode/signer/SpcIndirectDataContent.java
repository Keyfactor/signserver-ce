/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
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
 *
 * @author user
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
