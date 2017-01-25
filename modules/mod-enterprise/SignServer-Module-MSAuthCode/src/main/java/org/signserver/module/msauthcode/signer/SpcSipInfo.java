/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.signserver.module.msauthcode.signer;

import java.util.Enumeration;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.BERSequence;

/**
 *
 * @author user
 */
public class SpcSipInfo extends ASN1Object {
    
    private final ASN1Integer a;
    private final ASN1OctetString string;
    private final ASN1Integer b;
    private final ASN1Integer c;
    private final ASN1Integer d;
    private final ASN1Integer e;
    private final ASN1Integer f;

    public SpcSipInfo(ASN1Integer a, ASN1OctetString string, ASN1Integer b, ASN1Integer c, ASN1Integer d, ASN1Integer e, ASN1Integer f) {
        this.a = a;
        this.string = string;
        this.b = b;
        this.c = c;
        this.d = d;
        this.e = e;
        this.f = f;
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(a);
        v.add(string);
        v.add(b);
        v.add(c);
        v.add(d);
        v.add(e);
        v.add(f);
        return new BERSequence(v);
    }

    public static SpcSipInfo getInstance(ASN1Sequence seq) {
        Enumeration os = seq.getObjects();
        return new SpcSipInfo((ASN1Integer) os.nextElement(), (ASN1OctetString) os.nextElement(), (ASN1Integer) os.nextElement(), (ASN1Integer) os.nextElement(), (ASN1Integer) os.nextElement(), (ASN1Integer) os.nextElement(), (ASN1Integer) os.nextElement());
    }

    @Override
    public String toString() {
        return "SpcSipInfo{" + "a=" + a + ", string=" + string + ", b=" + b + ", c=" + c + ", d=" + d + ", e=" + e + ", f=" + f + '}';
    }
    
}
