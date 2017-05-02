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
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.BERSequence;

/**
 *
 * @author Emmanual Bourgh
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
