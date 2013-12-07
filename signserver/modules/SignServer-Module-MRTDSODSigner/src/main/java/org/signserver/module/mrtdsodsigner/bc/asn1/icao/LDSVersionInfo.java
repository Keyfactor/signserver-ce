package org.signserver.module.mrtdsodsigner.bc.asn1.icao;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;

/**
 * The LDS and Unicode version information.
 *
 * <pre>
 * LDSVersionInfo ::= SEQUENCE {
 *   ldsVersion PRINTABLE STRING
 *   unicodeVersion PRINTABLE STRING }
 * </pre>
 */

public class LDSVersionInfo
    extends ASN1Object
{
    private DERPrintableString ldsVersion;
    private DERPrintableString unicodeVersion;

    public static LDSVersionInfo getInstance(
        Object obj)
    {
        if (obj == null || obj instanceof LDSVersionInfo)
        {
            return (LDSVersionInfo)obj;
        }

        if (obj instanceof ASN1Sequence)
        {
            return new LDSVersionInfo(ASN1Sequence.getInstance(obj));
        }

        throw new IllegalArgumentException(
                "unknown object in getInstance: " + obj.getClass().getName());
    }

    public LDSVersionInfo(
        ASN1Sequence seq)
    {
        if (seq == null || seq.size() == 0)
        {
            throw new IllegalArgumentException(
                    "null or empty sequence passed.");
        }
        if (seq.size() != 2) {
            throw new IllegalArgumentException(
                    "Incorrect sequence size: " + seq.size());
        }

        ldsVersion = DERPrintableString.getInstance(seq.getObjectAt(0));
        unicodeVersion = DERPrintableString.getInstance(seq.getObjectAt(1));
    }

    public LDSVersionInfo(
        DERPrintableString ldsVersion,
        DERPrintableString unicodeVersion)
    {
        this.ldsVersion = ldsVersion;
        this.unicodeVersion = unicodeVersion;
    }

    public String getLdsVersion() {
        return ldsVersion.getString();
    }

    public String getUnicodeVersion() {
        return unicodeVersion.getString();
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector seq = new ASN1EncodableVector();

        seq.add(ldsVersion);
        seq.add(unicodeVersion);

        return new DERSequence(seq);
    }
}
