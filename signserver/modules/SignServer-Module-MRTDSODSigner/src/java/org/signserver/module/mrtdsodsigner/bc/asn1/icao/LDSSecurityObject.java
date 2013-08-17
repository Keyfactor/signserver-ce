package org.signserver.module.mrtdsodsigner.bc.asn1.icao;

import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.icao.DataGroupHash;
import org.bouncycastle.asn1.icao.ICAOObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * The LDSSecurityObject object.
 * <pre>
 * LDSSecurityObject ::= SEQUENCE {
 *   version                LDSSecurityObjectVersion,
 *   hashAlgorithm          DigestAlgorithmIdentifier,
 *   dataGroupHashValues    SEQUENCE SIZE (2..ub-DataGroups) OF DataHashGroup
 *   ldsVersionInfo LDSVersionInfo OPTIONAL
 *   -- If present, version MUST be V1}
 *
 * DigestAlgorithmIdentifier ::= AlgorithmIdentifier,
 *
 * LDSSecurityObjectVersion ::= INTEGER {V0(0), V1(1)
 * -- If LDSSecurityObjectVersion is V1, ldsVersionInfo MUST be present
 *
 * </pre>
 */

public class LDSSecurityObject
    extends ASN1Object
    implements ICAOObjectIdentifiers
{

    public static final int ub_DataGroups = 16;

    DERInteger version;
    AlgorithmIdentifier digestAlgorithmIdentifier;
    DataGroupHash[] datagroupHash;
    LDSVersionInfo ldsVersionInfo;

    public static LDSSecurityObject getInstance(
        Object obj)
    {
        if (obj == null || obj instanceof LDSSecurityObject)
        {
            return (LDSSecurityObject)obj;
        }

        if (obj instanceof ASN1Sequence)
        {
            return new LDSSecurityObject(ASN1Sequence.getInstance(obj));
        }

        throw new IllegalArgumentException("unknown object in getInstance: " + obj.getClass().getName());
    }

    public LDSSecurityObject(
        ASN1Sequence seq)
    {
        if (seq == null || seq.size() == 0)
        {
            throw new IllegalArgumentException("null or empty sequence passed.");
        }

        Enumeration e = seq.getObjects();

        // version
        version = DERInteger.getInstance(e.nextElement());
        // digestAlgorithmIdentifier
        digestAlgorithmIdentifier = AlgorithmIdentifier.getInstance(e.nextElement());

        ASN1Sequence datagroupHashSeq = ASN1Sequence.getInstance(e.nextElement());

        checkDatagroupHashSeqSize(datagroupHashSeq.size());

        datagroupHash = new DataGroupHash[datagroupHashSeq.size()];
        for (int i= 0; i< datagroupHashSeq.size();i++)
        {
            datagroupHash[i] = DataGroupHash.getInstance(datagroupHashSeq.getObjectAt(i));
        }

        if (version.equals(new DERInteger(1))) {
            ldsVersionInfo = LDSVersionInfo.getInstance(e.nextElement());
        }
    }

    public LDSSecurityObject(
        AlgorithmIdentifier digestAlgorithmIdentifier,
        DataGroupHash[]       datagroupHash)
    {
        this.version = new DERInteger(0);
        this.digestAlgorithmIdentifier = digestAlgorithmIdentifier;
        this.datagroupHash = datagroupHash;

        checkDatagroupHashSeqSize(datagroupHash.length);
    }

    public LDSSecurityObject(
        AlgorithmIdentifier digestAlgorithmIdentifier,
        DataGroupHash[]       datagroupHash,
	LDSVersionInfo ldsVersionInfo)
    {
        this.version = ldsVersionInfo == null ? new DERInteger(0) : new DERInteger(1);
        this.digestAlgorithmIdentifier = digestAlgorithmIdentifier;
        this.datagroupHash = datagroupHash;
        this.ldsVersionInfo = ldsVersionInfo;

        checkDatagroupHashSeqSize(datagroupHash.length);
    }

    private void checkDatagroupHashSeqSize(int size)
    {
        if ((size < 2) || (size > ub_DataGroups))
        {
               throw new IllegalArgumentException("wrong size in DataGroupHashValues : not in (2.."+ ub_DataGroups +")");
        }
    }

    public DERInteger getVersion()
    {
        return version;
    }

    public AlgorithmIdentifier getDigestAlgorithmIdentifier()
    {
        return digestAlgorithmIdentifier;
    }

    public DataGroupHash[] getDatagroupHash()
    {
        return datagroupHash;
    }

    public LDSVersionInfo getLdsVersionInfo()
    {
        return ldsVersionInfo;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector seq = new ASN1EncodableVector();

        seq.add(version);
        seq.add(digestAlgorithmIdentifier);

        ASN1EncodableVector seqname = new ASN1EncodableVector();
        for (int i = 0; i < datagroupHash.length; i++)
        {
            seqname.add(datagroupHash[i]);
        }
        seq.add(new DERSequence(seqname));

        if (ldsVersionInfo != null)
        {
            seq.add(ldsVersionInfo);
        }

        return new DERSequence(seq);
    }
}
