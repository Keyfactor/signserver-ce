package org.signserver.module.tsa.bc;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.BEROctetString;
import org.bouncycastle.asn1.BERSet;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.io.TeeOutputStream;
import org.signserver.module.tsa.MSAuthCodeTimeStampSigner;

/**
 * Utility class containing static methods based on modified code from BouncyCastle
 * to handle the requirements of the MSAuthCodeTimeStampSigner
 * 
 * @author Marcus Lundblad
 * @version $Id$
 *
 */
public class MSAuthCodeCMSUtils
{
    /**
     * Modified from {@link org.bouncycastle.cms.CMSSignedDataGenerator#generate(CMSTypedData, boolean)}
     * Added parameters for passing certs, CRLs and the ContentInfo instance, since this method will be run as
     * stand-alone invocation, instead using the CMSSignedGenerator instance as the origninal BC implementation, allowing
     * the MSAuthCodeTimeStampSigner to generate the content info.
     * 
     * @param content
     * @param encapsulate
     * @param signerGens
     * @param certs
     * @param crls
     * @param ci
     * @return
     * @throws CMSException
     */
    public static CMSSignedData generate(
            // FIXME Avoid accessing more than once to support CMSProcessableInputStream
            CMSTypedData content,
            boolean encapsulate, Collection signerGens, final List certs, final List crls, ContentInfo ci)
            throws CMSException
    {

        ASN1EncodableVector  digestAlgs = new ASN1EncodableVector();
        ASN1EncodableVector  signerInfos = new ASN1EncodableVector();

        final Map digests = new HashMap();
        digests.clear();  // clear the current preserved digest state

        //
        // add the precalculated SignerInfo objects.
        //
        //            for (Iterator it = _signers.iterator(); it.hasNext();)
        //            {
        //                SignerInformation signer = (SignerInformation)it.next();
        //                digestAlgs.add(CMSSignedHelper.INSTANCE.fixAlgID(signer.getDigestAlgorithmID()));
        //
        //                // TODO Verify the content type and calculated digest match the precalculated SignerInfo
        //                signerInfos.add(signer.toASN1Structure());
        //            }

        //
        // add the SignerInfo objects
        //
        ASN1ObjectIdentifier contentTypeOID = content.getContentType();

        ASN1OctetString octs = null;

        if (content != null)
        {
            ByteArrayOutputStream bOut = null;

            if (encapsulate)
            {
                bOut = new ByteArrayOutputStream();
            }

            OutputStream cOut = attachSignersToOutputStream(signerGens, bOut);

            // Just in case it's unencapsulated and there are no signers!
            cOut = getSafeOutputStream(cOut);

            try
            {
                content.write(cOut);

                cOut.close();
            }
            catch (IOException e)
            {
                throw new CMSException("data processing exception: " + e.getMessage(), e);
            }

            if (encapsulate)
            {
                octs = new BEROctetString(bOut.toByteArray());
            }
        }

        for (Iterator it = signerGens.iterator(); it.hasNext();)
        {
            SignerInfoGenerator sGen = (SignerInfoGenerator)it.next();
            SignerInfo inf = sGen.generate(contentTypeOID);

            digestAlgs.add(inf.getDigestAlgorithm());
            signerInfos.add(inf);

            byte[] calcDigest = sGen.getCalculatedDigest();

            if (calcDigest != null)
            {
                digests.put(inf.getDigestAlgorithm().getAlgorithm().getId(), calcDigest);
            }
        }

        ASN1Set certificates = null;

        // Changes from the original BouncyCastle implementation:
        // the cert and CRL lists are supplied directly to this method (instead of being managed for the instance (in CMSSignedGenerator)
        if (!certs.isEmpty())
        {
            certificates = createBerSetFromList(certs);
        }

        ASN1Set certrevlist = null;

        if (!crls.isEmpty())
        {
            certrevlist = createBerSetFromList(crls);
        }

        // Changes from the original implementation in BouncyCaste:
        // the ContentInfo instance is supplied to this method via a parameter, it is constructed by the MSAuthCodeTimeStampSigner
        ContentInfo encInfo = ci;

        SignedData  sd = new SignedData(
                new DERSet(digestAlgs),
                encInfo,
                certificates,
                certrevlist,
                new DERSet(signerInfos));

        ContentInfo contentInfo = new ContentInfo(
                CMSObjectIdentifiers.signedData, sd);

        return new CMSSignedData(content, contentInfo);
    }
    
    /**
     * Copied from {@link org.bouncycastle.cms.CMSUtil#getCertificatesFromStore}
     * This method is supplied here for use by {@link MSAuthCodeTimeStampSigner}
     * 
     * @param certStore
     * @return
     * @throws CMSException
     */
    public static List getCertificatesFromStore(Store certStore) throws CMSException
    {
        List certs = new ArrayList();

        try
        {
            for (Iterator it = certStore.getMatches(null).iterator(); it.hasNext();)
            {
                X509CertificateHolder c = (X509CertificateHolder)it.next();

                certs.add(c.toASN1Structure());
            }

            return certs;
        }
        catch (ClassCastException e)
        {
            throw new CMSException("error processing certs", e);
        }
    }

    /**
     * Copied from {@link org.bouncycastle.cms.CMSUtils#attachSignersToOutputStream(Collection, OutputStream)}
     * Used internally by {@link #generate(CMSTypedData, boolean, Collection, List, List, ContentInfo)}
     * 
     * @param signers
     * @param s
     * @return
     */
    private static OutputStream attachSignersToOutputStream(Collection signers, OutputStream s)
    {
        OutputStream result = s;
        Iterator it = signers.iterator();
        while (it.hasNext())
        {
            SignerInfoGenerator signerGen = (SignerInfoGenerator)it.next();
            result = getSafeTeeOutputStream(result, signerGen.getCalculatingOutputStream());
        }
        return result;
    }
    
    /**
     * Copied from {@link org.bouncycastle.cms.CMSUtils#getSafeOutputStream(OutputStream)}
     * Used internally by {@link #generate(CMSTypedData, boolean, Collection, List, List, ContentInfo)}
     * 
     * @param s
     * @return
     */
    private static OutputStream getSafeOutputStream(OutputStream s)
    {
        return s == null ? new NullOutputStream() : s;
    }
    
    /**
     * Copied from {@link org.bouncycastle.cms.CMSUtils#getSafeTeeOutputStream}
     * Used internally by {@link #generate(CMSTypedData, boolean, Collection, List, List, ContentInfo)}
     * 
     * @param s1
     * @param s2
     * @return
     */
    private static OutputStream getSafeTeeOutputStream(OutputStream s1,
            OutputStream s2)
    {
        return s1 == null ? getSafeOutputStream(s2)
                : s2 == null ? getSafeOutputStream(s1) : new TeeOutputStream(
                        s1, s2);
    }
    
    /**
     * Copied from {@link org.bouncycastle.cms.CMSUtils#createBerSetFromList(List)}
     * Used internally by {@link #generate(CMSTypedData, boolean, Collection, List, List, ContentInfo)}
     * 
     * @param derObjects
     * @return
     */
    private static ASN1Set createBerSetFromList(List derObjects)
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        for (Iterator it = derObjects.iterator(); it.hasNext();)
        {
            v.add((ASN1Encodable)it.next());
        }

        return new BERSet(v);
    }
    
    /**
     * Copied from {@link org.bouncycastle.cms.NullOutputStream}
     * Used internally by {@link #generate(CMSTypedData, boolean, Collection, List, List, ContentInfo)}
     *
     */
    private static class NullOutputStream extends OutputStream
    {
        @Override
        public void write(byte[] buf)
                throws IOException {
            // do nothing
        }

        @Override
        public void write(byte[] buf, int off, int len)
                throws IOException {
            // do nothing
        }
    
        public void write(int b) throws IOException {
            // do nothing
        }
    }
    
}
