/*************************************************************************
 *                                                                       *
 *  SignServer: The OpenSource Automated Signing Server                  *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.signserver.validationservice.server;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import org.bouncycastle.asn1.ASN1Sequence;

import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuingDistributionPoint;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.CertificateList;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.jce.provider.X509CRLObject;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.jce.provider.X509CertificateObject;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.util.Base64;

/**
 * Contains help methods for testing the validation service
 * 
 * 
 * @author Philip Vendil 30 nov 2007
 *
 * @version $Id$
 */
public class ValidationTestUtils {

    public static X509Certificate genCert(String dn, String issuerdn, PrivateKey privKey, PublicKey pubKey, Date startDate, Date endDate, boolean isCA) throws CertificateEncodingException, InvalidKeyException, IllegalStateException, NoSuchAlgorithmException, SignatureException, CertIOException, OperatorCreationException, CertificateParsingException {
       return genCert(dn, issuerdn, privKey, pubKey, startDate, endDate, isCA, 0);
    }


    public static X509Certificate genCert(String dn, String issuerdn, PrivateKey privKey, PublicKey pubKey, Date startDate, Date endDate, boolean isCA, int keyUsage) throws CertificateEncodingException, InvalidKeyException, IllegalStateException, NoSuchAlgorithmException, SignatureException, CertIOException, OperatorCreationException, CertificateParsingException {
        return genCert(dn, issuerdn, privKey, pubKey, startDate, endDate, isCA, keyUsage, null);
    }

    public static X509Certificate genCert(String dn, String issuerdn, PrivateKey privKey, PublicKey pubKey, Date startDate, Date endDate, boolean isCA, int keyUsage, CRLDistPoint crlDistPoint) throws CertificateEncodingException, InvalidKeyException, IllegalStateException, NoSuchAlgorithmException, SignatureException, CertIOException, OperatorCreationException, CertificateParsingException {        
        byte[] serno = new byte[8];
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        random.setSeed((new Date().getTime()));
        random.nextBytes(serno);

        final SubjectPublicKeyInfo spki =
                new SubjectPublicKeyInfo(ASN1Sequence.getInstance(pubKey.getEncoded()));
        final X509v3CertificateBuilder certBuilder =
                new X509v3CertificateBuilder(new X500Name(issuerdn),
                                             (new BigInteger(serno)).abs(),
                                             startDate, endDate,
                                             new X500Name(dn), spki);

        // CRL Distribution point
        if (crlDistPoint != null) {
            certBuilder.addExtension(Extension.cRLDistributionPoints, false, crlDistPoint);
        }

        // Basic constranits is always critical and MUST be present at-least in CA-certificates.
        BasicConstraints bc = new BasicConstraints(isCA);
        certBuilder.addExtension(Extension.basicConstraints, true, bc);

        // Put critical KeyUsage in CA-certificates

        if (keyUsage == 0) {
            if (isCA == true) {
                int keyusage = X509KeyUsage.keyCertSign + X509KeyUsage.cRLSign;

                X509KeyUsage ku = new X509KeyUsage(keyusage);
                certBuilder.addExtension(Extension.keyUsage, true, ku);
            }
        } else {
            X509KeyUsage ku = new X509KeyUsage(keyUsage);
            certBuilder.addExtension(Extension.keyUsage, true, ku);
        }

        final ContentSigner signer =
                new JcaContentSignerBuilder("SHA1WithRSA").setProvider("BC").build(privKey);
        final X509CertificateHolder certHolder = certBuilder.build(signer);

        final Certificate cert = certHolder.toASN1Structure();
        
        return new X509CertificateObject(cert);
    }

    public static String genPEMStringFromChain(List<X509Certificate> chain) throws CertificateEncodingException {
        String beginKey = "\n-----BEGIN CERTIFICATE-----\n";
        String endKey = "\n-----END CERTIFICATE-----\n";
        String retval = "";
        for (X509Certificate cert : chain) {
            retval += beginKey;
            retval += new String(Base64.encode(cert.getEncoded(), true));
            retval += endKey;
        }

        return retval;
    }

    public static X509CRL genCRL(X509Certificate cacert, PrivateKey privKey,
            DistributionPoint dp, Collection<RevokedCertInfo> certs,
            int crlPeriod, int crlnumber)
            throws IOException, SignatureException, NoSuchProviderException,
                InvalidKeyException, CRLException, NoSuchAlgorithmException, OperatorCreationException {
        final String sigAlg = "SHA1WithRSA";

        boolean crlDistributionPointOnCrlCritical = true;
        boolean crlNumberCritical = false;

        Date thisUpdate = new Date();
        Date nextUpdate = new Date();

        // crlperiod is hours = crlperiod*60*60*1000 milliseconds
        nextUpdate.setTime(nextUpdate.getTime() + (crlPeriod * (long) (60 * 60 * 1000)));
        X509v2CRLBuilder crlBuilder =
                new X509v2CRLBuilder(new X500Name(cacert.getIssuerX500Principal().getName()),
                                     thisUpdate);
        crlBuilder.setNextUpdate(nextUpdate);

        CRLNumber crlnum = new CRLNumber(BigInteger.valueOf(crlnumber));
        crlBuilder.addExtension(Extension.cRLNumber, crlNumberCritical, crlnum);

        if (certs != null) {
            Iterator<RevokedCertInfo> it = certs.iterator();
            while (it.hasNext()) {
                RevokedCertInfo certinfo = it.next();
                crlBuilder.addCRLEntry(certinfo.getUserCertificate(), certinfo.getRevocationDate(), certinfo.getReason());
            }
        }

        // CRL Distribution point URI  	    
        IssuingDistributionPoint idp = new IssuingDistributionPoint(dp.getDistributionPoint(), false, false, null, false, false);

        // According to the RFC, IDP must be a critical extension.
        // Nonetheless, at the moment, Mozilla is not able to correctly
        // handle the IDP extension and discards the CRL if it is critical.
        crlBuilder.addExtension(Extension.issuingDistributionPoint, crlDistributionPointOnCrlCritical, idp);

        X509CRL crl;
        final ContentSigner signer =
                new JcaContentSignerBuilder(sigAlg).setProvider("BC").build(privKey);
        final X509CRLHolder crlHolder = crlBuilder.build(signer);
        
        final CertificateList cl = crlHolder.toASN1Structure();

        // Verify before sending back
        crl = new X509CRLObject(cl);

        crl.verify(cacert.getPublicKey());

        return crl;
    }

    public static CRLDistPoint generateDistPointWithUrl(URL cdpUrl) {
        GeneralName gn = new GeneralName(GeneralName.uniformResourceIdentifier, new DERIA5String(cdpUrl.toExternalForm()));
        GeneralNames gns = new GeneralNames(gn);
        DistributionPointName dpn = new DistributionPointName(0, gns);
        return new CRLDistPoint(new DistributionPoint[]{new DistributionPoint(dpn, null, null)});
    }

    public static CRLDistPoint generateDistPointWithIssuer(String issuer) {
        GeneralName gn = new GeneralName(new X500Name(issuer));
        GeneralNames gns = new GeneralNames(gn);
        DistributionPointName dpn = new DistributionPointName(0, gns);
        return new CRLDistPoint(new DistributionPoint[]{new DistributionPoint(dpn, null, null)});
    }
}
