/**
 * **********************************************************************
 * *
 * SignServer: The OpenSource Automated Signing Server                  *
 * *
 * This software is free software; you can redistribute it and/or       *
 * modify it under the terms of the GNU Lesser General Public           *
 * License as published by the Free Software Foundation; either         *
 * version 2.1 of the License, or any later version.                    *
 * *
 * See terms of license at gnu.org.                                     *
 * *
 * ***********************************************************************
 */
package org.signserver.pq.verifier;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertStore;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import org.apache.commons.io.FileUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSProcessableFile;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Selector;
import org.bouncycastle.util.Store;

/**
 *
 *
 * @version $Id: ClientWSWithSignedRequestSampleApp.java 13026 2021-11-16
 * 19:20:43Z netmackan $
 */
public class VerifierApp {

    private static final Logger LOG = Logger.getLogger(VerifierApp.class);

    public static void main(String[] args) throws Exception {

        if (args.length < 4 || !"cms".equalsIgnoreCase(args[0])) {
            System.err.println("USAGE: VerifierApp cms [content.bin.p7s] [content.bin] [trust-dir]");
            System.exit(1);
            return;
        }

        LOG.debug("VerifierApp");

        Security.addProvider(new BouncyCastleProvider());

        final File signatureFile = new File(args[1]);
        if (!signatureFile.exists()) {
            System.err.println("No such signature file: " + signatureFile.getAbsolutePath());
            System.exit(1);
            return;
        }

        final File contentFile = new File(args[2]);
        if (!contentFile.exists()) {
            System.err.println("No such content file: " + contentFile.getAbsolutePath());
            System.exit(1);
            return;
        }

        final File trustDir = new File(args[3]);
        if (!trustDir.exists() || !trustDir.isDirectory()) {
            System.err.println("No such trust directory: " + trustDir.getAbsolutePath());
            System.exit(1);
            return;
        }

        // Load trusted keys and certificates
        Set<TrustAnchor> trustAnchors = new HashSet<>();
        CertificateFactory cf = CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);
        for (File file : trustDir.listFiles((File f) -> f.getName().endsWith(".crt") || f.getName().endsWith(".cer"))) {
            try (BufferedInputStream in = new BufferedInputStream(new FileInputStream(file))) {
                trustAnchors.add(new TrustAnchor((X509Certificate) cf.generateCertificate(in), null));
                System.out.println("Added " + file.getName() + " as trust anchor");
            }
        }

        byte[] signedBytes = FileUtils.readFileToByteArray(signatureFile);

        final CMSSignedData signedData = new CMSSignedData(new CMSProcessableFile(contentFile), signedBytes);

        int verified = 0;

        Store<X509CertificateHolder> certStore = signedData.getCertificates();
        SignerInformationStore signers = signedData.getSignerInfos();
        Collection<SignerInformation> c = signers.getSigners();
        Iterator<SignerInformation> it = c.iterator();

        X509Certificate validatedSigner = null;

        while (it.hasNext()) {
            SignerInformation signer = it.next();
            Collection certCollection = certStore.getMatches(signer.getSID());

            Iterator certIt = certCollection.iterator();
            X509CertificateHolder cert = (X509CertificateHolder) certIt.next();

            X509Certificate xcert = new JcaX509CertificateConverter().getCertificate(cert);
            System.out.println("Verifying signer " + xcert.getSubjectX500Principal());

            PublicKey publicKey = xcert.getPublicKey();

            System.out.println("alg: " + signer.getEncryptionAlgOID());

            // hardcoded, assume SPHICS+
            if ("1.3.6.1.4.1.22554.2.5".equals(signer.getEncryptionAlgOID()) &&
                    signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(publicKey))) {
                verified++;
                System.out.println("Verified");

                X509CertSelector certSelector = new X509CertSelector();
                certSelector.setCertificate(xcert);

                CertStore xcertStore = CertStore.getInstance("Collection",
                        new CollectionCertStoreParameters(certStore.getMatches(new Selector<X509CertificateHolder>() {
                            @Override
                            public boolean match(X509CertificateHolder arg0) {
                                return true;
                            }

                            @Override
                            public Object clone() {
                                return this;
                            }
                        })));

                try {
                    validatedSigner = validate(xcertStore, certSelector, trustAnchors, false);
                    if (validatedSigner != null) {
                        break;
                    }
                } catch (Exception ex) {
                    System.out.println("Error: " + ex.getMessage());
                }
            } else {
                System.out.println("Did not verify");
            }
        }

        if (validatedSigner == null) {
            System.out.println("No valid and trusted signature found");
            System.exit(-1);
        } else {
            System.out.println("Valid trusted signature using " + validatedSigner.getSigAlgName() + " from " + validatedSigner.getSubjectDN());
            System.exit(0);
        }
    }

    private static X509Certificate validate(CertStore certStore, X509CertSelector certSelector, Set<TrustAnchor> trustAnchors, boolean revocationEnabled) throws CertificateException, CertPathValidatorException, InvalidAlgorithmParameterException, Exception {


        PKIXBuilderParameters builderParams;
        builderParams = new PKIXBuilderParameters(trustAnchors, certSelector);


        PKIXCertPathBuilderResult builderRes;
        //CertPath certPath;
        try {
            CertPathBuilder builder = CertPathBuilder.getInstance("PKIX", "BC");
            /*if (otherCerts != null)
            {
                CollectionCertStoreParameters ccsp = new CollectionCertStoreParameters(otherCerts);
                CertStore othersCertStore = CertStore.getInstance("Collection", ccsp);
                builderParams.addCertStore(othersCertStore);
            }*/
            // - The external certificates/CRLs.
            /*for (int i = 0; i < intermCertsAndCrls.length; i++)
            {
                builderParams.addCertStore(intermCertsAndCrls[i]);
            }*/
            builderParams.addCertStore(certStore);

            builderParams.setRevocationEnabled(false);
            //builderParams.setMaxPathLength(maxPathLength);
            builderParams.setDate(new Date());
            builderParams.setSigProvider("BC");

            builderRes = (PKIXCertPathBuilderResult) builder.build(builderParams);
        } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException | NoSuchProviderException |
                 CertPathBuilderException e) {
            System.out.println("Exception on preparing parameters for validation: " + e.getMessage());
            throw new Exception(e.toString(), e);
        }

        List<X509Certificate> certPath = (List<X509Certificate>) builderRes.getCertPath().getCertificates();
        // - Create a new list since the previous is immutable.
        certPath = new ArrayList<>(certPath);
        // - Add the trust anchor certificate.
        X509Certificate rootCert = builderRes.getTrustAnchor().getTrustedCert();
        certPath.add(rootCert);

        //// Building path done

        PKIXParameters params;
        CertPathValidator validator;
        try {
            validator = CertPathValidator.getInstance("PKIX", "BC");
            params = new PKIXParameters(trustAnchors);
            params.addCertStore(certStore);
            params.setDate(new Date());
            params.setRevocationEnabled(false); // We do revocation checking our selves
        } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException | NoSuchProviderException e) {
            System.out.println("Exception on preparing parameters for validation: " + e.getMessage());
            throw new Exception(e.toString(), e);
        }

        // Do the validation
        PKIXCertPathValidatorResult result = (PKIXCertPathValidatorResult) validator.validate(builderRes.getCertPath(), params);

        X509Certificate signerCert = certPath.get(0);

        if (!result.getPublicKey().equals(signerCert.getPublicKey())) {
            throw new Exception("Unexpected difference in public keys"); // Should not happen
        }

        return signerCert;

    }

    public static byte[] hash(String value) throws NoSuchAlgorithmException,
            NoSuchProviderException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return md.digest(value == null ? new byte[0]
                : value.getBytes(StandardCharsets.UTF_8));
    }

}
