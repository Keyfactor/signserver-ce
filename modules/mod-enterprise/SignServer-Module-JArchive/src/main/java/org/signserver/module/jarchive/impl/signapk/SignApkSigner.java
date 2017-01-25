/**
 * ***********************************************************************
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
 ************************************************************************
 */
package org.signserver.module.jarchive.impl.signapk;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.Attribute;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.operator.OperatorCreationException;
import org.signserver.common.CompileTimeSettings;
import org.signserver.common.SignServerException;

/**
 * Signer implementation using the SignApk as backend.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public abstract class SignApkSigner {

    private final PrivateKey privateKey;
    private final X509Certificate[] certificateChain;
    private final Provider provider;
    private final String signatureAlgorithm;
    private final String digestAlgorithm;
    private final boolean timeStamp;
    private final boolean zipAlign;
    private final boolean keepSignatures;
    private final boolean replaceSignature;
    private final String signatureName;
    private final ASN1ObjectIdentifier reqPolicy;

    /** Value to use in the created-by headers. */
    private static final String CREATED_BY = CompileTimeSettings.getInstance().getProperty(CompileTimeSettings.SIGNSERVER_VERSION);

    public SignApkSigner(PrivateKey privateKey, X509Certificate[] certificateChain, Provider provider, String signatureAlgorithm, String digestAlgorithm, boolean timeStamp, boolean zipAlign, boolean keepSignatures, boolean replaceSignature, String signatureName, ASN1ObjectIdentifier reqPolicy) {
        this.privateKey = privateKey;
        this.certificateChain = certificateChain;
        this.provider = provider;
        this.signatureAlgorithm = signatureAlgorithm;
        this.digestAlgorithm = digestAlgorithm;
        this.timeStamp = timeStamp;
        this.zipAlign = zipAlign;
        this.keepSignatures = keepSignatures;
        this.replaceSignature = replaceSignature;
        this.signatureName = signatureName;
        this.reqPolicy = reqPolicy;
    }

    public void sign(final File input, final File output) throws GeneralSecurityException, IOException, OperatorCreationException, CMSException {

        final SignApk.TimeStampingProvider timeStamping;

        if (timeStamp) {
            timeStamping = new SignApk.TimeStampingProvider() {
                @Override
                public CMSSignedData timestamp(CMSSignedData cms) throws IOException {
                    for (SignerInformation si : (Collection<SignerInformation>) cms.getSignerInfos().getSigners()) {
                        try {
                            MessageDigest md = MessageDigest.getInstance("SHA1"); // TODO: Future: Make this configurable
                            byte[] imprint = md.digest(si.getSignature());

                            try {
                                byte[] token = SignApkSigner.this.timestamp(imprint, CMSAlgorithm.SHA1, reqPolicy);

                                ASN1Primitive obj = new ASN1InputStream(token).readObject();
                                Attribute a = new Attribute(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken, new DERSet(obj));
                                ASN1EncodableVector dv = new ASN1EncodableVector();
                                dv.add(a);
                                AttributeTable at = new AttributeTable(dv);
                                si = SignerInformation.replaceUnsignedAttributes(si, at);

                                Collection<SignerInformation> ss = new CMSSignedData(token).getSignerInfos().getSigners();
                                ss.clear();
                                ss.add(si);
                                SignerInformationStore sis = new SignerInformationStore(ss);

                                cms = CMSSignedData.replaceSigners(cms, sis);
                            } catch (SignServerException | CMSException ex) {
                                throw new IOException(ex);
                            }
                        } catch (NoSuchAlgorithmException ex) {
                            throw new IOException(ex);
                        }
                    }
                    return cms;
                }
            };
        } else {
            timeStamping = null;
        }

        final boolean signWholeFile = false;
        final int alignment = zipAlign ? 4 : 0;

        JarFile inputJar = null;
        FileOutputStream outputFile = null;
        try {
            // TODO: Future: Make optional:
            // Set the ZIP file timestamp to the starting valid time
            // of the 0th certificate plus one hour (to match what
            // we've historically done).
            long timestamp = certificateChain[0].getNotBefore().getTime() + 3600L * 1000;

            inputJar = new JarFile(input, false);  // Don't verify.
            outputFile = new FileOutputStream(output);
            if (signWholeFile) {
                SignApk.signWholeFile(inputJar, /*publicKeyFile*/ null,
                        certificateChain, privateKey, provider, outputFile, signatureAlgorithm, digestAlgorithm, timeStamping, keepSignatures, replaceSignature, signatureName, CREATED_BY);
            } else {
                // For signing .apks, use the maximum compression to make
                // them as small as possible (since they live forever on
                // the system partition).  For OTA packages, use the
                // default compression level, which is much much faster
                // and produces output that is only a tiny bit larger
                // (~0.1% on full OTA packages I tested).
                try (JarOutputStream outputJar = new JarOutputStream(outputFile)) {
                    // For signing .apks, use the maximum compression to make
                    // them as small as possible (since they live forever on
                    // the system partition).  For OTA packages, use the
                    // default compression level, which is much much faster
                    // and produces output that is only a tiny bit larger
                    // (~0.1% on full OTA packages I tested).
                    outputJar.setLevel(9);
                    Manifest manifest = SignApk.addDigestsToManifest(inputJar, Arrays.asList(digestAlgorithm), CREATED_BY);
                    SignApk.copyFiles(manifest, inputJar, outputJar, timestamp, alignment, keepSignatures, replaceSignature, signatureName);
                    SignApk.signFile(manifest, inputJar, new X509Certificate[][]{certificateChain}, new PrivateKey[]{privateKey}, provider, outputJar, signatureAlgorithm, digestAlgorithm, timeStamping, keepSignatures, signatureName, CREATED_BY);
                }
            }
        } finally {
            if (inputJar != null) {
                try {
                    inputJar.close();
                } catch (IOException ignored) {} // NOPMD
            }   
            if (outputFile != null) {
                try {
                    outputFile.close();
                } catch (IOException ignored) {} // NOPMD
            }
        }
    }

    protected abstract byte[] timestamp(byte[] imprint, ASN1ObjectIdentifier digestAlgorithm, ASN1ObjectIdentifier reqPolicy) throws IOException, SignServerException;

}
