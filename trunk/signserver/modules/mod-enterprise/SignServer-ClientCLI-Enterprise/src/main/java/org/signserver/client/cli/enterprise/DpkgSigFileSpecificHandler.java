/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.client.cli.enterprise;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.encoders.Hex;
import org.signserver.client.cli.defaultimpl.AbstractFileSpecificHandler;
import org.signserver.client.cli.defaultimpl.InputSource;
import org.signserver.client.cli.defaultimpl.OutputCollector;
import org.signserver.common.CompileTimeSettings;
import org.signserver.common.IllegalRequestException;
import org.signserver.debiandpkgsig.ar.ArFileHeader;
import org.signserver.debiandpkgsig.ar.ParsedArFile;
import org.signserver.debiandpkgsig.utils.DebianDpkgSigUtils;

/**
 * Filespecific handler implementing the dpkg-sig format.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public class DpkgSigFileSpecificHandler extends AbstractFileSpecificHandler {
    private TwoPhasePGPContentSignerBuilder contentSignerBuilder;
    private final long keyId;
    private final byte[] fingerprint;
    private final int keyAlgorithm;
    private int hashDigestAlgorithm;
    private PGPSignatureSubpacketVector hashedSubpackets;
    private OutputStream os;
    private String manifest;

    public DpkgSigFileSpecificHandler(final File inFile,
                                      final File outFile,
                                      final long keyId,
                                      final byte[] fingerprint,
                                      final int keyAlgorithm) {
        super(inFile, outFile);
        this.keyId = keyId;
        this.fingerprint = fingerprint;
        this.keyAlgorithm = keyAlgorithm;
    }

    @Override
    public boolean isSignatureInputHash() {
        return true;
    }

    @Override
    public InputSource produceSignatureInput(String algorithm) throws NoSuchAlgorithmException, IOException, IllegalRequestException {
        if (algorithm == null) {
            throw new IllegalArgumentException("Algorithm must be provided");
        }

        hashDigestAlgorithm = OpenPGPFileHandlerUtils.getPGPAlgorithm(algorithm);
        os = closeLater(new FileOutputStream(getOutFile()));
        
        try (final InputStream is = new FileInputStream(getInFile())) {
            ParsedArFile arFile =
                    ParsedArFile.parseCopyAndHash(is, os, new AlgorithmIdentifier(CMSAlgorithm.MD5), new AlgorithmIdentifier(CMSAlgorithm.SHA1));

            // Setup the builders to be used now and later when generating final signature
            contentSignerBuilder =
                    new TwoPhasePGPContentSignerBuilder(keyAlgorithm,
                                                        hashDigestAlgorithm,
                                                        PGPSignature.CANONICAL_TEXT_DOCUMENT,
                                                        keyId);
            
            final PGPSignatureSubpacketGenerator subGenerator = new PGPSignatureSubpacketGenerator();
            subGenerator.setSignatureCreationTime(false, new Date());
            hashedSubpackets = subGenerator.generate();
            manifest = DebianDpkgSigUtils.createManifest(fingerprint, new Date(),
                                                         arFile);

            // Init signature generator (note: same way as in assemble)
            final PGPSignatureGenerator generator = createAndInitializeSignatureGenerator();
            final InputStream manifestInput =
                    new ByteArrayInputStream(manifest.getBytes(StandardCharsets.US_ASCII));

            OpenPGPFileHandlerUtils.hashClearText(generator, manifestInput);
                                                  
            // Finish the generation and get the digest
            generator.generate();
            final byte[] digest2 = contentSignerBuilder.getDigest();
            final byte[] encoded =
                    OpenPGPFileHandlerUtils.getEncoded(digest2, keyAlgorithm,
                                                       hashDigestAlgorithm);

            // create metadata map
            final Map<String, String> metadata = new HashMap<>();

            metadata.put("KEY_ID", Long.toHexString(keyId));
            metadata.put("KEY_ALGORITHM", Integer.toString(keyAlgorithm));
            metadata.put("KEY_FINGERPRINT", Hex.toHexString(fingerprint));

            // Return the signature input
            return new InputSource(new ByteArrayInputStream(encoded),
                                   encoded.length, null, metadata);
        } catch (OperatorCreationException | PGPException | SignatureException ex) {
            throw new IOException("Failed to hash input file: ", ex);
        }
    }

    @Override
    public void assemble(OutputCollector oc) throws IOException, IllegalArgumentException {
        final byte[] sigBytes = oc.toByteArray();

        try {
            // Init signature generator (note: same way as in produceSignatureOutput)
            final PGPSignatureGenerator generator = createAndInitializeSignatureGenerator();

            // Set fixed signature
            contentSignerBuilder.setFixedSignature(sigBytes);

            final ByteArrayOutputStream signedManifestOutput =
                    new ByteArrayOutputStream();
            final ArmoredOutputStream aOut =
                    new ArmoredOutputStream(signedManifestOutput);
            final InputStream manifestIn =
                    new ByteArrayInputStream(manifest.getBytes(StandardCharsets.US_ASCII));
            aOut.setHeader(ArmoredOutputStream.VERSION_HDR,
                                   CompileTimeSettings.getInstance().getProperty(CompileTimeSettings.SIGNSERVER_VERSION));
            OpenPGPFileHandlerUtils.processClearText(aOut, manifestIn,
                                                     hashDigestAlgorithm);
            
            try (final BCPGOutputStream bOut = new BCPGOutputStream(aOut)) {
                generator.generate().encode(bOut);
            }

            long currentTimeInSeconds = System.currentTimeMillis() / 1000;
            byte[] signedManifestBytes = signedManifestOutput.toByteArray();  
            
            // Create AR heaader
            ArFileHeader header = new ArFileHeader("_gpgbuilder", currentTimeInSeconds, 0, 0, 100644, signedManifestBytes.length);
            
            // Write AR header (to out)
            os.write(header.getEncoded());
            
            // Write signed manifest
            os.write(signedManifestBytes);

            // pad 2 byte aligned
            if (signedManifestBytes.length % 2 != 0) {
                os.write('\n');
            }
        } catch (PGPException | SignatureException e) {
            throw new IOException("Unable to assemble signature: " + e.getMessage(), e);
        }
    }

    @Override
    public String getFileTypeIdentifier() {
        return "DPKG_SIG";
    }

    private PGPSignatureGenerator createAndInitializeSignatureGenerator() throws PGPException {
        final PGPSignatureGenerator generator = new PGPSignatureGenerator(contentSignerBuilder);
        generator.setHashedSubpackets(hashedSubpackets);
        final PGPPrivateKey pgpPrivateKey = null;
        generator.init(PGPSignature.CANONICAL_TEXT_DOCUMENT, pgpPrivateKey);

        return generator;
    }
}
