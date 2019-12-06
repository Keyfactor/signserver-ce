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

import java.io.IOException;
import java.io.OutputStream;
import java.security.SecureRandom;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.operator.PGPContentSigner;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.util.encoders.Hex;

/**
 * PGPContentSignerBuilder that can be used in two phases so that the signature
 * input creation is done first and then the same builder is used a second time
 * but with a fixed signature and the final signature can be obtained.
 *
 * Phase 1:
 * - The content is feed and the digest calculated.
 * - A dummy signature (0000...) is used.
 * - Call to generate produces the final digest
 * 
 * Phase 2:
 * - No content should be feed.
 * - Set the fixed signature to use.
 * - Call to generate produces the final output.
 * 
 * @author Markus Kilås
 * @version $Id$
 */
public class TwoPhasePGPContentSignerBuilder implements PGPContentSignerBuilder {

    /**
     * Logger for this class.
     */
    private static final Logger LOG = Logger.getLogger(TwoPhasePGPContentSignerBuilder.class);

    private final BcPGPDigestCalculatorProvider digestCalculatorProvider = new BcPGPDigestCalculatorProvider();
    private final PGPContentSigner contentSigner;
    private final PGPDigestCalculator digestCalculator;
    private byte[] fixedSignature;
    private SecureRandom random;

    public TwoPhasePGPContentSignerBuilder(int keyAlgorithm, int hashAlgorithm, int signatureType, long keyID) throws PGPException {
        this.digestCalculator = digestCalculatorProvider.get(hashAlgorithm);
        this.contentSigner = new PGPContentSigner() {

            private byte[] digest;

            @Override
            public int getType() {
                return signatureType;
            }

            @Override
            public int getHashAlgorithm() {
                return hashAlgorithm;
            }

            @Override
            public int getKeyAlgorithm() {
                return keyAlgorithm;
            }

            @Override
            public long getKeyID() {
                return keyID;
            }

            @Override
            public OutputStream getOutputStream() {
                return digestCalculator.getOutputStream();
            }

            @Override
            public byte[] getSignature() {
                byte[] result = getFixedSignature();
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Signature: " + Hex.toHexString(result));
                }
                return result;
            }

            @Override
            public byte[] getDigest() {
                if (digest == null) {
                    digest = digestCalculator.getDigest();
                }
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Digest: " + Hex.toHexString(digest));
                }
                return digest;
            }
        };
    }

    public TwoPhasePGPContentSignerBuilder setSecureRandom(SecureRandom random) {
        this.random = random;

        return this;
    }

    public byte[] getFixedSignature() {
        if (fixedSignature == null) {
            final ASN1Sequence seq;
            
            seq = new DERSequence(new ASN1Encodable[] {new ASN1Integer(1L),
                                                       new ASN1Integer(1L)});

            try {
                fixedSignature = seq.getEncoded();
            } catch (IOException e) {
                // this should not happen…
                throw new RuntimeException(e);
            }
        }
        return fixedSignature;
    }

    public void setFixedSignature(byte[] fixedSignature) {
        this.fixedSignature = fixedSignature;
    }
    
    public byte[] getDigest() {
        return contentSigner.getDigest();
    }

    @Override
    public PGPContentSigner build(int signatureType, PGPPrivateKey privateKey) throws PGPException {
        return contentSigner;
    }

}
