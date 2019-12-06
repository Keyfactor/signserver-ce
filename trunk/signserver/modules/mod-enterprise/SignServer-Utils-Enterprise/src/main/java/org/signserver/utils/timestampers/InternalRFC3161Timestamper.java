/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.utils.timestampers;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Collection;
import net.jsign.DigestAlgorithm;
import net.jsign.timestamp.RFC3161Timestamper;
import net.jsign.timestamp.TimestampingException;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.SignServerException;
import org.signserver.ejb.interfaces.InternalProcessSessionLocal;
import org.signserver.server.data.impl.UploadConfig;

/**
 * Implementation of the Timestamper interface using RFC#3161 format timestamps
 * using an internal SignServer TimeStamp signer
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public abstract class InternalRFC3161Timestamper extends RFC3161Timestamper {

        private final String workerNameOrId;
        private final ASN1ObjectIdentifier policy;
        private final String username;
        private final String password;
        private final InternalProcessSessionLocal workerSession;

        private final File fileRepository = new UploadConfig().getRepository();
        private final boolean useStandardCMS;

        public InternalRFC3161Timestamper(final String tsaWorkerNameOrId,
                                          final ASN1ObjectIdentifier policy,
                                          final String username,
                                          final String password,
                                          final InternalProcessSessionLocal workerSession) {
            this(tsaWorkerNameOrId, policy, username, password, false, workerSession);
        }
        
        public InternalRFC3161Timestamper(final String tsaWorkerNameOrId,
                                          final ASN1ObjectIdentifier policy,
                                          final String username,
                                          final String password,
                                          final boolean useStandardCMS,
                                          final InternalProcessSessionLocal workerSession) {
            this.workerNameOrId = tsaWorkerNameOrId;
            this.policy = policy;
            this.username = username;
            this.password = password;
            this.workerSession = workerSession;
            this.useStandardCMS = useStandardCMS;
        }
        
        @Override
        protected CMSSignedData timestamp(DigestAlgorithm algo, byte[] encryptedDigest) throws IOException, TimestampingException {
            TimeStampRequestGenerator reqgen = new TimeStampRequestGenerator();
            BigInteger nonce = BigInteger.valueOf(System.currentTimeMillis());
            reqgen.setCertReq(true);
            if (policy != null) {
                reqgen.setReqPolicy(policy);
            }
            TimeStampRequest req = reqgen.generate(algo.oid, algo.getMessageDigest().digest(encryptedDigest), nonce);
            byte request[] = req.getEncoded();

            try {
                return TimestampHelper.responseToRFCTimestamp(TimestampHelper.fetchTimestampInternal(request, workerNameOrId, username,
                        password, hashCode(), workerSession,
                        fileRepository), req);
            } catch (TSPException | IllegalRequestException |
                     CryptoTokenOfflineException | SignServerException ex) {
                throw new TimestampingException("Failed to timestamp", ex);
            }
        }

    @Override
    protected CMSSignedData modifySignedData(CMSSignedData sigData,
                                             AttributeTable unsignedAttributes,
                                             Collection<X509CertificateHolder> extraCertificates)
            throws IOException, CMSException {
        if (useStandardCMS) {
            return TimestampHelper.addCounterSignatureForTimestamp(sigData, unsignedAttributes);
        } else {
            return super.modifySignedData(sigData, unsignedAttributes,
                                          extraCertificates);
        }
    }
}