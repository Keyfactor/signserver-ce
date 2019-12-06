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

import java.io.IOException;
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
import org.bouncycastle.util.encoders.Base64;

/**
 * Implementation of the Timestamper interface using RFC#3161 timestamps
 * using an external TSA.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public abstract class ExternalRFC3161Timestamper extends RFC3161Timestamper {
        private final String basicAuthorization;
        private final boolean useStandardCMS;
        private final ASN1ObjectIdentifier policy;

        public ExternalRFC3161Timestamper(final ASN1ObjectIdentifier policy, final String username,
                                          final String password) {
            this(policy, username, password, false);
        }

        public ExternalRFC3161Timestamper(final ASN1ObjectIdentifier policy, 
                                          final String username,
                                          final String password,
                                          final boolean useStandardCMS) {
            this.policy = policy;
            if (username == null) {
                basicAuthorization = null;
            } else {
                final String usrAndPwd = username + ":" + password;
                basicAuthorization = Base64.toBase64String(usrAndPwd.getBytes());
            }
            this.useStandardCMS = useStandardCMS;
            this.setRetries(1);
            this.setRetryWait(0);
        }
        
        @Override
        protected CMSSignedData timestamp(DigestAlgorithm algo, byte[] encryptedDigest) throws IOException, TimestampingException {
            try {
                TimeStampRequestGenerator reqgen = new TimeStampRequestGenerator();
                reqgen.setCertReq(true);
                if (policy != null) {
                    reqgen.setReqPolicy(policy);
                }
                TimeStampRequest req = reqgen.generate(algo.oid, algo.getMessageDigest().digest(encryptedDigest));
                byte request[] = req.getEncoded();
                
                return TimestampHelper.responseToRFCTimestamp(TimestampHelper.fetchTimestampExternal(request, tsaurl, basicAuthorization,
                                                                     "application/timestamp-query",
                                                                     "application/timestamp-reply"),
                                              req);
            } catch (TSPException | CMSException ex) {
                throw new TimestampingException("Failed to timestamp", ex);
            }
        }

    @Override
    protected CMSSignedData modifySignedData(CMSSignedData sigData, AttributeTable unsignedAttributes, Collection<X509CertificateHolder> extraCertificates) throws IOException, CMSException {
        if (useStandardCMS) {
            return TimestampHelper.addCounterSignatureForTimestamp(sigData, unsignedAttributes);
        } else {
            return super.modifySignedData(sigData, unsignedAttributes, 
                                          extraCertificates);
        }
    }
}
