/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.module.ades.signer;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.TimestampBinary;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.SignServerException;
import org.signserver.ejb.interfaces.InternalProcessSessionLocal;
import org.signserver.ejb.interfaces.ProcessSessionLocal;
import org.signserver.server.data.impl.UploadConfig;
import org.signserver.utils.timestampers.TimestampHelper;

/**
 * TSPSource implementing an internal connection to a TimeStampSigner
 * in SignServer.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public class InternalTSPSource implements TSPSource {

    private final String workerNameOrId;
    private final String username;
    private final String password;

    private final InternalProcessSessionLocal workerSession;

    private final File fileRepository = new UploadConfig().getRepository();
    
    public InternalTSPSource(final String workerNameOrId,
                             final String username,
                             final String password,
                             final InternalProcessSessionLocal workerSession) {
        this.workerNameOrId = workerNameOrId;
        this.username = username;
        this.password = password;
        this.workerSession = workerSession;
    }
            
    @Override
    public TimestampBinary getTimeStampResponse(final DigestAlgorithm da,
                                                final byte[] digest)
            throws DSSException {
        TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
        BigInteger nonce = BigInteger.valueOf(System.currentTimeMillis());
        reqGen.setCertReq(true);
        try {
            final TimeStampRequest req =
                reqGen.generate(new ASN1ObjectIdentifier(da.getOid()),
                                digest,
                                nonce);
            final byte[] request = req.getEncoded();

            final CMSSignedData cms =
                    TimestampHelper.responseToRFCTimestamp(TimestampHelper.fetchTimestampInternal(request,
                                                           workerNameOrId,
                                                           username,
                                                           password, hashCode(),
                                                           workerSession,
                                                           fileRepository), req);
            return new TimestampBinary(cms.getEncoded());
        } catch (IOException | IllegalRequestException | 
                CryptoTokenOfflineException | SignServerException |
                TSPException ex) {
            throw new DSSException("Failed to timestamp", ex);
        }
    }
    
}
