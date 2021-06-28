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
import net.jsign.DigestAlgorithm;
import net.jsign.asn1.authenticode.AuthenticodeTimeStampRequest;
import net.jsign.timestamp.AuthenticodeTimestamper;
import net.jsign.timestamp.TimestampingException;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.util.encoders.Base64;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.SignServerException;
import org.signserver.ejb.interfaces.InternalProcessSessionLocal;
import org.signserver.server.data.impl.UploadConfig;

/**
 * Implementation of the Timestamper interface using Authenticode® format
 * using an internal SignServer TimeStamp signer.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public class InternalAuthenticodeTimestamper extends AuthenticodeTimestamper {

        private final String workerNameOrId;
        private final String username;
        private final String password;
        private final InternalProcessSessionLocal workerSession;
        
        private final File fileRepository = new UploadConfig().getRepository();
      
        public InternalAuthenticodeTimestamper(final String tsaWorkerNameOrId,
                                               final String username,
                                               final String password,
                                               final InternalProcessSessionLocal workerSession) {
            this.workerNameOrId = tsaWorkerNameOrId;
            this.username = username;
            this.password = password;
            this.workerSession = workerSession;
        }
        
        
        @Override
        protected CMSSignedData timestamp(DigestAlgorithm algo, byte[] encryptedDigest) throws IOException, TimestampingException {
            AuthenticodeTimeStampRequest timestampRequest = new AuthenticodeTimeStampRequest(encryptedDigest);
            byte[] request = Base64.encode(timestampRequest.getEncoded("DER"));
            
            try {
                return TimestampHelper.responseToAuthcodeTimestamp(TimestampHelper.fetchTimestampInternal(request, workerNameOrId, username,
                                          password, hashCode(), workerSession,
                                          fileRepository));
            } catch (CMSException | IllegalRequestException |
                     CryptoTokenOfflineException | SignServerException ex) {
                throw new TimestampingException("Failed to timestamp", ex);
            }
        }
    }