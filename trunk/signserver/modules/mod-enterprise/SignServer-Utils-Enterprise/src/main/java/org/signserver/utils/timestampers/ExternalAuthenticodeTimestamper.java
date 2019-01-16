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
package org.signserver.utils.timestampers;

import java.io.IOException;
import net.jsign.DigestAlgorithm;
import net.jsign.asn1.authenticode.AuthenticodeTimeStampRequest;
import net.jsign.timestamp.AuthenticodeTimestamper;
import net.jsign.timestamp.TimestampingException;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.util.encoders.Base64;

/**
 * Implementation of the Timestamper interface using Authenticode® format
 * using an external TSA.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public class ExternalAuthenticodeTimestamper extends AuthenticodeTimestamper {

        private final String basicAuthorization;

        public ExternalAuthenticodeTimestamper(final String username,
                                               final String password) {
            if (username == null) {
                basicAuthorization = null;
            } else {
                final String usrAndPwd = username + ":" + password;
                basicAuthorization = Base64.toBase64String(usrAndPwd.getBytes());
            }
        }

        @Override
        protected CMSSignedData timestamp(DigestAlgorithm algo, byte[] encryptedDigest) throws IOException, TimestampingException {
            try {
                AuthenticodeTimeStampRequest timestampRequest = new AuthenticodeTimeStampRequest(encryptedDigest);
                
                byte[] request = Base64.encode(timestampRequest.getEncoded("DER"));
                
                return TimestampHelper.responseToAuthcodeTimestamp(TimestampHelper.fetchTimestampExternal(request, tsaurl, basicAuthorization,
                                                   "application/octet-stream",
                                                   "application/octet-stream"));
            } catch (CMSException ex) {
                throw new TimestampingException("Failed to timestamp", ex);
            }
        }
    }