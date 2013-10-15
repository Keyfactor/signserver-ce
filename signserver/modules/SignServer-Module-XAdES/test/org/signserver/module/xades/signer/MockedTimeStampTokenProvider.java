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
package org.signserver.module.xades.signer;

import java.io.IOException;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.Date;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.encoders.Base64;


import xades4j.providers.TimeStampTokenGenerationException;
import xades4j.providers.TimeStampTokenProvider;
import xades4j.providers.TimeStampTokenVerificationException;
import xades4j.providers.TimeStampVerificationProvider;

/**
 * Mocked XADES4J TimeStampTokenProvider used for testing the XAdESSigner.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 *
 */
public class MockedTimeStampTokenProvider implements TimeStampTokenProvider {

    /** Logger for this class. */
    private static Logger LOG = Logger.getLogger(MockedTimeStampTokenProvider.class);
    
    /**
     * Hard-coded test response data.
     */
    private static final String RESPONSE_DATA =
            "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";
  
    /**
     * Hard-coded test time stamp.
     */
    public static final long TIMESTAMP = 1379686957;
    
    private static Date overrideTimestamp = null;
    
    /**
     * Counters of performed timestamps and verifications.
     */
    private static boolean requestedTimeStampToken;
    private static boolean performedTimeStampVerification;

    /**
     * Resets the mock timestamp and verification counters.
     */
    public static void reset() {
        requestedTimeStampToken = false;
        performedTimeStampVerification = false;
        overrideTimestamp = null;
    }
    
    public static void overrideTimestamp(final Date timestamp) {
        overrideTimestamp = timestamp;
    }
    
    /**
     * Check if a time stamp token has been requested (since resetting).
     * 
     * @return True if a token has been requested.
     */
    public static boolean hasRequestedTimeStampToken() {
        return requestedTimeStampToken;
    }
    
    /**
     * Check if time stamp verification has been performed (since resetting).
     * 
     * @return True if a token has been requested to be verified.
     */
    public static boolean hasPerformedTimeStampVerification() {
        return performedTimeStampVerification;
    }
    
    @Override
    public TimeStampTokenRes getTimeStampToken(byte[] dummy, String arg1)
            throws TimeStampTokenGenerationException {
        
        /*
        final ASN1Sequence data = ASN1Sequence.getInstance(Base64.decode(RESPONSE_DATA));
        final ASN1Encodable token = data.getObjectAt(1);
        */
        
        /*
        try {
            TODO: implement overridable tampering...
            final TimeStampToken tst = new TimeStampToken(ContentInfo.getInstance(token));
            
            if (overrideTimestamp != null) {
                tst.getTimeStampInfo().getGenTime().setTime(overrideTimestamp.getTime());
            }
            
            final TimeStampTokenRes res = new TimeStampTokenRes(tst.getEncoded(),
                    new Date(overrideTimestamp != null ? overrideTimestamp.getTime() : TIMESTAMP));
            */
        final TimeStampTokenRes res = new TimeStampTokenRes(Base64.decode(RESPONSE_DATA), new Date(TIMESTAMP));

        requestedTimeStampToken = true;
        return res;
    }
    
    /**
     * Mocked XADES4J time stamp verification provider just checking the token against the "canned" token provided by
     * the mocked tokem provider.
     */
    public static class MockedTimeStampVerificationProvider implements TimeStampVerificationProvider {

        @Override
        public Date verifyToken(byte[] token, byte[] tsDigest)
                throws TimeStampTokenVerificationException {            
            LOG.info("Verifying mocked time stamp token");

            if (Arrays.equals(token, Base64.decode(RESPONSE_DATA))) {
                performedTimeStampVerification = true;
                LOG.info("requested token matched expected");
                return new Date(TIMESTAMP);
            } else {
                LOG.info("requested token doesn't match expected");
                throw new TimeStampTokenVerificationException("Unexpected time stamp token");
            }
        }
        
    }

}
