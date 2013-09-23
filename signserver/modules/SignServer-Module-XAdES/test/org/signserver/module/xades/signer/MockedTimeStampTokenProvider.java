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
import java.util.Arrays;
import java.util.Date;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Sequence;
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

    /**
     * Hard-coded test response data.
     */
    private static final String RESPONSE_DATA =
            "MIIC/zADAgEAMIIC9gYJKoZIhvcNAQcCoIIC5zCCAuMCAQMxCzAJBgUrDgMCGgUAMF4GCyqGSIb3"
            +"DQEJEAEEoE8ETTBLAgEBBgIqAzAhMAkGBSsOAwIaBQAEFDswPYsDZNkmXAatyFhCWDdhUMm1Agg9"
            +"FeNulOms3hgPMjAxMzA5MjAxNDIyMzdaAgQ+QpWvMYICbzCCAmsCAQEwWTBNMRcwFQYDVQQDDA5E"
            +"U1MgUm9vdCBDQSAxMDEQMA4GA1UECwwHVGVzdGluZzETMBEGA1UECgwKU2lnblNlcnZlcjELMAkG"
            +"A1UEBhMCU0UCCHgrwEuTsACbMAkGBSsOAwIaBQCggewwGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJ"
            +"EAEEMBwGCSqGSIb3DQEJBTEPFw0xMzA5MjAxNDIyMzdaMCMGCSqGSIb3DQEJBDEWBBTdWQ0n7S4K"
            +"EpN4P4JvrnoG3TmUYzCBigYLKoZIhvcNAQkQAgwxezB5MHcwdQQU7xjPEDzrgId/sLPCqZTAjilQ"
            +"sd0wXTBRpE8wTTEXMBUGA1UEAwwORFNTIFJvb3QgQ0EgMTAxEDAOBgNVBAsMB1Rlc3RpbmcxEzAR"
            +"BgNVBAoMClNpZ25TZXJ2ZXIxCzAJBgNVBAYTAlNFAgh4K8BLk7AAmzANBgkqhkiG9w0BAQEFAASC"
            +"AQAdHq/qeqr3G7K4IyXggVA1LJ6/muO+vw9+SY5EAr74tY8QcV1Te8qzAEMXHeO7CkBVUfwFsh3Q"
            +"6MF2Qxy/K1C4DZZRJeH2ZR9gigVYD+rvIJGgGel8KQuPNmE132wahcZUgpOWi4rgRq5NMKBlph9N"
            +"BX2tSPos2RLoE6yx6+Xf1G6pTlRy/Qd+U8c/C+6EDFkXzQ13bv025LsBeXyI0pfKGk+M/MC5rtHb"
            +"o1QIXSMFA8QwJmvtRXk6+O3O+w4G9Qw5ilSqqJLRRYnmWEbB5e56TIe1k1q9js7nVvYEQxnvgSIX"
            +"tAxt4qXoC+4i8c7XWtNJj4OciFesAWZmiJpWoNC7";
    
    /**
     * Hard-coded test time stamp.
     */
    public static final long TIMESTAMP = 1379686957;
    
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
        
        final ASN1Sequence data = ASN1Sequence.getInstance(Base64.decode(RESPONSE_DATA));
        final ASN1Encodable token = data.getObjectAt(1);
        
        try {
            final TimeStampTokenRes res = new TimeStampTokenRes(token.toASN1Primitive().getEncoded(), new Date(TIMESTAMP));
            requestedTimeStampToken = true;
            return res;
        } catch (IOException e) {
            throw new TimeStampTokenGenerationException(e.getMessage(), e);
        }
    }
    
    /**
     * Mocked XADES4J time stamp verification provider just checking the token against the "canned" token provided by
     * the mocked tokem provider.
     */
    public static class MockedTimeStampVerificationProvider implements TimeStampVerificationProvider {

        @Override
        public Date verifyToken(byte[] token, byte[] tsDigest)
                throws TimeStampTokenVerificationException {
            final ASN1Sequence data = ASN1Sequence.getInstance(Base64.decode(RESPONSE_DATA));
            final ASN1Encodable expToken = data.getObjectAt(1);
            
            try {
                if (Arrays.equals(token, expToken.toASN1Primitive().getEncoded())) {
                    performedTimeStampVerification = true;
                    return new Date(TIMESTAMP);
                } else {
                    throw new TimeStampTokenVerificationException("Unexpected time stamp token");
                }
            } catch (IOException e) {
                throw new TimeStampTokenVerificationException("Malformed time stamp token");
            }
        }
        
    }

}
