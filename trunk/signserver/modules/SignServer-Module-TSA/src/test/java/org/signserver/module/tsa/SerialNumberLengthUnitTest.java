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
package org.signserver.module.tsa;

import java.math.BigInteger;

import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;

import junit.framework.TestCase;
import org.signserver.common.WorkerStatus;
import org.signserver.server.IServices;
import org.signserver.server.cryptotokens.ICryptoTokenV4;
import org.signserver.server.cryptotokens.NullCryptoToken;

/**
 * Unit test for the configurable serial number length feature in TimeStampSigner.
 * 
 * @author Marcus Lundblad
 * @version $Id$ 
 */
public class SerialNumberLengthUnitTest extends TestCase {

    private static final int SIGNER_ID_BASE = 10000;

	public SerialNumberLengthUnitTest(String testName) {
        super(testName);
    }
    
    @Override
    protected void setUp() throws Exception {
        super.setUp();
    }
    
    @Override
    protected void tearDown() throws Exception {
        super.tearDown();
    }
    
    private TimeStampSigner createTestSigner(int signerId, final String maxSerialNumberLength) {
    	final WorkerConfig config = new WorkerConfig();
        
        if (maxSerialNumberLength != null) {
        	config.setProperty(TimeStampSigner.MAXSERIALNUMBERLENGTH, maxSerialNumberLength);
        }
        
        // Mock away the crypto stuff as we only test the init() method
        TimeStampSigner signer = new TimeStampSigner() {
                @Override
                public ICryptoTokenV4 getCryptoToken(final IServices services) throws SignServerException {
                    return new NullCryptoToken(WorkerStatus.STATUS_ACTIVE);
                }
        };
        signer.init(signerId, config, null, null);
        
        return signer;
    }

    /**
     * Test the serial number max length functionality.
     * @param maxSerialNumberLength Set the max length, set to null to use the signer's default
     * @param expectedMax The expected max length
     */
    private void testSerialNumberLength(int signerId, final String maxSerialNumberLength, int expectedMax) {
        final TimeStampSigner signer = createTestSigner(signerId, maxSerialNumberLength);
        
        try {
            int numTooLong = 0;
            int numOfMaxLength = 0;
            int numNegative = 0;
                
            for (int i = 0; i < 20; i++) {
                final BigInteger serno = signer.getSerialNumber();
                    
                // we will strip off the sign, so we'll get one bit short of the max...
                if (serno.bitLength() > expectedMax * 8 - 1) {
                    numTooLong++;
                }
				
                if (serno.bitLength() == expectedMax * 8 - 1) {
                    numOfMaxLength++;
                }
                
                if (serno.signum() == -1) {
                    numNegative++;
                }
            }
            
            // check that no serial number was too long
            assertEquals("Serial number too long", 0, numTooLong);
            
            // check that at least one serial number was of max allowed range
            // (note: this test is expected to fail occasionally since this is random...)
            assertTrue("No serial number was of max length", numOfMaxLength > 0);
                
            // also, we should avoid generating negative serial numbers to avoid
            // ambiguities regarding hexadecimal encoding
            assertEquals("Serial number should not be negative", 0, numNegative);
        } catch (SignServerException ignored) {
            // NOPMD
        }
    }
	
    /**
     * Test that the default serial number length is within the bounds of a 64 bit integer.
     * @throws Exception
     */
    public void testDefaultSerialNumberLength() throws Exception {
        testSerialNumberLength(SIGNER_ID_BASE, null, 8);
    }
	
    /**
     * Test setting an explicit value.
     * 
     * @throws Exception
     */
    public void testExplicitSerialNumberLength() throws Exception {
        testSerialNumberLength(SIGNER_ID_BASE + 1, "16", 16);
    }
	
    /**
     * Test setting a too small value.
     * 
     * @throws Exception
     */
    public void testTooSmallSerialNumberLength() throws Exception {
        final TimeStampSigner signer = createTestSigner(SIGNER_ID_BASE + 2, "6");
        final String error = signer.getFatalErrors(null).toString();
		
        assertTrue("Expect error about serial number: " + error,
                error.contains("Maximum serial number length specified is too small: 6"));
    }
	
    /**
     * Test setting a too large value.
     * 
     * @throws Exception
     */
    public void testTooLargeSerialNumberLength() throws Exception {
        final TimeStampSigner signer = createTestSigner(SIGNER_ID_BASE + 3, "30");
        final String error = signer.getFatalErrors(null).toString();
        
        assertTrue("Expect error about serial number: " + error,
                error.contains("Maximum serial number length specified is too large: 30"));
    } 
	
    /**
     * Test setting a invalid (non-integer) value.
     * 
     * @throws Exception
     */
    public void testInvalidSerialNumberLength() throws Exception {
        final TimeStampSigner signer = createTestSigner(SIGNER_ID_BASE + 4, "foobar");
        final String error = signer.getFatalErrors(null).toString();
        
        assertTrue("Expect error about serial number: " + error,
                error.contains("Maximum serial number length specified is invalid: \"foobar\""));
    }
}
