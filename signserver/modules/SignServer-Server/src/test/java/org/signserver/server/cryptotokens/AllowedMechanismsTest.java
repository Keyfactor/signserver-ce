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
package org.signserver.server.cryptotokens;

import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * Unit tests for AllowedMechanisms class.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class AllowedMechanismsTest {
    
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(AllowedMechanismsTest.class);

    /**
     * Tests parsing of hex and decimal values with some different delimiters.
     */
    @Test
    public void testParseHexAndDecimal() {
        LOG.info(">testParseHexAndDecimal");
        String allowedMechanismsProperty = " 0x00000040, 0x00000000 0x00000250;0x252 ,624 0x81234567"; // Note: leading whitespace, mix or space and comma and semicolon is intentional
        Long[] expected = new Long[] { 0x40l, 0l, 0x250l, 0x252l, 624l, 0x81234567L };
        
        AllowedMechanisms result = AllowedMechanisms.parse(allowedMechanismsProperty);
        assertArrayEquals(expected, result.toLongArray());
    }
    
    /**
     * Tests parsing of hex, decimal and constant name values.
     */
    @Test
    public void testParseHexAndDecimalAndConstant() {
        LOG.info(">testParseHexAndDecimalAndConstant");
        String allowedMechanismsProperty = " CKM_SHA256_RSA_PKCS, 0x00000000 CKM_SHA256;CKM_SHA256_HMAC_GENERAL ,624 0x81234567"; // Note: leading whitespace, mix or space and comma and semicolon is intentional
        Long[] expected = new Long[] { 0x40l, 0l, 0x250l, 0x252l, 624l, 0x81234567L };
        
        AllowedMechanisms result = AllowedMechanisms.parse(allowedMechanismsProperty);
        assertArrayEquals(expected, result.toLongArray());
    }
    
    /**
     * Tests parsing of hex and decimal values with empty value.
     */
    @Test
    public void testParseHexAndDecimal_empty() {
        LOG.info(">testParseHexAndDecimal_empty");

        String allowedMechanismsProperty = "";
        AllowedMechanisms result = AllowedMechanisms.parse(allowedMechanismsProperty);
        assertArrayEquals(new Long[0], result.toLongArray());
        
        allowedMechanismsProperty = " "; // Note: leading whitespace is intentional
        result = AllowedMechanisms.parse(allowedMechanismsProperty);
        assertArrayEquals(new Long[0], result.toLongArray());

        allowedMechanismsProperty = ", , "; // Note: empty values
        result = AllowedMechanisms.parse(allowedMechanismsProperty);
        assertArrayEquals(new Long[0], result.toLongArray());
    }

    /**
     * Tests parsing with incorrect hexadecimal value.
     */
    @Test(expected = IllegalArgumentException.class)
    public void testParseHexAndDecimal_incorrectValue1() {
        LOG.info(">testParseHexAndDecimal_incorrectValue1");
        String allowedMechanismsProperty = " 0x00000040, 0x00000000 0xnotANumber;0x252 ,624"; // 0xnotANumber
        AllowedMechanisms.parse(allowedMechanismsProperty);
    }
    
    /**
     * Tests parsing with incorrect decimal value.
     */
    @Test(expected = IllegalArgumentException.class)
    public void testParseHexAndDecimal_incorrectValue2() {
        LOG.info(">testParseHexAndDecimal_incorrectValue2");
        String allowedMechanismsProperty = " 0x00000040, 0x00000000 notANumberNorConstant;0x252 ,624"; // notANumberNorConstant
        AllowedMechanisms.parse(allowedMechanismsProperty);
    }

    /**
     * Tests the encoding into the form expected by PKCS#11 for the CKA_ALLOWED_MECHANISMS attribute.
     */
    @Test
    public void testToBinaryEncoding() {
        LOG.info(">testToBinaryEncoding");
        String allowedMechanismsProperty = " 0x00000040, 0x00000000, 0x00000250, 0x252, 624, 0x81234567";
        
        AllowedMechanisms instance = AllowedMechanisms.parse(allowedMechanismsProperty);
        final String expected = 
                  "4000000000000000"
                + "0000000000000000"
                + "5002000000000000"
                + "5202000000000000"
                + "7002000000000000"
                + "6745238100000000";
        assertEquals(expected, Hex.toHexString(instance.toBinaryEncoding()));
    }
    
    /**
     * Tests parsing of the binary encoding from a CKA_ALLOWED_MECHANISMS attribute.
     */
    @Test
    public void testFromBinaryEncoding() {
        LOG.info(">testFromBinaryEncoding");
        final Long[] expected = new Long[] { 0x00000040l, 0x00000000l, 0x00000250l, 0x252l, 624l, 0x81234567l };

        final String binary = 
                  "4000000000000000"
                + "0000000000000000"
                + "5002000000000000"
                + "5202000000000000"
                + "7002000000000000"
                + "6745238100000000";

        assertArrayEquals(expected, AllowedMechanisms.fromBinaryEncoding(Hex.decode(binary)).toLongArray());
    }

    /**
     * Test of toString method.
     */
    @Test
    public void testToString() {
        LOG.info(">testToString");
        String allowedMechanismsProperty = " 0x00000040, 0x00000000 0x00000250;0x252 ,624 0x81234567"; // Note: leading whitespace, mix or space and comma and semicolon is intentional
        String expected = "AllowedMechanisms{CKM_SHA256_RSA_PKCS, CKM_RSA_PKCS_KEY_PAIR_GEN, CKM_SHA256, CKM_SHA256_HMAC_GENERAL, CKM_SHA512, 0x81234567}";
        
        AllowedMechanisms result = AllowedMechanisms.parse(allowedMechanismsProperty);
        assertEquals(expected, result.toString());
    }
    
}
