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

import java.util.Arrays;
import java.util.List;
import java.util.Properties;
import java.util.TreeSet;
import static junit.framework.TestCase.assertEquals;
import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;
import org.pkcs11.jacknji11.CKA;

/**
 * Unit tests for the AttributeProperties class.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class AttributePropertiesTest {
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(AttributePropertiesTest.class);

    /**
     * Tests parsing from worker properties with one property in hex.
     */
    @Test
    public void testFromWorkerProperties_onePropertyHex() {
        LOG.info(">testFromWorkerProperties_onePropertyHex");
        
        Properties properties = new Properties();
        properties.setProperty("ATTRIBUTE.PUBLIC.RSA.0x0000010a", "true"); // CKA_VERIFY
        properties.setProperty("OTHER", "true");
        properties.setProperty("ATTRIBUTES", "Attributes value");
        properties.setProperty("ATTRIBUTE", "Attribute value");
        
        List<AttributeProperties.Attribute> expectedPublicRsaAttributes = Arrays.asList(
                new AttributeProperties.Attribute(CKA.VERIFY, Boolean.TRUE)
        );

        AttributeProperties attributes = AttributeProperties.fromWorkerProperties(properties);
        assertEquals(expectedPublicRsaAttributes.toString(), attributes.getPublicTemplate("RSA").toString());
    }
    
    /**
     * Tests parsing from worker properties with one property in capital hex.
     * (This is needed as worker properties in SignServer are all using capital letters)
     */
    @Test
    public void testFromWorkerProperties_onePropertyCapitalHex() {
        LOG.info(">testFromWorkerProperties_onePropertyCapitalHex");
        
        Properties properties = new Properties();
        properties.setProperty("ATTRIBUTE.PUBLIC.RSA.0X0000010A", "true"); // CKA_VERIFY
        properties.setProperty("OTHER", "true");
        properties.setProperty("ATTRIBUTES", "Attributes value");
        properties.setProperty("ATTRIBUTE", "Attribute value");
        
        List<AttributeProperties.Attribute> expectedPublicRsaAttributes = Arrays.asList(
                new AttributeProperties.Attribute(CKA.VERIFY, Boolean.TRUE)
        );

        AttributeProperties attributes = AttributeProperties.fromWorkerProperties(properties);
        assertEquals(expectedPublicRsaAttributes.toString(), attributes.getPublicTemplate("RSA").toString());
    }
    
    /**
     * Tests parsing from worker properties with one property in decimal.
     */
    @Test
    public void testFromWorkerProperties_onePropertyDecimal() {
        LOG.info(">testFromWorkerProperties_onePropertyDecimal");
        
        Properties properties = new Properties();
        properties.setProperty("ATTRIBUTE.PRIVATE.RSA.266", "false"); // CKA_VERIFY
        properties.setProperty("OTHER", "true");
        properties.setProperty("ATTRIBUTES", "Attributes value");
        properties.setProperty("ATTRIBUTE", "Attribute value");
        
        List<AttributeProperties.Attribute> expectedPrivateRsaAttributes = Arrays.asList(
                new AttributeProperties.Attribute(CKA.VERIFY, Boolean.FALSE)
        );

        AttributeProperties attributes = AttributeProperties.fromWorkerProperties(properties);
        assertEquals(expectedPrivateRsaAttributes.toString(), attributes.getPrivateTemplate("RSA").toString());
    }
    
    /**
     * Tests parsing from worker properties with one property in literal form.
     */
    @Test
    public void testFromWorkerProperties_onePropertyLiteral() {
        LOG.info(">testFromWorkerProperties_onePropertyLiteral");
        
        Properties properties = new Properties();
        properties.setProperty("ATTRIBUTE.PRIVATE.RSA.CKA_VERIFY", "True"); // CKA_VERIFY
        properties.setProperty("OTHER", "true");
        properties.setProperty("ATTRIBUTES", "Attributes value");
        properties.setProperty("ATTRIBUTE", "Attribute value");
        
        List<AttributeProperties.Attribute> expectedPrivateRsaAttributes = Arrays.asList(
                new AttributeProperties.Attribute(CKA.VERIFY, Boolean.TRUE)
        );

        AttributeProperties attributes = AttributeProperties.fromWorkerProperties(properties);
        assertEquals(expectedPrivateRsaAttributes.toString(), attributes.getPrivateTemplate("RSA").toString());
    }
    
    /**
     * Tests parsing from worker properties with one property in literal form with false boolean value.
     */
    @Test
    public void testFromWorkerProperties_booleanFalse() {
        LOG.info(">testFromWorkerProperties_booleanFalse");
        
        Properties properties = new Properties();
        properties.setProperty("ATTRIBUTE.PRIVATE.RSA.CKA_VERIFY", "FaLsE");
        properties.setProperty("OTHER", "true");
        properties.setProperty("ATTRIBUTES", "Attributes value");
        properties.setProperty("ATTRIBUTE", "Attribute value");
        
        List<AttributeProperties.Attribute> expectedPrivateRsaAttributes = Arrays.asList(
                new AttributeProperties.Attribute(CKA.VERIFY, Boolean.FALSE)
        );

        AttributeProperties attributes = AttributeProperties.fromWorkerProperties(properties);
        assertEquals(expectedPrivateRsaAttributes.toString(), attributes.getPrivateTemplate("RSA").toString());
    }
    
    /**
     * Tests parsing from worker properties with one property in literal form.
     */
    @Test(expected = IllegalArgumentException.class)
    public void testFromWorkerProperties_booleanIllegal() {
        LOG.info(">testFromWorkerProperties_booleanIllegal");
        
        Properties properties = new Properties();
        properties.setProperty("ATTRIBUTE.PRIVATE.RSA.CKA_VERIFY", "not-boolean");

        AttributeProperties.fromWorkerProperties(properties);
    }

    /**
     * Tests parsing from worker properties with multiple properties.
     */
    @Test
    public void testFromWorkerProperties_multiple() {
        LOG.info(">testFromWorkerProperties_multiple");
        
        Properties properties = new Properties();
        properties.setProperty("ATTRIBUTE.PUBLIC.RSA.0x0000010a", "true"); // CKA_VERIFY
        properties.setProperty("ATTRIBUTE.PRIVATE.RSA.CKA_VERIFY", "false");
        properties.setProperty("ATTRIBUTE.PUBLIC.ECDSA.CKA_ENCRYPT", "false");
        properties.setProperty("ATTRIBUTE.PRIVATE.ECDSA.0x162", "false"); // CKA_EXTRACTABLE
        properties.setProperty("ATTRIBUTE.PRIVATE.ECDSA.263", "true"); // CKA_UNWRAP
        properties.setProperty("OTHER", "true");
        properties.setProperty("ATTRIBUTES", "Attributes value");
        properties.setProperty("ATTRIBUTE", "Attribute value");
        
        
        TreeSet<AttributeProperties.Attribute> expectedPublicRsaAttributes = new TreeSet<>(Arrays.asList(
                new AttributeProperties.Attribute(CKA.VERIFY, Boolean.TRUE)
        ));
        TreeSet<AttributeProperties.Attribute> expectedPrivateRsaAttributes = new TreeSet<>(Arrays.asList(
                new AttributeProperties.Attribute(CKA.VERIFY, Boolean.FALSE)
        ));
        TreeSet<AttributeProperties.Attribute> expectedPublicEcdsaAttributes = new TreeSet<>(Arrays.asList(
                new AttributeProperties.Attribute(CKA.ENCRYPT, Boolean.FALSE)
        ));
        TreeSet<AttributeProperties.Attribute> expectedPrivateEcdsaAttributes = new TreeSet<>(Arrays.asList(
                new AttributeProperties.Attribute(CKA.EXTRACTABLE, Boolean.FALSE), 
                new AttributeProperties.Attribute(CKA.UNWRAP, Boolean.TRUE)
        ));
        
        AttributeProperties attributes = AttributeProperties.fromWorkerProperties(properties);
        
        assertEquals(expectedPublicRsaAttributes.toString(), new TreeSet<>(attributes.getPublicTemplate("RSA")).toString());
        assertEquals(expectedPrivateRsaAttributes.toString(), new TreeSet<>(attributes.getPrivateTemplate("RSA")).toString());
        assertEquals(expectedPublicEcdsaAttributes.toString(), new TreeSet<>(attributes.getPublicTemplate("ECDSA")).toString());
        assertEquals(expectedPrivateEcdsaAttributes.toString(), new TreeSet<>(attributes.getPrivateTemplate("ECDSA")).toString());
    }
    
    /**
     * Tests parsing from worker properties with CKA_ALLOWED_MECHANISMS.
     */
    @Test
    public void testFromWorkerProperties_allowedMechanisms() {
        LOG.info(">testFromWorkerProperties_allowedMechanisms");
        
        Properties properties = new Properties();
        properties.setProperty("ATTRIBUTE.PRIVATE.RSA.CKA_ALLOWED_MECHANISMS", "SHA256_RSA_PKCS, RSA_PKCS_KEY_PAIR_GEN");
        properties.setProperty("ATTRIBUTE.PRIVATE.ECDSA.CKA_ALLOWED_MECHANISMS", "ECDSA_SHA1");
        
        List<AttributeProperties.Attribute> expectedPrivateRsaAttributes = Arrays.asList(
                new AttributeProperties.Attribute(CKA.ALLOWED_MECHANISMS, Hex.decode("40000000000000000000000000000000"))
        );
        
        List<AttributeProperties.Attribute> expectedPrivateEcdsaAttributes = Arrays.asList(
                new AttributeProperties.Attribute(CKA.ALLOWED_MECHANISMS, Hex.decode("4210000000000000"))
        );

        AttributeProperties attributes = AttributeProperties.fromWorkerProperties(properties);
        
        LOG.info("Attributes: " + attributes);

        assertEquals(expectedPrivateRsaAttributes.toString(), attributes.getPrivateTemplate("RSA").toString());
        assertEquals(expectedPrivateEcdsaAttributes.toString(), attributes.getPrivateTemplate("ECDSA").toString());
    }
    
    /**
     * Test of toWorkerProperties method.
     */
    @Test
    public void testToWorkerProperties() {
        LOG.info(">testToWorkerProperties");
        
        Properties properties = new Properties();
        properties.setProperty("ATTRIBUTE.PRIVATE.RSA.CKA_VERIFY", "True"); // CKA_VERIFY
        properties.setProperty("OTHER", "true");
        properties.setProperty("ATTRIBUTE.PRIVATE.RSA.CKA_ALLOWED_MECHANISMS", "SHA256_RSA_PKCS, RSA_PKCS_KEY_PAIR_GEN");
        properties.setProperty("ATTRIBUTES", "Attributes value");
        properties.setProperty("ATTRIBUTE.PRIVATE.ECDSA.0x162", "false"); // CKA_EXTRACTABLE
        properties.setProperty("ATTRIBUTE", "Attribute value");

        Properties actual = AttributeProperties.fromWorkerProperties(properties).toWorkerProperties();
        
        assertEquals("ATTRIBUTE.PRIVATE.RSA.CKA_VERIFY", "true", actual.get("ATTRIBUTE.PRIVATE.RSA.CKA_VERIFY"));
        assertEquals("ATTRIBUTE.PRIVATE.RSA.CKA_ALLOWED_MECHANISMS", "CKM_SHA256_RSA_PKCS, CKM_RSA_PKCS_KEY_PAIR_GEN", actual.get("ATTRIBUTE.PRIVATE.RSA.CKA_ALLOWED_MECHANISMS"));
        assertEquals("ATTRIBUTE.PRIVATE.ECDSA.CKA_EXTRACTABLE", "false", actual.get("ATTRIBUTE.PRIVATE.ECDSA.CKA_EXTRACTABLE"));        
    }
    
}
