/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.p11ng.common.cryptotoken;

import java.util.Properties;
import junit.framework.TestCase;
import org.junit.Test;
import org.signserver.common.CryptoTokenInitializationFailureException;

/**
 * Unit tests for the JackNJI11CryptoToken.
 *  
 * @author Marcus Lundblad
 * @version $Id$
 */
public class JackNJI11CryptoTokenUnitTest extends TestCase {
    
    /**
     * Test that SHAREDLIBRARYNAME must be set.
     * 
     * @throws Exception 
     */
    @Test
    public void testInit_sharedLibraryNameRequired() throws Exception {
        final JackNJI11CryptoToken instance = new JackNJI11CryptoToken();
        final Properties config = new Properties();
        
        config.setProperty("SLOTLABELTYPE", "SLOT_NUMBER");
        config.setProperty("SLOTLABELVALUE", "1");
        
        try {
            instance.init(42, config, null);
            fail("Should throw CryptoTokenInitializationFailureException");
        } catch (CryptoTokenInitializationFailureException ex) {
            assertTrue("Contains error message",
                       ex.getMessage().startsWith("Missing SHAREDLIBRARYNAME property"));
        } catch (Exception ex) {
            fail("Unexpected exception: " + ex.getClass().getName());
        }
    }
    
    /**
     * Test that setting SHAREDLIBRARYNAME to a value not corresponding to
     * a defined library results in a error mentioning that.
     * 
     * @throws Exception 
     */
    @Test
    public void testInit_illegalSharedLibraryName() throws Exception {
        final JackNJI11CryptoToken instance = new JackNJI11CryptoToken();
        final Properties config = new Properties();
        
        config.put("SHAREDLIBRARYNAME", "non_existing_library_name");
        config.setProperty("SLOTLABELTYPE", "SLOT_NUMBER");
        config.setProperty("SLOTLABELVALUE", "1");
        try {
            instance.init(42, config, null);
            fail("Should throw CryptoTokenInitializationFailureException");
        } catch (CryptoTokenInitializationFailureException ex) {
            assertTrue("Should mention non-existing library name",
                       ex.getMessage().startsWith("SHAREDLIBRARYNAME non_existing_library_name is not referring to a defined value"));
        }
    }
    
    /**
     * Test that setting SLOTLABELTYPE is required.
     * 
     * @throws Exception 
     */
    @Test
    public void testInit_slotLabelTypeRequired() throws Exception {
        final JackNJI11CryptoToken instance = new JackNJI11CryptoToken();
        final Properties config = new Properties();
        
        try {
            instance.init(42, config, null);
            fail("Should throw CryptoTokenInitializationFailureException");
        } catch (CryptoTokenInitializationFailureException ex) {
            assertTrue("Should mention missing SLOTLABELTYPE",
                    ex.getMessage().equals("Missing SLOTLABELTYPE property"));
        }
    }
    
    /**
     * Test that setting SLOTLABEVALUE is required.
     * 
     * @throws Exception 
     */
    @Test
    public void testInit_slotLabelValueRequired() throws Exception {
        final JackNJI11CryptoToken instance = new JackNJI11CryptoToken();
        final Properties config = new Properties();
        
        config.setProperty("SLOTLABELTYPE", "SLOT_NUMBER");
        
        try {
            instance.init(42, config, null);
            fail("Should throw CryptoTokenInitializationFailureException");
        } catch (CryptoTokenInitializationFailureException ex) {
            assertTrue("Should mention missing SLOTLABELVALUE",
                    ex.getMessage().equals("Missing SLOTLABELVALUE property"));
        }
    }
    
    /**
     * Test that setting a totally unknown SLOTLABELTYPE value results in an
     * error mentioning that.
     * 
     * @throws Exception 
     */
    @Test
    public void testInit_illegalSlotLabelType() throws Exception {
        final JackNJI11CryptoToken instance = new JackNJI11CryptoToken();
        final Properties config = new Properties();
        
        config.setProperty("SLOTLABELTYPE", "_ILLEGAL_");
        
        try {
            instance.init(42, config, null);
            fail("Should throw CryptoTokenInitializationFailureException");
        } catch (CryptoTokenInitializationFailureException ex) {
            assertTrue("Should mention illegal SLOTLABELTYPE",
                    ex.getMessage().equals("Illegal SLOTLABELTYPE property: _ILLEGAL_"));
        }
    }
    
    /**
     * Test that setting a value for SLOTLABELTYPE that this token currently
     * doesn't support mentions only SLOT_NUMBER and SLOT_INDEX is supported.
     * 
     * @throws Exception 
     */
    @Test
    public void testInit_unsupportedSlotLabelType() throws Exception {
        final JackNJI11CryptoToken instance = new JackNJI11CryptoToken();
        final Properties config = new Properties();
        
        config.setProperty("SLOTLABELTYPE", "SLOT_LABEL");
        
        try {
            instance.init(42, config, null);
            fail("Should throw CryptoTokenInitializationFailureException");
        } catch (CryptoTokenInitializationFailureException ex) {
            assertTrue("Should show unsupported SLOTLABELTYPE",
                    ex.getMessage().equals("Only SLOT_NUMBER and SLOT_INDEX supported for SLOTLABELTYPE"));
        }
    }
    
    /**
     * Test that setting the legacy SLOT property is not allowed. As otherwise
     * that would cause fixP11Properties() to rewrite the config with corresponding
     * new properties.
     * 
     * @throws Exception 
     */
    @Test
    public void testInit_legacySlotNotAllowed() throws Exception {
        final JackNJI11CryptoToken instance = new JackNJI11CryptoToken();
        final Properties config = new Properties();
        
        config.setProperty("SLOT", "1");
        
        try {
            instance.init(42, config, null);
            fail("Should throw CryptoTokenInitializationFailureException");
        } catch (CryptoTokenInitializationFailureException ex) {
            assertTrue("Should show unsupported SLOTLABELTYPE",
                    ex.getMessage().equals("Setting legacy properties SLOT or SLOTLISTINDEX is not allowed"));
        }
    }
    
    /**
     * Test that setting the legacy SLOTLISTINDEX property is not allowed. As otherwise
     * that would cause fixP11Properties() to rewrite the config with corresponding
     * new properties.
     * 
     * @throws Exception 
     */
    @Test
    public void testInit_legacySlotlistindexNotAllowed() throws Exception {
        final JackNJI11CryptoToken instance = new JackNJI11CryptoToken();
        final Properties config = new Properties();
        
        config.setProperty("SLOTLISTINDEX", "i1");
        
        try {
            instance.init(42, config, null);
            fail("Should throw CryptoTokenInitializationFailureException");
        } catch (CryptoTokenInitializationFailureException ex) {
            assertTrue("Should show unsupported SLOTLABELTYPE",
                    ex.getMessage().equals("Setting legacy properties SLOT or SLOTLISTINDEX is not allowed"));
        }
    }
    
}
