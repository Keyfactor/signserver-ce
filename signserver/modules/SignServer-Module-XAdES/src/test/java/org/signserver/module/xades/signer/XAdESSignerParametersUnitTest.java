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

import org.apache.log4j.Logger;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * Unit tests for the XAdESSignerParameters class.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class XAdESSignerParametersUnitTest {
    
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(XAdESSignerParametersUnitTest.class);

    /**
     * Test of getXadesForm method, of class XAdESSignerParameters.
     */
    @Test
    public void testGetXadesForm() {
        LOG.info("getXadesForm");
        XAdESSignerParameters instance = new XAdESSignerParameters(XAdESSigner.Profiles.BES);
        XAdESSigner.Profiles expResult = XAdESSigner.Profiles.BES;
        XAdESSigner.Profiles result = instance.getXadesForm();
        assertEquals("ctor1", expResult, result);
        
        instance = new XAdESSignerParameters(XAdESSigner.Profiles.T, null);
        expResult = XAdESSigner.Profiles.T;
        result = instance.getXadesForm();
        assertEquals("ctor2", expResult, result);
    }

    /**
     * Test of getTsaParameters method, of class XAdESSignerParameters.
     */
    @Test
    public void testGetTsaParameters() {
        LOG.info("getTsaParameters");
        TSAParameters tsa = new TSAParameters("http://example.com/?test=3");
        XAdESSignerParameters instance = new XAdESSignerParameters(XAdESSigner.Profiles.T, tsa);
        TSAParameters expResult = tsa;
        TSAParameters result = instance.getTsaParameters();
        assertEquals(expResult, result);
    }

    /**
     * Test of isTSAAvailable method, of class XAdESSignerParameters.
     */
    @Test
    public void testIsTSAAvailable() {
        LOG.info("isTSAAvailable");
        XAdESSignerParameters instance = new XAdESSignerParameters(XAdESSigner.Profiles.BES);
        assertFalse("ctor1", instance.isTSAAvailable());
        instance = new XAdESSignerParameters(XAdESSigner.Profiles.BES, null);
        assertFalse("ctor2a", instance.isTSAAvailable());
        instance = new XAdESSignerParameters(XAdESSigner.Profiles.BES, new TSAParameters("http://example.com/?test=4"));
        assertTrue("ctor2b", instance.isTSAAvailable());
    }
}
