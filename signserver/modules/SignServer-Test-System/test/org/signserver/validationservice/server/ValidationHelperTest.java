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
package org.signserver.validationservice.server;

import java.util.HashMap;
import java.util.Properties;

import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;

import junit.framework.TestCase;
import static org.junit.Assert.*;
import org.junit.Test;

/**
 * TODO: Document me!
 * 
 * @version $Id$
 */
public class ValidationHelperTest {

    @Test
    public void testGetValidatorProperties() {
        WorkerConfig config = new WorkerConfig();
        config.setProperty("SOMEGENDATA", "TESTDATA");
        config.setProperty("validator1.KEY1", "key1data");
        config.setProperty("VALIDATOR1.KEY2", "key2data");
        config.setProperty("VAL1.KEY3", "key3data");
        config.setProperty("val1.KEY4", "key4data");
        config.setProperty("vali1.KEY5", "key5data");
        config.setProperty("val3.KEY6", "key6data");
        config.setProperty("val255.KEY7", "key7data");
        config.setProperty("VALIDATOR255.KEY8", "key8data");

        Properties props = ValidationHelper.getValidatorProperties(1, config);
        assertTrue(props.get("SOMEGENDATA").equals("TESTDATA"));
        assertTrue(props.get("KEY1").equals("key1data"));
        assertTrue(props.get("key1") == null);
        assertTrue(props.get("KEY2").equals("key2data"));
        assertTrue(props.get("KEY3").equals("key3data"));
        assertTrue(props.get("KEY4").equals("key4data"));
        assertTrue(props.get("KEY5") == null);
        assertTrue(props.get("vali1.KEY5").equals("key5data"));
        assertTrue(props.get("val3.KEY6") == null);

        assertTrue(ValidationHelper.getValidatorProperties(2, config) == null);
        assertTrue(ValidationHelper.getValidatorProperties(3, config).getProperty("KEY6").equals("key6data"));
        assertTrue(ValidationHelper.getValidatorProperties(255, config).getProperty("KEY7").equals("key7data"));
        assertTrue(ValidationHelper.getValidatorProperties(255, config).getProperty("KEY8").equals("key8data"));
        assertTrue(ValidationHelper.getValidatorProperties(255, config).getProperty("SOMEGENDATA").equals("TESTDATA"));

    }

    @Test
    public void testgenValidators() throws SignServerException {
        WorkerConfig config = new WorkerConfig();
        config.setProperty("TESTPROP", "TESTDATA");
        config.setProperty("validator1.KEY1", "key1data");
        config.setProperty("VALIDATOR1.KEY2", "key2data");
        config.setProperty("VALIDATOR1.CLASSPATH", "org.signserver.validationservice.server.DummyValidator");
        config.setProperty("VAL1.KEY3", "key3data");
        config.setProperty("val1.KEY4", "key4data");
        config.setProperty("vali1.KEY5", "key5data");
        config.setProperty("val3.KEY6", "key6data");
        config.setProperty("val3.CLASSPATH", "org.signserver.validationservice.server.DummyValidator");

        HashMap<Integer, IValidator> vals = ValidationHelper.genValidators(1, config, null, null);
        assertTrue(vals.get(1) != null);
        assertTrue(vals.get(2) == null);
        assertTrue(vals.get(3) != null);

        config.setProperty("VALIDATOR255.KEY8", "key8data");

        try {
            vals = ValidationHelper.genValidators(1, config, null, null);
            assertTrue(false);
        } catch (SignServerException e) {
        }

    }

    @Test
    public void testGetIssuerProperties() {
        Properties config = new Properties();
        config.setProperty("SOMEGENDATA", "TESTDATA");
        config.setProperty("issuer1.KEY1", "key1data");
        config.setProperty("issuer1.KEY2", "key2data");
        config.setProperty("ISSUER1.KEY3", "key3data");
        config.setProperty("ISSUERi1.KEY5", "key5data");
        config.setProperty("issuer3.KEY6", "key6data");
        config.setProperty("issuer255.KEY7", "key7data");
        config.setProperty("ISSUER255.KEY8", "key8data");

        Properties props = ValidationHelper.getIssuerProperties(1, config);
        assertTrue(props.get("SOMEGENDATA").equals("TESTDATA"));
        assertTrue(props.get("KEY1").equals("key1data"));
        assertTrue(props.get("key1") == null);
        assertTrue(props.get("KEY2").equals("key2data"));
        assertTrue(props.get("KEY3").equals("key3data"));
        assertTrue(props.get("KEY5") == null);
        assertTrue(props.get("ISSUERi1.KEY5").equals("key5data"));
        assertTrue(props.get("issuer3.KEY6") == null);

        assertTrue(ValidationHelper.getIssuerProperties(2, config) == null);
        assertTrue(ValidationHelper.getIssuerProperties(3, config).getProperty("KEY6").equals("key6data"));
        assertTrue(ValidationHelper.getIssuerProperties(255, config).getProperty("KEY7").equals("key7data"));
        assertTrue(ValidationHelper.getIssuerProperties(255, config).getProperty("KEY8").equals("key8data"));
        assertTrue(ValidationHelper.getIssuerProperties(255, config).getProperty("SOMEGENDATA").equals("TESTDATA"));
    }
}
