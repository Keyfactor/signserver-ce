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
package org.signserver.server;

import java.util.List;
import static org.junit.Assert.assertTrue;
import org.junit.Test;
import org.signserver.common.WorkerConfig;

/**
 * Unit tests for JWTAuthorizer.
 *
 * @author Marcus Lundblad
 * @version $Id$
 */
public class JWTAuthorizerUnitTest {

    /**
     * Test that setting an illegal value for MAX_ALLOWED_CLOCK_SCEW
     * results in an error message.
     *
     * @throws Exception 
     */
    @Test
    public void testIllegalMaxAllowedClockScew() throws Exception {
        final JWTAuthorizer instance = new JWTAuthorizer();
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("MAX_ALLOWED_CLOCK_SCEW", "foobar123");
        instance.init(42, config, null);

        final List<String> fatalErrors = instance.getFatalErrors();

        assertTrue("Contains error: " + fatalErrors.toString(),
                   fatalErrors.contains("Illegal value for MAX_ALLOWED_CLOCK_SCEW: foobar123"));
    }

    /**
     * Test that setting a negative value for MAX_ALLOWED_CLOCK_SCEW
     * results in an error message.
     *
     * @throws Exception 
     */
    @Test
    public void testNegativeMaxAllowedClockScew() throws Exception {
        final JWTAuthorizer instance = new JWTAuthorizer();
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("MAX_ALLOWED_CLOCK_SCEW", "-1");
        instance.init(42, config, null);

        final List<String> fatalErrors = instance.getFatalErrors();

        assertTrue("Contains error: " + fatalErrors.toString(),
                   fatalErrors.contains("MAX_ALLOWED_CLOCK_SCEW must be positive"));
    }

    /**
     * Test that setting a valid value for MAX_ALLOWED_CLOCK_SCEW works.
     *
     * @throws Exception 
     */
    @Test
    public void testLegalMaxAllowedClockScew() throws Exception {
        final JWTAuthorizer instance = new JWTAuthorizer();
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("MAX_ALLOWED_CLOCK_SCEW", "60");
        instance.init(42, config, null);

        final List<String> fatalErrors = instance.getFatalErrors();

        assertTrue("Contains no error: " + fatalErrors.toString(),
                   fatalErrors.isEmpty());
    }
}
