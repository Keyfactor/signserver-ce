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
package org.signserver.web;

import java.util.Collections;

/**
 * Tests the Health check.
 * 
 * @author Markus Kilås
 * @version $Id$
 */
public class HealthCheckTest extends WebTestCase {

    @Override
    protected String getServletURL() {
        return "http://localhost:8080/signserver/healthcheck/signserverhealth";
    }

    /**
     * Sets up a dummy signer.
     * @throws Exception in case of error
     */
    public void test00SetupDatabase() throws Exception {
//        addDummySigner1();
//        addCMSSigner1();
    }

    /**
     * Test that a successful request returns status code 200.
     */
    public void test01HttpStatus200() {
        assertStatusReturned(Collections.<String, String>emptyMap(), 200);
    }

    /**
     * Remove the workers created etc.
     * @throws Exception in case of error
     */
    public void test99TearDownDatabase() throws Exception {
//        removeWorker(getSignerIdDummy1());
//        removeWorker(getSignerIdCMSSigner1());
    }
}
