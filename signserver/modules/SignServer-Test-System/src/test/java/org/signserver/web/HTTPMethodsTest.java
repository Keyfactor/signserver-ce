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

import java.util.HashMap;
import java.util.Map;
import org.junit.After;
import org.junit.FixMethodOrder;
import org.junit.runners.MethodSorters;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

/**
 * Tests different HTTP methods to make sure only GET and POST are allowed
 * 
 * @author Marcus Lundblad
 * @version $Id$
 *
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class HTTPMethodsTest extends WebTestCase {

	private boolean useProcess = true;
	
	@Override
	protected String getServletURL() {
		return "http://localhost:8080/signserver" + (useProcess ? "/process" : "");
	}

	@Before
	public void setUp() throws Exception {
		// set up dummy signer
		addDummySigner1();
		useProcess = true;
	}

	@After
	public void tearDown() throws Exception {
		// remove dummy signer
		removeWorker(getSignerIdDummy1());
	}

    /**
     * Testing HTTP PUT should fail with HTTP error 403 or 405.
     */
    @Test
    public void test01HttpPUT() throws Exception {
        final Map<String, String> fields = new HashMap<String, String>();
        fields.put("data", "<root/>");
        final int actual = queryStatusReturned(fields, "PUT");
        assertTrue("status returned: " + actual, actual == 403 || actual == 405);
    }

    /**
     * Testing HTTP DELETE should fail with HTTP error 403 or 405.
     */
    @Test
    public void test02HttpDELETE() throws Exception {
        final Map<String, String> fields = new HashMap<String, String>();
        fields.put("data", "<root/>");
        final int actual = queryStatusReturned(fields, "DELETE");
        assertTrue("status returned: " + actual, actual == 403 || actual == 405);
    }

	/**
	 * Testing HTTP OPTIONS
	 * should fail with error 403
	 */
    @Test
	public void test03HttpOPTIONS() {
		Map<String, String> fields = new HashMap<String, String>();
		fields.put("data", "<root/>");

		assertStatusReturned(fields, "OPTIONS", 403);
	}

	/**
	 * Testing HTTP TRACE
	 * using the URL /signserver here, since there seems to be some bug related to
	 * servlet injection in JBoss 5 that makes TRACE success on the servlet unless a GET was issued first.
	 */
    @Test
	public void test04HttpTRACE() {
		Map<String, String> fields = new HashMap<String, String>();
		useProcess = false;
		
		assertStatusReturnedNotEqual(fields, "TRACE", 200);
	}

}
