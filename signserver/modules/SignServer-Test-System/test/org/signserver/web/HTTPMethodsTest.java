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

/**
 * Tests different HTTP methods to make sure only GET and POST are allowed
 * 
 * @author Marcus Lundblad
 * @version $Id$
 *
 */

public class HTTPMethodsTest extends WebTestCase {

	private boolean useProcess = true;
	
	@Override
	protected String getServletURL() {
		return "http://localhost:8080/signserver" + (useProcess ? "/process" : "");
	}

	@Override
	protected void setUp() throws Exception {
		// set up dummy signer
		addDummySigner1();
		useProcess = true;
	}

	@Override
	protected void tearDown() throws Exception {
		// remove dummy signer
		removeWorker(getSignerIdDummy1());
	}

	/**
	 * Testing HTTP PUT
	 * should fail with error 403
	 */
	public void test01HttpPUT() {
		Map<String, String> fields = new HashMap<String, String>();
		fields.put("data", "<root/>");

		assertStatusReturned(fields, "PUT", 403);
	}
	
	/**
	 * Testing HTTP DELETE
	 * should fail with error 403
	 */
	public void test02HttpDELETE() {
		Map<String, String> fields = new HashMap<String, String>();
		fields.put("data", "<root/>");

		assertStatusReturned(fields, "DELETE", 403);
	}

	/**
	 * Testing HTTP OPTIONS
	 * should fail with error 403
	 */
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
	public void test04HttpTRACE() {
		Map<String, String> fields = new HashMap<String, String>();
		useProcess = false;
		
		assertStatusReturnedNotEqual(fields, "TRACE", 200);
	}

}
