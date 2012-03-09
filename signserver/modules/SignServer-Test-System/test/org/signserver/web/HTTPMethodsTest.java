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

	@Override
	protected String getServletURL() {
		return "http://localhost:8080/signserver/process";
	}

	@Override
	protected void setUp() throws Exception {
		// set up dummy signer
		addDummySigner1();
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

	// we will not test HTTP TRACE, it is actually supposed to return the query (like a ping)

}
