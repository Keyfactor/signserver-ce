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

package org.signserver.server.statistics;

import junit.framework.TestCase;

public class TestEvent extends TestCase {

	protected void setUp() throws Exception {
		super.setUp();
	}

	public void testBasics() throws InterruptedException {
		Event event = new Event(123);
		assertTrue(event.getWorkerId() == 123);
		assertNull(event.getStartTimeStamp());
		assertNull(event.getEndTimeStamp());
		event.start();
		Thread.sleep(100);
		event.stop();
		assertNotNull(event.getStartTimeStamp());
		assertNotNull(event.getEndTimeStamp());
		assertTrue(event.getStartTimeStamp().before(event.getEndTimeStamp()));
	}

	public void testCustomData() {
		Event event = new Event(123);
		assertNull(event.getCustomData());
		event.addCustomStatistics("SOMECUSTOM", 111);
		assertNotNull(event.getCustomData());
		assertTrue(event.getCustomData().get("SOMECUSTOM").equals(111));
	}

}
