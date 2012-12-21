package org.signserver.test.performance;
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
import org.apache.log4j.Logger;
import org.signserver.test.performance.WorkerThread;

import junit.framework.TestCase;

/**
 * Test for the statistical methods of the performance tool.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 *
 */
public class WorkerThreadTest extends TestCase {
	/** Logger for this class */
	private static Logger LOG = Logger.getLogger(WorkerThreadTest.class);
		
	public void test01Average() throws Exception {
		WorkerThread thread = new WorkerThread("test", null);
		
		thread.addResponseTime(42);
		thread.addResponseTime(47);
		thread.addResponseTime(43);
		
		assertEquals("Average", 44.0, thread.getAverageResponseTime());
	}
	
	public void test02Min() throws Exception {
		WorkerThread thread = new WorkerThread("test", null);
		
		thread.addResponseTime(42);
		thread.addResponseTime(47);
		thread.addResponseTime(43);
		
		assertEquals("Average", 42, thread.getMinResponseTime());
	}
	
	public void test03Max() throws Exception {
		WorkerThread thread = new WorkerThread("test", null);
		
		thread.addResponseTime(42);
		thread.addResponseTime(47);
		thread.addResponseTime(43);
		
		assertEquals("Average", 47, thread.getMaxResponseTime());
	}
	
	public void test04StdDev() throws Exception {
		WorkerThread thread = new WorkerThread("test", null);
		
		thread.addResponseTime(0);
		thread.addResponseTime(1);
		
		assertEquals("Average", 0.5, thread.getStdDevResponseTime());
	}
}
