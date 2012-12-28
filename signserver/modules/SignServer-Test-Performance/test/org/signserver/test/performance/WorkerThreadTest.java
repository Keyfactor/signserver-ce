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
import junit.framework.TestCase;
import org.apache.log4j.Logger;

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
		
    /**
     * Tests the calculation of average.
     */
	public void test01Average() throws Exception {
        LOG.info("test01Average");
		WorkerThread thread = new WorkerThread("test", null);
		
        assertEquals("Average no samples", Double.NaN, thread.getAverageResponseTime());
        
		thread.addResponseTime(42);
		thread.addResponseTime(47);
		thread.addResponseTime(43);
		
		assertEquals("Average", 44.0, thread.getAverageResponseTime());
        assertEquals("Operations", 3, thread.getOperationsPerformed());
	}
	
    /**
     * Tests the calculation of the minimum value.
     */
	public void test02Min() throws Exception {
        LOG.info("test02Min");
		WorkerThread thread = new WorkerThread("test", null);
		
        assertEquals("Min no samples", Long.MAX_VALUE, thread.getMinResponseTime());
        
		thread.addResponseTime(42);
		thread.addResponseTime(47);
		thread.addResponseTime(43);
        thread.addResponseTime(44);
		
		assertEquals("Min", 42, thread.getMinResponseTime());
        assertEquals("Operations", 4, thread.getOperationsPerformed());
	}
	
    /**
     * Tests the calculation of the maximum value.
     */
	public void test03Max() throws Exception {
        LOG.info("test03Max");
		WorkerThread thread = new WorkerThread("test", null);
		
        assertEquals("Max no samples", 0, thread.getMaxResponseTime());
        
		thread.addResponseTime(42);
		thread.addResponseTime(47);
		thread.addResponseTime(43);
		
		assertEquals("Max", 47, thread.getMaxResponseTime());
        
        thread.addResponseTime(59);
        thread.addResponseTime(59);
        thread.addResponseTime(48);
        assertEquals("Max", 59, thread.getMaxResponseTime());
	}
	
}
