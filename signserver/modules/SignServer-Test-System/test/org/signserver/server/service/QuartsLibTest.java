package org.signserver.server.service;

import java.text.ParseException;
import java.util.Calendar;
import java.util.Date;

import junit.framework.TestCase;

import org.quartz.CronExpression;

public class QuartsLibTest extends TestCase {

	protected void setUp() throws Exception {
		super.setUp();
	}
	
	public void test01CronExpressions() throws ParseException{
		CronExpression ce = new CronExpression("0/15 * * ? * *");
		Calendar c = Calendar.getInstance();
		c.setTime(ce.getNextValidTimeAfter(new Date()));
		assertTrue( (c.get(Calendar.SECOND) %15 ) == 0);
		
		assertTrue((c.getTime().getTime() - System.currentTimeMillis()) > 0);
		

	}

}
