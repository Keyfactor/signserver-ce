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
package org.signserver.server.service;

import java.text.ParseException;
import java.util.Calendar;
import java.util.Date;

import org.quartz.CronExpression;
import static org.junit.Assert.*;
import org.junit.Test;

/**
 * TODO: Document me!
 * 
 * @version $Id$
 */
public class QuartsLibTest {

    @Test
    public void test01CronExpressions() throws ParseException {
        CronExpression ce = new CronExpression("0/15 * * ? * *");
        Calendar c = Calendar.getInstance();
        c.setTime(ce.getNextValidTimeAfter(new Date()));
        assertTrue((c.get(Calendar.SECOND) % 15) == 0);

        assertTrue((c.getTime().getTime() - System.currentTimeMillis()) > 0);
    }
}
