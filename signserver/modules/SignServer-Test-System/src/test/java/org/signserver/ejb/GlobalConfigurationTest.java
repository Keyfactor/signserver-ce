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
package org.signserver.ejb;

import org.signserver.common.GlobalConfiguration;
import org.signserver.common.ServiceLocator;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.signserver.ejb.interfaces.GlobalConfigurationSessionRemote;

/**
 * TODO: Document me!
 * 
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class GlobalConfigurationTest {

    private static GlobalConfigurationSessionRemote globalConfigSession;

    @Before
    public void setUp() throws Exception {
        globalConfigSession = ServiceLocator.getInstance().lookupRemote(GlobalConfigurationSessionRemote.class);
    }

    /*
     * Test method for 'org.signserver.common.GlobalConfigurationFileParser.getBaseProperty(String)'
     */
    @Test
    public void test01SetProperty() throws Exception {
        GlobalConfiguration gc = globalConfigSession.getGlobalConfiguration();

        globalConfigSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "TEST", "TESTVALUE");
        globalConfigSession.setProperty(GlobalConfiguration.SCOPE_NODE, "TEST2", "TESTVALUE");
        gc = globalConfigSession.getGlobalConfiguration();
        assertTrue(gc != null);
        assertTrue(gc.getProperty(GlobalConfiguration.SCOPE_GLOBAL, "TEST").equals("TESTVALUE"));
        assertTrue(gc.getProperty(GlobalConfiguration.SCOPE_NODE, "TEST") == null);


        assertTrue(gc.getProperty(GlobalConfiguration.SCOPE_NODE, "TEST2").equals("TESTVALUE"));
        assertTrue(gc.getProperty(GlobalConfiguration.SCOPE_GLOBAL, "TEST2") == null);

        assertTrue(gc.getProperty(GlobalConfiguration.SCOPE_NODE, "WORKER1.CLASSPATH") == null);

        globalConfigSession.removeProperty(GlobalConfiguration.SCOPE_GLOBAL, "TEST");
        gc = globalConfigSession.getGlobalConfiguration();
    }
}
