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
package org.signserver.cli;

import org.signserver.testutils.CLITestHelper;
import static org.signserver.testutils.CLITestHelper.assertPrinted;
import org.signserver.testutils.ModulesTestCase;


/**
 * Test for the audit log query CLI command.
 * This is a separe class to be able to exclude this when running with no DB.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public class AuditLogCLITest extends ModulesTestCase { 
    private CLITestHelper cli = getAdminCLI();
    
    /**
     * Test running the auditlog query command.
     */
    public void testQueryAuditLog() throws Exception {
        // make sure an error message is printed if not setting the mandatory -limit argument
        assertEquals("", CommandLineInterface.RETURN_INVALID_ARGUMENTS, cli.execute("auditlog", "-query"));
        assertPrinted("Should output error", cli.getOut(), "Must specify a limit");
        
        // test a simple criteria
        cli.execute("setproperty", "global", "FOO_PROPERTY_1234567", "BAR");
        assertEquals(CommandLineInterface.RETURN_SUCCESS,
                     cli.execute("auditlog","-query", "-limit", "1", "-criteria", "additionalDetails LIKE %FOO_PROPERTY_1234567%"));
        assertPrinted("Should contain log record", cli.getOut(), "GLOBALCONFIG_PROPERTY=GLOB.FOO_PROPERTY_1234567, GLOBALCONFIG_VALUE=BAR");
        
        // test with multiple criterias
        assertEquals(CommandLineInterface.RETURN_SUCCESS,
                cli.execute("auditlog", "-query", "-limit", "1", "-criteria", "authToken EQ CLI user", "-criteria", "additionalDetails LIKE %FOO_PROPERTY_1234567%"));
        assertPrinted("Should contain log record", cli.getOut(), "GLOBALCONFIG_PROPERTY=GLOB.FOO_PROPERTY_1234567, GLOBALCONFIG_VALUE=BAR");
        

    }
}
