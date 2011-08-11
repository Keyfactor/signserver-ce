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
package org.signserver.test.system;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.signserver.cli.SignServerCLITest;
import org.signserver.client.validationservice.ValidationCLITest;
import org.signserver.common.clusterclassloader.ClusterClassLoaderTestSuite;

/**
 * TODO: Document me!
 * 
 * @version $Id$
 */
public class MainTestSuite extends TestCase {
    
    public MainTestSuite(String testName) {
        super(testName);
    }

    public static Test suite() {
        TestSuite suite = new TestSuite("MainTestSuite");
        suite.addTest(new TestSuite(SignServerCLITest.class, "SignServerCLI"));
        suite.addTest(new TestSuite(ValidationCLITest.class, "ValidationCLI"));
        suite.addTest(ClusterClassLoaderTestSuite.suite());
        return suite;
    }

    @Override
    protected void setUp() throws Exception {
        super.setUp();
    }

    @Override
    protected void tearDown() throws Exception {
        super.tearDown();
    }

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        junit.textui.TestRunner.run(MainTestSuite.suite());
    }

}
