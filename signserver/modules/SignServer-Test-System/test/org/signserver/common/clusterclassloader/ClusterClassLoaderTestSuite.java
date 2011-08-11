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
package org.signserver.common.clusterclassloader;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

/**
 * TODO: Document me!
 * 
 * @version $Id$
 */
public class ClusterClassLoaderTestSuite extends TestCase {

    public ClusterClassLoaderTestSuite() {
    }

    public ClusterClassLoaderTestSuite(String testName) {
        super(testName);
    }

    public static Test suite() {
        TestSuite suite = new TestSuite("ClusterClassLoaderTestSuite");
        suite.addTestSuite(ClusterClassLoaderUtilsTest.class);
        suite.addTestSuite(FindInterfacesClassLoaderTest.class);
        suite.addTestSuite(MARFileParserTest.class);
        suite.addTestSuite(TransactionInjectionTest.class);
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
}
