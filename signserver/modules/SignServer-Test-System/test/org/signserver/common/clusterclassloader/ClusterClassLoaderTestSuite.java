/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package org.signserver.common.clusterclassloader;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

/**
 *
 * @author markus
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
