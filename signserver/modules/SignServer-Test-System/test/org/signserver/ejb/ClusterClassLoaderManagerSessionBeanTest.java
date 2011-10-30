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

import java.util.Arrays;
import java.util.Map;
import java.util.jar.JarInputStream;


import junit.framework.TestCase;

import org.signserver.cli.module.AddModuleCommand;
import org.signserver.common.ServiceLocator;
import org.signserver.common.clusterclassloader.FindInterfacesClassLoader;
import org.signserver.common.clusterclassloader.MARFileParser;
import org.signserver.ejb.interfaces.IClusterClassLoaderManagerSession;

/**
 * TODO: Document me!
 *
 * @version $Id$
 */
public class ClusterClassLoaderManagerSessionBeanTest extends TestCase {

    private static IClusterClassLoaderManagerSession.IRemote cclMan;
    private static String signserverhome;

    @Override
    protected void setUp() throws Exception {
        super.setUp();
        cclMan = ServiceLocator.getInstance().lookupRemote(
                IClusterClassLoaderManagerSession.IRemote.class);

        signserverhome = System.getenv("SIGNSERVER_HOME");
        assertNotNull(signserverhome);
    }

    public void testMARFile() throws Exception {
        addMAR(signserverhome + "/res/test/testmodule-withoutdescr.mar");

        String[] moduleNames = cclMan.listAllModules();
        assertNotNull(moduleNames);
        assertTrue(moduleNames.length > 0);
        assertTrue(Arrays.asList(moduleNames).contains("TESTMODULE-WITHOUTDESCR"));

        Integer[] versions = cclMan.listAllModuleVersions("TESTMODULE-WITHOUTDESCR");
        assertNotNull(versions);
        assertTrue(versions.length == 1);
        assertTrue(versions[0] == 1);

        String[] allparts = cclMan.listAllModuleParts("TESTMODULE-WITHOUTDESCR", 1);
        assertNotNull(allparts);
        assertTrue(allparts.length == 1);
        assertTrue(allparts[0].equals("server"));

        String[] allJars = cclMan.getJarNames("TESTMODULE-WITHOUTDESCR", "server", 1);
        assertNotNull(allJars);
        assertTrue(allJars.length == 3);

        addMAR(signserverhome + "/res/test/testmodule-withdescr.mar");
        moduleNames = cclMan.listAllModules();
        assertNotNull(moduleNames);
        assertTrue(moduleNames.length > 0);
        assertTrue(Arrays.asList(moduleNames).contains("TESTMODULE-WITHDESCR"));

        versions = cclMan.listAllModuleVersions("TESTMODULE-WITHDESCR");
        assertNotNull(versions);
        assertTrue(versions.length == 1);
        assertTrue(versions[0] == 2);

        allparts = cclMan.listAllModuleParts("TESTMODULE-WITHDESCR", 2);
        assertNotNull(allparts);
        assertTrue(allparts.length == 2);
        assertTrue(Arrays.asList(allparts).contains("part1"));
        assertTrue(Arrays.asList(allparts).contains("part2"));

        allJars = cclMan.getJarNames("TESTMODULE-WITHDESCR", "part2", 2);
        assertNotNull(allJars);
        assertTrue(allJars.length == 2);
    }

    public void testRemoveModules() throws Exception {
        cclMan.removeModulePart("TESTMODULE-WITHOUTDESCR", "server", 1);
        cclMan.removeModulePart("TESTMODULE-WITHDESCR", "part1", 2);
        cclMan.removeModulePart("TESTMODULE-WITHDESCR", "part2", 2);

        String[] moduleNames = cclMan.listAllModules();
        assertNotNull(moduleNames);
        assertFalse(Arrays.asList(moduleNames).contains("TESTMODULE-WITHOUTDESCR"));
        assertFalse(Arrays.asList(moduleNames).contains("TESTMODULE-WITHDESCR"));
    }

    private void addMAR(String marPath) throws Exception {
        MARFileParser mARFileParser = new MARFileParser(marPath);
        String moduleName = mARFileParser.getModuleName();
        int version = mARFileParser.getVersionFromMARFile();
        String[] parts = mARFileParser.getMARParts();

        for (String part : parts) {
            FindInterfacesClassLoader ficl = new FindInterfacesClassLoader(mARFileParser, part, System.out);
            Map<String, JarInputStream> jarContents = mARFileParser.getJARFiles(part);
            for (String jarName : jarContents.keySet()) {
                Map<String, byte[]> jarContent = mARFileParser.getJarContent(jarContents.get(jarName));
                for (String resourceName : jarContent.keySet()) {
                    if (!resourceName.endsWith("/")) {
                        cclMan.addResource(moduleName, part, version, jarName, resourceName, AddModuleCommand.appendAllInterfaces(ficl.getImplementedInterfaces(resourceName)), null, null, jarContent.get(resourceName));
                    }
                }
            }
        }
    }
}
