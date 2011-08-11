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

import java.util.Map;
import java.util.jar.JarInputStream;

import junit.framework.TestCase;

/**
 * TODO: Document me!
 * 
 * @version $Id$
 */
public class MARFileParserTest extends TestCase {

    private static String signserverhome;

    protected void setUp() throws Exception {
        super.setUp();
        signserverhome = System.getenv("SIGNSERVER_HOME");
        assertNotNull(signserverhome);
    }

    public void testMarFileWithoutDescriptor() throws Exception {
        MARFileParser mARFileParser = new MARFileParser(signserverhome + "/src/test/testmodule-withoutdescr.mar");
        assertTrue(mARFileParser.getMARName().equals("testmodule-withoutdescr.mar"));
        assertTrue(mARFileParser.getModuleName().equals("TESTMODULE-WITHOUTDESCR"));
        assertTrue(mARFileParser.getDescriptionFromMARFile().equals(""));
        assertTrue(mARFileParser.getVersionFromMARFile() == 1);

        String[] parts = mARFileParser.getMARParts();
        assertTrue(parts.length == 1);
        assertTrue(parts[0].equals("server"));

        Map<String, JarInputStream> jarMap = mARFileParser.getJARFiles("server");
        assertTrue(jarMap.keySet().size() == 3);
        assertTrue(jarMap.keySet().contains("testjar.jar"));
        assertTrue(jarMap.keySet().contains("testjar2.jar"));
        assertNotNull(jarMap.get("testjar.jar"));
        assertNotNull(jarMap.get("testjar2.jar"));

        jarMap = mARFileParser.getJARFiles("someother");
        assertTrue(jarMap.keySet().size() == 0);

        jarMap = mARFileParser.getJARFiles("server");

        Map<String, byte[]> resourceMap = mARFileParser.getJarContent(jarMap.get("testjar.jar"));
        assertNotNull(resourceMap);
        assertTrue(resourceMap.size() == 10);
        byte[] classData = resourceMap.get("org/signserver/server/statistics/StatisticsManager.class");
        assertNotNull(classData);
        assertTrue(classData.length == 4352);

    }

    public void testMarFileWithDescriptor() throws Exception {
        MARFileParser mARFileParser = new MARFileParser(signserverhome + "/src/test/testmodule-withdescr.mar");
        assertTrue(mARFileParser.getMARName().equals("testmodule-withdescr.mar"));
        assertTrue(mARFileParser.getDescriptionFromMARFile(), mARFileParser.getDescriptionFromMARFile().equals("sometext"));
        assertTrue(mARFileParser.getVersionFromMARFile() == 2);

        String[] parts = mARFileParser.getMARParts();
        assertTrue(parts.length == 2);
        assertTrue(parts[0].equals("part1"));
        assertTrue("'" + parts[1] + "'", parts[1].equals("part2"));

        Map<String, JarInputStream> jarMap = mARFileParser.getJARFiles("part1");
        assertTrue(jarMap.keySet().size() == 2);
        assertTrue(jarMap.keySet().contains("testjar.jar"));
        assertTrue(jarMap.keySet().contains("testjar2.jar"));
        assertNotNull(jarMap.get("testjar.jar"));
        assertNotNull(jarMap.get("testjar2.jar"));

        jarMap = mARFileParser.getJARFiles("someother");
        assertTrue(jarMap.keySet().size() == 0);
    }
}
