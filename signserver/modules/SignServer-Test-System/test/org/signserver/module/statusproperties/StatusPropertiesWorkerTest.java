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
package org.signserver.module.statusproperties;

import java.io.ByteArrayInputStream;
import java.util.Enumeration;
import org.signserver.statusrepo.common.StatusEntry;
import org.signserver.web.*;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import org.apache.log4j.Logger;
import org.signserver.statusrepo.common.StatusName;

/**
 * Tests that the right HTTP status codes are returned in different situations.
 * 
 * @author Markus Kilås
 * @version $Id$
 */
public class StatusPropertiesWorkerTest extends WebTestCase {
    
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(StatusPropertiesWorkerTest.class);
    
    private static final String WORKERNAME = "TestStatusPropertiesWorker";
    private static final int WORKERID = 9310;

    @Override
    protected String getServletURL() {
        return "http://localhost:8080/signserver/process";
    }

    /**
     * Sets up a StatusPropertiesWorker.
     */
    public void test00SetupDatabase() throws Exception {
        Properties properties = new Properties();
        properties.setProperty("GLOB.WORKER" + WORKERID + ".CLASSPATH", "org.signserver.module.statusproperties.StatusPropertiesWorker");
        properties.setProperty("GLOB.WORKER" + WORKERID + ".SIGNERTOKEN.CLASSPATH", "org.signserver.server.cryptotokens.HardCodedCryptoToken");
        properties.setProperty("WORKER" + WORKERID + ".NAME", WORKERNAME);
        properties.setProperty("WORKER" + WORKERID + ".AUTHTYPE", "NOAUTH");
        setProperties(properties);
        getWorkerSession().reloadConfiguration(WORKERID);
    }

    /**
     * Test that a successful request returns status code 200.
     */
    public void test01HttpStatus200() {
        Map<String, String> fields = new HashMap<String, String>();
        fields.put("workerName", WORKERNAME);
        fields.put("data", "");
        assertStatusReturned(fields, 200);
    }

    /**
     * Tests that passing in no arguments (in the data) results in all status 
     * properties being returned.
     * Assumption: No other process is currently updating the status values 
     * while this test is running.
     */
    public void testNoArgumentsReturnsAll() throws Exception {
        Map<String, String> fields = new HashMap<String, String>();
        fields.put("workerName", WORKERNAME);
        fields.put("data", "");
        
        Map<String, StatusEntry> allEntries = getStatusSession().getAllEntries();
        Set<String> allValidNames = new HashSet<String>();
        for (String name : allEntries.keySet()) {
            if (getStatusSession().getValidEntry(name) != null) {
                allValidNames.add(name);
            }
        }
        
        byte[] body = sendPostFormUrlencodedReadBody(getServletURL(), fields);
        
        // The response should contain all valid status properties
        Properties properties = new Properties();
        properties.load(new ByteArrayInputStream(body));
        for (String name : allValidNames) {
            String value = properties.getProperty(name + ".VALUE");
            String expiration = properties.getProperty(name + ".EXPIRATION");
            LOG.info("Value: " + allEntries.get(name).getValue() + ", " + value);
            assertEquals(allEntries.get(name).getValue(), value);
            assertEquals(String.valueOf(allEntries.get(name).getExpirationTime()), expiration);
        }
    }
    
    /**
     * Tests querying one property only returns that property.
     */
    public void testGetAProperty() throws Exception {
        Map<String, String> fields = new HashMap<String, String>();
        fields.put("workerName", WORKERNAME);
        fields.put("data", "GET=SERVER_STARTED");
        
        byte[] body = sendPostFormUrlencodedReadBody(getServletURL(), fields);
        Properties properties = new Properties();
        properties.load(new ByteArrayInputStream(body));
        
        // Should only contain the SERVER_STARTED status property
        assertNotNull("contains SERVER_STARTED.VALUE", properties.getProperty("SERVER_STARTED.VALUE"));
        assertNotNull("contains SERVER_STARTED.EXPIRATION", properties.getProperty("SERVER_STARTED.EXPIRATION"));
        Enumeration<Object> elements = properties.elements();
        while (elements.hasMoreElements()) {
            String name = (String) elements.nextElement();
            if (!name.equals("SERVER_STARTED.VALUE") && name.contains(".VALUE")) {
                fail("Should not have got: " + name);
            }
            if (!name.equals("SERVER_STARTED.EXPIRATION") && name.contains(".EXPIRATION")) {
                fail("Should not have got: " + name);
            }
        }
    }
    
    /**
     * Tests that querying for 3 properties where one is expired only returns
     * the two valid ones.
     */
    public void testGetMultipleProperties() throws Exception {
        Map<String, String> fields = new HashMap<String, String>();
        fields.put("workerName", WORKERNAME);
        fields.put("data", "GET=TEST_PROPERTY1,TEST_PROPERTY2,TEST_PROPERTY3");
        
        getStatusSession().update(StatusName.TEST_PROPERTY1.name(), null, 1);
        getStatusSession().update(StatusName.TEST_PROPERTY2.name(), "VALUE2");
        getStatusSession().update(StatusName.TEST_PROPERTY3.name(), "VALUE3");
        
        byte[] body = sendPostFormUrlencodedReadBody(getServletURL(), fields);
        Properties properties = new Properties();
        properties.load(new ByteArrayInputStream(body));
        
        // Should only contain TEST2 and TEST3 (TEST1 is expired)
        assertNotNull("contains TEST2.VALUE", properties.getProperty(StatusName.TEST_PROPERTY2.name() + ".VALUE"));
        assertNotNull("contains TEST2.EXPIRATION", properties.getProperty(StatusName.TEST_PROPERTY2.name() + ".EXPIRATION"));
        assertNotNull("contains TEST3.VALUE", properties.getProperty(StatusName.TEST_PROPERTY3.name() + ".VALUE"));
        assertNotNull("contains TEST3.EXPIRATION", properties.getProperty(StatusName.TEST_PROPERTY3.name() + ".EXPIRATION"));
        Enumeration<Object> elements = properties.elements();
        while (elements.hasMoreElements()) {
            String name = (String) elements.nextElement();
            if (!name.equals(StatusName.TEST_PROPERTY2.name() + ".VALUE") &&
                    !name.equals(StatusName.TEST_PROPERTY2.name() + ".EXPIRATION") &&
                    !name.equals(StatusName.TEST_PROPERTY1.name() + ".VALUE") &&
                    !name.equals(StatusName.TEST_PROPERTY1.name() + ".EXPIRATION")) {
                if (name.contains(".VALUE") || name.contains(".EXPIRATION")) {
                    fail("Should not have got: " + name);
                }
            }
        }
    }
    
    /**
     * Test setting 3 status properties. Two with expiration and one without.
     * @throws Exception 
     */
    public void testSetProperties() throws Exception {
        long expiration1 = System.currentTimeMillis() + 10 * 60 * 1000;
        long expiration2 = System.currentTimeMillis() + 20 * 60 * 1000;
        long expiration3 = 0;
        
        Map<String, String> fields = new HashMap<String, String>();
        fields.put("workerName", WORKERNAME);
        fields.put("data", 
                  "TEST_PROPERTY1.VALUE=VALUE11\n"
                + "TEST_PROPERTY1.EXPIRATION=" + expiration1 + "\n"
                + "TEST_PROPERTY2.VALUE=VALUE22\n"
                + "TEST_PROPERTY2.EXPIRATION=" + expiration2 + "\n"
                + "TEST_PROPERTY3.VALUE=VALUE33");
        
        byte[] body = sendPostFormUrlencodedReadBody(getServletURL(), fields);
        Properties properties = new Properties();
        properties.load(new ByteArrayInputStream(body));
        
        // Should have set value and expiration for TEST1 and TEST2 and only 
        // value for TEST3 and the new values should be returned and set in 
        // the repository
        assertEquals("VALUE11", properties.getProperty(StatusName.TEST_PROPERTY1.name() + ".VALUE"));
        assertEquals("VALUE22", properties.getProperty(StatusName.TEST_PROPERTY2.name() + ".VALUE"));
        assertEquals("VALUE33", properties.getProperty(StatusName.TEST_PROPERTY3.name() + ".VALUE"));
        assertEquals(String.valueOf(expiration1), properties.getProperty(StatusName.TEST_PROPERTY1.name() + ".EXPIRATION"));
        assertEquals(String.valueOf(expiration2), properties.getProperty(StatusName.TEST_PROPERTY2.name() + ".EXPIRATION"));
        assertEquals(String.valueOf(expiration3), properties.getProperty(StatusName.TEST_PROPERTY3.name() + ".EXPIRATION"));
        
        // Check repository as well
        Map<String, StatusEntry> allEntries = getStatusSession().getAllEntries();
        StatusEntry entry1 = allEntries.get(StatusName.TEST_PROPERTY1.name());
        StatusEntry entry2 = allEntries.get(StatusName.TEST_PROPERTY2.name());
        StatusEntry entry3 = allEntries.get(StatusName.TEST_PROPERTY3.name());
        assertEquals("VALUE11", entry1.getValue());
        assertEquals("VALUE22", entry2.getValue());
        assertEquals("VALUE33", entry3.getValue());
        assertEquals(expiration1, entry1.getExpirationTime());
        assertEquals(expiration2, entry2.getExpirationTime());
        assertEquals(expiration3, entry3.getExpirationTime());
    }

    /**
     * Remove the workers created etc.
     * @throws Exception in case of error
     */
    public void test99TearDownDatabase() throws Exception {
        removeWorker(WORKERID);
    }
}
