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
package org.signserver.common;

import java.util.Map;

import org.apache.log4j.Logger;

import junit.framework.TestCase;

/**
 * Tests for the WorkerConfig logging functions.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 *
 */
public class WorkerConfigTest extends TestCase {
    /** Logger for this class */
    private static Logger LOG = Logger.getLogger(WorkerConfigTest.class);

    /**
     * Test that adding a property to a worker config yields the right diff.
     * @throws Exception
     */
    public void test01AddProperty() throws Exception {
        final WorkerConfig oldConf = new WorkerConfig();
        final WorkerConfig newConf = new WorkerConfig();

        oldConf.setProperty("foo", "bar");
        newConf.setProperty("foo", "bar");
        newConf.setProperty("newprop", "newval");

        final Map<String, String> diff = WorkerConfig.propertyDiff(oldConf, newConf);

        assertEquals("Number of diff entries", 1, diff.size());
        assertTrue("Cotains entry", "newval".equals(diff.get("added:newprop")));
    }

    /**
     * Tests that changing a property yields a correct diff.
     * @throws Exception
     */
    public void test02ChangeProperty() throws Exception {
        final WorkerConfig oldConf = new WorkerConfig();
        final WorkerConfig newConf = new WorkerConfig();

        oldConf.setProperty("foo", "bar");
        oldConf.setProperty("bar", "foobar");
        newConf.setProperty("foo", "bar");
        newConf.setProperty("bar", "newval");

        final Map<String, String> diff = WorkerConfig.propertyDiff(oldConf, newConf);

        assertEquals("Number of diff entries", 1, diff.size());
        assertTrue("Cotains entry", "newval".equals(diff.get("changed:bar")));
    }

    /**
     * Tests that removing a property yields a correct diff.
     * @throws Exception
     */
    public void test03RemoveProperty() throws Exception {
        final WorkerConfig oldConf = new WorkerConfig();
        final WorkerConfig newConf = new WorkerConfig();

        oldConf.setProperty("foo", "bar");
        oldConf.setProperty("bar", "foobar");
        newConf.setProperty("foo", "bar");

        final Map<String, String> diff = WorkerConfig.propertyDiff(oldConf, newConf);

        assertEquals("Number of diff entries", 1, diff.size());
        assertTrue("Contains entry", "foobar".equals(diff.get("removed:bar")));
    }

    /**
     * Tests adding a new property and changing an existing.
     * @throws Exception
     */
    public void test04ChangeAndAddProperty() throws Exception {
        final WorkerConfig oldConf = new WorkerConfig();
        final WorkerConfig newConf = new WorkerConfig();

        oldConf.setProperty("foo", "bar");
        newConf.setProperty("foo", "foobar");
        newConf.setProperty("bar", "foo");

        final Map<String, String> diff = WorkerConfig.propertyDiff(oldConf, newConf);

        assertEquals("Number of diff entries", 2, diff.size());
        assertTrue("Contains entries",
                "foo".equals(diff.get("added:bar")) && "foobar".equals(diff.get("changed:foo")));

    }

    /**
     * Tests changing one property and removing another
     * @throws Exception
     */
    public void test05ChangeAndRemoveProperty() throws Exception {
        final WorkerConfig oldConf = new WorkerConfig();
        final WorkerConfig newConf = new WorkerConfig();

        oldConf.setProperty("foo", "bar");
        oldConf.setProperty("bar", "foo");
        newConf.setProperty("foo", "foobar");

        final Map<String, String> diff = WorkerConfig.propertyDiff(oldConf, newConf);

        assertEquals("Number of diff entries", 2, diff.size());
        assertTrue("Contains entries",
                "foo".equals(diff.get("removed:bar")) && "foobar".equals(diff.get("changed:foo")));
    }

    /**
     * Tests adding a property and removing another.
     * @throws Exception
     */
    public void test06RemoveAndAddProperty() throws Exception {
        final WorkerConfig oldConf = new WorkerConfig();
        final WorkerConfig newConf = new WorkerConfig();

        oldConf.setProperty("foo", "bar");
        oldConf.setProperty("bar", "foo");
        newConf.setProperty("bar", "foo");
        newConf.setProperty("foobar", "foobar");

        final Map<String, String> diff = WorkerConfig.propertyDiff(oldConf, newConf);

        assertEquals("Number of diff entries", 2, diff.size());
        assertTrue("Contains entries",
                "foobar".equals(diff.get("added:foobar")) && "bar".equals(diff.get("removed:foo")));
    }
}
