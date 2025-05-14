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

import org.apache.log4j.Logger;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;
import static org.junit.Assert.assertNotNull;

/**
 * Tests for the ComponentLoader class.
 */
public class ComponentLoaderTest {

    private static final Logger LOG = Logger.getLogger(ComponentLoaderTest.class);

    /**
     * Test loading a class by correct name and class type.
     */
    @Test
    public void test01LoadClass() {
        LOG.info("test01LoadClass");

        final String sampleClassName = ComponentLoaderTest.class.getName();
        final ComponentLoader componentLoader = new ComponentLoader();

        try {
            final ComponentLoaderTest test = componentLoader.load(sampleClassName, ComponentLoaderTest.class, getClass().getClassLoader());
            assertNotNull("Loaded object should not be null", test);
        } catch (ComponentLoadingException e) {
            LOG.error("test01LoadClass failed: ", e);
            fail("test01Load: Component loading failed");
        }
    }

    /**
     * Test failure in loading a class by name using not existing class name.
     */
    @Test
    public void test02LoadClass_WrongClassName() {
        LOG.info("test02LoadClass_WrongClassName");

        final String sampleClassName = "org.signserver.common.DummyNotExistingClass123";
        final ComponentLoader componentLoader = new ComponentLoader();

        try {
            final ComponentLoaderTest test = componentLoader.load(sampleClassName, ComponentLoaderTest.class, getClass().getClassLoader());
            fail("Should have thrown an exception");
        } catch (ComponentLoadingException e) {
            assertEquals("Should be exactly this general message without details.", e.getLocalizedMessage(), ("Loading component by class name failed."));
        }
    }

    /**
     * Test failure in loading a class by name using a wrong class type.
     */
    @Test
    public void test03LoadClass_WrongClassType() {
        LOG.info("test03LoadClass_WrongClassType");

        final String sampleClassName = ComponentLoaderTest.class.getName();
        final ComponentLoader componentLoader = new ComponentLoader();

        try {
            final ComponentLoader test = componentLoader.load(sampleClassName, ComponentLoader.class, getClass().getClassLoader());
            fail("Should have thrown an exception");
        } catch (ComponentLoadingException e) {
            assertEquals("Should be exactly this general message without details.", e.getLocalizedMessage(), ("Loading component by class name failed."));
        }
    }

    /**
     * Test failure in loading a class by name where class doesn't have default constructor.
     */
    @Test
    public void test04LoadClass_NoSuchMethodException() {
        LOG.info("test04LoadClass_NoSuchMethodException");

        final String sampleClassName = NoDefaultConstructorDummyClass.class.getName();
        final ComponentLoader componentLoader = new ComponentLoader();

        try {
            final NoDefaultConstructorDummyClass test = componentLoader.load(sampleClassName, NoDefaultConstructorDummyClass.class, getClass().getClassLoader());
            fail("Should have thrown an exception");
        } catch (ComponentLoadingException e) {
            assertEquals("Should be exactly this general message without details.", e.getLocalizedMessage(), ("Loading component by class name failed."));
        }
    }


    /**
     * Test failure in loading a class by name where class is private and expect to get IllegalAccessException.
     */
    @Test
    public void test05LoadClass_IllegalAccessException() {
        LOG.info("test05LoadClass_IllegalAccessException");

        final String sampleClassName = PrivateConstractorDummyClass.class.getName();
        final ComponentLoader componentLoader = new ComponentLoader();

        try {
            final PrivateConstractorDummyClass test = componentLoader.load(sampleClassName, PrivateConstractorDummyClass.class, getClass().getClassLoader());
            fail("Should have thrown an exception");
        } catch (ComponentLoadingException e) {
            assertEquals("Should be exactly this general message without details.", e.getLocalizedMessage(), ("Loading component by class name failed."));
        }

    }


    /**
     * Test failure in loading a class by name where class is abstract and expect to get InstantiationException.
     */
    @Test
    public void test06LoadClass_InstantiationException() {
        LOG.info("test06LoadClass_InstantiationException");

        final String sampleClassName = AbstractDummyClass.class.getName();
        final ComponentLoader componentLoader = new ComponentLoader();

        try {
            final AbstractDummyClass test = componentLoader.load(sampleClassName, AbstractDummyClass.class, getClass().getClassLoader());
            fail("Should have thrown an exception");
        } catch (ComponentLoadingException e) {
            assertEquals("Should be exactly this general message without details.", e.getLocalizedMessage(), ("Loading component by class name failed."));
        }

    }

    /**
     * Tests failure when attempting to load a class by name that throws an exception. We expect InvocationTargetException.
     */
    @Test
    public void test07LoadClass_InvocationTargetException() {
        LOG.info("test07LoadClass_InvocationTargetException");

        final String sampleClassName = ThrowingExceptionDummyClass.class.getName();
        final ComponentLoader componentLoader = new ComponentLoader();

        try {
            componentLoader.load(sampleClassName, DummyClass.class, getClass().getClassLoader());
            fail("Should have thrown an exception");
        } catch (ComponentLoadingException e) {
            assertEquals("Should be exactly this general message without details.", e.getLocalizedMessage(), ("Loading component by class name failed."));
        }
    }
}
