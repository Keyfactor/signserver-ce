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
package org.signserver.testutils;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import junit.framework.Assert;

import org.apache.log4j.Logger;
import org.signserver.cli.signserver;

/**
 * Class containing utility methods used to simplify testing.
 *
 * @author Philip Vendil 21 okt 2007
 * @version $Id$
 */
public class TestUtils {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(TestUtils.class);
    
    public static void setupSSLTruststore() {
        Properties buildConfig = new Properties();
        try {
            buildConfig.load(new FileInputStream(new File(new File(
                    System.getenv("SIGNSERVER_HOME")),
                    "signserver_build.properties")));
        } catch (FileNotFoundException ignored) {
            LOG.debug("No signserver_build.properties");
        } catch (IOException ex) {
            LOG.error("Not using signserver_build.properties: " + ex.getMessage());
        }
        System.setProperty("javax.net.ssl.trustStore", 
                new File(new File(System.getenv("SIGNSERVER_HOME")),
                    "p12/truststore.jks").getAbsolutePath());
        System.setProperty("javax.net.ssl.trustStorePassword",
                buildConfig.getProperty("java.trustpassword", "changeit"));
        //System.setProperty("javax.net.ssl.keyStore", "../../p12/testadmin.jks");
        //System.setProperty("javax.net.ssl.keyStorePassword", "foo123");
    }
    
    /**
     * A simple grep util that searches a large string if the substring exists.
     * @param inString the input data
     * @param searchstring the text to search for.
     * @return true if searchstring exists
     */
    public static boolean grep(String inString, String searchstring) {
        Pattern p = Pattern.compile(searchstring);
        // Create a matcher with an input string
        Matcher m = p.matcher(inString);
        return m.find();
    }

    /**
     * Method to see if the matchString is a subset of all the output
     * in the temporary system output buffer. 
     * @param matchString the string to search for
     * @return true if it exists.
     */
    public static boolean grepTempOut(String matchString) {
        return grep(new String(tempOutputStream.toByteArray()), matchString);
    }

    /**
     * Method used to redirect OutputStream to a temporate buffer
     * so it is possible to search for matching values later.
     */
    public static void redirectToTempOut() {
        stdOut = System.out;
        tempOutputStream = new ByteArrayOutputStream();
        System.setOut(new PrintStream(tempOutputStream));
    }
    private static ByteArrayOutputStream tempOutputStream;
    private static PrintStream stdOut;

    /**
     * Method used to clear the current content of the
     * temporary output stream.
     */
    public static void flushTempOut() {
        tempOutputStream = new ByteArrayOutputStream();
        System.setOut(new PrintStream(tempOutputStream));
    }

    /**
     * Method to see if the matchString is a subset of all the output
     * in the temporary system error buffer. 
     * @param matchString the string to search for
     * @return true if it exists.
     */
    public static boolean grepTempErr(String matchString) {
        return grep(new String(tempErrorStream.toByteArray()), matchString);
    }

    /**
     * Method used to redirect error stream to a temporary buffer
     * so it is possible to search for matching values later.
     */
    public static void redirectToTempErr() {
        //stdErr = System.err;
        tempErrorStream = new ByteArrayOutputStream();
        System.setErr(new PrintStream(tempErrorStream));
    }
    private static ByteArrayOutputStream tempErrorStream;
    //private static PrintStream stdErr;

    /**
     * Method used to clear the current content of the
     * temporary error stream.
     */
    public static void flushTempErr() {
        tempErrorStream = new ByteArrayOutputStream();
        System.setErr(new PrintStream(tempErrorStream));
    }

    /**
     * Method used to print the contents in TempOut to System.out
     */
    public static void printTempOut() {
        stdOut.print(tempOutputStream);
    }

    /**
     * Method used to print the contents in TempErr to System.out
     */
    public static void printTempErr() {
        stdOut.print(tempErrorStream);
    }

    public static void assertSuccessfulExecution(String[] args) {
        try {
            TestUtils.flushTempOut();
            signserver.main(args);
        } catch (ExitException e) {
            TestUtils.printTempErr();
            TestUtils.printTempOut();
            Assert.assertTrue(false);
        }
    }

    public static void assertSuccessfulExecution(Object o, String[] args) {
        try {
            TestUtils.flushTempOut();
            Method m = o.getClass().getMethod("main", String[].class);
            Object[] arguments = {args};
            m.invoke(o, arguments);
        } catch (ExitException e) {
            TestUtils.printTempErr();
            TestUtils.printTempOut();
            Assert.assertTrue(false);
        } catch (SecurityException e) {
            Assert.assertTrue(false);
            e.printStackTrace();
        } catch (NoSuchMethodException e) {
            Assert.assertTrue(false);
            e.printStackTrace();
        } catch (IllegalArgumentException e) {
            Assert.assertTrue(false);
            e.printStackTrace();
        } catch (IllegalAccessException e) {
            Assert.assertTrue(false);
            e.printStackTrace();
        } catch (InvocationTargetException e) {
            if (!(e.getTargetException() instanceof ExitException)) {
                Assert.assertTrue(false);
                e.printStackTrace();
            }
        }
    }

    public static int assertFailedExecution(String[] args) {
        try {
            TestUtils.flushTempOut();
            signserver.main(args);
            Assert.assertTrue(false);
        } catch (ExitException e) {
            return e.number;
        }
        return 0;
    }

    public static int assertFailedExecution(Object o, String[] args) {
        try {
            TestUtils.flushTempOut();
            Method m = o.getClass().getMethod("main", String[].class);
            Object[] arguments = {args};
            m.invoke(o, arguments);
            Assert.assertTrue(false);
        } catch (ExitException e) {
            return e.number;
        } catch (NoSuchMethodException e) {
            e.printStackTrace();
            Assert.assertTrue(false);
        } catch (IllegalArgumentException e) {
            e.printStackTrace();
            Assert.assertTrue(false);
        } catch (IllegalAccessException e) {
            e.printStackTrace();
            Assert.assertTrue(false);
        } catch (InvocationTargetException e) {
            if (e.getTargetException() instanceof ExitException) {
                return ((ExitException) e.getTargetException()).number;
            }
        }
        return 0;
    }
}
