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
import java.io.IOException;
import java.io.PrintStream;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import junit.framework.TestCase;
import org.signserver.cli.CommandLineInterface;
import org.signserver.cli.spi.UnexpectedCommandFailureException;

/**
 * Helper methods for executing AdminCLI commands.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class CLITestHelper {
  
    private ByteArrayOutputStream out;
    private ByteArrayOutputStream err;
    
    private Class<? extends CommandLineInterface> cliClazz;

    public CLITestHelper(Class<? extends CommandLineInterface> cli) {
        this.cliClazz = cli;
    }
    
    public int execute(String... args) throws UnexpectedCommandFailureException, IOException {
        out = new ByteArrayOutputStream();
        err = new ByteArrayOutputStream();
        try {
            CommandLineInterface cli = cliClazz.newInstance();
            cli.setOut(new PrintStream(new TeeOutputStream(/*System.out, */out)));
            cli.setErr(new PrintStream(new TeeOutputStream(System.err, err)));
            return cli.execute(args);
        } catch (IllegalAccessException ex) {
            throw new UnexpectedCommandFailureException(ex);
        } catch (InstantiationException ex) {
            throw new UnexpectedCommandFailureException(ex);
        }
    }

    public ByteArrayOutputStream getErr() {
        return err;
    }

    public ByteArrayOutputStream getOut() {
        return out;
    }
    
    /**
     * A simple grep utility that searches a byte stream if the substring exists.
     * @param stream the output stream to grep in
     * @param searchString the text to search for.
     * @return true if searchString exists
     */
    private static boolean grep(ByteArrayOutputStream stream, String searchString) {
        Pattern p = Pattern.compile(searchString);
        // Create a matcher with an input string
        Matcher m = p.matcher(stream.toString());
        return m.find();
    }
    
    public static void assertPrinted(String message, ByteArrayOutputStream stream, String searchString) {
        TestCase.assertTrue(message + ", expected: " + searchString, grep(stream, searchString));
    }
    
    public static void assertNotPrinted(String message, ByteArrayOutputStream stream, String searchString) {
        TestCase.assertFalse(message + ", should not match: " + searchString, grep(stream, searchString));
    }
    
}
