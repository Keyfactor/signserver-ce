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
package org.signserver.cli.spi;

import java.io.PrintStream;
import java.util.Properties;

/**
 * Context for command factories.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class CommandFactoryContext {
    private Properties configuration;
    private PrintStream outputStream;
    private PrintStream errorStream;

    public CommandFactoryContext(Properties configuration, PrintStream outputStream, PrintStream errorStream) {
        this.configuration = configuration;
        this.outputStream = outputStream;
        this.errorStream = errorStream;
    }

    public PrintStream getErrorStream() {
        return errorStream;
    }

    public PrintStream getOutputStream() {
        return outputStream;
    }

    public Properties getConfiguration() {
        return configuration;
    }
    
}
