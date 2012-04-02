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
 * Class implementing many of the Command interface methods for convenience.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public abstract class AbstractCommand implements Command {

    protected PrintStream out;
    protected PrintStream err;
    
    private CommandContext context;
    
    /**
     * @see Command#init(org.signserver.cli.spi.CommandContext) 
     */
    @Override
    public void init(CommandContext context) {
        this.context = context;
        this.out = context.getFactoryContext().getOutputStream();
        this.err = context.getFactoryContext().getErrorStream();
    }
    
    /**
     * @see Command#getCommand() 
     */
    @Override
    public String getCommand() {
        return context.getCommand();
    }

    /**
     * @see Command#getCommandGroup() 
     */
    @Override
    public String getCommandGroup() {
        return context.getCommandGroup();
    }
    
    /**
     * @return The CLI configuration
     */
    protected Properties getConfiguration() {
        return context.getFactoryContext().getConfiguration();
    }
    
    /**
     * @return The CLI output stream
     */
    protected PrintStream getOutputStream() {
        return out;
    }
    
    /**
     * @return The CLI error stream
     */
    protected PrintStream getErrorStream() {
        return err;
    }
}
