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

/**
 * Class implementing the command context.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class CommandContext {
    private String command;
    
    private CommandFactoryContext factoryContext;
    
    private String usagePrefix;
    
    private String commandGroup;

    /**
     * Creates a new instance of CommandContext.
     *
     * @param commandGroup Name of the command group
     * @param command Name of the command
     * @param factoryContext The factory context
     */
    public CommandContext(String commandGroup, String command, CommandFactoryContext factoryContext) {
        this.command = command;
        this.commandGroup = commandGroup;
        this.factoryContext = factoryContext;
    }
    
    /**
     * @return The name of the command
     */
    public String getCommand() {
        return command;
    }
    
    /**
     * @return The name of the command group
     */
    public String getCommandGroup() {
        return commandGroup;
    }

    /**
     * @return The associated factory context
     */
    public CommandFactoryContext getFactoryContext() {
        return factoryContext;
    }

    /**
     * Sets the usage prefix.
     * @param usagePrefix The prefix to set
     */
    public void setUsagePrefix(String usagePrefix) {
        this.usagePrefix = usagePrefix;
    }
    
    /**
     * @return The usage prefix
     */
    protected String getUsagePrefix() {
        return usagePrefix;
    }
}
