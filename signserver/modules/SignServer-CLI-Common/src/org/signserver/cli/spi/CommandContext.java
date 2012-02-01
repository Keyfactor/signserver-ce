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
 *
 * @author Markus Kilås
 */
public class CommandContext {
    private String command;
    
    private CommandFactoryContext factoryContext;
    
    private String usagePrefix;
    
    private String commandGroup;

    public CommandContext(String commandGroup, String command, CommandFactoryContext factoryContext) {
        this.command = command;
        this.commandGroup = commandGroup;
        this.factoryContext = factoryContext;
    }
    
    public String getCommand() {
        return command;
    }
    
    public String getCommandGroup() {
        return commandGroup;
    }

    public CommandFactoryContext getFactoryContext() {
        return factoryContext;
    }

    public void setUsagePrefix(String usagePrefix) {
        this.usagePrefix = usagePrefix;
    }
    
    protected String getUsagePrefix() {
        return usagePrefix;
    }
}
