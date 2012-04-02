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

import java.util.Collection;

/**
 * Interface for Command factories.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public interface CommandFactory {

    /**
     * Initialize this CommandFactory.
     *
     * @param context The factory context
     */
    void init(CommandFactoryContext context);
    
    /**
     * @return True if this CommandFactory has been initialized
     */
    boolean isInitialized();
    
    /**
     * Get a command given the provided command line.
     * @param args Command line
     * @return The matching command or null if none
     */
    Command getCommand(String... args);
    
    /**
     * @return Collection of all top-level commands
     */
    Collection<Command> getTopLevelCommands();
    
    /**
     * @return Collection of all command groups
     */
    Collection<String> getCommandGroups();

    /**
     * Query all sub commands in the given group.
     * @param group name to query
     * @return Collection of all commands in the group
     */
    Collection<Command> getSubCommands(String group);
    
}
