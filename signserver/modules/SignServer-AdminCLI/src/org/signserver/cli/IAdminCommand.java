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
package org.signserver.cli;

/**
 * Interface for Commands used for admin cmdline GUI
 *
 * @version $Id$
 */
public interface IAdminCommand {

    /**
     * Runs the command
     *
     * @throws IllegalAdminCommandException Error in command args
     * @throws ErrorAdminCommandException Error running command
     */
    void execute(String hostname) throws IllegalAdminCommandException, ErrorAdminCommandException;
    
    /**
     * Type of command that only need to call the master node
     * to affect the entire cluster.
     */
    int TYPE_EXECUTEONMASTER = 1;
    
    /**
     * Type of command that needs one call for every node
     * in the cluster
     */
    int TYPE_EXECUTEONALLNODES = 2;

    /**
     * Method returning on of the TYPE_ constants.
     */
    int getCommandType();
}
