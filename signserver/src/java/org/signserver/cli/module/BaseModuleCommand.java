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

package org.signserver.cli.module;

import org.signserver.cli.BaseCommand;
import org.signserver.common.GlobalConfiguration;



/**
 * Command containing common help methods for module commands
 * used to manage the cluster class loader. 
 *
 * @version $Id$
 * @author Philip Vendil
 */
public abstract class BaseModuleCommand extends BaseCommand {
	
	
	
    /**
     * 
     *
     * @param args command line arguments
     */
    public BaseModuleCommand(String[] args) {
        super(args);
    }

    protected boolean isClusterClassLoaderEnabled(){
    	boolean retval = GlobalConfiguration.isClusterClassLoaderEnabled();
    	if(retval){
    		getOutputStream().println("Using cluster class loader.\n");
    	}else{
    		getOutputStream().println("ERROR: Module (Cluster Class Loader) functionality is disabled");
    	}
    	return retval;
    }

    // execute
}
