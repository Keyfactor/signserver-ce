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

package org.signserver.server;

import java.util.Date;
import java.util.Properties;

/**
 * Interface defining a accurate time source, could be the local computer clock or a connection to a time device
 * 
 * Its main function is getGenTime returning a java.util.Date
 * 
 * @author philip
 * £Id$
 */
public interface ITimeSource {

 	   /** 
	    * Method called after creation of instance.
	    * Contains the signers properties
	    */	
		public abstract void init(Properties props);
		
		
		/**
		 * Main method that should retrieve the current time from the device.
		 * @return an accurate current time.
		 */
		public abstract Date getGenTime();
	
	
}
