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

import java.util.Properties;

import org.signserver.common.GlobalConfiguration;

/**
 * Cache used to store temporary data during a database failure
 * Should only be used from the GlobalConfigurationSessionBean!
 * 
 * @author Philip Vendil 2007 jan 22
 *
 * @version $Id$
 */ 

public class GlobalConfigurationCache {

	
	/**
	 * Cached configuration used for non-synced state.
	 */
	private static Properties cachedGlobalConfig = null;
	private static String currentState = GlobalConfiguration.STATE_INSYNC;

	public synchronized  static  Properties getCachedGlobalConfig() {
		return cachedGlobalConfig;
	}
	public synchronized static void setCachedGlobalConfig(Properties cachedGlobalConfig) {
		GlobalConfigurationCache.cachedGlobalConfig = cachedGlobalConfig;
	}
	public synchronized static String getCurrentState() {
		return currentState;
	}
	public synchronized static void setCurrentState(String currentState) {
		GlobalConfigurationCache.currentState = currentState;
	}

}
