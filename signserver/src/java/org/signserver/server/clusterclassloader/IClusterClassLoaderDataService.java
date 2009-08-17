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
package org.signserver.server.clusterclassloader;


/**
 * Interface containing all methods in common for different persistence implementations
 * of the Cluster Class Loader.
 *           
 * @author Philip Vendil
 */
public interface IClusterClassLoaderDataService {

	/**
	 * Method to find resource data for a given resource name.
	 */
	IClusterClassLoaderDataBean findByResourceName(String resourceName);

	/**
	 * 
	 * @return returns all resources in the service class configured module, version and part.
	 */
	java.util.Collection<IClusterClassLoaderDataBean> findResources();

	/**
	 * 
	 * @return returns all class resources that implements a given interface, useful for finding
	 * plug-in classes.
	 */
	java.util.Collection<IClusterClassLoaderDataBean> findImplementorsInModule(
			String interfaceName);
	
	/**
	 * Returns the latest version of an uploaded module 
	 * @param moduleName the name of the module.
	 */
	int findLatestVersionOfModule(String moduleName);

}