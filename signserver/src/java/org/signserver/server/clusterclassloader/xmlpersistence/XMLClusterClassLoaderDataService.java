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

package org.signserver.server.clusterclassloader.xmlpersistence;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Set;

import org.signserver.server.clusterclassloader.BaseClusterClassLoaderDataService;
import org.signserver.server.clusterclassloader.IClusterClassLoaderDataBean;

/**
 * Helper class mainly used by the ClusterClassLoader to search for resource data
 * belonging to this worker.
 * 
 * 
 * @author Philip Vendil 31 jul 2008
 *
 * @version $Id$
 */

public class XMLClusterClassLoaderDataService extends
		BaseClusterClassLoaderDataService {
	
	private HashMap<String, IClusterClassLoaderDataBean> moduleResources = new HashMap<String, IClusterClassLoaderDataBean>();

	public XMLClusterClassLoaderDataService(String moduleName) {
		super(null, moduleName);
		moduleResources = XMLCCLResourceManager.getAvailableResources(moduleName, part, version);
	}

	public XMLClusterClassLoaderDataService(String moduleName, String part, int version) {
		super(null, moduleName, part, version);
		moduleResources = XMLCCLResourceManager.getAvailableResources(moduleName, part, version);
	}


	public XMLClusterClassLoaderDataService(String moduleName, int version) {
		super(null, moduleName, version);
		moduleResources = XMLCCLResourceManager.getAvailableResources(moduleName, part, version);
	}


	/**
	 * @see org.signserver.server.clusterclassloader.IClusterClassLoaderDataService#findByResourceName(java.lang.String)
	 */
	public IClusterClassLoaderDataBean findByResourceName(String resourceName) {		
		return moduleResources.get(resourceName);
	}

	/**
	 * @see org.signserver.server.clusterclassloader.IClusterClassLoaderDataService#findImplementorsInModule(java.lang.String)
	 */
	public Collection<IClusterClassLoaderDataBean> findImplementorsInModule(
			String interfaceName) {
		ArrayList<IClusterClassLoaderDataBean> retval = new ArrayList<IClusterClassLoaderDataBean>();
		
		for(IClusterClassLoaderDataBean next : moduleResources.values()){
			String[] allImpl = next.getImplInterfaces().split(";");
			for(String iface : allImpl){
				if(iface.equals(interfaceName)){
					retval.add(next);
				}
			}
		}
		
		return retval;
	}



	/**
	 * @see org.signserver.server.clusterclassloader.IClusterClassLoaderDataService#findResources()
	 */
	public Collection<IClusterClassLoaderDataBean> findResources() {
		return moduleResources.values();
	}

	/**
	 * @see org.signserver.server.clusterclassloader.IClusterClassLoaderDataService#findLatestVersionOfModule(String)
	 */
	public int findLatestVersionOfModule(String moduleName) {
		Set<Integer> versions = XMLCCLResourceManager.getVersionsOfModule(moduleName);
		if(versions.size() == 0){
		  return 0;
		}
		
		int retval = Integer.MIN_VALUE;
		for(int version : versions){
			if(version > retval){
				retval = version;
			}
		}
		
		return retval;
	}
	

}
