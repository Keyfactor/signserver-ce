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

import java.util.HashMap;

import javax.persistence.EntityManager;

import org.apache.log4j.Logger;

/**
 * Contains help method to make queries to the
 * resource repository in database. 
 */


public abstract class BaseClusterClassLoaderDataService implements IClusterClassLoaderDataService {
 
	public transient Logger log = Logger.getLogger(this.getClass());
	
	protected EntityManager em;

	protected String moduleName;

	protected String part;

	protected int version;
	
	protected static HashMap<String, String> typeMapper = new HashMap<String,String>();
	// Add typeMapper mappings, should be all lower case.
	static{
		typeMapper.put("jpg", "jpeg");
	}
	
	public BaseClusterClassLoaderDataService(EntityManager em, String moduleName){
		this.em = em;
		this.moduleName = moduleName;
		this.part = "server";
		this.version = 1;
	}
	
	public BaseClusterClassLoaderDataService(EntityManager em, String moduleName, int version){
		this.em = em;
		this.moduleName = moduleName;
		this.part = "server";
		this.version = version;
	}
	
	public BaseClusterClassLoaderDataService(EntityManager em, String moduleName, String part, int version){
		this.em = em;
		this.moduleName = moduleName;
		this.part = part;
		this.version = version;
	}

    
    /**
     * Method generating type from a resource name postfix, supports
     * multiple names for one type of file, for instance will
     * both 'jpeg' and 'jpg' result in the type 'jpeg'.
     * @param resourceName
     */
    public static String getType(String resourceName) {
    	if(resourceName.endsWith(".")){
    		return "";
    	}
		String type = resourceName.substring(resourceName.lastIndexOf('.') + 1);
		type = type.toLowerCase();
		if(typeMapper.get(type) != null){
			type = typeMapper.get(type);
		}
		return type;
	}
}
