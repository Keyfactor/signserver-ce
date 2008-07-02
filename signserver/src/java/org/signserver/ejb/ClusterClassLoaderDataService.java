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
 
package org.signserver.ejb;

import java.util.ArrayList;
import java.util.HashMap;

import javax.persistence.EntityManager;

import org.apache.log4j.Logger;

/**
 * Contains help method to make queries to the
 * resource repository in database. 
 */


public class ClusterClassLoaderDataService {
 
	public transient Logger log = Logger.getLogger(this.getClass());
	
	private EntityManager em;

	private String moduleName;

	private String part;

	private int version;
	
	private static HashMap<String, String> typeMapper = new HashMap<String,String>();
	// Add typeMapper mappings, should be all lower case.
	static{
		typeMapper.put("jpg", "jpeg");
	}
	
	public ClusterClassLoaderDataService(EntityManager em, String moduleName){
		this.em = em;
		this.moduleName = moduleName;
		this.part = "server";
		this.version = 1;
	}
	
	public ClusterClassLoaderDataService(EntityManager em, String moduleName, int version){
		this.em = em;
		this.moduleName = moduleName;
		this.part = "server";
		this.version = version;
	}
	
	public ClusterClassLoaderDataService(EntityManager em, String moduleName, String part, int version){
		this.em = em;
		this.moduleName = moduleName;
		this.part = part;
		this.version = version;
	}


    
	/**
     * Method to find resource data for a given resource name.
     */
    public ClusterClassLoaderDataBean findByResourceName(String resourceName){    	
    	try{
    		return (ClusterClassLoaderDataBean) em.createNamedQuery("ClusterClassLoaderDataBean.findByResourceName")
    		.setParameter(1, resourceName)
    		.setParameter(2, moduleName)
    		.setParameter(3, part)
    		.setParameter(4, version)
    		.getSingleResult();
    	}catch(javax.persistence.NoResultException e){}
    	
    	return null;
    }
	
	/**
     * Method to find the latest version of the resource of
     * 0 in no resource of that name could be found.
     */
    public int findLatestVersionOfResource(String resourceName){    	
    	try{
    		return (Integer) em.createNamedQuery("ClusterClassLoaderDataBean.findLatestVersionOfResource")
    		.setParameter(1, resourceName)
    		.getSingleResult();
    	}catch(javax.persistence.NoResultException e){}
    	
    	return 0;
    }
    
	/**
     * Method to find the latest version of the resource of
     * 0 in no resource of that name could be found.
     */
    public int findLatestVersionOfModule(String moduleName){    	
    	try{
    		return (Integer) em.createNamedQuery("ClusterClassLoaderDataBean.findLatestVersionOfModule")
    		.setParameter(1, moduleName)
    		.getSingleResult();
    	}catch(javax.persistence.NoResultException e){}
    	
    	return 0;
    }
    
    
	@SuppressWarnings("unchecked")
	public java.util.Collection<ClusterClassLoaderDataBean> findResources(){
    	try{
    		return em.createNamedQuery("ClusterClassLoaderDataBean.findResources")
    		.setParameter(1, moduleName)
    		.setParameter(2, part)
    		.setParameter(3, version)
    		.getResultList();
    	}catch(javax.persistence.NoResultException e){}
    	return new ArrayList<ClusterClassLoaderDataBean>();
    }
	
	@SuppressWarnings("unchecked")
	public java.util.Collection<ClusterClassLoaderDataBean> findAllResourcesInModule(){
    	try{
    		return em.createNamedQuery("ClusterClassLoaderDataBean.findAllResourcesInModule")
    		.setParameter(1, moduleName)
    		.setParameter(2, version)
    		.getResultList();
    	}catch(javax.persistence.NoResultException e){}
    	return new ArrayList<ClusterClassLoaderDataBean>();
    }
	
	@SuppressWarnings("unchecked")
	public java.util.Collection<ClusterClassLoaderDataBean> findImplementorsInModule(String interfaceName){
    	try{
    		return em.createNamedQuery("ClusterClassLoaderDataBean.findImplementorsInModule")
    		.setParameter(1, interfaceName)
    		.setParameter(2, moduleName)
    		.setParameter(3, part)
    		.setParameter(4, version)
    		.getResultList();
    	}catch(javax.persistence.NoResultException e){}
    	return new ArrayList<ClusterClassLoaderDataBean>();
    }
	
	
		
    
    /**
     * Method generating type from a resource name postfix, supports
     * multiple names for one type of file, for instance will
     * both 'jpeg' and 'jpg' result in the type 'jpeg'.
     * @param resourceName
     * @return
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
