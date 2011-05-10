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


import java.util.Collection;
import java.util.List;

import javax.ejb.Stateless;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.apache.log4j.Logger;
import org.signserver.ejb.interfaces.IClusterClassLoaderManagerSession;
import org.signserver.server.clusterclassloader.IClusterClassLoaderDataBean;
import org.signserver.server.clusterclassloader.IClusterClassLoaderDataService;

/**
 * The implementation of the IClusterClassLoaderManagerSession
 * 
 * 
 * 
 * @see org.signserver.ejb.interfaces.IClusterClassLoaderManagerSession 
 *           
 * @version $Id$
 */
@Stateless
public class ClusterClassLoaderManagerSessionBean implements IClusterClassLoaderManagerSession.ILocal, IClusterClassLoaderManagerSession.IRemote {
    @PersistenceContext(unitName="SignServerJPA")
    EntityManager em;
    
	private static final long serialVersionUID = 1L;
	
	
	/** Log4j instance for actual implementation class */
	private static final Logger log = Logger.getLogger(ClusterClassLoaderManagerSessionBean.class);
 
	/**
	 * 
	 */
	public ClusterClassLoaderManagerSessionBean() {
		super();
		// Do Nothing     
	}

	
	/**
	 * Method used to add a resource to the cluster class loader.
	 * @param moduleName the name of the module
	 * @param part the name of the module part
	 * @param version the version of the module
	 * @param jarName the name of the jar containing the resource
	 * @param resourceName the full name of the resource
	 * @param implInterfaces all interfaces implemented if the resource is a class.
	 * @param description optional description of the resource
	 * @param comment optional comment of the resource
	 * @param resourceData the actual resource data
	 */
	public void addResource(String moduleName, String part, int version, String jarName, String resourceName, String implInterfaces, String description, String comment, byte[] resourceData){
		if(moduleName == null){
			// special case where a XML back end i signaled to save it's data, but this is just ignored
			// for DB back ends.
			return;
		}
		log.debug("Creating resource data for resource name=" + resourceName + ", modulename=" + moduleName + ", part=" + part + ", version " +version);
		IClusterClassLoaderDataService s = new ClusterClassLoaderDataService(em,moduleName,part,version);
		
		IClusterClassLoaderDataBean cldb = s.findByResourceName(resourceName);
		if(cldb == null){
			cldb = new ClusterClassLoaderDataBean();
		}
		cldb.setResourceName(resourceName);
		cldb.setJarName(jarName);
		cldb.setModuleName(moduleName);
		cldb.setPart(part);
		cldb.setType(ClusterClassLoaderDataService.getType(resourceName));
		cldb.setVersion(version);
		cldb.setResourceData(resourceData);
		cldb.setDescription(description);
		cldb.setComment(comment);
		cldb.setTimeStamp(System.currentTimeMillis());
		cldb.setImplInterfaces(implInterfaces);

		em.persist(cldb);   
	}
	
	/**
	 * Method removing the specified part of the given module
	 * @param moduleName the name of the module.
	 * @param part the part of the module to remove
	 * @param version the version of the module
	 */
	public void removeModulePart(String moduleName, String part, int version){		
		ClusterClassLoaderDataService s = new ClusterClassLoaderDataService(em,moduleName,part,version);
		Collection<IClusterClassLoaderDataBean> result = s.findResources();
		for(IClusterClassLoaderDataBean next : result){
			em.remove(next);
		}
	}
	
	/**
	 * 
	 * @see org.signserver.ejb.interfaces.IClusterClassLoaderManagerSession#listAllModules()
	 */
	@SuppressWarnings("unchecked")
	public String[] listAllModules(){
    	try{
    		List<String> results = em.createNamedQuery("ClusterClassLoaderDataBean.findAllModules")
    		.getResultList();
    		String[] retval = new String[results.size()];
    		int i=0;
    		for(String data : results){
    			retval[i] = data;
    			i++;
    		}
    		
    		return retval;
    	}catch(javax.persistence.NoResultException e){}
    	return new String[0];
	}
	
	/**
	 * Lists all jars in the given module part.
	 * @param moduleName the name of the module
	 * @param part the name of the part in the module
	 * @param version the version
	 * @return an array of jar names in the module.
	 */
	@SuppressWarnings("unchecked")
	public String[] getJarNames(String moduleName, String part, int version){
	   	try{
    		List<String> results = em.createNamedQuery("ClusterClassLoaderDataBean.findAllJarsInPart")
    		.setParameter(1, moduleName)
    		.setParameter(2, part)
    		.setParameter(3, version)
    		.getResultList();
    		String[] retval = new String[results.size()];
    		int i=0;
    		for(String data : results){
    			retval[i] = data;
    			i++;
    		}
    		
    		return retval;
    	}catch(javax.persistence.NoResultException e){}
    	return new String[0];
	}
	




    /**
     * 
     * @see org.signserver.ejb.interfaces.IClusterClassLoaderManagerSession#listAllModuleParts(String, int)
     */
	@SuppressWarnings("unchecked")
	public String[] listAllModuleParts(String moduleName, int version) {
	   	try{
    		List<String> results = em.createNamedQuery("ClusterClassLoaderDataBean.findAllPartsOfModule")
    		.setParameter(1, moduleName)
    		.setParameter(2, version)
    		.getResultList();
    		String[] retval = new String[results.size()];
    		int i=0;
    		for(String data : results){
    			retval[i] = data;
    			i++;
    		}
    		
    		return retval;
    	}catch(javax.persistence.NoResultException e){}
    	return new String[0];
	}

    /**
     * 
     * @see org.signserver.ejb.interfaces.IClusterClassLoaderManagerSession#listAllModuleVersions(String)
     */
	@SuppressWarnings("unchecked")
	public Integer[] listAllModuleVersions(String moduleName) {
	   	try{
    		List<Integer> results = em.createNamedQuery("ClusterClassLoaderDataBean.findAllVersionOfModule")
    		.setParameter(1, moduleName)
    		.getResultList();
    		Integer[] retval = new Integer[results.size()];
    		int i=0;
    		for(Integer data : results){
    			retval[i] = data;
    			i++;
    		}
    		
    		return retval;
    	}catch(javax.persistence.NoResultException e){}
    	return new Integer[0];
	}

	

}
