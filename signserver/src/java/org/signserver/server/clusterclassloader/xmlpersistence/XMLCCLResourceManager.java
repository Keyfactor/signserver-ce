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

import java.io.File;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;

import org.apache.log4j.Logger;
import org.signserver.server.clusterclassloader.BaseClusterClassLoaderDataService;
import org.signserver.server.clusterclassloader.IClusterClassLoaderDataBean;



/**
 * Helper class mainly used by to manage cluster class loader data.
 * 
 * 
 * @author Philip Vendil 31 jul 2008
 *
 * @version $Id$
 */
public class XMLCCLResourceManager {
	
	/** Log4j instance for actual implementation class */
	public static transient Logger log = Logger.getLogger(XMLCCLResourceManager.class);
	
	/** Path to the location were the XML file is located **/
	static String xMLFileLocation = null;
	
	private static JAXBContext jaxbContext = null;
	
    static{
		try{
			jaxbContext = JAXBContext.newInstance(org.signserver.server.clusterclassloader.xmlpersistence.XMLClusterClassLoaderDataList.class,org.signserver.server.clusterclassloader.xmlpersistence.XMLClusterClassLoaderDataBean.class);
		}catch(JAXBException e){
			log.error(e.getMessage(),e);
		}
    }
		
    /** Map of '<moduleName>;<version>;<part>' to another map of 'resourceName' -> data bean*/
	private static HashMap<String,HashMap<String,IClusterClassLoaderDataBean>> availableModules= null;
	/** Map of '<moduleName>;<version>' to a set of parts in that module. */
	private static HashMap<String,Set<String>> partsInModule = null;
	/** Map of '<moduleName>' to all available versions */
	private static HashMap<String,Set<Integer>> versionsOfModule = null;
	
	/** 
	 * Method used to add a resource to the cluster class loader.
	 * Works very similar to the EJB method in the SignServer but have a special behavior to
	 * save it's content after a moduleName have a 'null' value. This to avoid unnecessary writes
	 * to the file system when batch uploading resources.
	 * 
	 * @param moduleName the name of the module, a 'null' value signals that the data service should save
	 * the current memory database. 
	 * @param part the name of the module part
	 * @param version the version of the module
	 * @param jarName the name of the jar containing the resource
	 * @param resourceName the full name of the resource
	 * @param implInterfaces all interfaces implemented if the resource is a class.
	 * @param description optional description of the resource
	 * @param comment optional comment of the resource
	 * @param resourceData the actual resource data
	 */
	public static void addResource(String moduleName, String part, int version, String jarName, String resourceName, String implInterfaces, String description, String comment, byte[] resourceData){
		log.debug("Creating resource data for resource name=" + resourceName + ", modulename=" + moduleName + ", part=" + part + ", version " +version);
		
		
		if(moduleName == null){
			saveData();
			loadData();
		}else{
			IClusterClassLoaderDataBean cldb = new XMLClusterClassLoaderDataBean();
			cldb.setResourceName(resourceName);
			cldb.setJarName(jarName);
			cldb.setModuleName(moduleName);
			cldb.setPart(part);
			cldb.setType(BaseClusterClassLoaderDataService.getType(resourceName));
			cldb.setVersion(version);
			cldb.setResourceData(resourceData);
			cldb.setDescription(description);
			cldb.setComment(comment);
			cldb.setTimeStamp(System.currentTimeMillis());
			cldb.setImplInterfaces(implInterfaces);
			
			HashMap<String, IClusterClassLoaderDataBean> resources = getAvailableResources(moduleName, part, version);
			resources.put(resourceName, cldb);						
		}
	}
	
	/**
	 * Method removing the specified part of the given module
	 * @param moduleName the name of the module.
	 * @param part the part of the module to remove
	 * @param version the version of the module
	 */
	public static void removeModulePart(String moduleName, String part, int version){
		getAvailableModules().remove(moduleName + ";" + version + ";" + part);
		saveData();
		loadData();
	}
	
	/**
	 * 
	 * @return a list of all module names in the system.
	 */
	public static String[] listAllModules(){
		if(versionsOfModule == null){
			loadData();
		}
		if(versionsOfModule.keySet().size() == 0){
			return new String[0];
		}
		return versionsOfModule.keySet().toArray(new String[0]);
	}
	
	/**
	 * 
	 * @return a list of all version for the specified module.
	 */
	public static Integer[] listAllModuleVersions(String moduleName){
		if(versionsOfModule.get(moduleName) == null){
			return new Integer[0];
		}
		return versionsOfModule.get(moduleName).toArray(new Integer[0]);
	}
	
	/**
	 * 
	 * @return a list of all parts for the specified module.
	 */
	public static String[] listAllModuleParts(String moduleName, int version){
		if(partsInModule.get(moduleName + ";" + version) == null){
			return new String[0];
		}
		return partsInModule.get(moduleName + ";" + version).toArray(new String[0]);
	}
	
	/**
	 * Lists all jars in the given module part.
	 * @param moduleName the name of the module
	 * @param part the name of the part in the module
	 * @param version the version
	 * @return an array of jar names in the module.
	 */
	public static String[] getJarNames(String moduleName, String part, int version){
		HashMap<String,IClusterClassLoaderDataBean> resources = getAvailableResources(moduleName, part, version);
		HashSet<String> jarNames = new HashSet<String>();
		
		for(IClusterClassLoaderDataBean next : resources.values()){
			jarNames.add(next.getJarName());
		}
		
		return jarNames.toArray(new String[0]);
		
	}
	
	/**
	 * Method that returns a hash map containing all resources connected to a specified module. 
	 * 
	 * @param moduleName
	 * @param part
	 * @param version
	 */
	public static HashMap<String,IClusterClassLoaderDataBean> getAvailableResources(String moduleName, String part, int version){
		HashMap<String,IClusterClassLoaderDataBean> retval= getAvailableModules().get(moduleName + ";" + version + ";" + part);
		if(retval == null){
			retval = new HashMap<String,IClusterClassLoaderDataBean>();
			availableModules.put(moduleName + ";" + version + ";" + part, retval);
		}
		return retval;
	}
	
	
	/**
	 * Method that returns all versions of the specified module, or null if no module with the specified name
	 * exists.
	 * @param moduleName
	 */
	public static Set<Integer> getVersionsOfModule(String moduleName){
		if(versionsOfModule.get(moduleName) == null){
			return new HashSet<Integer>();
		}
		return versionsOfModule.get(moduleName);
	}
	
	private static HashMap<String,HashMap<String,IClusterClassLoaderDataBean>> getAvailableModules(){
		if(availableModules == null){
			loadData();
		}
		return availableModules;
	}

	/**
	 * Method that reads all the resource data from file into memory.
	 */
	private static void loadData() {
		try{
			Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();
			XMLClusterClassLoaderDataList resources = new XMLClusterClassLoaderDataList();
			if(new File(getXMLFileLocation()).exists()){
			  resources = (XMLClusterClassLoaderDataList) unmarshaller.unmarshal(new File(getXMLFileLocation()));
			}
			
			availableModules = new HashMap<String, HashMap<String,IClusterClassLoaderDataBean>>();
			partsInModule = new HashMap<String, Set<String>>();
			versionsOfModule = new HashMap<String, Set<Integer>>();
			
			for(XMLClusterClassLoaderDataBean next : resources.getList()){
				String uniqueName = next.getModuleName() + ";" + next.getVersion() + ";" + next.getPart();
				HashMap<String,IClusterClassLoaderDataBean> availableResources = availableModules.get(uniqueName);
				if(availableResources == null){
					availableResources = new HashMap<String,IClusterClassLoaderDataBean>();
					availableModules.put(uniqueName, availableResources);
				}
				availableResources.put(next.getResourceName(), next);
				
				String moduleAndVersion = next.getModuleName() + ";" + next.getVersion();
				Set<String> parts = partsInModule.get(moduleAndVersion);
				if(parts == null){
					parts = new HashSet<String>(); 
					partsInModule.put(moduleAndVersion, parts);
				}
				parts.add(next.getPart());
				
				String moduleName = next.getModuleName();
				Set<Integer> versions = versionsOfModule.get(moduleName);
				if(versions == null){
					versions = new HashSet<Integer>();
					versionsOfModule.put(moduleName, versions);
				}
				versions.add(next.getVersion());
			}
			
		}catch(JAXBException e){
			log.error("Error loading Cluster Class Loader data from XML File, error : " + e.getMessage(),e);
		}		
	}
	


	/**
	 * Method that writes all the resource data to file.
	 */
	private static void saveData() {
		XMLClusterClassLoaderDataList resources = new XMLClusterClassLoaderDataList();
		for(HashMap<String, IClusterClassLoaderDataBean> moduleResources : availableModules.values()){
			for(IClusterClassLoaderDataBean next : moduleResources.values()){
				resources.add((XMLClusterClassLoaderDataBean) next);
			}
		}
		
		try {
			Marshaller marshaller = jaxbContext.createMarshaller();
			marshaller.marshal(resources, new File(getXMLFileLocation()));
		} catch (JAXBException e) {
			log.error("Error storing Cluster Class Loader data into XML File, error : " + e.getMessage(),e);
		}
		
		availableModules = null;
		partsInModule = null;
		versionsOfModule = null;

	}

	private static String getXMLFileLocation() {
		if(xMLFileLocation == null){
			   String phoenixhome = System.getenv("PHOENIX_HOME");
			   File confDir = new File(phoenixhome +"/conf");
			   if(phoenixhome != null && confDir.exists()){
				   xMLFileLocation  = phoenixhome +"/conf/cclresources.xml";
			   }			   
		}
		if(xMLFileLocation == null){
			   String signserverhome = System.getenv("SIGNSERVER_HOME");
			   if(signserverhome == null){
				   log.error("Error: Environment variable SIGNSERVER_HOME isn't set");
			   }
			   xMLFileLocation  = signserverhome +"/extapps/james/conf/cclresources.xml";
		}
		return xMLFileLocation;
	}
}
