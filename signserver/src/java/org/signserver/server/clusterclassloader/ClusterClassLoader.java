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

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import javax.persistence.EntityManager;

import org.apache.log4j.Logger;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.SignServerException;
import org.signserver.common.clusterclassloader.ClusterClassLoaderUtils;
import org.signserver.ejb.ClusterClassLoaderDataService;
import org.signserver.server.clusterclassloader.xmlpersistence.XMLClusterClassLoaderDataService;

/**
 * Class loader used to find all classes that implements interfaces 
 * of a collection of classes. 
 * 
 * Should only be used temporary when uploading a plug-in zip
 * to the ClusterClassLoader.
 * 
 * @author Philip Vendil 15 maj 2008
 *
 */

public class ClusterClassLoader extends ClassLoader {
	
	private transient Logger log = Logger.getLogger(this.getClass());
	
	protected static String[] SUPPORTED_CONFIGURATIONFILES = {".xml", ".properties"};
	
	/**
	 * HashMap containing class name of class and the actual class.
	 */
	private HashMap<String, byte[]> availableClasses = new HashMap<String,byte[]>();

	/**
	 * HashMap containing loaded classes by class name and Class
	 */
	HashMap<String, Class<?>> loadedClasses = new HashMap<String,Class<?>>();
	
	/**
	 * HashMap containing version mappings used during the rename process
	 */
	HashMap<String, String> mappings = new HashMap<String, String>();
	
	private IClusterClassLoaderDataService cclds = null;

	private int moduleVersion;
	private String moduleName;
	
	private boolean useClassVersions = true;
    /**
     * Constructor used when no version is configured, will find and use the
     * latest version of the given module.
     * @param em the Entity Manager, if null will the XMLPersistence be used instead of database. 
     * @param moduleName the name of the module
     * @param part the part that this cluster class loader should use as repository. 
     * 
     */
	public ClusterClassLoader(ClassLoader parent, EntityManager em, String moduleName, String part) {
		super(parent);
		IClusterClassLoaderDataService cclds;
		if(em != null){
          cclds = new ClusterClassLoaderDataService(em,moduleName);
		}else{
			cclds = new XMLClusterClassLoaderDataService(moduleName);			
		}
		int version = cclds.findLatestVersionOfModule(moduleName);
		init(em,GlobalConfiguration.isUseClassVersions(),moduleName,part,version);
	}
	


	/**
     * Constructor used when  version is configured.
     * @param em the Entity Manager
     * @param moduleName the name of the module 
     * @param part the part that this cluster class loader should use as repository.
     * @param version that should be used for this class loader. 
     * 
     */
	public ClusterClassLoader(ClassLoader parent, EntityManager em, String moduleName, String part, int version){
		super(parent);
		init(em,GlobalConfiguration.isUseClassVersions(),moduleName,part,version);
	}
	
	private void init(EntityManager em, boolean useClassVersions, String moduleName, String part,
			int version) {
		try{			
			this.useClassVersions = useClassVersions;
			if(em != null){
			  cclds = new ClusterClassLoaderDataService(em,moduleName,part,version);
			}else{
				cclds = new XMLClusterClassLoaderDataService(moduleName,part,version);
			}
			this.moduleVersion = version;
			this.moduleName = moduleName;
			Collection<IClusterClassLoaderDataBean> result = cclds.findResources();
			if(useClassVersions){
				for(IClusterClassLoaderDataBean next : result){					
					if(next.getResourceName().endsWith(".class")){
						defineAvailablePackage("v"+version+"/" + next.getResourceName());
						String strippedResourceName = ClusterClassLoaderUtils.stripClassPostfix(next.getResourceName());
						mappings.put(strippedResourceName, "v"+version+"/" + strippedResourceName);
					}else{
						defineAvailablePackage(next.getResourceName());
					}
				}
				for(IClusterClassLoaderDataBean next : result){
					if(next.getResourceName().endsWith(".class")){	
						byte[] injectedData =  performInjections(getVerifyResourceData(next.getResourceData()));
						availableClasses.put("v"+ version + "." + ClusterClassLoaderUtils.getClassNameFromResourcePath(next.getResourceName()), ClusterClassLoaderUtils.addVersionToClass(mappings, injectedData));					
					}
				}
			}else{
				for(IClusterClassLoaderDataBean next : result){
					defineAvailablePackage(next.getResourceName());
					if(next.getResourceName().endsWith(".class")){				
						byte[] injectedData =  performInjections(getVerifyResourceData(next.getResourceData()));
						availableClasses.put(ClusterClassLoaderUtils.getClassNameFromResourcePath(next.getResourceName()), injectedData);					
					}
				}
			}
			
			for(String classNames: availableClasses.keySet()){				
			  loadClass(classNames);
			}
		}catch (Exception e) {
			log.error("Error during initialization of cluster class loader, Exception of type : " + e.getClass().getSimpleName() + ", with a error messaage of  : " + e.getMessage(),e );
		}
	}
	




	/* (non-Javadoc)
	 * @see java.lang.ClassLoader#findClass(java.lang.String)
	 */
	@Override
	protected Class<?> findClass(String name) throws ClassNotFoundException {
		name = name.trim();		
		Class<?> retval = null;
		try{
			retval = getParent().loadClass(name);
		}catch(ClassNotFoundException e){			
			  if(loadedClasses.containsKey(name)){
				  retval = loadedClasses.get(name);
			  }else{
				  if(useClassVersions &&  !name.startsWith("v" + moduleVersion +".")){
					  name = "v" + moduleVersion + "." + name;
				  }
				  if(useClassVersions && loadedClasses.containsKey(name)){
					  retval = loadedClasses.get(name);
				  }else{
					  byte[] classData = availableClasses.get(name);
					  if(classData != null){
					    retval = defineClass(name, classData, 0, classData.length);
					    loadedClasses.put(name, retval);
					  }else{
						  log.debug("Error class with name : " + name + " couldn't be found in cluster class loader.");
					  }
				  }
			  }
		}
		
		if(retval == null){
			throw new ClassNotFoundException("Error class " + name + " not found.");
		}
		
		return retval;
	}

	/**
	 * Method that first looks up the resource in
	 * the cluster class loader repository before
	 * it is looked up in the parents repository.
	 * 
	 * @see java.lang.ClassLoader#getResourceAsStream(java.lang.String)
	 */
	@Override
	public InputStream getResourceAsStream(String name) {
		IClusterClassLoaderDataBean data = cclds.findByResourceName(ClusterClassLoaderUtils.normalizeResourcePath(name));
		if(data == null){
			return getParent().getResourceAsStream(name);
		}
		
		ByteArrayInputStream retval = null;
		try{ 
		  byte[] verifiedData = getVerifyResourceData(data.getResourceData());	
		  		  
		  if(useClassVersions){
			  verifiedData = insertVersionInConfigFiles(name, verifiedData);
		  }
		  retval = new ByteArrayInputStream(verifiedData);
		}catch(Exception e){
			log.error("Error fetching cluster class loader resource data as stream", e);
		}
				
		return retval;
	}
	
	
	
	private byte[] insertVersionInConfigFiles(String name,
			byte[] data) {
		byte[] retval = data;
		for(String supportedConfigFile : SUPPORTED_CONFIGURATIONFILES){
			if(name.endsWith(supportedConfigFile)){
				String config = new String(data);
				Iterator<String> iter = mappings.keySet().iterator();
				while(iter.hasNext()){
					String orgName = iter.next();
					String classVerName = mappings.get(orgName).replaceAll( "/","\\.");
					String classOrgName = orgName.replaceAll( "/","\\.");
					config = config.replaceAll(classOrgName, classVerName);
				}
				retval = config.getBytes();
				break;
			}
		}
		return retval;
	}



	/**
	 * @see java.lang.ClassLoader#findResource(java.lang.String)
	 */
	@Override
	protected URL findResource(String name) {
		IClusterClassLoaderDataBean data = cclds.findByResourceName(ClusterClassLoaderUtils.normalizeResourcePath(name));
		if(data == null){
			return getParent().getResource(name);
		}
		
		URL retval = null;
		try {
			retval = new URL(name);
		} catch (MalformedURLException e) {
			log.error(e);
		}
		
		return retval;
	}

	
	

    /**
     * Method that defines a package in the class loader
     * for all new packages.
     * 
     * module name and module version will be used for the
     * tags.
     * 
     * @param resourceName the full name of the resource, the
     * package name will be extracted from the resource path.
     * 
     */
	protected void defineAvailablePackage(String resourceName) {
		String name = ClusterClassLoaderUtils.getPackageFromResourceName(resourceName);
		if(!name.equals("") && getPackage(name) == null){
			definePackage(name, moduleName, "" +moduleVersion, "", moduleName, "" +moduleVersion, "", null);
		}
		
	}


	/**
	 * Help Method taking care if verification of resource data
	 * @param the stored resourceData
	 * @param the raw resource data.
	 * @throws CertificateException if certificates are invalid.
	 * @throws NoSuchAlgorithmException if requested algorithm isn't supported
	 * @throws KeyStoreException if trust store is invalid.
	 * @throws SignServerException if the data was unsigned and the configuration requires it.
	 * @throws SignatureException if signature of resource data didn't verify correctly
	 * @throws IOException if other I/O related error occurred.
	 */
	protected byte[] getVerifyResourceData(byte[] signedResourceData) throws SignatureException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, SignServerException{
		return ClusterClassLoaderUtils.verifyResourceData(signedResourceData, getTrustStore());
	}
	
	/**
	 * 
	 * @return the configured truststore on null if signing isn't required.
	 * @throws KeyStoreException 
	 * @throws IOException 
	 * @throws CertificateException 
	 * @throws NoSuchAlgorithmException 
	 */
	protected KeyStore getTrustStore() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException{
		if(!GlobalConfiguration.isRequireSigning()){
			return null;
		}
		if(trustStore == null){
		   File trustStoreFile = new File(GlobalConfiguration.getPathToTrustStore());
		   if(trustStoreFile.exists() && trustStoreFile.isFile() && trustStoreFile.canRead()){
			   try {
				FileInputStream fis = new FileInputStream(trustStoreFile);
				trustStore = KeyStore.getInstance("JKS");
				trustStore.load(fis,GlobalConfiguration.getCCLTrustStorePasswd());				
			} catch (FileNotFoundException e) {
				log.error("Error reading cluster class loader truststore : " + e.getMessage(), e);
			}	
		   }else{
			   log.error("Error check that the path to the cluster class loader trust store i set correctly : " + trustStoreFile.getPath());
		   }
		}
		return trustStore;
	}
	private KeyStore trustStore= null;
	
	/**
	 * Method that returns all implementations of a specific interface
	 * 
	 * 
	 * @param iface that the classes must implement
	 * @return a Set of classes that implements the specific interface, never null.
	 */
	public Set<Class<?>> getAllImplementations(Class<?> iface) {
		HashSet<Class<?>> retval = new HashSet<Class<?>>();
		
		
		for(Class<?> c : loadedClasses.values()){
			checkInterfaces(c, c, retval, iface);
		}
		
		return retval;
	}

	private void checkInterfaces(Class<?> topClass, Class<?> c,
			HashSet<Class<?>> classes, Class<?> iface) {
		if(c != null && !c.equals(Object.class)){
			for(Class<?> i : c.getInterfaces()){
				if(i.getName().equals(iface.getName())){
					classes.add(topClass);
				}
				checkInterfaces(topClass,i, classes, iface);
			}
			checkInterfaces(topClass, c.getSuperclass(), classes,iface);
		}		
	}
	
	/**
	 * Method called by the init method to perform injections
	 * of the byte code. This method is empty and doesn't
	 * perform any injections, but can be overloaded
	 * by subclasses
	 * 
	 * @param classData original class data.
	 * @return injected classData
	 */
	protected byte[] performInjections(byte[] classData){
		return classData;
	}
	
	
}
