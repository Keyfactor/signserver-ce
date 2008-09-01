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
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.util.Collection;
import java.util.HashMap;

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

	private int version;
	
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
			this.version = version;
			Collection<IClusterClassLoaderDataBean> result = cclds.findResources();
			if(useClassVersions){
				for(IClusterClassLoaderDataBean next : result){
					if(next.getResourceName().endsWith(".class")){	
						String strippedResourceName = ClusterClassLoaderUtils.stripClassPostfix(next.getResourceName());
						mappings.put(strippedResourceName, "v"+version+"/" + strippedResourceName);
					}
				}
				for(IClusterClassLoaderDataBean next : result){
					if(next.getResourceName().endsWith(".class")){				
						availableClasses.put("v"+ version + "." + ClusterClassLoaderUtils.getClassNameFromResourcePath(next.getResourceName()), ClusterClassLoaderUtils.addVersionToClass(mappings, getVerifyResourceData(next.getResourceData())));					
					}
				}
			}else{
				for(IClusterClassLoaderDataBean next : result){
					if(next.getResourceName().endsWith(".class")){				
						availableClasses.put(ClusterClassLoaderUtils.getClassNameFromResourcePath(next.getResourceName()), getVerifyResourceData(next.getResourceData()));					
					}
				}
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
		
		Class<?> retval = null;
		try{
			retval = getParent().loadClass(name);
		}catch(ClassNotFoundException e){			
			  if(loadedClasses.containsKey(name)){
				  retval = loadedClasses.get(name);
			  }else{
				  if(useClassVersions &&  !name.startsWith("v" + version +".")){
					  name = "v" + version + "." + name;
				  }
				  if(useClassVersions && loadedClasses.containsKey(name)){
					  retval = loadedClasses.get(name);
				  }else{
					  byte[] classData = availableClasses.get(name);
					  retval = defineClass(name, classData, 0, classData.length);
					  loadedClasses.put(name, retval);
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
		IClusterClassLoaderDataBean data = cclds.findByResourceName(name);
		if(data == null){
			return getParent().getResourceAsStream(name);
		}
		ByteArrayInputStream retval = null;
		try{ 
		  retval = new ByteArrayInputStream(getVerifyResourceData(data.getResourceData()));			
		}catch(Exception e){
			log.error("Error fetching cluster class loader resource data as stream", e);
		}
		
		return retval;
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
	private byte[] getVerifyResourceData(byte[] signedResourceData) throws SignatureException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, SignServerException{
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
	private KeyStore getTrustStore() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException{
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

	
}
