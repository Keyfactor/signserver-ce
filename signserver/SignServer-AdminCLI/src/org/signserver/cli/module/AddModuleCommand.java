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

package org.signserver.cli.module;

import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Map;
import java.util.Properties;
import java.util.jar.JarInputStream;

import org.signserver.cli.ErrorAdminCommandException;
import org.signserver.cli.IllegalAdminCommandException;
import org.signserver.cli.SetPropertiesHelper;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.SignServerConstants;
import org.signserver.common.clusterclassloader.ClusterClassLoaderUtils;
import org.signserver.common.clusterclassloader.FindInterfacesClassLoader;
import org.signserver.common.clusterclassloader.MARFileParser;



/**
 * Command used to add a  modules to the cluster class loader 
 *
 * @version $Id$
 * @author Philip Vendil
 */
public class AddModuleCommand extends BaseModuleCommand {
	
    private String keyStorePath;
	private String keyStoreAlias;
	private String keyStorePwd;

	/**
     * Creates a new instance of RemoveModuleCommand
     *
     * @param args command line arguments
     */
    public AddModuleCommand(String[] args) {
        super(args);
    }

    /**
     * Runs the command
     *
     * @throws IllegalAdminCommandException Error in command args
     * @throws ErrorAdminCommandException Error running command
     */
    public void execute(String hostname) throws IllegalAdminCommandException, ErrorAdminCommandException {
    	if(!isClusterClassLoaderEnabled()){
    		System.exit(-1);
    	}
        if (args.length < 3 || args.length > 7 ||  args.length == 5) {
	       throw new IllegalAdminCommandException("Usage:\n signserver module add <path-to-marfile> <environment (optional)>\n" +
	    		                                  "or if module signing is required :\n"+
	    		                                  " signserver module add <path-to-marfile> <sign-keystore> <keystore-alias> <keystore-pwd> <environment (optional)>\n\n"  +
	    		                                  "Where : \n" +
	    		                                  "  path-to-marfile : The location of the module file\n"+
	    		                                  "  sign-keystore   : The location to the JKS keystore performing the signature\n"+
	    		                                  "  keystore-alias  : The key alias in the key store\n"+
	    		                                  "  keystore-pwd    : The password to unlock the keystore\n"+
	    		                                  "  environment     : The module configuration to load (optional)\n\n"+
	    		                                  "Example 1: 'signserver module add /tmp/testmodule.mar'\n"+
	    		                                  "Example 2: 'signserver module add /tmp/testmodule.mar production'\n"+
	    		                                  "Example 3: 'signserver module add /tmp/testmodule.mar signkeys.jks mysignkey mypwd testenv'\n\n");
	       		                                  	       
	    }	
        
        String marPath = args[2];
        
        File marFile = new File(marPath);
        if(!marFile.exists() || !marFile.isFile() || !marFile.canRead()){
 	       throw new IllegalAdminCommandException("Usage: Error path to module archive " + marPath + " doesn't seem valid, make" +
 	       		                                  "sure the file exists and is readable.");
        }
        
        String environment = null;
        keyStorePath = null;
        keyStoreAlias = null;
        keyStorePwd = null;
        if(args.length == 4){
        	environment = args[3];
        }
        if(args.length > 5 ){
        	keyStorePath = args[3];
        	keyStoreAlias = args[4];
        	keyStorePwd = args[5];
        	if(args.length == 7){
        	  environment = args[6];
        	}
        }
        
        try {    
    		MARFileParser mARFileParser = new MARFileParser(marPath);
    		String moduleName = mARFileParser.getModuleName();
    		int version = mARFileParser.getVersionFromMARFile();
    		String[] parts = mARFileParser.getMARParts();
    		
    		getOutputStream().println("Loading module " + moduleName + " with version " + version + " ....");
    						
    		for(String part : parts){
    		  getOutputStream().println("Loading part " + part + " ....");
    		  FindInterfacesClassLoader ficl = new FindInterfacesClassLoader(mARFileParser,part,getOutputStream());
    		  Map<String, JarInputStream> jarContents = mARFileParser.getJARFiles(part);
    		  for(String jarName : jarContents.keySet()){
    			Map<String, byte[]> jarContent = mARFileParser.getJarContent(jarContents.get(jarName));
    			for(String resourceName : jarContent.keySet()){
    				if(!resourceName.endsWith("/")){
    					getCommonAdminInterface(hostname).addResource(moduleName, part, version, jarName, resourceName, appendAllInterfaces(ficl.getImplementedInterfaces(resourceName)), null, null, signContent(jarContent.get(resourceName)));
    				}
    			}			
    		  }
    		  addPartProperties(hostname, mARFileParser, part, environment);
    		}
    		//Signal to save (only used by the mailsigner, ignored by the signserver)
    		getCommonAdminInterface(hostname).addResource(null, null, 0, null, null, null, null, null,null );
    		getOutputStream().println("Module loaded successfully.");
        } catch (IllegalAdminCommandException e) {
        	throw e;                    
        } catch (Exception e) {
        	throw new ErrorAdminCommandException(e);            
        }
    }



    /**
     * Method signing content
     * @param content
     * @return signed content if it's required.
     * @throws Exception 
     */
	private byte[] signContent(byte[] content) throws Exception {		
		return ClusterClassLoaderUtils.generateCMSMessageFromResource(content, getSignerCert(), getSigningKey(), "BC");
	}

	private PrivateKey signingKey=null;
	private PrivateKey getSigningKey() throws Exception {
		if(keyStorePath != null && signingKey== null){
			KeyStore ks = getSignKeyStore();
			signingKey = (PrivateKey) ks.getKey(keyStoreAlias, keyStorePwd.toCharArray());
			if(signingKey == null){
				throw new IllegalAdminCommandException("Error: given alias '" + keyStoreAlias + "' doesn't exist in keystore '"+keyStorePath+"'");
			}
		}
		return signingKey;
	}

	private X509Certificate signerCert= null;
	private X509Certificate getSignerCert() throws Exception {
		if(keyStorePath != null && signerCert== null){
			KeyStore ks = getSignKeyStore();
			signerCert =  (X509Certificate) ks.getCertificate(keyStoreAlias);
			if(signerCert == null){
				throw new IllegalAdminCommandException("Error: given alias '" + keyStoreAlias + "' doesn't exist in keystore '"+keyStorePath+"'");
			}
		}
		return signerCert;
	}

	private KeyStore keyStore= null;
	private KeyStore getSignKeyStore() throws Exception{
		if(keyStore == null){
	        File ksFile = new File(keyStorePath);
	        if(!ksFile.exists() || !ksFile.isFile() || !ksFile.canRead()){
	 	       throw new IllegalAdminCommandException("Usage: Error path to signing keystore " + keyStorePath + " doesn't seem valid, make " +
	 	       		                                  "sure the file exists and is readable.");
	        }
			keyStore = KeyStore.getInstance("JKS");
			keyStore.load(new FileInputStream(ksFile),keyStorePwd.toCharArray());
		}
		return keyStore;
	}

	public int getCommandType() {
		return TYPE_EXECUTEONMASTER;
	}
	
	public static String appendAllInterfaces(Collection<String> interfaces){
		String retval = "";
		for(String iface : interfaces){
			retval = retval + ";" +iface;
		}
		
		return retval;
	}
	
	private void addPartProperties(String hostname, MARFileParser fileParser, String part,
			String environment) throws Exception {
		SetPropertiesHelper helper = new SetPropertiesHelper(getOutputStream(),getCommonAdminInterface(hostname));
		
		Properties partProperties = fileParser.getPartConfig(part, environment);
		if(partProperties != null){
			if(environment == null){
			  getOutputStream().println("Configuring properties included in the part : " + part);
			}else{
			  getOutputStream().println("Configuring properties included in the part : " + part + ", for the environment " + environment);
			}
			helper.process(partProperties);
			// for each declared worker, add module name and version
			for(Integer workerId : helper.getKeyWorkerDeclarations()){
			   helper.processKey(GlobalConfiguration.WORKERPROPERTY_BASE + workerId + "." + SignServerConstants.MODULENAME, fileParser.getModuleName());
			   helper.processKey(GlobalConfiguration.WORKERPROPERTY_BASE + workerId + "." + SignServerConstants.MODULEVERSION, "" + fileParser.getVersionFromMARFile());
			}
		}

    	this.getOutputStream().println("\n\n");
	}

    // execute
}
