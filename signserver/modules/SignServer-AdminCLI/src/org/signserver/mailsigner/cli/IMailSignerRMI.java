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
package org.signserver.mailsigner.cli;

/**
 * RMI interface for the signserver cli.
 * 
 * 
 * @author Philip Vendil
 * $Id$
 */
import java.rmi.Remote;
import java.rmi.RemoteException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;

import org.signserver.common.CryptoTokenAuthenticationFailureException;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.ICertReqData;
import org.signserver.common.ISignerCertReqInfo;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.MailSignerUser;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerStatus;

public interface IMailSignerRMI extends Remote {
	
	/**
	 * Returns the current status of a mail signer. 
	 *
	 * Should be used with the cmd-line status command.
	 * @param signerId of the signer
	 * @return a MailSignerStatus object
	 *  
	 */
	public WorkerStatus getStatus(int workerId) throws InvalidWorkerIdException, RemoteException;
	
	/**
	 * Returns the Id of a  given a name of a MailSigner 
	 *
	 * @param signerName of the mail signer, cannot be null
	 * @return The Id of a named signer or 0 if no such name exists
	 *  
	 */
	public int getWorkerId(String signerName) throws RemoteException;
	
	/**
	 * Method used when a configuration have been updated. And should be
	 * called from the command line.
	 *	  
	 *
	 * @param workerId of the mail signer that should be reloaded, or 0 to reload
	 *  all available mail signers 
	 */
	public void reloadConfiguration(int workerId) throws RemoteException;
	
	/**
	 * Method used to activate the crypto-token of a mail signer.
	 * Should be called from the command line.
	 *    
	 * 
	 * @param signerId of the mail signer
	 * @param authenticationCode (PIN) used to activate the token.
	 * 
	 * @throws CryptoTokenOfflineException 
	 * @throws CryptoTokenAuthenticationFailureException 
	 *
	 */
	public void activateCryptoToken(int signerId, String authenticationCode)
		throws CryptoTokenAuthenticationFailureException,
		CryptoTokenOfflineException, InvalidWorkerIdException, RemoteException;
	
	/**
	 * Method used to deactivate the sign-token of a mail signer.
	 * Should be called from the command line.
	 *    
	 * 
	 * @param signerId of the signer
	 * @param authenticationCode (PIN) used to activate the token.
	 * @return true if deactivation was successful.
	 * @throws CryptoTokenOfflineException 
	 * @throws InvalidWorkerIdException 
	 *
	 */
	public boolean deactivateCryptoToken(int signerId)
		throws CryptoTokenOfflineException, InvalidWorkerIdException, RemoteException;
	
	/**
	 * Method used to upload a certificate to a signers configuration
	 * 
	 * @param signerId id of the signer
	 * @param signerCert the certificate used to sign signature requests
	 *  
	 */
	public void uploadSignerCertificate(int signerId, X509Certificate signerCert) throws RemoteException;
	
	/**
	 * Method used to upload a complete certificate chain to a configuration
	 * 
	 * @param signerId id of the signer
	 * @param signerCerts the certificate chain used to sign signature requests
	 */
	public void uploadSignerCertificateChain(int signerId, Collection<Certificate> signerCerts) throws RemoteException;
	
	/**
	 * Method used to remove a key from a mail signer.
	 * 
	 * @param signerId id of the signer
	 * @param purpose on of ICryptoToken.PURPOSE_ constants
	 * @return true if removal was successful.
	 * 
	 */
	public boolean destroyKey(int signerId, int purpose) throws	InvalidWorkerIdException, RemoteException;
	
	/**
	 * Method used to let a mail signer generate a certificate request
	 * using the signers own genCertificateRequest method
	 * 
	 * @param signerId id of the signer
	 * @param certReqInfo information used by the signer to create the request
	 * 
	 */
	public ICertReqData genCertificateRequest(int signerId, ISignerCertReqInfo certReqInfo) throws		
		CryptoTokenOfflineException, InvalidWorkerIdException, RemoteException;
	
	/**
	 * Returns the current configuration of a mail signer.
	 * 
	 * Observe that this config might not be active until a reload command have been executed.
	 * 
	 * 
	 * @param signerId
	 * @return the current (not always active) configuration
	 * 
	 *  
	 */
	public WorkerConfig getCurrentWorkerConfig(int signerId) throws RemoteException;
	
	/**
	 * Sets a parameter in a worker configuration
	 * 
	 * Observe that the worker isn't activated with this config until reload is performed.
	 * 
	 * @param workerId
	 * @param key
	 * @param value
	 * 
	 */
	public void setWorkerProperty(int workerId, String key, String value) throws RemoteException;
	
	/**
	 * Removes a given workers property
	 * 
	 * @param workerId
	 * @param key
	 * @return true if the property did exist and was removed otherwise false
	 * 
	 */	
	public boolean removeWorkerProperty(int workerId, String key) throws RemoteException;
	
	/**
	 * Method setting a global configuration property. For node. prefix will the node id be appended.
	 * @param scope one of the GlobalConfiguration.SCOPE_ constants
	 * @param key of the property should not have any scope prefix, never null
	 * @param value the value, never null.
	 */
	public void setGlobalProperty( java.lang.String scope,java.lang.String key,java.lang.String value )
	throws java.rmi.RemoteException;

	   /**
	    * Method used to remove a property from the global configuration.
	    * @param scope  one of the GlobalConfiguration.SCOPE_ constants
	    * @param key of the property should not have any scope prefix, never null
	    * @return true if removal was successful, otherwise false.
	    */
	   public boolean removeGlobalProperty( java.lang.String scope,java.lang.String key )
	      throws java.rmi.RemoteException;

	   /**
	    * Method that returns all the global properties with Global Scope and Node scopes properties for this node.
	    * @return A GlobalConfiguration Object, never null
	    */
	   public org.signserver.common.GlobalConfiguration getGlobalConfiguration(  )
	      throws java.rmi.RemoteException;
	   
		/**
		 * Methods that generates a free worker id that can be used for new signers
		 */
		public int genFreeWorkerId()throws java.rmi.RemoteException;

		/**
		 * Method returning a list of available workers.
		 * @param workerType constant defined in GlobalConfiguration.WORKERTYPE_
		 * @return the list of available worker id's
		 * @throws java.rmi.RemoteException
		 */
		public List<Integer> getWorkers(int workerType) throws java.rmi.RemoteException;
		
		/**
		 * Method adding an authorized user to a mail signer.
		 * 
		 * It's only possible to give access to the entire mail signer and
		 * not to individual mail signers.
		 * 
		 * @param username case insensitive username of the user.
		 * @param password the password used to authenticate the user.
		 * 
		 */
		void addAuthorizedUser(String username, String password)  throws java.rmi.RemoteException;
		
		/**
		 * Method to remove a authorized user from the mail signer
		 * 
		 * @param username case insensitive username of the user.
		 * @return true if the user exists and was removed, false otherwise
		 */
		boolean removeAuthorizedUser(String username)  throws java.rmi.RemoteException;
		
		/**
		 * 
		 * @return A list of all authorized users sorted by user name. Never null.
		 */
		List<MailSignerUser> getAuthorizedUsers()  throws java.rmi.RemoteException;
		
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
		public void addResource(String moduleName, String part, int version, String jarName, String resourceName, String implInterfaces, String description, String comment, byte[] resourceData) throws RemoteException;
		
		/**
		 * Method removing the specified part of the given module
		 * @param moduleName the name of the module.
		 * @param part the part of the module to remove
		 * @param version the version of the module
		 */
		public void removeModulePart(String moduleName, String part, int version) throws RemoteException;
		
		/**
		 * 
		 * @return a list of all module names in the system.
		 */
		public String[] listAllModules() throws RemoteException;
		
		/**
		 * 
		 * @return a list of all version for the specified module.
		 */
		public Integer[] listAllModuleVersions(String moduleName)throws RemoteException; 
		
		/**
		 * 
		 * @return a list of all parts for the specified module.
		 */
		public String[] listAllModuleParts(String moduleName, int version) throws RemoteException;
		
		/**
		 * Lists all jars in the given module part.
		 * @param moduleName the name of the module
		 * @param part the name of the part in the module
		 * @param version the version
		 * @return an array of jar names in the module.
		 */
		public String[] getJarNames(String moduleName, String part, int version) throws RemoteException;
}
