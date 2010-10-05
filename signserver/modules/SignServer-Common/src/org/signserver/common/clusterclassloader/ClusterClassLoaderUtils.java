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

package org.signserver.common.clusterclassloader;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.persistence.EntityManager;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSSignedGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.commons.RemappingClassAdapter;
import org.objectweb.asm.commons.SimpleRemapper;
import org.signserver.common.SignServerException;
import org.signserver.server.annotations.Transaction;
import org.signserver.server.annotations.TransactionType;
import org.signserver.server.annotations.WorkerEntityManager;



/**
 * Class containing utility methods related to the Cluster Class Loader.
 * 
 * 
 * 
 * @author Philip Vendil 15 maj 2008
 *
 */

public class ClusterClassLoaderUtils {
	
	/**
	 * Help method that transforms a resource path
	 * to a valid class name.
	 * 
	 * @param resourcePath path of class with / and .class
	 * @return a valid class name or null if it doesn't seem to be a class
	 */
	public static String getClassNameFromResourcePath(String resourcePath){
		if(resourcePath.endsWith(".class")){
		  return resourcePath.substring(0, resourcePath.length()-6).replaceAll("/", "\\.");
		}
		
		return null;
	}
	
	/**
	 * Help method that strips the '.class' postfix from a resource path
	 * if it exists
	 * 
	 * @param resourcePath path of class with / and .class
	 * @return a classname with / and no .class
	 */
	public static String stripClassPostfix(String resourcePath){
		if(resourcePath.endsWith(".class")){
		  return resourcePath.substring(0, resourcePath.length()-6);
		}
		
		return resourcePath;
	}
	
	/**
	 * Help method that transforms a class name
	 * to a valid resource path.
	 * 
	 * @param className full class name
	 * @return path of the class with / and .class
	 */
	public static String getResourcePathFromClassName(String className){
		return className.replaceAll("\\.", "/") + ".class";
	}
	
	/**
	 * Method that takes a class name returned by class.getName()
	 * and returns an internal name used in asm.
	 * @param className the class name
	 * @return the internal name.
	 */
	public static String getInternalObjectName(String className){
		return className.replaceAll("\\.", "/");
	}
	
	/**
	 * Method that takes a class name returned by class.getName()
	 * and returns an internal name used in asm with 'L' in front
	 * and ';' in the end
	 * @param className the class name
	 * @return the internal name.
	 */
	public static String getInternalObjectNameWithL(String className){
		return "L" + className.replaceAll("\\.", "/") +";";
	}

	/**
	 * Method that removes the path of a resource and only returns
	 * the actual name of the resource
	 * @param resourcePath
	 * @return the name of the resource only.
	 */
	public static String removePath(String resourcePath) {
		return resourcePath.substring(resourcePath.lastIndexOf("/")+1);		
	}
	
	/**
	 * Method that returns the package name from a resource name.
	 * 
	 * It stripps the last '/' and everything behind it and
	 * replaces all '/' with '.' 
	 * @param resourceName
	 * @return the package name of the resource.
	 */
	public static String getPackageFromResourceName(String resourceName) {
		String retval = "";
		if(resourceName.length()>0){
			String resName = normalizeResourcePath(resourceName);
			if(resName.lastIndexOf("/") > 1){
				retval = resName.substring(0,resName.lastIndexOf("/"));
				retval = retval.replaceAll( "/","\\.");
			}
		}
		return retval;	
	}
	
	/**
	 * Method that removes an initial '/' from the resource path
	 * if it exists.
	 * @param resourcePath
	 * @return resourcePath without initial '/'
	 */
	public static String normalizeResourcePath(String resourcePath) {
		String retval = resourcePath;
		if(retval != null){
			if(retval.startsWith("/")){
				retval = retval.substring(1);
			}
		}
		return retval;		
	}
	
	/**
	 * Method that rewrites the byte-code of the current class 
	 * renaming all names in the mapping file.
	 * @param mappings of old name -> new name of all classes in plug-in.
	 * @param classData the actual data of the class.
	 * @return the versioned class
	 */
	public static byte[] addVersionToClass(Map<String,String> mappings, byte[] classData) {
		ClassReader cr = new ClassReader(classData);
		ClassWriter cw = new ClassWriter(0);
		SimpleRemapper sr = new SimpleRemapper(mappings);
		RemappingClassAdapter cv = new RemappingClassAdapter(cw,sr);		
		cr.accept(cv, ClassReader.EXPAND_FRAMES);
		return cw.toByteArray();
	}
	
	/**
	 * Method finding the version tag from a class name of internal name
	 * or null if no version tag could be found.
	 */
	public static String findVersionTag(String name){
		String retval = null;
	    Matcher match = versionInClassNamePattern.matcher(name);
	    if(match.find()){
	    	retval = match.group();
	    }
	    
	    if(retval == null){
		    match = VersionInInternalNamePattern.matcher(name);
		    if(match.find()){
		    	retval = match.group();
		    }
	    }
	    
	    return retval;
	}
	private static Pattern versionInClassNamePattern = Pattern.compile("^v\\d+\\.");
	private static Pattern VersionInInternalNamePattern = Pattern.compile("^v\\d+/");


	/**
	 * Help method used to sign uploaded resource data if needed.
	 * @param resourceData the raw resource data.
	 * @param signerCert that should sign this message or null if no signing should be used.
	 * @param signingKey that should sign this message or null if no signing should be used.
	 * @param provider that should be used for the signing.
	 * @return a byte array with a boolean indicating that the data is signed or not, then a signed CMS message or the raw data.
	 * @throws CMSException if something goes wrong with the CMS data generation.
	 * @throws NoSuchProviderException if the BC provider isn't installed
	 * @throws NoSuchAlgorithmException if the given algorithm isn't support by the given provider.
	 * @throws IOException  if CMS to byte array conversion failed.
	 * @throws InvalidAlgorithmParameterException 
	 * @throws CertStoreException 
	 * @see org.signserver.common.clusterclassloader.ClusterClassLoaderUtils#verifyResourceData(byte[], KeyStore)
	 */
	public static byte[] generateCMSMessageFromResource(byte[] resourceData, X509Certificate signerCert, PrivateKey signingKey, String provider) throws NoSuchAlgorithmException, NoSuchProviderException, CMSException, IOException, InvalidAlgorithmParameterException, CertStoreException{

		boolean isSigned = false;
		byte[] processData = resourceData;
		if(signerCert != null && signingKey != null){
			ArrayList<X509Certificate> certList = new ArrayList<X509Certificate>();
	        certList.add(signerCert);
	        CertStore certs = CertStore.getInstance("Collection", new CollectionCertStoreParameters(certList), provider);
			CMSSignedDataGenerator    gen = new CMSSignedDataGenerator();
			gen.addCertificatesAndCRLs(certs);
			gen.addSigner(signingKey, signerCert, CMSSignedGenerator.DIGEST_SHA256);
			CMSSignedData           data = gen.generate(new CMSProcessableByteArray(resourceData), true, provider);
			processData = data.getEncoded();
			isSigned = true;			
		}
		
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		DataOutputStream dos = new DataOutputStream(baos);
		dos.writeBoolean(isSigned);
		dos.write(processData);
				
		return baos.toByteArray();
	}
	
	/**
	 * Help method used to verify the resource data against
	 * a set of trusted CA certificates.
	 * 
	 * @param signedData the signed data.
	 * @param trustStore the key store containing the CA chain of trusted certificates. Use null if verification isn't required.
	 * @return the raw resource data.
	 * @throws SignServerException if the data was unsigned and the configuration requires it.
	 * @throws SignatureException if signature of resource data didn't verify correctly
	 * @throws IOException if other I/O related error occurred.
	 */
	public static byte[] verifyResourceData(byte[] signedData, KeyStore trustStore) throws IOException, SignServerException, SignatureException{
		byte[] retval = null;
		DataInputStream dis = new DataInputStream(new ByteArrayInputStream(signedData));
		boolean isSigned = dis.readBoolean();
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		while(dis.available() != 0){
			baos.write(dis.read());
		}
		retval = baos.toByteArray();
		if(isSigned){
			try {				
				retval = verifySignature(getCACertificatesFromKeyStore(trustStore), null, retval, new Date());
			} catch (KeyStoreException e) {
				throw new IOException("Error reading certificates from truststore : " + e.getMessage());
			}
		}else{
			if(trustStore != null){
				throw new SignServerException("Error: all resource data in the ClusterClassLoader have to be signed.");
			}
		}
		
		return retval;
	}
	
	/**
	 * Method used to verify signed data.
	 * 
	 * @param TrustedCACerts a Collection of trusted certificates, should contain the entire chains
	 * @param TrustedCRLs a Collection of trusted CRLS, use null if no CRL check should be used.
	 * @param signedData the data to verify
	 * @param date the date used to check the validity against.
	 * @return the raw content of the CMS message.
	 * @throws SignatureException if the data doesn't verify
	 */
	private static byte[] verifySignature(Collection<X509Certificate> cACertChain, Collection<X509CRL> trustedCRLs, byte[] signedData, Date date) throws SignatureException{
		boolean verifies = false;        
        X509Certificate usercert = null;        
                
        try{
        	// First verify the signature
        	CMSSignedData     sp = new CMSSignedData(signedData);            	        	        	
        	
        	CertStore               certs = sp.getCertificatesAndCRLs("Collection", "BC");
        	SignerInformationStore  signers = sp.getSignerInfos();        	
        	
        	Collection<?>              c = signers.getSigners();
        	Iterator<?>                it = c.iterator();
        	
        	while (it.hasNext())
        	{
        		SignerInformation signer = (SignerInformation)it.next();
        		
        		Collection<?> certCollection = certs.getCertificates(signer.getSID());
        		
        		Iterator<?> certIt = certCollection.iterator();
        		usercert = (X509Certificate)certIt.next();   
        		
        		String signAlg = signer.getDigestAlgOID();
        		boolean validAlg = getTrustedSignAlgorithms().contains(signAlg);
        		if(!validAlg){
        			throw new SignatureException("Error : Signature algorithm " + signAlg + " isn't one of the trusted algorithms.");
        		}
        		
        		verifies = signer.verify(usercert.getPublicKey(), "BC");
        		if(!verifies){
        			throw new SignatureException("Error the resource data signature doesn't verify");
        		}
        	}
        	
        	// Second validify the certificate           
        	
        	X509Certificate rootCert = null;
        	Iterator<?> iter = cACertChain.iterator();
        	while(iter.hasNext()){
        		X509Certificate cert = (X509Certificate) iter.next();
        		if(cert.getIssuerDN().equals(cert.getSubjectDN())){
        			rootCert = cert;
        			break;
        		}
        	}
        	
        	if(rootCert == null){
        		throw new CertPathValidatorException("Error Root CA cert not found in cACertChain"); 
        	}
         
        	if(usercert.getExtendedKeyUsage() == null || !usercert.getExtendedKeyUsage().contains("1.3.6.1.5.5.7.3.3")){
        		throw new CertPathValidatorException("Error: Signing certificate doesn't have the required extended key usage 'Code Signing'.");
        	}
        	
        	
        	List<Object> list = new ArrayList<Object>();
        	list.add(usercert);
        	list.add(cACertChain);
        	if(trustedCRLs != null){
        		list.add(trustedCRLs);
        	}
        	
        	CollectionCertStoreParameters ccsp = new CollectionCertStoreParameters(list);
        	CertStore store = CertStore.getInstance("Collection", ccsp);
        	
        	//validating path
        	List<X509Certificate> certchain = new ArrayList<X509Certificate>();
        	certchain.addAll(cACertChain);
        	certchain.add(usercert);
        	CertPath cp = CertificateFactory.getInstance("X.509","BC").generateCertPath(certchain);
        	
        	Set<TrustAnchor> trust = new HashSet<TrustAnchor>();
        	trust.add(new TrustAnchor(rootCert, null));
        	
        	CertPathValidator cpv = CertPathValidator.getInstance("PKIX","BC");
        	PKIXParameters param = new PKIXParameters(trust);
        	param.addCertStore(store);
        	param.setDate(date);
        	if(trustedCRLs == null){
        		param.setRevocationEnabled(false);
        	}else{
        		param.setRevocationEnabled(true);
        	}
        	cpv.validate(cp, param);
        	        	
        	return (byte[]) sp.getSignedContent().getContent();
        }catch(CMSException e){
        	throw new SignatureException(e.getMessage(),e);
        } catch (CertPathValidatorException e) {
        	throw new SignatureException(e.getMessage(),e);
		} catch (InvalidAlgorithmParameterException e) {
			throw new SignatureException(e.getMessage(),e);
		} catch (NoSuchAlgorithmException e) {
			throw new SignatureException(e.getMessage(),e);
		} catch (NoSuchProviderException e) {
			throw new SignatureException(e.getMessage(),e);
		} catch (CertificateException e) {
			throw new SignatureException(e.getMessage(),e);
		} catch (CertStoreException e) {
			throw new SignatureException(e.getMessage(),e);
		}
        	
	}

	/**
	 * Method keeping track of trusted signing algorithms 
	 * @return a list of trusted algorithms
	 */
	private static List<String> getTrustedSignAlgorithms() {
		if(trustedSignAlgorithms == null){
			trustedSignAlgorithms = new ArrayList<String>();
			trustedSignAlgorithms.add(CMSSignedGenerator.DIGEST_SHA256);
		}

		return trustedSignAlgorithms;
	}
    private static List<String> trustedSignAlgorithms = null;
    
    /**
     * A help method to retrieve all the certificates from a keystore
     * and returns them as a collection of X509Certificates. 
     * 
     * @param keyStore the key store to fetch certificates from, never null
     * @return a collection of certificates never null.
     * @throws KeyStoreException if certificate couldn't be read from the keystore
     */
    private static Collection<X509Certificate> getCACertificatesFromKeyStore(KeyStore keyStore) throws KeyStoreException{
    	Collection<X509Certificate> retval = new HashSet<X509Certificate>();
    	Enumeration<String> e = keyStore.aliases();
    	while(e.hasMoreElements()){
    		String next = e.nextElement();
    		Certificate[] cachain = keyStore.getCertificateChain(next);
    		if(cachain != null){
    			for(Certificate cert : cachain){
    				if(((X509Certificate) cert).getBasicConstraints() != -1){
    			 	  retval.add((X509Certificate) cert);
    				}
    			}
    		}
    		X509Certificate nextCert = (X509Certificate) keyStore.getCertificate(next);
    		if(nextCert.getBasicConstraints() != -1){
    		  retval.add(nextCert);
    		}
    	}
    	
    	return retval;
    }
    
    public static byte[] injectTransaction(byte[] classData){
    	ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        ClassReader cr = new ClassReader(classData);
        TransactionFinder tr = new TransactionFinder(cw);
        cr.accept(tr, ClassReader.EXPAND_FRAMES);
        return cw.toByteArray();
    }
    
    /**
     * Method that searches a class for a WorkerEntityManager annotated
     * EntityManager field and returns a reference to it.
     * 
     * Used by the injectTransaction() method.
     * 
     * @param c the class
     * @param o the object
     * @return a reference to the worker entity manager or null if not found.
     * @throws IllegalArgumentException
     * @throws SecurityException
     * @throws IllegalAccessException
     */
	public static EntityManager findWorkerEntityManager(Class<?> c, Object o) throws IllegalArgumentException, SecurityException, IllegalAccessException{
		EntityManager workerEntityManager = null;	
		
		workerEntityManager = findWorkerEntityManagerFromFields(c.getDeclaredFields(),o);
		if(workerEntityManager == null){
			Class<?> sc = c.getSuperclass();
			while(sc != null && !sc.getName().equals(Object.class.getName()) ){
               workerEntityManager = findWorkerEntityManagerFromFields(sc.getDeclaredFields(),o);
               sc = sc.getSuperclass();
			}
		}
		
		return workerEntityManager;
	}
	
	private static EntityManager findWorkerEntityManagerFromFields(Field[] fields, Object object) throws IllegalArgumentException, IllegalAccessException{
		EntityManager retval = null;
		for(Field f : fields){
			if(f.getAnnotation(WorkerEntityManager.class) != null){

					boolean isAccessable = f.isAccessible();
					f.setAccessible(true);
					retval = (EntityManager) f.get(object);
					f.setAccessible(isAccessable);
					break;
			}
		}
		return retval;		
	}
	
	/**
	 * Method that returns the transaction type of the calling method.
	 * It assumes that the calling method have a Transaction annotation.
	 * It looks up and returns the value of that annotation, default is 
	 * TransactionType.Required
	 * 
	 * @param c the class
	 * @param o an instanced object
	 * @return the transaction type configured for the method-
	 */
	public static TransactionType findTransactionType(Class<?> c, Object o){
		TransactionType transactionType = TransactionType.SUPPORTS;		

		try
		{
			throw new Exception("");
		}
		catch( Exception e )
		{
			Method[] methods = c.getMethods();
			for(Method m : methods){
				if(m.getName().equals(e.getStackTrace()[1].getMethodName())){
					if(m.getAnnotation(Transaction.class) != null){
						transactionType = m.getAnnotation(Transaction.class).value();
						break;
					}
				}
			}            
		}
		return transactionType;
	}
	

	
}
