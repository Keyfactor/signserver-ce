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
 
package org.signserver.module.wsra.core;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import javax.persistence.EntityManager;
import javax.persistence.NoResultException;

import org.apache.log4j.Logger;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.signserver.common.SignServerException;
import org.signserver.module.wsra.beans.CertificateDataBean;
import org.signserver.module.wsra.beans.TokenDataBean;
import org.signserver.module.wsra.common.tokenprofiles.ITokenProfile;

/**
 * Class in charge of managing the logic for token and
 * certificate database access.
 * 
 * All data manipulation regarding certificate and token
 * data should go through this class.
 * 
 * 
 * @author Philip Vendil 12 okt 2008
 *
 * @version $Id$
 */

public class TokenManager {

	private Logger log = Logger.getLogger(this.getClass());	
	
	private Set<ITokenProfile> availableTokenProfiles = new HashSet<ITokenProfile>();
	
	private EntityManager workerEntityManager;

	private boolean encryptSensitiveData = false;;
	private X509Certificate encryptCert = null;
	private PrivateKey encKey = null;
	private String encProvider = null;
	
    /**
     * Default constructor 
     * @param workerEntityManager the worker entity manager
     * @param encryptSensitiveData true if sensitive data should be
     * encrypted.
     * @param encryptCert certificate used when encrypting data
     * @param encKey key used when decrypting data.
     * @param encProvider provider used when encrypting 
     */
	public TokenManager(EntityManager workerEntityManager, Set<Class<?>> availableTokenProfileClasses,
			            boolean encryptSensitiveData, 
			            X509Certificate encryptCert, PrivateKey encKey,
			            String encProvider){
		this(workerEntityManager,availableTokenProfileClasses);
		this.encryptSensitiveData = encryptSensitiveData;
		this.encryptCert = encryptCert;
		this.encKey = encKey;
	}
	
	/**
	 * Constructor used if no protection of sensitive data
	 * @param workerEntityManager 
	 */
	public TokenManager(EntityManager workerEntityManager, Set<Class<?>> availableTokenProfileClasses){
		this.workerEntityManager = workerEntityManager;	
		for(Class<?> c: availableTokenProfileClasses){
			if(!c.isInterface()){
				try {
					availableTokenProfiles.add((ITokenProfile) c.newInstance());
				} catch (InstantiationException e) {
					log.error("Error creating ITokenProfile : " +c.getName(),e );
				} catch (IllegalAccessException e) {
					log.error("Error creating ITokenProfile : " +c.getName(),e );
				}
			}
		}
		
		
	}

	/**
	 * Method to add/edit a token. the tokens serialNumber
	 * is used as unique identifier.
	 * 
	 * @param token the token data to add or edit.
	 * @throws SignServerException if something goes wrong during encryption 
	 * of sensitive data.
	 * @return the generated id
	 */
	public int editToken(TokenDataBean token) throws SignServerException{
		TokenDataBean persistData = findToken(token.getOrganizationId(),token.getSerialNumber(),false);		
		boolean persist = false;		
				
		if(persistData == null){
			persistData = new TokenDataBean();
			persist = true;
		}
		
		persistData.setOrganizationId(token.getOrganizationId());
		persistData.setCopyOf(token.getCopyOf());
		persistData.setUserId(token.getUserId());
		persistData.setComment(token.getComment());
		persistData.setProfile(token.getProfile());
		persistData.setSerialNumber(token.getSerialNumber());
		
		if(token.getSensitiveData() != null){
		  persistData.setSensitiveData(encryptData(token.getSensitiveData()));
		}
		if(persist){
			workerEntityManager.persist(persistData);
		}
						
				
		if(token.getCertificates() != null){
			for(CertificateDataBean c: token.getCertificates()){
				c.setTokenId(persistData.getId());
				editCertificate(c);
			}
		}		
		return persistData.getId();
	}
	
    /**
     * Method used to remove a token from the database.
     * 
     * The certificate placed on this token is removed as well.
     * 
     * Important this call should generally only be done by test scripts or
     * someone who knows what he is doing. Set the status flag instead.
     * @param tokenId the tokenId
     */
	public void removeToken(int tokenId) {		
		
		TokenDataBean data = workerEntityManager.find(TokenDataBean.class, tokenId);				
		if(data != null){
			for(CertificateDataBean cdb : data.getCertificates()){
				cdb.setTokenId(0);
				workerEntityManager.remove(cdb);
			}

			workerEntityManager.remove(data);
		}

	}
		
	
	
	/**
	 * Method that fetches a token given it's serialNumber
	 * 
	 * @param serialNumber the unique serial number of the token in
	 * the organization.
	 * @param includeSensitiveData true if sensitive data, that may be encrypted
	 * in database should be decrypted and included.
	 * @return the token that matches the serialNumber or null if
	 * no token could be found.
	 * @throws SignServerException if something goes wrong during decryption 
	 * of sensitive data.
	 */
	public TokenDataBean findToken(int organizationId, String serialNumber, boolean includeSensitiveData) throws SignServerException{
		TokenDataBean retval = null;
		
		try{
			retval = (TokenDataBean) workerEntityManager.createNamedQuery("TokenDataBean.findBySerialNumber")
			                            .setParameter(1, organizationId)
			                            .setParameter(2, serialNumber)
			                            .getSingleResult();
			
			if(includeSensitiveData && retval.getSensitiveData() != null){
				retval.setSensitiveData(decryptData(retval.getSensitiveData()));
			}else{
				retval.setSensitiveData(null);
			}
			retval.getCertificates().size();
		}catch(NoResultException e){}
		
		return retval;
	}
	
	/**
	 * Method that fetches a token given it's token id
	 * 
	 * @param tokenId the unique id in database
	 * @param includeSensitiveData true if sensitive data, that may be encrypted
	 * in database should be decrypted and included.
	 * @return the token that matches the id or null if
	 * no token could be found.
	 * @throws SignServerException if something goes wrong during decryption 
	 * of sensitive data.
	 */
	public TokenDataBean findToken(int tokenId, boolean includeSensitiveData) throws SignServerException{
		TokenDataBean retval = null;
		
		try{
			retval = (TokenDataBean) workerEntityManager.find(TokenDataBean.class, tokenId);
			
			if(includeSensitiveData && retval.getSensitiveData() != null){
				retval.setSensitiveData(decryptData(retval.getSensitiveData()));
			}else{
				retval.setSensitiveData(null);
			}
			retval.getCertificates().size();
		}catch(NoResultException e){}
		
		return retval;
	}
	


	/**
	 * Method used to add/edit a certificate in the 
	 * certificate DB.
	 * @param cert data to add/edit
	 * @return the generated id
	 */	
	public int editCertificate(CertificateDataBean certData){
		CertificateDataBean persistData = findCertificateByFingerprint(certData.getFingerprint());
		boolean persist = false;
		
				
		if(persistData == null){
			persistData = new CertificateDataBean();
			persist = true;
		}
		persistData.setCertificateData(certData.getCertificateData());
		persistData.setExpireDate(certData.getExpireDate());
		persistData.setIssuerDN(certData.getIssuerDN());
		persistData.setSubjectDN(certData.getSubjectDN());
		persistData.setSerialNumber(certData.getSerialNumber());
		persistData.setFingerprint(certData.getFingerprint());		
		persistData.setStatus(certData.getStatus());
		persistData.setComment(certData.getComment());
		persistData.setType(certData.getType());
		persistData.setProfile(certData.getProfile());
		persistData.setTokenId(certData.getTokenId());
		if(persist){
			workerEntityManager.persist(persistData);
		}
				
		return persistData.getId();
	}
	
	
	public CertificateDataBean findCertificate(String serialNumberInDec, String issuerDN){
		CertificateDataBean retval = null;
		
		try{
			retval = (CertificateDataBean) workerEntityManager.createNamedQuery("CertificateDataBean.findByIssuerAndSerial")
			                            .setParameter(1, issuerDN)
			                            .setParameter(2, serialNumberInDec)
			                            .getSingleResult();
		}catch(NoResultException e){}
		
		return retval;
	}
	
	public CertificateDataBean findCertificateByFingerprint(String fingerPrint){
		CertificateDataBean retval = null;
		
		try{
			retval = (CertificateDataBean) workerEntityManager.createNamedQuery("CertificateDataBean.findByFingerprint")
			                            .setParameter(1, fingerPrint).getSingleResult();
		}catch(NoResultException e){}
		
		return retval;
	}
	
	@SuppressWarnings("unchecked")
	public List<CertificateDataBean> findCertificateBySubject(String subjectDN, String issuerDN){
		List<CertificateDataBean> retval = null;
		
		try{
			retval = workerEntityManager.createNamedQuery("CertificateDataBean.findByIssuerAndSubject")
			                            .setParameter(1, issuerDN)
			                            .setParameter(2, subjectDN)
			                            .getResultList();
		}catch(NoResultException e){}
		
		return retval;
	}
	
    /**
     * Method used to remove a certificate from the database.
     * 
     * 
     * Important this call should generally only be done by test scripts or
     * someone who knows what he is doing. Set the status flag instead.
     * @param tokenId the tokenId
     */
	public void removeCertificate(int certificateId) {
		
		CertificateDataBean data = workerEntityManager.find(CertificateDataBean.class, certificateId);				
		if(data != null){
			workerEntityManager.remove(data);		
		}

	}

	
	/**
	 * Method that decrypts data from the specification
	 * in worker config. 
	 * @throws SignServerException if something goes wrong during decryption
	 * of data.
	 */
	private byte[] decryptData(byte[] data) throws SignServerException {
		if(encryptSensitiveData){
			try{
				CMSEnvelopedData ed = new CMSEnvelopedData(data);
				RecipientInformationStore  recipients = ed.getRecipientInfos();           	
				Iterator<?>    it =  recipients.getRecipients().iterator();
				RecipientInformation   recipient = (RecipientInformation) it.next();
				byte[] recdata = recipient.getContent(encKey,encProvider);
				return recdata;
			}catch(Exception e){
	            log.error("Error when decrypting sensitive data: ", e);
	            throw new SignServerException("Error when decrypting sensitive data: " +e.getMessage(),e); 
			}

			
		}
		return data;
	}
	
	/**
	 * Method that encrypts data from the specification
	 * in worker configuration.
	 * @throws SignServerException if something goes wrong during encryption
	 * of data.
	 */
	private byte[] encryptData(byte[] data) throws SignServerException {		
		if(encryptSensitiveData){
			byte[] retval;
	       CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();    	    	    	    	             
	    	CMSEnvelopedData ed;
			try {
				edGen.addKeyTransRecipient( encryptCert.getPublicKey(),keyId);
				ed = edGen.generate(
						new CMSProcessableByteArray(data), CMSEnvelopedDataGenerator.AES256_CBC,"BC");
				retval = ed.getEncoded();
			} catch (Exception e) {
	            log.error("Error when encrypting sensitive data: ", e);
	            throw new SignServerException("Error when encrypting sensitive data: " +e.getMessage(),e);        
			}				
			
			return retval;
		}
		return data;
	}
    private static byte[]  keyId = new byte[] { 1, 2, 3, 4, 5 };

}
