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

package org.signserver.mailsigner;



import javax.mail.MessagingException;

import org.apache.mailet.Mail;
import org.apache.mailet.MailetContext;
import org.signserver.common.CryptoTokenAuthenticationFailureException;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.ICertReqData;
import org.signserver.common.ISignerCertReqInfo;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerStatus;

/**
 * Interface used by all MailSigner plug-ins in order to 
 * process mails.
 * 
 * 
 * @author Philip Vendil
 * $Id: IMailProcessor.java,v 1.1 2008-01-19 03:41:57 herrvendil Exp $
 */
public interface IMailProcessor {
		
	/**
	 * Main method used when processing mails
	 * @param mail the mail sent through the SMTP server
	 * @throws MessagingException if error occurred during processing of mail.
	 * @throws CryptoTokenOfflineException if the signing token not available at the time of the process.
	 */
	void service(Mail mail) throws MessagingException, CryptoTokenOfflineException;
	
	/**
	 * Method used to activate a crypto token using the supplied authentication Code
	 * @param authenticationCode 
	 */
	void activateCryptoToken(String authenticationCode) throws CryptoTokenAuthenticationFailureException, CryptoTokenOfflineException;
	
	/**
	 * Method used to de-activate a crypto token when it's not used anymore
	 */	
	boolean deactivateCryptoToken() throws CryptoTokenOfflineException;
	
	
	/**
	 * Method used to tell the processable to create a certificate request using its sign token.
	 */
	ICertReqData genCertificateRequest(ISignerCertReqInfo info) throws CryptoTokenOfflineException;
	
	
	/**
	 * Method used to remove a key in the crypto-token that shouldn't be used any more
	 * @param purpose on of ICryptoToken.PURPOSE_ constants
	 * @return true if removal was successful.
	 */
	 boolean destroyKey(int purpose);
	 
		/**
		 * Initialization method that should be called directly after creation.
		 * @param workerId the unique id of the worker
		 * @param config the configuration stored in database
		 * @param the mailet context containing the mail signer configuration.
		 */
		public void init(int workerId, WorkerConfig config, MailetContext mailetContext);
		
		/**
		 * Should return the actual status of the worker, status could be if
		 * the signer is activated or not, or equivalent for a service.
		 * @return a WorkerStatus object.
		 */
		public WorkerStatus getStatus();



}
