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

import org.apache.mailet.Mail;
import org.signserver.common.ISignerCertReqData;
import org.signserver.common.ISignerCertReqInfo;
import org.signserver.common.SignTokenAuthenticationFailureException;
import org.signserver.common.SignTokenOfflineException;
import org.signserver.server.IWorker;

/**
 * Interface used by all MailSigner plug-ins in order to 
 * 
 * 
 * @author Philip Vendil
 * $Id: IMailSigner.java,v 1.1 2007-10-28 12:26:13 herrvendil Exp $
 */
public interface IMailSigner extends IWorker{
		
	/**
	 * Main method used when signing mails
	 * @param mail the mail sent through the SMTP server
	 */
	void service(Mail mail);
	
	/**
	 * Method used to activate a signer using the supplied authentication Code
	 * @param authenticationCode 
	 */
	void activateSigner(String authenticationCode) throws SignTokenAuthenticationFailureException, SignTokenOfflineException;
	
	/**
	 * Method used to de-activate a signer when it's not used anymore
	 */	
	boolean deactivateSigner() throws SignTokenOfflineException;
	
	
	/**
	 * Method used to tell the signer to create a certificate request using its sign token.
	 */
	ISignerCertReqData genCertificateRequest(ISignerCertReqInfo info) throws SignTokenOfflineException;
	
	
	/**
	 * Method used to remove a key in the sign-token that shouldn't be used any more
	 * @param purpose on of ISignToken.PURPOSE_ constants
	 * @return true if removal was successful.
	 */
	 boolean destroyKey(int purpose);
	 
	 

}
