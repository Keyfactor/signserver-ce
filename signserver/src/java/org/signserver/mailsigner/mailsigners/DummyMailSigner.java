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

package org.signserver.mailsigner.mailsigners;

import org.apache.log4j.Logger;
import org.apache.mailet.Mail;
import org.signserver.mailsigner.BaseMailSigner;

/**
 * Empty demo implementation of a mail signer
 * that demonstrates how to develop a mail signer plug-in
 * 
 * Also used for test purposes.
 * 
 * @author Philip Vendil 23 sep 2007
 *
 * @version $Id: DummyMailSigner.java,v 1.1 2007-10-28 12:26:13 herrvendil Exp $
 */

public class DummyMailSigner extends BaseMailSigner {

	public transient Logger log = Logger.getLogger(this.getClass());
	
	/**
	 * @see org.signserver.mailsigner.IMailSigner#service(org.apache.mailet.Mail)
	 */
	public void service(Mail mail) {
		log.info("Service called for mailsigner with id " + workerId);
		
		
	}
	
	

}
