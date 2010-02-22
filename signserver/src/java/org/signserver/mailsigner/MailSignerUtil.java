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

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;

import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;

import org.apache.log4j.Logger;
import org.apache.mailet.Mail;
import org.signserver.common.GlobalConfiguration;
import org.signserver.mailsigner.core.NonEJBGlobalConfigurationSession;

/**
 * Containing common util methods used for various reasons
 * 
 * 
 * @author Philip Vendil 2007 jan 26
 *
 * @version $Id$
 */

public class MailSignerUtil {

	public static final String TESTMODE_SETTING = "TESTMODE";
	
	private static Logger log = Logger.getLogger(MailSignerUtil.class);
	


    /**
     * Method used to check if a Mail Signer is used in test mode. 
     */
    public static boolean isTestMode(){
    	GlobalConfiguration gc = NonEJBGlobalConfigurationSession.getInstance().getGlobalConfiguration();
    	return gc.getProperty(GlobalConfiguration.SCOPE_GLOBAL, TESTMODE_SETTING)!= null &&
				gc.getProperty(GlobalConfiguration.SCOPE_GLOBAL, TESTMODE_SETTING).equalsIgnoreCase("TRUE");
    }
	/**
	 * Method used to test a mail signer, checks if setting TESTMODE is set
	 * to TRUE in global configuration. If so is the mail serialized and
	 * written to the temporary directory for later inspection.
	 * 
	 * Important, only used in the Mail Signer
	 * 
	 * @param mail
	 */
	public static void mailTest(Mail mail) {
            if (Mail.ERROR.equals(mail.getState())) {
                log.debug("Not creating test mail for mail in error state");
            } else {
			if(isTestMode()){
			  try {
				mailTest(mail.getMessage());
			} catch (MessagingException e) {
				log.error("Error performing test of mail signer : " + e.getMessage(),e);
			}	
			  mail.setState(Mail.GHOST);
			}
		}
	}
	
	public static void mailTest(MimeMessage mail) {		
			GlobalConfiguration gc = NonEJBGlobalConfigurationSession.getInstance().getGlobalConfiguration();
			if(gc.getProperty(GlobalConfiguration.SCOPE_GLOBAL, TESTMODE_SETTING)!= null &&
					gc.getProperty(GlobalConfiguration.SCOPE_GLOBAL, TESTMODE_SETTING).equalsIgnoreCase("TRUE")){
				String signserverhome = System.getenv("SIGNSERVER_HOME");
				if(signserverhome == null){
					log.error("Error performing test of mail signer, environment variable SIGNSERVER_HOME isn't set");
				}

				try {
					FileOutputStream fos = new FileOutputStream(signserverhome + "/tmp/testmail");				
					mail.writeTo(fos);
					fos.close();
				} catch (FileNotFoundException e) {
					log.error("Error performing test of mail signer : " + e.getMessage());
				} catch (IOException e) {
					log.error("Error performing test of mail signer : " + e.getMessage());
				} catch (MessagingException e) {
					log.error("Error performing test of mail signer : " + e.getMessage());
				} 
		}
	}
}
