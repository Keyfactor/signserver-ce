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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.rmi.Naming;
import java.util.Date;
import java.util.Properties;

import javax.mail.Message;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;

import junit.framework.TestCase;

import org.signserver.common.CompileTimeSettings;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.MailSignerConfig;
import org.signserver.common.SignServerUtil;
import org.signserver.mailsigner.MailSignerUtil;
import org.signserver.mailsigner.cli.IMailSignerRMI;

/**
 * Abstract test class containing a lot of help methods in setting up and
 * configuring a mail signer junit test.
 *
 * @version $Id$
 */
public abstract class BaseMailSignerTester extends TestCase {


	protected static IMailSignerRMI iMailSignerRMI;
	protected static String signServerHome = null;
	
	protected void setUp() throws Exception {
		super.setUp();
		SignServerUtil.installBCProvider();
		iMailSignerRMI = getIMailSignerRMI();
		
		iMailSignerRMI.setGlobalProperty(GlobalConfiguration.SCOPE_GLOBAL, MailSignerUtil.TESTMODE_SETTING, "TRUE");
		
		iMailSignerRMI.setGlobalProperty(GlobalConfiguration.SCOPE_GLOBAL, GlobalConfiguration.WORKERPROPERTY_BASE + getWorkerId() + GlobalConfiguration.WORKERPROPERTY_CLASSPATH, getMailSignerClassPath());
		if(getCryptoTokenClasspath() != null){
			iMailSignerRMI.setGlobalProperty(GlobalConfiguration.SCOPE_GLOBAL, GlobalConfiguration.WORKERPROPERTY_BASE + getWorkerId() + GlobalConfiguration.CRYPTOTOKENPROPERTY_BASE + GlobalConfiguration.CRYPTOTOKENPROPERTY_CLASSPATH, getCryptoTokenClasspath());
		}		
		iMailSignerRMI.addAuthorizedUser(getSMTPAuthUser(), "foo123");
		
		signServerHome = System.getenv("SIGNSERVER_HOME");
		assertNotNull(signServerHome);
		
		iMailSignerRMI.reloadConfiguration(getWorkerId());
		

	}

	/**
	 * 
	 * @return the username that should be used for smtp authentication
	 */
	protected abstract String getSMTPAuthUser();

	/**
	 * 
	 * @return the classpath to the crypto token or null if no cryptotoken should be used
	 */
	protected abstract String getCryptoTokenClasspath();

	/**
	 * 
	 * @return the classpath of the mail signer under test.
	 */
	protected abstract String getMailSignerClassPath();

	/**
	 * 
	 * @return should return the workerId that it should be configured ass.
	 */
	protected abstract int getWorkerId();

	/**
	 * Method that sleeps for 2 seconds and then fetches the mail from the test in-box.
	 * 
	 * Make sure you have cleared the in-box in the beginning of the test session.
	 * 
	 * @return the mail send in test of null if it wasn't there.
	 * @throws Exception
	 */
	protected MimeMessage readTestInbox() throws Exception {
		File testInbox = new File(signServerHome + "/tmp/testmail");
		for(int i=0;i<20;i++){
		  if(!testInbox.exists()){
			  Thread.sleep(1000);
		  }
		}
				
		if(testInbox.exists()){
		   Session session = Session.getInstance(System.getProperties(), null);
		   FileInputStream fis = new FileInputStream(testInbox);
		   ByteArrayOutputStream baos = new ByteArrayOutputStream();
		   int b=0;
		   while((b=fis.read()) != -1){
			   baos.write(b);
		   }
		   
		   ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
		   MimeMessage msg = new MimeMessage(session,bais);	   		   
		   fis.close();
		   return msg;
		}
		return null;
	}

	/**
	 * Method to clear the test in-box (that only supports on email at the time) to make sure
	 * the tested one is fetched. Should be called before any send mail methods is done.
	 */
	protected void clearTestInbox() {
		File testInbox = new File(signServerHome + "/tmp/testmail");
		if(testInbox.exists()){
			assertTrue(testInbox.delete());
		}		
	}

	protected void sendMail(String from, String to, 
			String subject, String message) throws Exception{

		String host = "localhost";

		// create some properties and get the default Session
		Properties props = System.getProperties();
		props.put("mail.smtp.auth", "true");


		Session session = Session.getInstance(props, null);



		// create a message
		MimeMessage msg = new MimeMessage(session);
		msg.setFrom(new InternetAddress(from));
		InternetAddress[] address = {new InternetAddress(to)};
		msg.setRecipients(Message.RecipientType.TO, address);
		msg.setSubject(subject);

		msg.setText(message);

		// set the Date: header
		msg.setSentDate(new Date());

		// send the message

		Transport t = session.getTransport("smtp");
		
		try {
			
			t.connect(host,getPort(),getSMTPAuthUser(),"foo123");
			t.sendMessage(msg,msg.getAllRecipients());

		} finally {
			t.close();
		}

	}
	
	protected void sendMail(MimeMessage msg) throws Exception{

		String host = "localhost";

		// create some properties and get the default Session
		Properties props = System.getProperties();

		props.put("mail.smtp.auth", "true");


		Session session = Session.getInstance(props, null);

		Transport t = session.getTransport();
		try {
			t.connect(host,getSMTPAuthUser(),"foo123");
			t.sendMessage(msg,msg.getAllRecipients());

		} finally {
			t.close();
		}
	}
	
	protected int getPort(){
            final String port = CompileTimeSettings.getInstance()
                    .getProperty(CompileTimeSettings.MAILSIGNERPORT);
		if (port == null) {
			return 26;
		}
		return Integer.parseInt(port);
	}
	
	protected void tearDown() throws Exception {
		super.tearDown();
		iMailSignerRMI = getIMailSignerRMI();
		iMailSignerRMI.removeGlobalProperty(GlobalConfiguration.SCOPE_GLOBAL, MailSignerUtil.TESTMODE_SETTING);
		iMailSignerRMI.removeGlobalProperty(GlobalConfiguration.SCOPE_GLOBAL, GlobalConfiguration.WORKERPROPERTY_BASE + getWorkerId() + GlobalConfiguration.WORKERPROPERTY_CLASSPATH);
		if(getCryptoTokenClasspath() != null){
			iMailSignerRMI.removeGlobalProperty(GlobalConfiguration.SCOPE_GLOBAL, GlobalConfiguration.WORKERPROPERTY_BASE + getWorkerId() + GlobalConfiguration.CRYPTOTOKENPROPERTY_BASE + GlobalConfiguration.CRYPTOTOKENPROPERTY_CLASSPATH);
		}		
		iMailSignerRMI.removeAuthorizedUser(getSMTPAuthUser());
		
		iMailSignerRMI.reloadConfiguration(getWorkerId());
	}
	

	private IMailSignerRMI getIMailSignerRMI() throws Exception{
		if(iMailSignerRMI == null){
			String lookupName = "//localhost:" + MailSignerConfig.getRMIRegistryPort() + "/" +
			MailSignerConfig.RMI_OBJECT_NAME;

			iMailSignerRMI = (IMailSignerRMI) Naming.lookup(lookupName);
		}
		
		return iMailSignerRMI;
	}
	
	  
	protected boolean arrayEquals(byte[] signreq2, byte[] signres2) {
		boolean retval = true;

		if(signreq2.length != signres2.length){
			return false;
		}

		for(int i=0;i<signreq2.length;i++){
			if(signreq2[i] != signres2[i]){
				return false;
			}
		}
		return retval;
	}

}
