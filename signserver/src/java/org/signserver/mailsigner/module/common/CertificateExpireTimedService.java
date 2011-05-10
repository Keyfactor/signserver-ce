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

package org.signserver.mailsigner.module.common;

import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import java.util.Properties;

import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;

import org.apache.log4j.Logger;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.MailSignerStatus;
import org.signserver.mailsigner.IMailProcessor;
import org.signserver.mailsigner.MailSignerContext;
import org.signserver.mailsigner.MailSignerUtil;
import org.signserver.mailsigner.core.MailSignerWorkerConfigService;
import org.signserver.mailsigner.core.NonEJBGlobalConfigurationSession;
import org.signserver.server.ServiceExecutionFailedException;
import org.signserver.server.WorkerFactory;
import org.signserver.server.timedservices.BaseTimedService;

/**
 * A service that does the following:
 *  1. Iterates through all mail signers
 *  2. Checks the certificate if it is about to expire
 *  3. If a worker have an expiring certificate and email is sent
 *     to an administrator.
 *  4. If certificate haven't been renewed before it's time to remind will
 *     a reminder message be sent.
 *     
 * 
 * The service have the following settings:
 *   EXPIRETIMEDAYS   : Number of days of expiring certificate before e-mail is sent. (Default 30 days)
 *   REMINDERTIMEDAYS : Number of days before reminder of expiring certificate is sent. (Default 10 days)
 *   ADMINEMAIL       : Email address to administrator receiving the mail. (Default postmaster)
 *   FROMEMAIL        : From address used in certificate expiration message. (Default is 'certexpire@<postmaster-domain')
 *   MESSAGESUBJECT   : Subject used in expiring certificate message. If not set will a default message subject be sent.
 *   REMINDERSUBJECT  : Subject used in reminder message, if not set will a default message subject be sent.
 *   EXPIREMESSAGE    : Expire message body used in the expire message, if not set will a default message subject be sent.
 *   REMINDERMESSAGE  : Reminder message body, if not set will a default message subject be sent.
 *   
 * Message subject and body contain the substitution variables specified
 * in the NotificationParamGem class.
 *   
 * @author Philip Vendil 1 okt 2008
 *
 * @version $Id$
 */

public class CertificateExpireTimedService extends BaseTimedService {

	public transient Logger log = Logger.getLogger(this.getClass());
	
	public static final String EXPIRETIMEDAYS = "EXPIRETIMEDAYS";
	public static final String DEFAULT_EXPIRETIMEDAYS = "30";
	
	public static final String REMINDERTIMEDAYS = "REMINDERTIMEDAYS";
	public static final String DEFAULT_REMINDERTIMEDAYS = "10";
	
	public static final String ADMINEMAIL = "ADMINEMAIL";
	
	public static final String FROMEMAIL = "FROMEMAIL";
	public static final String DEFAULT_FROMEMAIL_USER = "certexpire";
	
	public static final String MESSAGESUBJECT = "MESSAGESUBJECT";
	public static final String DEFAULT_MESSAGESUBJECT = "WARNING: Mail Processor with id : ${WORKERID} is about to expire.";
	
	public static final String REMINDERSUBJECT = "REMINDERSUBJECT";
	public static final String DEFAULT_REMINDERSUBJECT = "REMINDER: Mail Processor with id : ${WORKERID} is about to expire.";
	
	public static final String EXPIREMESSAGE = "EXPIREMESSAGE";
	public static final String DEFAULT_EXPIREMESSAGE = "A mail processor at host ${HOSTNAME} have a certificate about to expire.${NL}${NL}The Mail Processor have id ${WORKERID} and a certificate with DN '${cert.CERTSUBJECTDN}' and will expire the ${cert.EXPIREDATE}. ${NL}";
	
	public static final String REMINDERMESSAGE = "REMINDERMESSAGE";
	public static final String DEFAULT_REMINDERMESSAGE = "This is a reminder that a mail processor at host ${HOSTNAME} have a certificate about to expire.${NL}${NL}The Mail Processor have id ${WORKERID} and a certificate with DN '${cert.CERTSUBJECTDN}' and will expire the ${cert.EXPIREDATE}. ${NL}";
					
	public static final String GLOBVAR_CERTEXPIRESERVICE_PREFIX = "CERTEXPIRESERVICE.";
	public static final String GLOBVAR_EXPIREDATE_POSTFIX = ".EXPIREDATE";
	public static final String GLOBVAR_EXPIREMAILSENT_POSTFIX = ".EXPIREMAILSENT";
	public static final String GLOBVAR_REMINDERMAILSENT_POSTFIX = ".REMINDERMAILSENT";
	
	@Override
	public void work() throws ServiceExecutionFailedException {
		List<Integer> mailSignerIds = NonEJBGlobalConfigurationSession.getInstance().getWorkers(GlobalConfiguration.WORKERTYPE_MAILSIGNERS);
		for(Integer id : mailSignerIds){
			IMailProcessor mp = (IMailProcessor) WorkerFactory.getInstance().getWorker(id, MailSignerWorkerConfigService.getInstance(), NonEJBGlobalConfigurationSession.getInstance(), getMailSignerContext());
			MailSignerStatus status = (MailSignerStatus) mp.getStatus();
			if(status.getSignerCertificate() != null){
				resetExpireDataIfNecessary(id, status);
				if(timeToSendExpireMail(id, status)){
					sendExpireMail(id, status);
				}
				if(timeToSendReminderMail(id, status)){
					sendReminderMail(id, status);
				}
			}
		}		
	}





	/**
	 * Method that checks if the current certificate have a later expire date than the
	 * one used during the last check.
	 * 
	 * The method does the following:
	 * Check the expire time of the current certificate against the global variable CERTEXPIRESERVICE.id.EXPIREDATE
	 *    if not set, use current certificate value
	 *    if current certificate expire date greater than variable, remove the variables CERTEXPIRESERVICE.id.EXPIREMAILSENT and CERTEXPIRESERVICE.id.REMINDERMAILSENT and
	 *    set variable to current certificate value.
	 *    
	 * @param id worker id
	 * @param status status from where signer certificate is fetched.
	 */
	private void resetExpireDataIfNecessary(Integer id, MailSignerStatus status) {
		NonEJBGlobalConfigurationSession gcSession = NonEJBGlobalConfigurationSession.getInstance();
		GlobalConfiguration gc = gcSession.getGlobalConfiguration();
		
		long currentCertExpireDate = ((X509Certificate) status.getSignerCertificate()).getNotAfter().getTime();
		if(gc.getProperty(GlobalConfiguration.SCOPE_GLOBAL, GLOBVAR_CERTEXPIRESERVICE_PREFIX +id + GLOBVAR_EXPIREDATE_POSTFIX) != null){
			long previousCertExpireDate = Long.parseLong(gc.getProperty(GlobalConfiguration.SCOPE_GLOBAL, GLOBVAR_CERTEXPIRESERVICE_PREFIX +id + GLOBVAR_EXPIREDATE_POSTFIX));
			if(currentCertExpireDate > previousCertExpireDate){
				gcSession.removeProperty(GlobalConfiguration.SCOPE_GLOBAL, GLOBVAR_CERTEXPIRESERVICE_PREFIX +id + GLOBVAR_EXPIREMAILSENT_POSTFIX);
				gcSession.removeProperty(GlobalConfiguration.SCOPE_GLOBAL, GLOBVAR_CERTEXPIRESERVICE_PREFIX +id + GLOBVAR_REMINDERMAILSENT_POSTFIX);
				gcSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, GLOBVAR_CERTEXPIRESERVICE_PREFIX +id + GLOBVAR_EXPIREDATE_POSTFIX, "" +currentCertExpireDate);				
			}
		}else{
			gcSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, GLOBVAR_CERTEXPIRESERVICE_PREFIX +id + GLOBVAR_EXPIREDATE_POSTFIX, "" +currentCertExpireDate);
		}
		
	}
	
	/**
	 * Method that checks if it is time to send an expire mail if it isn't
	 * sent already.
	 * @param id workerId
	 * @param status mail signer status
	 * @return true if it is time to send mail.
	 */
	private boolean timeToSendExpireMail(Integer id, MailSignerStatus status) {
		NonEJBGlobalConfigurationSession gcSession = NonEJBGlobalConfigurationSession.getInstance();
		GlobalConfiguration gc = gcSession.getGlobalConfiguration();
		
		Date currentCertExpireDate = ((X509Certificate) status.getSignerCertificate()).getNotAfter();	
		
		boolean alreadySent = gc.getProperty(GlobalConfiguration.SCOPE_GLOBAL, GLOBVAR_CERTEXPIRESERVICE_PREFIX +id + GLOBVAR_EXPIREMAILSENT_POSTFIX) != null &&
		                      gc.getProperty(GlobalConfiguration.SCOPE_GLOBAL, GLOBVAR_CERTEXPIRESERVICE_PREFIX +id + GLOBVAR_EXPIREMAILSENT_POSTFIX).equals("TRUE");
		return  !alreadySent && currentCertExpireDate.before(getExpireDate());
	}
	
	/**
	 * Method that checks if it is time to send a reminder mail if it isn't
	 * sent already.
	 * @param id workerId
	 * @param status mail signer status
	 * @return true if it is time to send reminder mail.
	 */
	private boolean timeToSendReminderMail(Integer id, MailSignerStatus status) {
		NonEJBGlobalConfigurationSession gcSession = NonEJBGlobalConfigurationSession.getInstance();
		GlobalConfiguration gc = gcSession.getGlobalConfiguration();
		
		Date currentCertExpireDate = ((X509Certificate) status.getSignerCertificate()).getNotAfter();
		boolean alreadySent = gc.getProperty(GlobalConfiguration.SCOPE_GLOBAL, GLOBVAR_CERTEXPIRESERVICE_PREFIX +id + GLOBVAR_REMINDERMAILSENT_POSTFIX) != null &&
		                      gc.getProperty(GlobalConfiguration.SCOPE_GLOBAL, GLOBVAR_CERTEXPIRESERVICE_PREFIX +id + GLOBVAR_REMINDERMAILSENT_POSTFIX).equals("TRUE");
		return !alreadySent && currentCertExpireDate.before(getReminderDate());
	}
	
	/**
	 * Method that sends a certificate is about to expire message
	 * to the administrator.
	 * 
	 * @param id worker id
	 * @param status current worker status
	 */
	private void sendExpireMail(Integer id, MailSignerStatus status) {
	  NotificationParamGen paramGen = new NotificationParamGen(status);
	  String subject = NotificationParamGen.interpolate(paramGen.getParams(), status.getActiveSignerConfig().getProperty(MESSAGESUBJECT, DEFAULT_MESSAGESUBJECT));
	  String msgBody = NotificationParamGen.interpolate(paramGen.getParams(), status.getActiveSignerConfig().getProperty(EXPIREMESSAGE, DEFAULT_EXPIREMESSAGE));
      String to = getAdminEmail();
      String from = getFromEmail();
      sendMail(to,subject,msgBody,from);
      NonEJBGlobalConfigurationSession.getInstance().setProperty(GlobalConfiguration.SCOPE_GLOBAL, GLOBVAR_CERTEXPIRESERVICE_PREFIX +id + GLOBVAR_EXPIREMAILSENT_POSTFIX,"TRUE");
	}

	/**
	 * Method that sends a reminder about a certificate that is about to expire 
	 * to the administrator.
	 * 
	 * @param id worker id
	 * @param status current worker status
	 */
	private void sendReminderMail(Integer id, MailSignerStatus status) {
		NotificationParamGen paramGen = new NotificationParamGen(status);
		String subject = NotificationParamGen.interpolate(paramGen.getParams(), status.getActiveSignerConfig().getProperty(REMINDERSUBJECT, DEFAULT_REMINDERSUBJECT));
		String msgBody = NotificationParamGen.interpolate(paramGen.getParams(), status.getActiveSignerConfig().getProperty(REMINDERMESSAGE, DEFAULT_REMINDERMESSAGE));
	    String to = getAdminEmail();
	    String from = getFromEmail();
	    sendMail(to,subject,msgBody,from);
	    NonEJBGlobalConfigurationSession.getInstance().setProperty(GlobalConfiguration.SCOPE_GLOBAL, GLOBVAR_CERTEXPIRESERVICE_PREFIX +id + GLOBVAR_REMINDERMAILSENT_POSTFIX,"TRUE");	    
	}
	
	private void sendMail(String to, String subject, String msgBody, String from) {

			try{
				// Get system properties
				Properties props = System.getProperties();

				// Setup mail server
				props.put("mail.smtp.host", "localhost");

				// Get session
				Session session = Session.getInstance(props, null);

				// Define message
				MimeMessage message = new MimeMessage(session);
				message.setFrom(new InternetAddress(from));
				message.addRecipient(Message.RecipientType.TO, 
						new InternetAddress(to));
				message.setSubject(subject);
				message.setText(msgBody);
				if(MailSignerUtil.isTestMode()){
					MailSignerUtil.mailTest(message);
				}else{
					getMailSignerContext().getMailetContext().sendMail(message);
				}
			} catch (MessagingException e) {
				log.error("Error sending certificate expire message to "+ to + " : " + e.getMessage(),e);
			}	
	}
	
	private Date getExpireDate(){
		Date retval=null;
		long timeInDays;
		try{
			timeInDays = Long.parseLong(config.getProperty(EXPIRETIMEDAYS, DEFAULT_EXPIRETIMEDAYS));
		}catch(NumberFormatException e){
			log.error("Error in CertificateExpireTimedServiceConfiguration with id " + workerId + " : setting " + EXPIRETIMEDAYS + " can only contain digits, using default value.");
			timeInDays = Long.parseLong(DEFAULT_EXPIRETIMEDAYS);
		}
		
		retval = new Date(System.currentTimeMillis() + (timeInDays * 24 * 3600 * 1000));
		
		return retval;
	}
	
	private Date getReminderDate(){
		Date retval=null;
		long timeInDays;
		try{
			timeInDays = Long.parseLong(config.getProperty(REMINDERTIMEDAYS, DEFAULT_REMINDERTIMEDAYS));
		}catch(NumberFormatException e){
			log.error("Error in CertificateExpireTimedServiceConfiguration with id " + workerId + " : setting " + REMINDERTIMEDAYS + " can only contain digits, using default value.");
			timeInDays = Long.parseLong(DEFAULT_REMINDERTIMEDAYS);
		}
		
		retval = new Date(System.currentTimeMillis() + (timeInDays * 24 * 3600 * 1000));
		
		return retval;
	}
	
	private String getAdminEmail(){
		if(config.getProperty(ADMINEMAIL) == null){
			return getMailSignerContext().getMailetContext().getPostmaster().toString();
		}else{
			return config.getProperty(ADMINEMAIL);
		}
	}
	
	private String fromEmail = null;
	private String getFromEmail(){
		if(fromEmail == null){
			if(config.getProperty(ADMINEMAIL) == null){
				fromEmail = DEFAULT_FROMEMAIL_USER + "@" + getMailSignerContext().getMailetContext().getPostmaster().getHost();
			}else{
				fromEmail = config.getProperty(FROMEMAIL);				
			}
		}
		
		return fromEmail;
	}
	

	private MailSignerContext getMailSignerContext() {
		if(workerContext != null && workerContext instanceof MailSignerContext){
			return (MailSignerContext) workerContext;
		}
		return null;
		
	}
}
