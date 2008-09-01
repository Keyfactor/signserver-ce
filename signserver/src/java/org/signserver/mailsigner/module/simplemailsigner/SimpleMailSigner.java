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

package org.signserver.mailsigner.module.simplemailsigner;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;

import javax.mail.Address;
import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;

import org.apache.james.security.SMIMEAttributeNames;
import org.apache.log4j.Logger;
import org.apache.mailet.Mail;
import org.apache.mailet.MailAddress;
import org.apache.mailet.RFC2822Headers;
import org.bouncycastle.mail.smime.SMIMESignedGenerator;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.mailsigner.BaseMailProcessor;
import org.signserver.mailsigner.core.SMIMEHelper;
import org.signserver.server.cryptotokens.ICryptoToken;

/**
 * Simple Mail Signer that simply creates a signed SMIME message of
 * the message (Regular mail) sent to the server.
 * 
 * 
 * A lot of the code is reused from the SMIME Mailet code in the JAMES
 * project.
 * 
 * For more information about the JAMES project see. http://james.apache.org/
 * 
 * Supported Properties:
 * EXPLAINATIONTEXT, USEREBUILDFROM, SIGNATUREALG, SIGNERNAME, FROMNAME,
 * REPLYTONAME, CHANGEREPLYTO, POSTMASTERSIGNS, REPLYTOADDRESS, SIGNERADDRESS,
 * FROMADDRESS, REQUIRESMTPAUTH
 * 
 * @author Philip Vendil 22 dec 2007
 *
 * @version $Id: SimpleMailSigner.java,v 1.2 2008-01-19 03:42:11 herrvendil Exp $
 */

public class SimpleMailSigner extends BaseMailProcessor {


	/**
	 * Setting indicating if the from field of the SMIME should be altered.
	 */
	public static final String USEREBUILDFROM = "USEREBUILDFROM";
	/**
	 * Default value of use rebuild from value if it isn't set.
	 */
	public static final String DEFAULT_USEREBUILDFROM = "TRUE";
	

	/**
	 * Setting configuring the signature algorithm that should be used in the SMIME message.
	 * Default is DIGEST_SHA1 if not set.
	 */
	public static final String SIGNATUREALG = "SIGNATUREALG";

	public static final String DEFAULT_SIGNATUREALG = SMIMESignedGenerator.DIGEST_SHA1;
	
	/**
	 * Readable name used in sender address field. (Optional)
	 */
	public static final String SIGNERNAME = "SIGNERNAME";
	
	/**
	 * Readable name used in from address field. (Optional)
	 */
	public static final String FROMNAME = "FROMNAME";
	
	/**
	 * Readable name used in reply-to address field. (Optional)
	 */
	public static final String REPLYTONAME = "REPLYTONAME";
	
	/**
	 * Indicates if the reply-to field should be altered to
	 * the original sender. (Default false)
	 */
	public static final String CHANGEREPLYTO = "CHANGEREPLYTO";	
	public static final String DEFAULT_CHANGEREPLYTO = "FALSE";
	
	/**
	 * Indicates if postmaster mail should be signed. (Default false)
	 */
	public static final String POSTMASTERSIGNS = "POSTMASTERSIGNS";
	public static final String DEFAULT_POSTMASTERSIGNS = "FALSE";
	
	/**
	 * The reply to email address if the reply always should be changed to
	 * a default address. (Required if CHANGEREPLYTO is true)
	 */
	public static final String REPLYTOADDRESS = "REPLYTOADDRESS";
	/**
	 * The email address that should be in the sender field. (Required)
	 */
	public static final String SIGNERADDRESS = "SIGNERADDRESS";
	
	/**
	 * The from email address used if rebuild from is set.
	 * (Required if USEREBUILDFROM is true)
	 */
	public static final String FROMADDRESS = "FROMADDRESS";
	
	/**
	 * Setting defining if SMTP AUTH should be required to
	 * sign the mail. (Default is true).
	 */
	public static final String REQUIRESMTPAUTH = "REQUIRESMTPAUTH";
	public static final String DEFAULT_REQUIRESMTPAUTH = "TRUE";
	
	/**
	 * Setting defining if mail that depending on configuration shouldn't
	 * be signed still should be sent as clear text or if they should be
	 * marked with "Error" in the mail server 
	 * 
	 * (Default is false, not to send unsigned messages).
	 */
	public static final String RESENDUNSIGNEDMESSAGES = "RESENDUNSIGNEDMESSAGES";
	public static final String DEFAULT_RESENDUNSIGNEDMESSAGES = "FALSE";
	
	public transient Logger log = Logger.getLogger(this.getClass());
	
	/**
	 * @see org.signserver.mailsigner.IMailProcessor#service(org.apache.mailet.Mail)
	 */
	public void service(Mail mail) throws MessagingException, CryptoTokenOfflineException{
		try{
			if (!isOkToSign(mail)) {
				if(!isResendUnsignedMessages()){
					mail.setState(Mail.ERROR);
				}
				return;
			}

			MimeBodyPart wrapperBodyPart = SMIMEHelper.getWrapperBodyPart(mail,config);

			MimeMessage originalMessage = mail.getMessage();

			// do it
			MimeMultipart signedMimeMultipart;
			if (wrapperBodyPart != null) {
				signedMimeMultipart = SMIMEHelper.generate(wrapperBodyPart, getCryptoToken().getPrivateKey(ICryptoToken.PROVIDERUSAGE_SIGN),(X509Certificate) getSigningCertificate(),getSignatureHashAlgorithm(), getCertStore(),getCryptoToken().getProvider(ICryptoToken.PROVIDERUSAGE_SIGN));
			} else {
				signedMimeMultipart = SMIMEHelper.generate(originalMessage, getCryptoToken().getPrivateKey(ICryptoToken.PROVIDERUSAGE_SIGN),(X509Certificate) getSigningCertificate(),getSignatureHashAlgorithm(), getCertStore(),getCryptoToken().getProvider(ICryptoToken.PROVIDERUSAGE_SIGN));
			}

			MimeMessage newMessage = new MimeMessage(Session.getDefaultInstance(System.getProperties(),
					null));
			Enumeration<?> headerEnum = originalMessage.getAllHeaderLines();
			while (headerEnum.hasMoreElements()) {
				newMessage.addHeaderLine((String) headerEnum.nextElement());
			}

			newMessage.setSender(new InternetAddress(getSignerAddress(), getSignerName()));

			if (isRebuildFrom()) {
				// builds a new "mixed" "From:" header
				InternetAddress modifiedFromIA = new InternetAddress(getFromAddress(), getFromName());
				newMessage.setFrom(modifiedFromIA);            
			}

			if( changeReplyTo()){
				Address[] replyAddresses = new Address[1];
				replyAddresses[0] = new InternetAddress(getReplyToAddress(),getReplyToName());
				newMessage.setReplyTo(replyAddresses);
			}else{
				if(mail.getMessage().getReplyTo() == null || mail.getMessage().getReplyTo().length == 0){
					Address[] replyAddresses = new Address[1];
					replyAddresses[0] = mail.getMessage().getSender();
					newMessage.setReplyTo(replyAddresses);
				}else{
					newMessage.setReplyTo(mail.getMessage().getReplyTo());
				}
			}

			newMessage.setContent(signedMimeMultipart, signedMimeMultipart.getContentType());
			String messageId = originalMessage.getMessageID();
			newMessage.saveChanges();
			if (messageId != null) {
				newMessage.setHeader(RFC2822Headers.MESSAGE_ID, messageId);
			}

			mail.setMessage(newMessage);

			// marks this mail as server-signed
			mail.setAttribute(SMIMEAttributeNames.SMIME_SIGNING_MAILET, this.getClass().getName());
			// it is valid for us by definition (signed here by us)
			mail.setAttribute(SMIMEAttributeNames.SMIME_SIGNATURE_VALIDITY, "valid");

			// saves the trusted server signer address
			// warning: should be same as the mail address in the certificate, but it is not guaranteed
			mail.setAttribute(SMIMEAttributeNames.SMIME_SIGNER_ADDRESS, getSignerAddress());


			log.debug("Message signed, reverse-path: " + mail.getSender() + ", Id: " + messageId);


		} catch (MessagingException me) {
			log.error("MessagingException found - could not sign!", me);
			throw me;
		} catch (CryptoTokenOfflineException e) {
			throw e;
		} catch (Exception e) {
			log.error("Exception found", e);
			throw new MessagingException("Exception thrown - could not sign!", e);
		}

	}

    /**
     * <P>Checks if the mail can be signed.</P>
     * <P>Rules:</P>
     * <OL>
     * <LI>The reverse-path != null (it is not a bounce).</LI>
     * <LI>The sender user must have been SMTP authenticated (if required).</LI>
     * <LI>Either:</LI>
     * <UL>
     * <LI>The reverse-path is the postmaster address and {@link #isPostmasterSigns} returns <I>true</I></LI>
     * <LI>or the reverse-path == the authenticated user
     * and there is at least one "From:" address == reverse-path.</LI>.
     * </UL>
     * <LI>The message has not already been signed (mimeType != <I>multipart/signed</I>
     * and != <I>application/pkcs7-mime</I>).</LI>
     * </OL>
     * @param mail The mail object to check.
     * @return True if can be signed.
     */
    protected boolean isOkToSign(Mail mail) throws MessagingException {

        MailAddress reversePath = mail.getSender();
        
        // Is it a bounce?
        if (reversePath == null) {
            return false;
        }
        
        String authUser = (String) mail.getAttribute("org.apache.james.SMTPAuthUser");
        if(getRequireSMTPAUTH()){        	
        	// was the sender user SMTP authorized?
        	if (authUser == null) {
        		return false;
        	}
        }
        
        // The sender is the postmaster?
        if (mailetContext.getPostmaster().equals(reversePath)) {
            // should not sign postmaster sent messages?
            if (!isPostmasterSigns()) {
                return false;
            }
        } else {
            // is the reverse-path user different from the SMTP authorized user?
            if (getRequireSMTPAUTH() && !reversePath.getUser().equals(authUser)) {
                return false;
            }
            // is there no "From:" address same as the reverse-path?
            if (!SMIMEHelper.fromAddressSameAsReverse(mail)) {
                return false;
            }
        }
        
        // if already signed return false
        MimeMessage mimeMessage = mail.getMessage();
        if (mimeMessage.isMimeType("multipart/signed")
            || mimeMessage.isMimeType("application/pkcs7-mime")) {
            return false;
        }
        
        return true;
    }

	private Boolean requireSMTPAUTH  = null;
	private boolean getRequireSMTPAUTH() {
		if(requireSMTPAUTH == null){
			String value = config.getProperties().getProperty(REQUIRESMTPAUTH,DEFAULT_REQUIRESMTPAUTH ).trim();
			if(value.equalsIgnoreCase("TRUE")){
				requireSMTPAUTH = true; 
			}else if(value.equalsIgnoreCase("FALSE")){
				requireSMTPAUTH = false; 
			}else{
				log.error("Error MailSigner property " + REQUIRESMTPAUTH + " is missconfigured, must be either true or false, using default value of " + DEFAULT_REQUIRESMTPAUTH);
				requireSMTPAUTH = Boolean.parseBoolean(DEFAULT_REQUIRESMTPAUTH);
			}
		}
		return requireSMTPAUTH;
	}
	
	private Boolean postmasterSigns  = null;
	private boolean isPostmasterSigns() {
		if(postmasterSigns == null){
			String value = config.getProperties().getProperty(POSTMASTERSIGNS,DEFAULT_POSTMASTERSIGNS ).trim();
			if(value.equalsIgnoreCase("TRUE")){
				postmasterSigns = true; 
			}else if(value.equalsIgnoreCase("FALSE")){
				postmasterSigns = false; 
			}else{
				log.error("Error MailSigner property " + POSTMASTERSIGNS + " is missconfigured, must be either true or false, using default value of " + DEFAULT_POSTMASTERSIGNS);
				postmasterSigns = Boolean.parseBoolean(DEFAULT_POSTMASTERSIGNS);
			}
		}
		return postmasterSigns;
	}

	protected String getReplyToName() {
		return config.getProperties().getProperty(REPLYTONAME);
	}

	private String replyToAddress = null;
	protected String getReplyToAddress() throws MessagingException {
		if(replyToAddress == null){
			replyToAddress = config.getProperties().getProperty(REPLYTOADDRESS);
			if(replyToAddress == null){
				log.error("Error required MailSigner property " + REPLYTOADDRESS + " is not set.");
				throw new MessagingException("Error required MailSigner property " + REPLYTOADDRESS + " is not set.");
			}
		}
		
		return replyToAddress;
	}

	private Boolean changeReplyTo  = null;
	protected boolean changeReplyTo() {
		if(changeReplyTo == null){
			String value = config.getProperties().getProperty(CHANGEREPLYTO,DEFAULT_CHANGEREPLYTO ).trim();
			if(value.equalsIgnoreCase("TRUE")){
				changeReplyTo = true; 
			}else if(value.equalsIgnoreCase("FALSE")){
				changeReplyTo = false; 
			}else{
				log.error("Error MailSigner property " + CHANGEREPLYTO + " is missconfigured, must be either true or false, using default value of " + DEFAULT_CHANGEREPLYTO);
				changeReplyTo = Boolean.parseBoolean(DEFAULT_CHANGEREPLYTO);
			}
		}
		return changeReplyTo;
	}

	protected String getFromName() {
		return config.getProperties().getProperty(FROMNAME);
	}

	private String fromAddress = null;
	protected String getFromAddress() throws MessagingException {
		if(fromAddress == null){
			fromAddress = config.getProperties().getProperty(FROMADDRESS);
			if(fromAddress == null){
				log.error("Error required MailSigner property " + FROMADDRESS + " is not set.");
				throw new MessagingException("Error required MailSigner property " + FROMADDRESS + " is not set.");
			}
		}
		
		return signerAddress;
	}

	private String signerAddress = null;
	protected String getSignerAddress() throws MessagingException{
		if(signerAddress == null){
			signerAddress = config.getProperties().getProperty(SIGNERADDRESS);
			if(signerAddress == null){
				log.error("Error required MailSigner property " + SIGNERADDRESS + " is not set.");
				throw new MessagingException("Error required MailSigner property " + SIGNERADDRESS + " is not set.");
			}
		}
		
		return signerAddress;
	}

	protected String getSignerName() {	
		return config.getProperties().getProperty(SIGNERNAME);
	}

	private Boolean resendUnsignedMessages  = null;
	protected boolean isResendUnsignedMessages() {
		if(resendUnsignedMessages == null){
		  String value = config.getProperties().getProperty(RESENDUNSIGNEDMESSAGES,DEFAULT_RESENDUNSIGNEDMESSAGES ).trim();
		  if(value.equalsIgnoreCase("TRUE")){
			  resendUnsignedMessages = true; 
		  }else if(value.equalsIgnoreCase("FALSE")){
			  resendUnsignedMessages = false; 
		  }else{
			  log.error("Error MailSigner property " + RESENDUNSIGNEDMESSAGES + " is missconfigured, must be either true or false, using default value of " + DEFAULT_RESENDUNSIGNEDMESSAGES);
			  resendUnsignedMessages = Boolean.parseBoolean(DEFAULT_RESENDUNSIGNEDMESSAGES);
		  }
		}
		return resendUnsignedMessages;
	}
	
	private Boolean rebuildFrom  = null;
	protected boolean isRebuildFrom() {
		if(rebuildFrom == null){
		  String value = config.getProperties().getProperty(USEREBUILDFROM,DEFAULT_USEREBUILDFROM ).trim();
		  if(value.equalsIgnoreCase("TRUE")){
			  rebuildFrom = true; 
		  }else if(value.equalsIgnoreCase("FALSE")){
			  rebuildFrom = false; 
		  }else{
			  log.error("Error MailSigner property " + USEREBUILDFROM + " is missconfigured, must be either true or false, using default value of " + DEFAULT_USEREBUILDFROM);
			  rebuildFrom = Boolean.parseBoolean(DEFAULT_USEREBUILDFROM);
		  }
		}
		return rebuildFrom;
	}

	private CertStore certStore = null;
	protected CertStore getCertStore() throws CryptoTokenOfflineException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
		if(certStore == null){
			ArrayList<Certificate> certCollection = new ArrayList<Certificate>();
			if(getSigningCertificateChain() != null){
				certCollection.addAll(getSigningCertificateChain());
				certStore = CertStore.getInstance("Collection",
                        new CollectionCertStoreParameters(certCollection), 
                        "BC");
			}
		}
		
		return certStore;
	}

	protected String getSignatureHashAlgorithm() {
		return config.getProperties().getProperty(SIGNATUREALG,DEFAULT_SIGNATUREALG);
	}
	


}
