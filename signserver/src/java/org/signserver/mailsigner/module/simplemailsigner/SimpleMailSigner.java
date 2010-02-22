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
import java.util.Collection;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Iterator;

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
import org.signserver.common.RequestContext;
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
 * FROMADDRESS, REQUIRESMTPAUTH, CHECKSMTPAUTHSENDER, SIGNBYDEFAULT, 
 * OPTIN, OPTOUT, USESUBJECTTAGS, SENDERNAME
 * 
 * @author Philip Vendil 22 dec 2007
 *
 * @version $Id$
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
         * If the From/Sender fields should be composed of the
         * FROMADDRESS/SIGNERADDRESS and the name from the From field of the
         * original e-mail.
         */
        public static final String SENDERNAME = "SENDERNAME";

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
	
	/**
	 * Setting defining if signatures should be done by default
	 * or if the recipient domain must exists on the OPTIN list.
	 * 
	 * (Default is true, to sign by default).
	 */
	public static final String SIGNBYDEFAULT = "SIGNBYDEFAULT";
	public static final String DEFAULT_SIGNBYDEFAULT = "TRUE";
	
	/**
	 * Setting defining which recipient domains that always should
	 * be signed. Used if SIGNBYDEFAULT is set to FALSE. Can
	 * be overridden with subject tag.
	 * 
	 * 
	 */
	public static final String OPTIN = "OPTIN";

	/**
	 * Setting defining which recipient domains that never should
	 * be signed. Used if SIGNBYDEFAULT is set to TRUE. Can
	 * be overridden with subject tag.
	 * 
	 */
	public static final String OPTOUT = "OPTOUT";
	
	/**
	 * Setting defining if subject tags will be supported. If
	 * used will the subject be searched for "SIGN" and "NOSIGN"
	 * in the subject and act accordingly.
	 * 
	 * (Default is false, not to use subject tags).
	 */
	public static final String USESUBJECTTAGS = "USESUBJECTTAGS";
	public static final String DEFAULT_USESUBJECTTAGS = "FALSE";
	public static final String SUBJECTTAG_SIGN = "SIGN";
	public static final String SUBJECTTAG_NOSIGN = "NOSIGN";
	
	/**
	 * Setting used if it is desired to check that the sender address (name part)
	 * is the same as the SMTP AUTH user. This can be used as an extra check
	 * that the user don't send mails in someone else name. In hosted environment
	 * it can be good to have this set to false.
	 * 
	 * Default: false
	 */
	public static final String CHECKSMTPAUTHSENDER = "CHECKSMTPAUTHSENDER";
	public static final String DEFAULT_CHECKSMTPAUTHSENDER = "FALSE";
	
	public transient Logger log = Logger.getLogger(this.getClass());
	
	/**
	 * @see org.signserver.mailsigner.IMailProcessor#service(Mail, RequestContext)
	 */
	public void service(Mail mail, RequestContext requestContext) throws MessagingException, CryptoTokenOfflineException{
		try{
			if (isOkToSign(mail).size() == 0) {
				if(!isResendUnsignedMessages()){
					mail.setState(Mail.ERROR);
				}
				return;
			}

			MimeBodyPart wrapperBodyPart = SMIMEHelper.getWrapperBodyPart(mail,config);

			MimeMessage originalMessage = mail.getMessage();
	        if(getUseSubjectTags()){
	        	if(mail.getMessage().getSubject().contains(SUBJECTTAG_NOSIGN)){
	        		mail.getMessage().setSubject(mail.getMessage().getSubject().replaceFirst(SUBJECTTAG_NOSIGN, ""));
	        	}
	        	if(mail.getMessage().getSubject().contains(SUBJECTTAG_SIGN)){
	        		mail.getMessage().setSubject(mail.getMessage().getSubject().replaceFirst(SUBJECTTAG_SIGN, ""));
	        	}
	        }

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

                        final String senderName;
                        if (Boolean.parseBoolean(config.getProperties().getProperty(SENDERNAME))) {
                            senderName = getSenderOrFromName(mail);
                        } else {
                            senderName = getSignerName();
                        }

			newMessage.setSender(new InternetAddress(getSignerAddress(), senderName));

			if (isRebuildFrom()) {
                            // builds a new "mixed" "From:" header
                            final String name;
                            if (Boolean.parseBoolean(config.getProperties().getProperty(SENDERNAME))) {
                                name = getSenderOrFromName(mail);
                            } else {
                                name = getFromName();
                            }

				InternetAddress modifiedFromIA = new InternetAddress(getFromAddress(), name);
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
     * Method responsible for checking if the mail should be signed or not.
     * 
     * 
     * @param mail The mail object to check.
     * @return a collection of MailAddress of all recipients that is OK to sign the mail to. Empty
     * collection means that the mail should'nt be signed at all.
     */
    @SuppressWarnings("unchecked")
	protected Collection<?> isOkToSign(Mail mail) throws MessagingException {
        HashSet retval = new HashSet();
    	
        MailAddress reversePath = mail.getSender();
        
        // Is it a bounce?
        if (reversePath == null) {
            return retval;
        }
        
        String authUser = (String) mail.getAttribute("org.apache.james.SMTPAuthUser");
        if(getRequireSMTPAUTH()){        	
        	// was the sender user SMTP authorized?
        	if (authUser == null) {
        		return retval;
        	}
        }
        
        // The sender is the postmaster?
        if (mailetContext.getPostmaster().equals(reversePath)) {
            // should not sign postmaster sent messages?
            if (!isPostmasterSigns()) {
                return retval;
            }
        } else {
            // is the reverse-path user different from the SMTP authorized user?
        	if(getCheckSMTPAuthSender()){
        		if (getRequireSMTPAUTH() && !reversePath.getUser().equals(authUser)) {
        			return retval;
        		}
        	}
            // is there no "From:" address same as the reverse-path?
            if (!SMIMEHelper.fromAddressSameAsReverse(mail)) {
                return retval;
            }
        }
        
        // if already signed return false
        MimeMessage mimeMessage = mail.getMessage();
        if (mimeMessage.isMimeType("multipart/signed")
            || mimeMessage.isMimeType("application/pkcs7-mime")) {
            return retval;
        }
        
        if(getUseSubjectTags()){
        	if(mail.getMessage().getSubject().contains(SUBJECTTAG_NOSIGN)){
        		// Message subject contains NOSIGN        		
        		return retval;
        	}
        	if(mail.getMessage().getSubject().contains(SUBJECTTAG_SIGN)){
        		// Message subject contains SIGN
        		return mail.getRecipients();
        	}
        }
        
        if(getSignByDefault()){
            if(getOptOutValues().size() != 0){
            	// Use Opt Out values 
            	Collection<?> r = mail.getRecipients();
            	Iterator<?> iter = r.iterator();
            	while(iter.hasNext()){
            		MailAddress mailAddress = (MailAddress) iter.next();
            		if(!getOptOutValues().contains(mailAddress.getHost())){
            			retval.add(mailAddress);
            		}
            	}
            	
            	
            	return retval;
            }
        }else{
            if(getOptInValues().size() != 0){
            	// Use Opt In values
            	Collection<?> r = mail.getRecipients();
            	Iterator<?> iter = r.iterator();
            	while(iter.hasNext()){
            		MailAddress mailAddress = (MailAddress) iter.next();
            		if(getOptInValues().contains(mailAddress.getHost())){
            			retval.add(mailAddress);
            		}
            	}
            	
            	return retval;
            }
        }

        if(retval.size() == 0){
        	retval.addAll(mail.getRecipients());
        }

        
        
        return retval;
    }
    
    

	/**
	 * Matcher that matches the opt-in and opt-out settings against
	 * the recipients.
	 * 
	 * @see org.signserver.mailsigner.BaseMailProcessor#match(org.apache.mailet.Mail)
	 */
	@Override
	public Collection<?> match(Mail mail) throws MessagingException {		
		return isOkToSign(mail);
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
	
	private Boolean checkSMTPAuthSender  = null;
	private boolean getCheckSMTPAuthSender() {
		if(checkSMTPAuthSender == null){
			String value = config.getProperties().getProperty(CHECKSMTPAUTHSENDER,DEFAULT_CHECKSMTPAUTHSENDER ).trim();
			if(value.equalsIgnoreCase("TRUE")){
				checkSMTPAuthSender = true; 
			}else if(value.equalsIgnoreCase("FALSE")){
				checkSMTPAuthSender = false; 
			}else{
				log.error("Error MailSigner property " + CHECKSMTPAUTHSENDER + " is missconfigured, must be either true or false, using default value of " + DEFAULT_CHECKSMTPAUTHSENDER);
				checkSMTPAuthSender = Boolean.parseBoolean(DEFAULT_CHECKSMTPAUTHSENDER);
			}
		}
		return checkSMTPAuthSender;
	}
	
	private Boolean useSubjectTags  = null;
	private boolean getUseSubjectTags() {
		if(useSubjectTags == null){
			String value = config.getProperties().getProperty(USESUBJECTTAGS,DEFAULT_USESUBJECTTAGS ).trim();
			if(value.equalsIgnoreCase("TRUE")){
				useSubjectTags = true; 
			}else if(value.equalsIgnoreCase("FALSE")){
				useSubjectTags = false; 
			}else{
				log.error("Error MailSigner property " + USESUBJECTTAGS + " is missconfigured, must be either true or false, using default value of " + DEFAULT_USESUBJECTTAGS);
				useSubjectTags = Boolean.parseBoolean(DEFAULT_USESUBJECTTAGS);
			}
		}
		return useSubjectTags;
	}
	
	private Boolean signByDefault  = null;
	private boolean getSignByDefault() {
		if(signByDefault == null){
			String value = config.getProperties().getProperty(SIGNBYDEFAULT,DEFAULT_SIGNBYDEFAULT ).trim();
			if(value.equalsIgnoreCase("TRUE")){
				signByDefault = true; 
			}else if(value.equalsIgnoreCase("FALSE")){
				signByDefault = false; 
			}else{
				log.error("Error MailSigner property " + SIGNBYDEFAULT + " is missconfigured, must be either true or false, using default value of " + DEFAULT_SIGNBYDEFAULT);
				signByDefault = Boolean.parseBoolean(DEFAULT_SIGNBYDEFAULT);
			}
		}
		return signByDefault;
	}
	
	private HashSet<String> oPTInValues = null;
	private HashSet<String> getOptInValues(){
		if(oPTInValues == null){
			oPTInValues = new HashSet<String>();
			String value = config.getProperties().getProperty(OPTIN);
			if(value != null){
				String[] values = value.split(",");
				for(String optInVal : values){
					oPTInValues.add(optInVal.trim());
				}
			}
		}
		
		return oPTInValues;
	}
	
	private HashSet<String> oPTOutValues = null;
	private HashSet<String> getOptOutValues(){
		if(oPTOutValues == null){
			oPTOutValues = new HashSet<String>();
			String value = config.getProperties().getProperty(OPTOUT);
			if(value != null){
				String[] values = value.split(",");
				for(String optInVal : values){
					oPTOutValues.add(optInVal.trim());
				}
			}
		}
		
		return oPTOutValues;
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

    /**
     * Method for extracting the personal (name) of a mail-address. First it
     * tries with the sender address and if that does not contain a name the
     * first From address is used.
     * @param mail The mail to read headers from.
     * @return Name from the Sender or From headers.
     * @throws MessagingException In case of problem reading the From field
     */
    private static String getSenderOrFromName(final Mail mail) throws MessagingException {
        String name = mail.getSender().toInternetAddress().getPersonal();
        if (name == null) {
            final Address[] fromS = mail.getMessage().getFrom();
            if (fromS != null && fromS.length > 0 && fromS[0] instanceof InternetAddress) {
                final InternetAddress from = (InternetAddress) fromS[0];
                name = from.getPersonal();
            }
        }
        return name;
    }
}
