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

package org.signserver.mailsigner.core;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.cert.CertStore;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import javax.mail.MessagingException;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;
import javax.mail.internet.ParseException;

import org.apache.log4j.Logger;
import org.apache.mailet.Mail;
import org.apache.mailet.MailAddress;
import org.bouncycastle.mail.smime.SMIMESignedGenerator;
import org.signserver.common.WorkerConfig;

/**
 * Contains static utility methods used to help the management 
 * of SMIME messages.
 * 
 * A lot of the code is reused from the SMIME Mailet code in the JAMES
 * project.
 * 
 * For more information about the JAMES project see. http://james.apache.org/
 * 
 * 
 * @author Philip Vendil 22 dec 2007
 *
 * @version $Id$
 */

public class SMIMEHelper {
	public static transient Logger log = Logger.getLogger(SMIMEHelper.class);
	
	/**
	 * Setting describing the extra text that is appended to the mail, 
	 * describing the signature message.
	 */
	public static final String EXPLAINATION_TEXT = "EXPLAINATIONTEXT";
	
	/**
	 * 
	 * @param mail the mail to wrap if an explanation text should be added.
	 * @param config the worker config of the mail signer
	 * @return a MimeBodyPart if the setting EXPLAINATIONTEXT is set otherwise null
	 * @throws MessagingException
	 * @throws IOException
	 */
    public static MimeBodyPart getWrapperBodyPart(Mail mail, WorkerConfig config) throws MessagingException, IOException{
        String explanationText = config.getProperties().getProperty(EXPLAINATION_TEXT);
        
        // if there is no explanation text there should be no wrapping
        if (explanationText == null) {
            return null;
        }

            MimeMessage originalMessage = mail.getMessage();

            MimeBodyPart messagePart = new MimeBodyPart();
            MimeBodyPart signatureReason = new MimeBodyPart();
            
            String contentType = originalMessage.getContentType();
            Object content = originalMessage.getContent();
            
            if (contentType != null && content != null) {
            messagePart.setContent(content, contentType);
            } else {
                throw new MessagingException("Either the content type or the content is null");
            }
            
            signatureReason.setText(explanationText);
            
            signatureReason.setFileName("SignatureExplanation.txt");
            
            MimeMultipart wrapperMultiPart = new MimeMultipart();
            
            wrapperMultiPart.addBodyPart(messagePart);
            wrapperMultiPart.addBodyPart(signatureReason);
            
            MimeBodyPart wrapperBodyPart = new MimeBodyPart();
            
            wrapperBodyPart.setContent(wrapperMultiPart);
            
            return wrapperBodyPart;
    }

    
    /**
     * Utility method for obtaining a string representation of the Message's headers
     * @param message The message to extract the headers from.
     * @return The string containing the headers.
     */
    public static String getMessageHeaders(MimeMessage message) throws MessagingException {
        Enumeration<?> heads = message.getAllHeaderLines();
        StringBuffer headBuffer = new StringBuffer(1024);
        while(heads.hasMoreElements()) {
            headBuffer.append(heads.nextElement().toString()).append("\r\n");
        }
        return headBuffer.toString();
    }
    
    /**
     * Creates an <CODE>SMIMESignedGenerator</CODE>. Includes a signer private key and certificate,
     * and a pool of certs and cerls (if any) to go with the signature.
     * @return The generated SMIMESignedGenerator.
     * @throws MessagingException  if error occurred during SMIME generation. 
     */    
    public static SMIMESignedGenerator createGenerator(PrivateKey privateKey, X509Certificate signerCertificate, String hashAlg, CertStore certStore) throws  MessagingException {
    	try{
    		// create the generator for creating an smime/signed message
    		SMIMESignedGenerator generator = new SMIMESignedGenerator();

    		// add a signer to the generator - this specifies we are using SHA1
    		// the encryption algorithm used is taken from the key
    		generator.addSigner(privateKey, signerCertificate, hashAlg);

    		// add our pool of certs and cerls (if any) to go with the signature
    		generator.addCertificatesAndCRLs(certStore);

    		return generator;
    	} catch (Exception e) {
    		log.error("Error creating SMIME Generator : " +e.getMessage(),e);
    		throw new MessagingException("Error creating SMIME Generator : " +e.getMessage(),e);
    	} 
    }
    
    /**
     * Generates a signed MimeMultipart from a MimeMessage.
     * @param message The message to sign.
     * @return The signed <CODE>MimeMultipart</CODE>.
     * @throws MessagingException if error occurred during SMIME generation. 
     */    
    public static MimeMultipart generate(MimeMessage message,PrivateKey privateKey, X509Certificate signerCertificate, 
    		String hashAlg, CertStore certStore, String provider) throws  MessagingException  {

    	SMIMESignedGenerator generator = createGenerator(privateKey, signerCertificate, hashAlg,certStore);
    	try {
    		return generator.generate(message, provider);
    	} catch (Exception e) {
    		log.error("Error creating SMIME Message : " +e.getMessage(),e);
    		throw new MessagingException("Error creating Message : " +e.getMessage(),e);
    	}

    }

    public static MimeMultipart generate(MimeBodyPart message,PrivateKey privateKey, X509Certificate signerCertificate, 
    		String hashAlg, CertStore certStore, String provider) throws  MessagingException  {

    	SMIMESignedGenerator generator = createGenerator(privateKey, signerCertificate, hashAlg,certStore);
    	try {
    		return generator.generate(message, provider);
    	} catch (Exception e) {
    		log.error("Error creating SMIME Message : " +e.getMessage(),e);
    		throw new MessagingException("Error creating Message : " +e.getMessage(),e);
    	}

    }
    
    /**
     * Utility method that checks if there is at least one address in the "From:" header
     * same as the <i>reverse-path</i>.
     * @param mail The mail to check.
     * @return True if an address is found, false otherwise.
     */    
    public static boolean fromAddressSameAsReverse(Mail mail) {
        
        MailAddress reversePath = mail.getSender();
        
        if (reversePath == null) {
            return false;
        }
        
        try {
            InternetAddress[] fromArray = (InternetAddress[]) mail.getMessage().getFrom();
            if (fromArray != null) {
                for (int i = 0; i < fromArray.length; i++) {
                    MailAddress mailAddress  = null;
                    try {
                        mailAddress = new MailAddress(fromArray[i]);
                    } catch (ParseException pe) {
                        log.error("Unable to parse a \"FROM\" header address: " + fromArray[i].toString() + "; ignoring.");
                        continue;
                    }
                    if (mailAddress.equals(reversePath)) {
                        return true;
                    }
                }
            }
        } catch (MessagingException me) {
            log.error("Unable to parse the \"FROM\" header; ignoring.");
        }
        
        return false;
        
    }

}
