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

import java.security.cert.CertStore;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;

import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;

import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.mail.smime.SMIMESigned;
import org.ejbca.util.CertTools;
import org.signserver.cli.CommonAdminInterface;
import org.signserver.common.clusterclassloader.MARFileParser;
import org.signserver.mailsigner.core.SMIMEHelper;
import org.signserver.mailsigner.mailsigners.BaseMailSignerTester;
import org.signserver.server.cryptotokens.P12CryptoToken;
import org.signserver.testutils.TestUtils;
import org.signserver.testutils.TestingSecurityManager;

/**
 * Tests for the SimpleMailSigner.
 *
 * @version $Id$
 */
public class TestSimpleMailSigner extends BaseMailSignerTester {

	private int moduleVersion;
	private String signserverhome;

    @Override
	protected void setUp() throws Exception {
		super.setUp();
		
		TestUtils.redirectToTempOut();
		TestUtils.redirectToTempErr();
		TestingSecurityManager.install();
        signserverhome = System.getenv("SIGNSERVER_HOME");
        assertNotNull(signserverhome);
        CommonAdminInterface.BUILDMODE = "MAILSIGNER";
		
		MARFileParser marFileParser = new MARFileParser(signserverhome +"/dist-server/simplemailsigner.mar");
		moduleVersion = marFileParser.getVersionFromMARFile();
		
		TestUtils.assertSuccessfulExecution(new String[] {"module", "add",
				signserverhome +"/dist-server/simplemailsigner.mar", "junittest"});		
	    assertTrue(TestUtils.grepTempOut("Loading module SIMPLEMAILSIGNER"));
	    assertTrue(TestUtils.grepTempOut("Module loaded successfully."));
	    
		// Set SimpleMailSigner properties
		iMailSignerRMI.setWorkerProperty(getWorkerId(), SimpleMailSigner.REQUIRESMTPAUTH, "TRUE");
		iMailSignerRMI.setWorkerProperty(getWorkerId(), SimpleMailSigner.FROMADDRESS, "mailsigner@someorg.org");		
		iMailSignerRMI.setWorkerProperty(getWorkerId(), SimpleMailSigner.SIGNERADDRESS, "mailsigner@someorg.org");
		iMailSignerRMI.setWorkerProperty(getWorkerId(), SimpleMailSigner.CHECKSMTPAUTHSENDER, "TRUE");
		
		
		// Set crypto token properties
		iMailSignerRMI.setWorkerProperty(getWorkerId(), P12CryptoToken.KEYSTOREPATH, signServerHome + "/src/test/mailsigner_test1.p12");
		iMailSignerRMI.setWorkerProperty(getWorkerId(), P12CryptoToken.KEYSTOREPASSWORD, "foo123");
		
		iMailSignerRMI.reloadConfiguration(0);
	}


	
	public void test01TestSimpleMailSigner() throws Exception{
		
		// Simplest Test		
		clearTestInbox();
		sendMail("dummy1@localhost", "dummy2@localhost", "DummyMessage", "This is a Dummy Message");
		MimeMessage mail = readTestInbox();
		assertNotNull("message not null", mail);
		assertTrue(mail.getSubject(), mail.getSubject().equals("DummyMessage"));
		assertTrue(((InternetAddress )mail.getFrom()[0]).getPersonal(), ((InternetAddress )mail.getFrom()[0]).getPersonal()== null);
		assertTrue(((InternetAddress )mail.getFrom()[0]).getAddress(), ((InternetAddress )mail.getFrom()[0]).getAddress().equals("mailsigner@someorg.org"));
		assertTrue(((InternetAddress )mail.getSender()).getPersonal()== null);
		assertTrue(((InternetAddress )mail.getSender()).getAddress().equals("mailsigner@someorg.org"));
		assertTrue(mail.getContentType().startsWith("multipart/signed"));
		assertTrue(mail.getContent().getClass().getName(), mail.getContent() instanceof MimeMultipart);
		MimeMultipart multiPart = (MimeMultipart) mail.getContent();
		assertTrue(multiPart.getCount()==2);
		MimeBodyPart part0 = (MimeBodyPart) multiPart.getBodyPart(0);	
		String data = (String) part0.getContent();
		assertTrue(data.trim().equals("This is a Dummy Message"));
		verifySMIMESig(multiPart);

	    		
	    // Test with Explanation
	    iMailSignerRMI.setWorkerProperty(getWorkerId(), SMIMEHelper.EXPLAINATION_TEXT, "This is a signed email.");
	    iMailSignerRMI.setWorkerProperty(getWorkerId(), SimpleMailSigner.FROMNAME,"Test1 Test1");
		iMailSignerRMI.setWorkerProperty(getWorkerId(), SimpleMailSigner.SIGNERNAME,"Test2 Test2");	
	    iMailSignerRMI.reloadConfiguration(getWorkerId());
	    
		clearTestInbox();
		sendMail("dummy1@localhost", "dummy2@localhost", "DummyMessage", "This is a Dummy Message");
		MimeMessage mail2 = readTestInbox();
		assertNotNull(mail2);
		assertTrue(mail2.getSubject(), mail2.getSubject().equals("DummyMessage"));
		assertTrue(((InternetAddress )mail2.getFrom()[0]).getPersonal().equals("Test1 Test1"));
		assertTrue(((InternetAddress )mail2.getSender()).getPersonal().equals("Test2 Test2"));
		assertTrue(((InternetAddress )mail2.getReplyTo()[0]).getAddress(),((InternetAddress )mail2.getReplyTo()[0]).getAddress().equals("dummy1@localhost"));
		assertTrue(mail2.getContentType().startsWith("multipart/signed"));
		assertTrue(mail2.getContent().getClass().getName(), mail2.getContent() instanceof MimeMultipart);
		MimeMultipart multiPart2 = (MimeMultipart) mail2.getContent();
		assertTrue(""+multiPart2.getCount(), multiPart2.getCount()==2);
		MimeBodyPart part20 = (MimeBodyPart) multiPart2.getBodyPart(0);	
		MimeMultipart subPart = (MimeMultipart) part20.getContent();
		assertTrue(""+subPart.getCount(), subPart.getCount()==2);
		String data2 = (String) subPart.getBodyPart(0).getContent();
		assertTrue(data2.trim().equals("This is a Dummy Message"));
		String signatureReasonText = (String) subPart.getBodyPart(1).getContent();
		assertTrue(signatureReasonText.trim().equals("This is a signed email."));
		assertTrue(subPart.getBodyPart(1).getFileName().equals("SignatureExplanation.txt"));
		verifySMIMESig(multiPart2);
		
		// Test with change of reply to
	    iMailSignerRMI.setWorkerProperty(getWorkerId(), SimpleMailSigner.CHANGEREPLYTO,"True");
	    iMailSignerRMI.setWorkerProperty(getWorkerId(), SimpleMailSigner.REPLYTOADDRESS,"test@someorg.org");
	    iMailSignerRMI.setWorkerProperty(getWorkerId(), SimpleMailSigner.REPLYTONAME,"Test3 Test3");
		iMailSignerRMI.setWorkerProperty(getWorkerId(), SimpleMailSigner.USEREBUILDFROM,"false");	
	    iMailSignerRMI.reloadConfiguration(getWorkerId());
	    
		clearTestInbox();
		sendMail("dummy1@localhost", "dummy2@localhost", "DummyMessage", "This is a Dummy Message");
		MimeMessage mail3 = readTestInbox();
		assertNotNull(mail3);
		assertTrue(mail3.getSubject(), mail3.getSubject().equals("DummyMessage"));
		assertTrue(((InternetAddress )mail3.getFrom()[0]).toString(), ((InternetAddress )mail3.getFrom()[0]).getAddress().equals("dummy1@localhost"));
		assertTrue(((InternetAddress )mail3.getFrom()[0]).toString(), ((InternetAddress )mail3.getFrom()[0]).getPersonal() == null);
		assertTrue(((InternetAddress )mail3.getSender()).getPersonal().equals("Test2 Test2"));
		assertTrue(((InternetAddress )mail3.getReplyTo()[0]).getAddress(),((InternetAddress )mail3.getReplyTo()[0]).getAddress().equals("test@someorg.org"));
		assertTrue(((InternetAddress )mail3.getReplyTo()[0]).getAddress(),((InternetAddress )mail3.getReplyTo()[0]).getPersonal().equals("Test3 Test3"));
	    
		// Test that unauth user sends, and marked as error.
		clearTestInbox();
		sendMail("dummy3@localhost", "dummy2@localhost", "DummyMessage", "This is a Dummy Message");
		MimeMessage mail4 = readTestInbox();
		assertNull(mail4);
		
		// Test Opt-In
		iMailSignerRMI.setWorkerProperty(getWorkerId(), SimpleMailSigner.CHECKSMTPAUTHSENDER,"FALSE");
		iMailSignerRMI.setWorkerProperty(getWorkerId(), SimpleMailSigner.SIGNBYDEFAULT,"FALSE");
		iMailSignerRMI.setWorkerProperty(getWorkerId(), SimpleMailSigner.OPTIN,"someorg.org, localhost, someorg2.org");
	    iMailSignerRMI.reloadConfiguration(getWorkerId());
		clearTestInbox();
		sendMail("dummy3@localhost", "dummy2@localhost", "DummyMessage", "This is a Dummy Message");
		MimeMessage mail5 = readTestInbox();
		assertNotNull(mail5);	
		multiPart2 = (MimeMultipart) mail5.getContent();
		assertTrue(""+multiPart2.getCount(), multiPart2.getCount()==2);
		part20 = (MimeBodyPart) multiPart2.getBodyPart(0);	
		subPart = (MimeMultipart) part20.getContent();
		assertTrue(""+subPart.getCount(), subPart.getCount()==2);
		data2 = (String) subPart.getBodyPart(0).getContent();
		assertTrue(data2.trim().equals("This is a Dummy Message"));
		signatureReasonText = (String) subPart.getBodyPart(1).getContent();
		assertTrue(signatureReasonText.trim().equals("This is a signed email."));
		assertTrue(subPart.getBodyPart(1).getFileName().equals("SignatureExplanation.txt"));
		verifySMIMESig(multiPart2);
		
		clearTestInbox();
		sendMail("dummy3@localhost", "dummy2@localhost2", "DummyMessage", "This is a Dummy Message");
		MimeMessage mail6 = readTestInbox();
		assertNull(mail6);	
		
		// Test subject tags
		iMailSignerRMI.setWorkerProperty(getWorkerId(), SimpleMailSigner.USESUBJECTTAGS,"TRUE");
	    iMailSignerRMI.reloadConfiguration(getWorkerId());
	    
		clearTestInbox();
		sendMail("dummy3@localhost", "dummy2@localhost2", "DummyMessage SIGN", "This is a Dummy Message");
		MimeMessage mail7 = readTestInbox();
		assertNotNull(mail7);	
		multiPart2 = (MimeMultipart) mail7.getContent();
		assertFalse(mail7.getSubject().contains("SIGN"));
		assertTrue(""+multiPart2.getCount(), multiPart2.getCount()==2);
		part20 = (MimeBodyPart) multiPart2.getBodyPart(0);	
		subPart = (MimeMultipart) part20.getContent();
		assertTrue(""+subPart.getCount(), subPart.getCount()==2);
		data2 = (String) subPart.getBodyPart(0).getContent();
		assertTrue(data2.trim().equals("This is a Dummy Message"));
		signatureReasonText = (String) subPart.getBodyPart(1).getContent();
		assertTrue(signatureReasonText.trim().equals("This is a signed email."));
		assertTrue(subPart.getBodyPart(1).getFileName().equals("SignatureExplanation.txt"));
		verifySMIMESig(multiPart2);
				
		clearTestInbox();
		sendMail("dummy3@localhost", "dummy2@localhost", "DummyMessage NOSIGN", "This is a Dummy Message");
		MimeMessage mail8 = readTestInbox();
		assertNull(mail8);	
		
		// Test Opt-out		
		iMailSignerRMI.setWorkerProperty(getWorkerId(), SimpleMailSigner.SIGNBYDEFAULT,"TRUE");
		iMailSignerRMI.setWorkerProperty(getWorkerId(), SimpleMailSigner.OPTOUT,"someorg.org, localhost2, someorg2.org");
	    iMailSignerRMI.reloadConfiguration(getWorkerId());
		clearTestInbox();
		sendMail("dummy3@localhost", "dummy2@localhost", "DummyMessage", "This is a Dummy Message");
		MimeMessage mail9 = readTestInbox();
		assertNotNull(mail9);	
		multiPart2 = (MimeMultipart) mail9.getContent();
		assertTrue(""+multiPart2.getCount(), multiPart2.getCount()==2);
		part20 = (MimeBodyPart) multiPart2.getBodyPart(0);	
		subPart = (MimeMultipart) part20.getContent();
		assertTrue(""+subPart.getCount(), subPart.getCount()==2);
		data2 = (String) subPart.getBodyPart(0).getContent();
		assertTrue(data2.trim().equals("This is a Dummy Message"));
		signatureReasonText = (String) subPart.getBodyPart(1).getContent();
		assertTrue(signatureReasonText.trim().equals("This is a signed email."));
		assertTrue(subPart.getBodyPart(1).getFileName().equals("SignatureExplanation.txt"));
		verifySMIMESig(multiPart2);
		
		clearTestInbox();
		sendMail("dummy3@localhost", "dummy2@localhost2", "DummyMessage", "This is a Dummy Message");
		MimeMessage mail10 = readTestInbox();
		assertNull(mail10);


                // TODO for some reason this method can not be run independantly.
                // There might be a problem with the setUp/tearDown methods
                // Running it directly here is a workeraround.
                iMailSignerRMI.removeWorkerProperty(getWorkerId(), SimpleMailSigner.FROMNAME);
		iMailSignerRMI.removeWorkerProperty(getWorkerId(), SimpleMailSigner.SIGNERNAME);
                iMailSignerRMI.removeWorkerProperty(getWorkerId(), SimpleMailSigner.CHANGEREPLYTO);
                iMailSignerRMI.removeWorkerProperty(getWorkerId(), SimpleMailSigner.REPLYTOADDRESS);
                iMailSignerRMI.removeWorkerProperty(getWorkerId(), SimpleMailSigner.REPLYTONAME);
                iMailSignerRMI.removeWorkerProperty(getWorkerId(), SimpleMailSigner.USEREBUILDFROM);
                iMailSignerRMI.removeWorkerProperty(getWorkerId(), SimpleMailSigner.SIGNBYDEFAULT);
                iMailSignerRMI.removeWorkerProperty(getWorkerId(), SimpleMailSigner.OPTOUT);
                iMailSignerRMI.removeWorkerProperty(getWorkerId(), SimpleMailSigner.CHECKSMTPAUTHSENDER);
		iMailSignerRMI.removeWorkerProperty(getWorkerId(), SimpleMailSigner.SIGNBYDEFAULT);
		iMailSignerRMI.removeWorkerProperty(getWorkerId(), SimpleMailSigner.OPTIN);
                iMailSignerRMI.removeWorkerProperty(getWorkerId(), SimpleMailSigner.USESUBJECTTAGS);
                iMailSignerRMI.removeWorkerProperty(getWorkerId(), SimpleMailSigner.OPTOUT);
                atest02SendernameTrue();
	}

        /**
         * Tests the SENDERNAME property (DSS-228).
         *
         * When an optional property SENDERNAME is set to TRUE the From/Sender
         * fields should be composed of the FROMADDRESS/SIGNERADDRESS and the
         * name from the From field of the original e-mail.
         *
         * <pre>
         *   Sending an original e-mail with:
         *   From: Markus Kilas <markus.k@primekey.se>
         *
         *   Will result in the MailSigner sending an e-mail with:
         *   From: Markus Kilas <mailsigner@mailsigner>
         *   Sender: Markus Kilas <mailsigner@mailsigner>
         *   Reply-To: Markus Kilas <markus.k@primekey.se>
         * </pre>
         *
         * @throws Exception
         */
        public void atest02SendernameTrue() throws Exception {
            // Test with SENDERNAME
	    iMailSignerRMI.setWorkerProperty(getWorkerId(),
                    SimpleMailSigner.SENDERNAME, "TRUE");
	    iMailSignerRMI.reloadConfiguration(getWorkerId());

            clearTestInbox();
            sendMail("SenderFirstname SenderLastname <dummy1.test02@localhost>",
                    "RecieverFirstname RecieverLastname <dummy2.test02@localhost>",
                    "Test 02", "This is a dummy message.");

            final MimeMessage mail1 = readTestInbox();

            assertNotNull("message not null", mail1);
            assertEquals("subject", "Test 02", mail1.getSubject());

            final InternetAddress[] from = (InternetAddress[]) mail1.getFrom();
            final InternetAddress sender = (InternetAddress) mail1.getSender();
            final InternetAddress[] replyTo = (InternetAddress[]) mail1.getReplyTo();

            System.out.println("Mail1: " + mail1);

            // Assert from/sender address is the mailsigner address
            assertEquals("from address", "mailsigner@someorg.org",
                    from[0].getAddress());
            assertEquals("sender address", "mailsigner@someorg.org",
                    sender.getAddress());

            // Assert from/sender names are taken from the mail
            assertEquals("from name", "SenderFirstname SenderLastname",
                    from[0].getPersonal());
            assertEquals("sender name", "SenderFirstname SenderLastname",
                    sender.getPersonal());

            // Assert reply-to is taken from the "from" field of original mail
            assertEquals("reply-to", "dummy1.test02@localhost", 
                    replyTo[0].getAddress());

            // Assert the message is signed
            assertTrue("mime type",
                    mail1.getContentType().startsWith("multipart/signed"));
            assertTrue(mail1.getContent().getClass().getName(),
                    mail1.getContent() instanceof MimeMultipart);
            final MimeMultipart multiPart2 = (MimeMultipart) mail1.getContent();
            verifySMIMESig(multiPart2);

            // Test with SENDERNAME
	    iMailSignerRMI.removeWorkerProperty(getWorkerId(),
                    SimpleMailSigner.SENDERNAME);
	    iMailSignerRMI.reloadConfiguration(getWorkerId());
        }
	
    @Override
	protected void tearDown() throws Exception {
		super.tearDown();
		// Set SimpleMailSigner properties
		iMailSignerRMI.removeWorkerProperty(getWorkerId(), SimpleMailSigner.REQUIRESMTPAUTH);
		iMailSignerRMI.removeWorkerProperty(getWorkerId(), SimpleMailSigner.FROMADDRESS);
		iMailSignerRMI.removeWorkerProperty(getWorkerId(), SimpleMailSigner.SIGNERADDRESS);	
		iMailSignerRMI.removeWorkerProperty(getWorkerId(), SMIMEHelper.EXPLAINATION_TEXT);
		iMailSignerRMI.removeWorkerProperty(getWorkerId(), SimpleMailSigner.FROMNAME);
		iMailSignerRMI.removeWorkerProperty(getWorkerId(), SimpleMailSigner.SIGNERNAME);
		iMailSignerRMI.removeWorkerProperty(getWorkerId(), SimpleMailSigner.REPLYTOADDRESS);
		iMailSignerRMI.removeWorkerProperty(getWorkerId(), SimpleMailSigner.REPLYTONAME);
		iMailSignerRMI.removeWorkerProperty(getWorkerId(), SimpleMailSigner.USEREBUILDFROM);
		iMailSignerRMI.removeWorkerProperty(getWorkerId(), SimpleMailSigner.CHANGEREPLYTO);
		iMailSignerRMI.removeWorkerProperty(getWorkerId(), SimpleMailSigner.CHECKSMTPAUTHSENDER);
		iMailSignerRMI.removeWorkerProperty(getWorkerId(), SimpleMailSigner.SIGNBYDEFAULT);
		iMailSignerRMI.removeWorkerProperty(getWorkerId(), SimpleMailSigner.OPTIN);
		iMailSignerRMI.removeWorkerProperty(getWorkerId(), SimpleMailSigner.USESUBJECTTAGS);
                iMailSignerRMI.removeWorkerProperty(getWorkerId(), SimpleMailSigner.SENDERNAME);
		
		// crypto token properties
		iMailSignerRMI.removeWorkerProperty(getWorkerId(), P12CryptoToken.KEYSTOREPATH);
		iMailSignerRMI.removeWorkerProperty(getWorkerId(), P12CryptoToken.KEYSTOREPASSWORD);

		TestUtils.assertSuccessfulExecution(new String[] {"removeworker",
		"" + getWorkerId()});
		
		TestUtils.assertSuccessfulExecution(new String[] {"module", "remove","SIMPLEMAILSIGNER", "" + moduleVersion});		
		assertTrue(TestUtils.grepTempOut("Removal of module successful."));
		
		iMailSignerRMI.reloadConfiguration(0);
		
		TestingSecurityManager.remove();
	}

	@Override
	protected String getCryptoTokenClasspath() {		
		return P12CryptoToken.class.getName();
	}

	@Override
	protected String getMailSignerClassPath() {		
		return SimpleMailSigner.class.getName();
	}

	@Override
	protected int getWorkerId() {
		return 4433;
	}
	
	@Override
	protected String getSMTPAuthUser() {
		return "dummy1";
	}
	
	private void verifySMIMESig(MimeMultipart multiPart) throws Exception{
		SMIMESigned sMIMESigned = new SMIMESigned(multiPart);
		CertStore certs = sMIMESigned.getCertificatesAndCRLs("Collection", "BC");
		assertTrue(certs.getCertificates(null).size()== 2);
		SignerInformationStore  signers = sMIMESigned.getSignerInfos();
		Collection<?>              c = signers.getSigners();
		Iterator<?>                it = c.iterator();
		assertTrue(it.hasNext());
		SignerInformation   signer = (SignerInformation)it.next();
		Collection<?>          certCollection = certs.getCertificates(signer.getSID());
        assertTrue(""+ certCollection.size() ,certCollection.size() == 1);
		Iterator<?>        certIt = certCollection.iterator();
		X509Certificate cert = (X509Certificate)certIt.next();
		assertTrue(CertTools.getSubjectDN(cert),CertTools.getSubjectDN(cert).equals("CN=Mail Signer Test,O=someorg"));        
	    assertTrue(signer.verify(cert,"BC"));
	}

}
