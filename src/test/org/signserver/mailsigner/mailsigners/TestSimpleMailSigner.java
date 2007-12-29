package org.signserver.mailsigner.mailsigners;

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
import org.signserver.mailsigner.core.SMIMEHelper;
import org.signserver.server.cryptotokens.P12CryptoToken;

public class TestSimpleMailSigner extends BaseMailSignerTester {

	protected void setUp() throws Exception {
		super.setUp();
		
		// Set SimpleMailSigner properties
		iMailSignerRMI.setWorkerProperty(getWorkerId(), SimpleMailSigner.REQUIRESMTPAUTH, "TRUE");
		iMailSignerRMI.setWorkerProperty(getWorkerId(), SimpleMailSigner.FROMADDRESS, "mailsigner@someorg.org");		
		iMailSignerRMI.setWorkerProperty(getWorkerId(), SimpleMailSigner.SIGNERADDRESS, "mailsigner@someorg.org");
		
		
		
		// Set crypto token properties
		iMailSignerRMI.setWorkerProperty(getWorkerId(), P12CryptoToken.KEYSTOREPATH, signServerHome + "/src/test/mailsigner_test1.p12");
		iMailSignerRMI.setWorkerProperty(getWorkerId(), P12CryptoToken.KEYSTOREPASSWORD, "foo123");
		
		iMailSignerRMI.reloadConfiguration(getWorkerId());
	}

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
		
		// crypto token properties
		iMailSignerRMI.removeWorkerProperty(getWorkerId(), P12CryptoToken.KEYSTOREPATH);
		iMailSignerRMI.removeWorkerProperty(getWorkerId(), P12CryptoToken.KEYSTOREPASSWORD);

		iMailSignerRMI.reloadConfiguration(getWorkerId());
	}
	
	public void test01TestSimpleMailSigner() throws Exception{
		
		// Simplest Test		
		clearTestInbox();
		sendMail("dummy1@localhost", "dummy2@localhost", "DummyMessage", "This is a Dummy Message");
		MimeMessage mail = readTestInbox();
		assertNotNull(mail);
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
		return 10;
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
