package org.signserver.mailsigner.mailsigners;

import javax.mail.internet.MimeMessage;

import org.signserver.mailsigner.module.simplemailsigner.SimpleMailSigner;

public class TestDummyMailSigner extends BaseMailSignerTester {


	protected String getCryptoTokenClasspath() {
		return null;
	}

	protected String getMailSignerClassPath() {
		return DummyMailSigner.class.getName();
	}

	protected int getWorkerId() {
		return 3;
	}
	
	public void test01DummySigner() throws Exception{
		clearTestInbox();
		sendMail("dummy1@localhost", "dummy2@localhost", "DummyMessage", "This is a Dummy Message");
		MimeMessage mail = readTestInbox();
		assertNotNull(mail);
		assertTrue(mail.getSubject().equals("DummyMessage"));
		assertTrue((String) mail.getContent(), ((String) mail.getContent()).trim().equals("This is a Dummy Message"));
		
		// Test Valid Users
		iMailSignerRMI.setWorkerProperty(getWorkerId(), SimpleMailSigner.VALIDUSERS,"testuser1, testuser2, testuser3");	
	    iMailSignerRMI.reloadConfiguration(getWorkerId());

	    clearTestInbox();
		sendMail("dummy1@localhost", "dummy2@localhost", "DummyMessage", "This is a Dummy Message");
		MimeMessage mail2 = readTestInbox();
		assertNotNull(mail2);
		assertTrue(mail.getSubject().equals("DummyMessage"));
		assertTrue((String) mail.getContent(), ((String) mail.getContent()).trim().equals("This is a Dummy Message"));

	    clearTestInbox();
		sendMail("dummy1@localhost", "dummy2@localhost", "DummyMessage", "This is a Dummy Message");
		iMailSignerRMI.setWorkerProperty(getWorkerId(), SimpleMailSigner.VALIDUSERS,"testuser2, testuser3");	
	    iMailSignerRMI.reloadConfiguration(getWorkerId());	
		MimeMessage mail3 = readTestInbox();
		assertNull(mail3);
	}

	protected void tearDown() throws Exception {
		super.tearDown();
		// Set SimpleMailSigner properties
		iMailSignerRMI.removeWorkerProperty(getWorkerId(), SimpleMailSigner.VALIDUSERS);
		iMailSignerRMI.reloadConfiguration(getWorkerId());
	}
	
	@Override
	protected String getSMTPAuthUser() {
		return "testuser1";
	}



}
