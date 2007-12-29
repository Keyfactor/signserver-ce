package org.signserver.mailsigner.mailsigners;

import javax.mail.internet.MimeMessage;

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
	}

	@Override
	protected String getSMTPAuthUser() {
		return "testuser1";
	}



}
