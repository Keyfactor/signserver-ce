package org.signserver.mailsigner.core;

import java.util.List;

import org.signserver.common.MailSignerUser;
import org.signserver.server.PropertyFileStore;

import junit.framework.TestCase;

public class TestMailSignerUserRepository extends TestCase {

	protected void setUp() throws Exception {
		super.setUp();
		
		// Special trick to set up the backend properties from a specified
		// file.
		PropertyFileStore.getInstance("tmp/testproperties.properties");
	}

	public void test01TestMailSignerUserRepository() {
		MailSignerUserRepository ur = new MailSignerUserRepository();
		ur.addUser("test3","pwd3");
		ur.addUser("test2","pwd2");
		ur.addUser("test1","pwd1");
		
		assertTrue(ur.countUsers() == 3);
		
		assertTrue(ur.test("test1", "pwd1"));
		assertTrue(ur.test("TEST1", "pwd1"));
		assertFalse(ur.test("test1", "pwd2"));
		assertFalse(ur.test("test4", "pwd2"));
		
		assertTrue(ur.list().next() != null);
		
		assertTrue(ur.contains("test1"));
		assertTrue(ur.contains("TEST1"));
		assertFalse(ur.contains("TEST4"));
		
		assertTrue(ur.containsCaseInsensitive("test1"));
		assertTrue(ur.containsCaseInsensitive("TEST1"));
		assertFalse(ur.containsCaseInsensitive("TEST4"));
		
		assertTrue(ur.getRealName("test1").equals("TEST1"));
		
		assertTrue(ur.getUserByName("test1").getUserName().equals("TEST1"));
		assertTrue(ur.getUserByName("test1").verifyPassword("pwd1"));
		assertTrue(ur.getUserByName("TEST1").getUserName().equals("TEST1"));
		assertTrue(ur.getUserByName("TEST1").verifyPassword("pwd1"));
		assertTrue(ur.getUserByName("test4")== null);
		
		assertTrue(ur.getUserByNameCaseInsensitive("test1").getUserName().equals("TEST1"));
		assertTrue(ur.getUserByNameCaseInsensitive("test1").verifyPassword("pwd1"));
		assertTrue(ur.getUserByNameCaseInsensitive("TEST1").getUserName().equals("TEST1"));
		assertTrue(ur.getUserByNameCaseInsensitive("TEST1").verifyPassword("pwd1"));
		assertTrue(ur.getUserByNameCaseInsensitive("test4")== null);
		
		List<MailSignerUser> users = ur.getUsersSorted();
		assertTrue(users.get(0).getUserName().equals("TEST1"));
		assertTrue(users.get(1).getUserName().equals("TEST2"));
		assertTrue(users.get(2).getUserName().equals("TEST3"));
		
		ur.removeUser("test1");
		assertTrue(ur.countUsers() == 2);
		ur.removeUser("TEST1");
		assertTrue(ur.countUsers() == 2);
		ur.removeUser("TEST2");
		assertTrue(ur.countUsers() == 1);
	}

}
