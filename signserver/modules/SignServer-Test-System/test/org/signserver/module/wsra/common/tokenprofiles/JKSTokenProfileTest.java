package org.signserver.module.wsra.common.tokenprofiles;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.util.Enumeration;
import java.util.HashSet;

import junit.framework.TestCase;

public class JKSTokenProfileTest extends TestCase {

	private static String signserverhome;

	protected void setUp() throws Exception {
		super.setUp();
        signserverhome = System.getenv("SIGNSERVER_HOME");
        assertNotNull(signserverhome);
	}

	public void testGetProfileIdentifier() {
		JKSTokenProfile tp = new JKSTokenProfile();
		assertTrue(tp.getProfileIdentifier().equals("JKSTOKENPROFILE"));
	}

	public void testGetKeyStore() throws Exception  {
		KeyStore ks = KeyStore.getInstance("JKS");
		ks.load(new FileInputStream(signserverhome +"/src/test/codesigntruststore.jks"),"foo123".toCharArray());
		
		HashSet<String> allAliases = new HashSet<String>();
		Enumeration<String> e = ks.aliases();
		while(e.hasMoreElements()){
			allAliases.add(e.nextElement());
		}
		
		
		byte[] data = JKSTokenProfile.serializeKeyStore(ks, "foo123");
		
		JKSTokenProfile tp = new JKSTokenProfile();
		tp.init(data);
		assertNotNull(tp.getKeyStore());
		assertNotNull(tp.getKeyStorePwd());
		KeyStore ks2 = tp.getKeyStore();
		
		Enumeration<String> e2 = ks2.aliases();
		while(e2.hasMoreElements()){
			assertTrue(allAliases.contains(e2.nextElement()));
		}
	}

}
