package org.signserver.common.clusterclassloader;

import java.io.IOException;
import java.util.Collection;

import junit.framework.TestCase;

import org.signserver.common.clusterclassloader.FindInterfacesClassLoader;
import org.signserver.common.clusterclassloader.MARFileParser;

public class FindInterfacesClassLoaderTest extends TestCase {

	private static String signserverhome;
	private static MARFileParser mARFileParser;
	
	protected void setUp() throws Exception {
		super.setUp();
		signserverhome = System.getenv("SIGNSERVER_HOME");
		assertNotNull(signserverhome);
		mARFileParser = new MARFileParser(signserverhome + "/src/test/testmodule-withoutdescr.mar");
		assertNotNull(mARFileParser);
	}

	public void testGetImplementedInterfaces() throws IOException {
		FindInterfacesClassLoader ficl = new FindInterfacesClassLoader(mARFileParser,"server", System.out);
		Collection<String> interfaces = ficl.getImplementedInterfaces("testPackage/SysPropTest.class");
		assertNotNull(interfaces);
		assertTrue(interfaces.size() == 0);
		interfaces = ficl.getImplementedInterfaces("testPackage/SubObject$SubSubObject.class");
		assertTrue(interfaces.size() == 1);
		interfaces = ficl.getImplementedInterfaces("testPackage/Sub2Object.class");
		assertTrue(interfaces.size() == 4);
		assertTrue(interfaces.contains("java.util.Observer"));
		assertTrue(interfaces.contains("testPackage.Test"));
		assertTrue(interfaces.contains("java.io.Externalizable"));
		assertTrue(interfaces.contains("java.lang.Cloneable"));		
	}
	


}
