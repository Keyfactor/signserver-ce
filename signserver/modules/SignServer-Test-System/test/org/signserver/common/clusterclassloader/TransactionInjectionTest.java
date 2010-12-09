package org.signserver.common.clusterclassloader;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

import junit.framework.TestCase;

import org.signserver.common.IllegalRequestException;


public class TransactionInjectionTest extends TestCase {

	protected void setUp() throws Exception {
		super.setUp();
	}
	
	public void test01TransactionInjection() throws Exception{
		byte[] classData = readClassData(SubClass.class.getName());
		byte[] transactionData = ClusterClassLoaderUtils.injectTransaction(classData);
		String className = SubClass.class.getName();
		ClassLoader cl = new SimpleClassLoader(this.getClass().getClassLoader(),transactionData,"v1." + className);
		Class<?> c = cl.loadClass("v1." + className);

		TEntityManager wem = new TEntityManager();
		
		FooInterface o = (FooInterface) c.newInstance();
		((BaseClass) o).setWorkerEntityManager(wem);
		assertFalse(wem.beginCalled);
		assertFalse(wem.commitCalled);
		assertFalse(wem.rollbackCalled);
		assertFalse(o.hasRun());
		
        o.revokeToken("noexception",1);
        
		assertTrue(wem.beginCalled);
		assertTrue(wem.commitCalled);
		assertFalse(wem.rollbackCalled);
		assertTrue(o.hasRun());
		
		wem = new TEntityManager();
		o = (FooInterface) c.newInstance();
		((BaseClass) o).setWorkerEntityManager(wem);
		assertFalse(wem.beginCalled);
		assertFalse(wem.commitCalled);
		assertFalse(wem.rollbackCalled);
		assertFalse(o.hasRun());
		
		try{
          o.revokeToken("exception",1);
          assertTrue(false);
		}catch(IllegalRequestException e){}
		assertTrue(wem.beginCalled);
		assertFalse(wem.commitCalled);
		assertTrue(wem.rollbackCalled);
		assertFalse(o.hasRun());
	}

	
	private byte[] readClassData(String className) throws IOException{
		InputStream is = this.getClass().getClassLoader().getResourceAsStream(ClusterClassLoaderUtils.getResourcePathFromClassName(className));
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		int d = 0;
		while((d = is.read()) != -1){
			baos.write(d);
		}
		
		return baos.toByteArray();
	}
	

}
