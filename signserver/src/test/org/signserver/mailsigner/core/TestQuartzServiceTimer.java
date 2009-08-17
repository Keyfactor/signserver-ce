package org.signserver.mailsigner.core;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;

import junit.framework.TestCase;

import org.signserver.common.GlobalConfiguration;
import org.signserver.common.ServiceConfig;
import org.signserver.mailsigner.MailSignerContext;
import org.signserver.server.PropertyFileStore;
import org.signserver.server.WorkerFactory;

public class TestQuartzServiceTimer extends TestCase {

	private static String srv1File;
	private static String srv2File;
	private static PropertyFileStore properties;
	private static NonEJBGlobalConfigurationSession  gCSession;
	private static String signserverhome;

	protected void setUp() throws Exception {
		super.setUp();
		
		// Special trick to set up the backend properties from a specified
		// file.
		PropertyFileStore.getInstance("tmp/testproperties2.properties");
	}
	
	public void test00SetupConfig() throws Exception{
		  gCSession = NonEJBGlobalConfigurationSession.getInstance();
		  properties = PropertyFileStore.getInstance("tmp/testproperties2.properties");
		  
		  gCSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER1717.CLASSPATH", "org.signserver.server.timedservices.DummyTimedService");
			
		  properties.setWorkerProperty(1717, ServiceConfig.ACTIVE, "TRUE");
		  properties.setWorkerProperty(1717, ServiceConfig.INTERVAL, "1");
		  signserverhome = System.getenv("SIGNSERVER_HOME");
		  assertNotNull(signserverhome);
		  srv1File = signserverhome +"/tmp/testservicefile1.tmp";
		  initCount(srv1File);
		  properties.setWorkerProperty(1717,"OUTPATH",srv1File);
		  
		  gCSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER1718.CLASSPATH", "org.signserver.server.timedservices.DummyTimedService");
			
		  properties.setWorkerProperty(1718, ServiceConfig.ACTIVE, "TRUE");
		  properties.setWorkerProperty(1718, ServiceConfig.INTERVAL, "2");
		  		  
		  srv2File = signserverhome +"/tmp/testservicefile2.tmp";
		  properties.setWorkerProperty(1718,"OUTPATH",srv2File);
		  initCount(srv2File);

	}
	
	public void test01BasicServiceTest() throws Exception{
		QuartzServiceTimer qst = QuartzServiceTimer.getInstance();
		qst.start();
		
		Thread.sleep(3400);	      
		assertTrue(""+ readCount(srv1File), readCount(srv1File) == 2 || readCount(srv1File) == 3) ;
		assertTrue(""+ readCount(srv2File), readCount(srv2File) == 1);
		
		qst.stop();
		Thread.sleep(2400);
		assertTrue(""+ readCount(srv1File), readCount(srv1File) == 3);
		assertTrue(""+ readCount(srv2File), readCount(srv2File) == 1);
		
		properties.setWorkerProperty(1718, ServiceConfig.ACTIVE, "FALSE");
		WorkerFactory.getInstance().reloadWorker(1718, MailSignerWorkerConfigService.getInstance(), NonEJBGlobalConfigurationSession.getInstance(), MailSignerContext.getInstance());
		qst.start();
		
		qst.reload(1718);
		
		Thread.sleep(3400);
		assertTrue(""+ readCount(srv1File), readCount(srv1File) > 3);
		assertTrue(""+ readCount(srv2File), readCount(srv2File) == 1);
	}
	
	public void test99RemoveConfig() throws Exception{
	    new File("tmp/testproperties2.properties").delete();
	    new File(srv1File).delete();
	    new File(srv2File).delete();
	    PropertyFileStore.getInstance(signserverhome +"/extapps/james/conf/mailsignerdata.properties");
	}
	
	
	
	private int readCount(String file) throws IOException{
		  FileInputStream fis = new FileInputStream(file);
		  ByteArrayOutputStream baos = new ByteArrayOutputStream();
		  int next = 0;
		  while((next = fis.read()) != -1){
			  baos.write(next);
		  }
		  return Integer.parseInt(new String(baos.toByteArray()));
	}
	
	private void initCount(String file) throws IOException{				
			FileOutputStream fos = new FileOutputStream(file);
			fos.write(("" + 0).getBytes());
			fos.close();
	}

}
