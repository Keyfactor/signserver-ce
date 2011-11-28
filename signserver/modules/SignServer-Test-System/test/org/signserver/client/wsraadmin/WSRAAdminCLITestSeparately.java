package org.signserver.client.wsraadmin;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;

import junit.framework.TestCase;

import org.signserver.common.SignServerUtil;
import org.signserver.module.wsra.beans.BackupRestoreBean;
import org.signserver.module.wsra.common.WSRAConstants.OrganizationStatus;
import org.signserver.module.wsra.core.DataFileParser;
import org.signserver.testutils.TestUtils;
import org.signserver.testutils.TestingSecurityManager;

public class WSRAAdminCLITestSeparately extends TestCase {

	private static String signserverhome;


	
	protected void setUp() throws Exception {
		super.setUp();
		
		SignServerUtil.installBCProvider();

		
		TestUtils.redirectToTempOut();
		TestUtils.redirectToTempErr();
		TestingSecurityManager.install();
        signserverhome = System.getenv("SIGNSERVER_HOME");
        assertNotNull(signserverhome);
	}
	
	protected void tearDown() throws Exception{
		TestingSecurityManager.remove();
	}
	
	public void test00SetupDatabase() throws Exception{
         File in = new File(signserverhome + "/src/module-configs/wsra/cli/wsraadmin.properties");
         File out = new File(signserverhome + "/tmp/test-wsraadmin.properties");
         StringBuilder sb = new StringBuilder();
         BufferedReader br  = new BufferedReader(new FileReader(in));
         String line = null;
         while((line = br.readLine()) != null){
        	 if(line.contains("hibernate.connection.url")){
        		 sb.append("hibernate.connection.url=jdbc:hsqldb:file:tmp/testdb" +"\n");
        	 }else{
        	   sb.append(line +"\n");
        	 }
         }
         br.close();
         String text = sb.toString();
         FileOutputStream fos = new FileOutputStream(out);
         fos.write(text.getBytes());
         fos.close();
				
	}
	
	public void testHelp() throws Exception{
		int result = TestUtils.assertFailedExecution(new WSRAAdminCLI(),new String[] {});
		assertTrue(result == WSRAAdminCLI.RETURN_BADARGUMENT);
		assertTrue(TestUtils.grepTempOut("Usage: "));
		result = TestUtils.assertFailedExecution(new WSRAAdminCLI(),new String[] {"-help"});
		assertTrue(TestUtils.grepTempOut("Usage: "));
		assertTrue(result == WSRAAdminCLI.RETURN_BADARGUMENT);

	}
	
	public void testAdd() throws Exception{
		int result = TestUtils.assertFailedExecution(new WSRAAdminCLI(),new String[] {"-action","add","-data",signserverhome + "/src/test/testwsraadmin1.xml","-config",signserverhome + "/tmp/test-wsraadmin.properties","-type","all"});
		assertTrue(result == WSRAAdminCLI.RETURN_OK);
		result = TestUtils.assertFailedExecution(new WSRAAdminCLI(),new String[] {"-action","add","-data",signserverhome + "/src/test/testwsraadmin1.xml","-config",signserverhome + "/tmp/test-wsraadmin.properties"});
		assertTrue(result == WSRAAdminCLI.RETURN_BADARGUMENT);
		result = TestUtils.assertFailedExecution(new WSRAAdminCLI(),new String[] {"-action","add","-data","-config",signserverhome + "/tmp/test-wsraadmin.properties","-type","all"});
		assertTrue(result == WSRAAdminCLI.RETURN_BADARGUMENT);
		result = TestUtils.assertFailedExecution(new WSRAAdminCLI(),new String[] {"-data",signserverhome + "/src/test/testwsraadmin1.xml","-config",signserverhome + "/tmp/test-wsraadmin.properties","-type","all"});
		assertTrue(result == WSRAAdminCLI.RETURN_BADARGUMENT);
	}
	
	public void testDump() throws Exception{
		int result = TestUtils.assertFailedExecution(new WSRAAdminCLI(),new String[] {"-action","dump","-data",signserverhome + "/tmp/testwsraadmindump.xml","-config",signserverhome + "/tmp/test-wsraadmin.properties","-type","all"});
		assertTrue(result == WSRAAdminCLI.RETURN_OK);	
		DataFileParser dfp = new DataFileParser(signserverhome + "/tmp/testwsraadmindump.xml");
		BackupRestoreBean brb = dfp.getData();
		assertTrue(brb.getOrganizations().get(0).getOrganizationName().equals("testorg1"));
		assertTrue(brb.getOrganizations().get(0).getUsers().size() == 0);
		assertTrue(brb.getOrganizations().size() == 1);
		assertTrue(brb.getProducts().get(0).getProductNumber().equals("1234") || brb.getProducts().get(0).getProductNumber().equals("2345"));
		assertTrue(brb.getProducts().size() == 2);
		assertTrue(brb.getPricing().get(0).getPriceClass().equals("standard"));
		assertTrue(brb.getPricing().size() == 1);
		assertTrue(brb.getProductMappings().size() == 3);
		
		
		result = TestUtils.assertFailedExecution(new WSRAAdminCLI(),new String[] {"-action","dump","-data",signserverhome + "/tmp/testwsraadmindump.xml","-config",signserverhome + "/tmp/test-wsraadmin.properties","-type","PRODUCTS"});
		assertTrue(result == WSRAAdminCLI.RETURN_OK);	
		dfp = new DataFileParser(signserverhome + "/tmp/testwsraadmindump.xml");
		brb = dfp.getData();
		assertNull(brb.getOrganizations());
		assertNull(brb.getPricing());
		assertNull(brb.getProductMappings());
		assertTrue(brb.getProducts().size()==2);
		
		result = TestUtils.assertFailedExecution(new WSRAAdminCLI(),new String[] {"-action","dump","-data",signserverhome + "/tmp/testwsraadmindump.xml","-config",signserverhome + "/tmp/test-wsraadmin.properties","-type","PRICES"});
		assertTrue(result == WSRAAdminCLI.RETURN_OK);	
		dfp = new DataFileParser(signserverhome + "/tmp/testwsraadmindump.xml");
		brb = dfp.getData();
		assertNull(brb.getOrganizations());
		assertTrue(brb.getPricing().size() == 1);
		assertNull(brb.getProductMappings());
		assertNull(brb.getProducts());
		
		result = TestUtils.assertFailedExecution(new WSRAAdminCLI(),new String[] {"-action","dump","-data",signserverhome + "/tmp/testwsraadmindump.xml","-config",signserverhome + "/tmp/test-wsraadmin.properties","-type","PRODUCTMAPPINGS"});
		assertTrue(result == WSRAAdminCLI.RETURN_OK);	
		dfp = new DataFileParser(signserverhome + "/tmp/testwsraadmindump.xml");
		brb = dfp.getData();
		assertNull(brb.getOrganizations());
		assertNull(brb.getPricing());
		assertTrue(brb.getProductMappings().size() == 3);
		assertNull(brb.getProducts());
	}
	
	public void testAddWithUsers() throws Exception{
		int result = TestUtils.assertFailedExecution(new WSRAAdminCLI(),new String[] {"-action","add","-data",signserverhome + "/src/test/testwsraadmin1.xml","-config",signserverhome + "/tmp/test-wsraadmin.properties","-type","organizations","-includeusers"});
		assertTrue(result == WSRAAdminCLI.RETURN_OK);
		result = TestUtils.assertFailedExecution(new WSRAAdminCLI(),new String[] {"-action","dump","-data",signserverhome + "/tmp/testwsraadmindump.xml","-config",signserverhome + "/tmp/test-wsraadmin.properties","-type","organizations","-includeusers"});
		assertTrue(result == WSRAAdminCLI.RETURN_OK);	
		DataFileParser dfp = new DataFileParser(signserverhome + "/tmp/testwsraadmindump.xml");
		BackupRestoreBean brb = dfp.getData();
		assertTrue(brb.getOrganizations().get(0).getOrganizationName().equals("testorg1"));
		assertTrue(brb.getOrganizations().get(0).getUsers().size() == 1);
		assertTrue(brb.getOrganizations().get(0).getUsers().get(0).getAuthData().size() == 1);
	}
	
	public void testChangeStatus() throws Exception{
		int result = TestUtils.assertFailedExecution(new WSRAAdminCLI(),new String[] {"-action","changestatus","-config",signserverhome + "/tmp/test-wsraadmin.properties","-type","organizations","-name","testorg1","-newstatus","archived"});
		assertTrue(result == WSRAAdminCLI.RETURN_OK);
		result = TestUtils.assertFailedExecution(new WSRAAdminCLI(),new String[] {"-action","dump","-data",signserverhome + "/tmp/testwsraadmindump.xml","-config",signserverhome + "/tmp/test-wsraadmin.properties","-type","organizations","-includeusers"});
		assertTrue(result == WSRAAdminCLI.RETURN_OK);	
		DataFileParser dfp = new DataFileParser(signserverhome + "/tmp/testwsraadmindump.xml");
		BackupRestoreBean brb = dfp.getData();
		assertTrue(brb.getOrganizations().get(0).getOrganizationName().equals("testorg1"));
		assertTrue(brb.getOrganizations().get(0).getStatus().equals(OrganizationStatus.ARCHIVED));		
	}

	public void testRemoveProductMapping() throws Exception{
		int result = TestUtils.assertFailedExecution(new WSRAAdminCLI(),new String[] {"-action","remove","-config",signserverhome + "/tmp/test-wsraadmin.properties","-type","PRODUCTMAPPINGS","-name","MAPPING1"});
		assertTrue(result == WSRAAdminCLI.RETURN_OK);
		result = TestUtils.assertFailedExecution(new WSRAAdminCLI(),new String[] {"-action","dump","-data",signserverhome + "/tmp/testwsraadmindump.xml","-config",signserverhome + "/tmp/test-wsraadmin.properties","-type","PRODUCTMAPPINGS"});
		assertTrue(result == WSRAAdminCLI.RETURN_OK);	
		DataFileParser dfp = new DataFileParser(signserverhome + "/tmp/testwsraadmindump.xml");
		BackupRestoreBean brb = dfp.getData();
		assertTrue(brb.getProductMappings().size()==2);		
	}
	
	public void test99RemoveDatabase() throws Exception{
		  
		  
	}
	


	


}
