package org.signserver.module.wsra.core;

import java.util.HashSet;
import java.util.List;

import org.signserver.common.SignServerUtil;
import org.signserver.module.wsra.beans.OrganizationDataBean;
import org.signserver.module.wsra.beans.PricingDataBean;
import org.signserver.module.wsra.beans.ProductsInOrganizationDataBean;
import org.signserver.module.wsra.beans.UserDataBean;
import org.signserver.module.wsra.common.Roles;
import org.signserver.module.wsra.common.WSRAConstants.OrganizationType;
import org.signserver.module.wsra.common.authtypes.CertSNAuthType;
import org.signserver.module.wsra.common.authtypes.CertSubjectAuthType;
import org.signserver.module.wsra.common.authtypes.SNinDNAuthType;

public class OrganizationManagerTest extends CommonManagerT {
	
	private static UserManager um = null;
	private static OrganizationManager om = null;
	private static Integer orgId1;
	private static Integer orgId2; 
		
	protected void setUp() throws Exception {
		super.setUp();
		if(um == null){
		  HashSet<Class<?>> availAuthTypes = new  HashSet<Class<?>>();
		  availAuthTypes.add(CertSNAuthType.class);
		  availAuthTypes.add(SNinDNAuthType.class);
		  availAuthTypes.add(CertSubjectAuthType.class);
		  
		   
		  TokenManager tm = new TokenManager(workerEntityManager,getAvailableTokenProfiles());
		  um = new UserManager(workerEntityManager,availAuthTypes,tm);
		  SignServerUtil.installBCProvider();
		  ProductManager pm = new ProductManager(workerEntityManager);
		  om = new OrganizationManager(workerEntityManager,um,pm);
		}
	}
	
	public void test01BasicOrganizationManager() throws Exception{
		
		HashSet<String> allowedIssuers = new HashSet<String>();
		allowedIssuers.add("CN=test1");
		allowedIssuers.add("CN=test2");
		HashSet<String> allowedCProfiles = new HashSet<String>();
		allowedCProfiles.add("cProfile1");
		HashSet<String> allowedTProfiles = new HashSet<String>();
		allowedTProfiles.add("tProfile1");
		
		OrganizationDataBean org1 = new OrganizationDataBean(OrganizationType.CUSTOMER,"testOrg1","Test Org 1",allowedIssuers,allowedCProfiles,allowedTProfiles);
		OrganizationDataBean org2 = new OrganizationDataBean(OrganizationType.PARTNER,"testOrg2","Test Org 2",allowedIssuers,allowedCProfiles,allowedTProfiles);
		OrganizationDataBean org3 = new OrganizationDataBean(OrganizationType.CUSTOMER,"testOrg3","Test Org 3",allowedIssuers,allowedCProfiles,allowedTProfiles);
                       
		tb();om.editOrganization(org1);tc();
		tb();om.editOrganization(org2);tc();
		tb();om.editOrganization(org3);tc();
		
		OrganizationDataBean result = om.findOrganization("testOrg1");
		assertNotNull(result);
		assertTrue(result.getOrganizationName().equals("testOrg1"));
		assertTrue(result.getDisplayName().equals("Test Org 1"));
		assertTrue(result.getType()==OrganizationType.CUSTOMER);
		assertTrue(result.getAllowedCProfiles().size()==1);
		assertTrue(result.getAllowedCProfiles().contains("cProfile1"));
		assertTrue(result.getAllowedTProfiles().size()==1);
		assertTrue(result.getAllowedTProfiles().contains("tProfile1"));
		assertTrue(result.getAllowedIssuers().size()==2);
		assertTrue(result.getAllowedIssuers().contains("CN=test1"));
		assertTrue(result.getAllowedIssuers().contains("CN=test2"));
		orgId1 = result.getId();
		result = om.findOrganization("testOrg2");
		assertNotNull(result);
		assertTrue(result.getOrganizationName().equals("testOrg2"));
		orgId2 = result.getId();
		
		HashSet<String> roles1 = new HashSet<String>();
		roles1.add(Roles.RAADMIN);
		roles1.add(Roles.MAINADMIN);
		UserDataBean ud = new UserDataBean("test1","Test 1",roles1,orgId1);		
		tb();um.editUser(ud);tc();
		
		ud = new UserDataBean("test2","Test 2",roles1,orgId2);		
		tb();um.editUser(ud);tc();
		
		ud = new UserDataBean("test3","Test 3",roles1,orgId1);		
		tb();um.editUser(ud);tc();
		
		result = om.findOrganization("testOrg1");
		assertNotNull(result);
		assertTrue(result.getUsers().size()==2);
		
		result.setComment("SomeComment");
		tb();om.editOrganization(result);tc();
		
		result = om.findOrganization("testOrg1");
		assertNotNull(result);
		assertTrue(result.getOrganizationName().equals("testOrg1"));
		assertTrue(result.getComment().equals("SomeComment"));
		
		result = om.findOrganization("testOrg123");
		assertNull(result);

		result = om.findOrganization(orgId1);
		assertNotNull(result);
		assertTrue(result.getOrganizationName().equals("testOrg1"));
		
		result = om.findOrganization(orgId1+123);
		assertNull(result);
		
		List<OrganizationDataBean> res = om.listOrganizations();
		assertTrue(res.size() == 3);
					
	}
	
	
	public void test02ProductsInOrganizationRelation() throws Exception{
		OrganizationDataBean result = om.findOrganization("testOrg1");		
		assertTrue(result.getProducts().size() == 0);
		
        ProductsInOrganizationDataBean pio1 = new ProductsInOrganizationDataBean(orgId1,123,321,PricingDataBean.CURRENCY_NOK);
		tb();om.editProductInOrganization(pio1);tc();
		
		result = om.findOrganization("testOrg1");
		assertTrue(result.getProducts().size() == 1);
		ProductsInOrganizationDataBean pio= result.getProducts().iterator().next();
		assertTrue(pio.getProductId() == 123);
		assertTrue(pio.getPriceId() == 321);
		assertTrue(pio.getCurrency() == PricingDataBean.CURRENCY_NOK);
		
        ProductsInOrganizationDataBean pio2 = new ProductsInOrganizationDataBean(orgId1,124,321,PricingDataBean.CURRENCY_SEK);
        tb();om.editProductInOrganization(pio2);tc();
		
		result = om.findOrganization("testOrg1");
		assertTrue(result.getProducts().size() == 2);
		
		pio = om.findProductInOrganization(orgId1, 123);	
		assertNotNull(pio);
		assertTrue(pio.getPriceId() == 321);
		
		pio.setCurrency(PricingDataBean.CURRENCY_SEK);
		tb();om.editProductInOrganization(pio);tc();
		
		pio = om.findProductInOrganization(orgId1, 123);	
		assertNotNull(pio);
		assertTrue(pio.getCurrency().equals(PricingDataBean.CURRENCY_SEK));
		
		tb();om.removeProductInOrganization(pio2.getOrganizationId(), pio2.getProductId());tc();
		
		result = om.findOrganization("testOrg1");		
		assertTrue(result.getProducts().size() == 1);
		
		assertNull(om.findProductInOrganization(pio2.getOrganizationId(), pio2.getProductId()));
		
	}

	
	public void test03RemoveOrganization() throws Exception{
		OrganizationDataBean result = om.findOrganization("testOrg1");
		assertNotNull(result);
		assertTrue(result.getOrganizationName().equals("testOrg1"));
		
		tb();om.removeOrganization(result.getId());tc();
		result = om.findOrganization("testOrg1");
		assertNull(result);
		
		result = om.findOrganization("testOrg2");
		assertNotNull(result);
		assertTrue(result.getOrganizationName().equals("testOrg2"));
		tb();om.removeOrganization(result.getId());tc();
		result = om.findOrganization("testOrg2");
		assertNull(result);
						
		assertNull(om.findProductInOrganization(orgId1, 123));
	}

}
