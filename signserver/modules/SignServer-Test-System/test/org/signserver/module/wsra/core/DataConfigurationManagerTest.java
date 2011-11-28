/*************************************************************************
 *                                                                       *
 *  SignServer: The OpenSource Automated Signing Server                  *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.signserver.module.wsra.core;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;

import javax.persistence.EntityManager;

import org.ejbca.util.CertTools;
import org.ejbca.util.keystore.KeyTools;
import org.signserver.common.SignServerUtil;
import org.signserver.module.wsra.beans.AuthDataBean;
import org.signserver.module.wsra.beans.BackupRestoreBean;
import org.signserver.module.wsra.beans.CertificateDataBean;
import org.signserver.module.wsra.beans.DataBankDataBean;
import org.signserver.module.wsra.beans.OrganizationDataBean;
import org.signserver.module.wsra.beans.PricingDataBean;
import org.signserver.module.wsra.beans.ProductDataBean;
import org.signserver.module.wsra.beans.ProductMappingBean;
import org.signserver.module.wsra.beans.ProductsInOrganizationDataBean;
import org.signserver.module.wsra.beans.TokenDataBean;
import org.signserver.module.wsra.beans.UserAliasDataBean;
import org.signserver.module.wsra.beans.UserDataBean;
import org.signserver.module.wsra.common.Roles;
import org.signserver.module.wsra.common.WSRAConstants;
import org.signserver.module.wsra.common.WSRAConstants.OrganizationType;
import org.signserver.module.wsra.common.authtypes.CertSNAuthType;
import org.signserver.module.wsra.common.authtypes.CertSubjectAuthType;
import org.signserver.module.wsra.common.authtypes.SNinDNAuthType;
import org.signserver.module.wsra.common.tokenprofiles.JKSTokenProfile;
import org.signserver.module.wsra.core.DataConfigurationManager.Type;

/**
 * TODO: Document me!
 * 
 * @version $Id$
 */
public class DataConfigurationManagerTest extends CommonManagerT {

    private static UserManager um = null;
    private static DataConfigurationManager dcm = null;
    private String testfile;
    private HashSet<Class<?>> availAuthTypes;
    private static DataBankManager dbm;
    private static ProductManager pm;
    private static Integer orgId1;
    private static X509Certificate cert1 = null;
    private static X509Certificate cert2 = null;

    protected void setUp() throws Exception {
        super.setUp();
        workerEntityManager = genEntityManager();
        if (um == null) {
            availAuthTypes = new HashSet<Class<?>>();
            availAuthTypes.add(CertSNAuthType.class);
            availAuthTypes.add(SNinDNAuthType.class);
            availAuthTypes.add(CertSubjectAuthType.class);

            TokenManager tm = new TokenManager(workerEntityManager, getAvailableTokenProfiles());
            um = new UserManager(workerEntityManager, availAuthTypes, tm);
            SignServerUtil.installBCProvider();
            KeyPair keys = KeyTools.genKeys("512", "RSA");
            cert1 = CertTools.genSelfCert("CN=test1", 1, null, keys.getPrivate(), keys.getPublic(), "SHA1WithRSA", false);
            cert2 = CertTools.genSelfCert("CN=test1, SERIALNUMBER=123", 1, null, keys.getPrivate(), keys.getPublic(), "SHA1WithRSA", false);
        }
        if (dcm == null) {
            dcm = new DataConfigurationManager(workerEntityManager);
        }
        if (pm == null) {
            pm = new ProductManager(workerEntityManager);
        }
        if (dbm == null) {
            dbm = new DataBankManager(workerEntityManager);
        }

        String signserverhome = System.getenv("SIGNSERVER_HOME");
        assertNotNull(signserverhome);

        testfile = signserverhome + "/tmp/testwsradump.xml";
    }

    public void test01OrganizationDump() throws Exception {
        setDB();

        BackupRestoreBean drb = dcm.dumpConfiguration(DataConfigurationManager.Type.ALL, true, true);

        assertTrue(drb.getOrganizations().size() == 2);

        DataFileParser dfp = new DataFileParser(drb);
        dfp.dumpData(testfile);


        DataFileParser dfp2 = new DataFileParser(testfile);
        BackupRestoreBean drb2 = dfp2.getData();

        EntityManager wem2 = genEntityManager();
        DataConfigurationManager dcm2 = new DataConfigurationManager(wem2);
        dcm2.storeConfiguration(Type.ALL, drb2, true, true);


        TokenManager tm2 = new TokenManager(wem2, getAvailableTokenProfiles());
        UserManager um2 = new UserManager(wem2, availAuthTypes, tm2);
        ProductManager pm2 = new ProductManager(wem2);
        OrganizationManager om2 = new OrganizationManager(wem2, um2, pm2);
        DataBankManager dbm2 = new DataBankManager(wem2);

        List<OrganizationDataBean> orgs = om2.listOrganizations();
        assertTrue(orgs.size() == 2);
        OrganizationDataBean org = orgs.get(0);
        List<DataBankDataBean> rdata = dbm2.getRelatedProperies(WSRAConstants.DATABANKTYPE_ORGANIZATION, org.getId());
        assertTrue(rdata.size() == 2);
        UserDataBean user = org.getUsers().get(0);
        assertTrue(user.getUserName().equals("test1"));
        CertSNAuthType at = new CertSNAuthType();
        assertTrue(user.getAuthData().iterator().next().getAuthType() == at.getAuthType());

        assertTrue(user.getAliases().size() == 2);

        List<ProductDataBean> prods2 = pm2.listProducts(null);
        assertTrue(prods2.size() == 2);
        assertTrue(prods2.get(0).getProductNumber() != null);

        List<PricingDataBean> prices2 = pm2.listPrices(null);
        assertTrue(prices2.size() == 2);
        assertTrue(prices2.get(0).getPriceClass() != null);

        ProductMapper pMapper = new ProductMapper(dbm2);
        ProductMappingBean pmb2 = pMapper.getProductMappings().get(0);
        assertTrue(pmb2.getMappingName().equals("MAPPING1"));

    }

    private void setDB() throws Exception {
        ProductDataBean pdb1 = new ProductDataBean("1234", "testprod1", "some test prod1");
        ProductDataBean pdb2 = new ProductDataBean("2345", "testprod2", "some test prod2");
        tb();
        pm.editProduct(pdb1);
        tc();
        tb();
        pm.editProduct(pdb2);
        tc();

        PricingDataBean prdb1 = new PricingDataBean("standard", "Standard price", (float) 1.0, "SEK");
        PricingDataBean prdb2 = new PricingDataBean("budget", "Budget price", (float) 0.5, "SEK");
        tb();
        pm.editPrice(prdb1);
        tc();
        tb();
        pm.editPrice(prdb2);
        tc();

        ArrayList<ProductMappingBean> pmaps = new ArrayList<ProductMappingBean>();
        pmaps.add(new ProductMappingBean("MAPPING1", "GENCERT", "TPROF1", "CPROF1", "Artnr1"));
        pmaps.add(new ProductMappingBean("MAPPING2", "*", "TPROF2", "*", "Artnr2"));
        pmaps.add(new ProductMappingBean("MAPPING3", "CHECKREV", "*", "*", "Artnr3"));

        ProductMapper pMapper = new ProductMapper(dbm);
        tb();
        pMapper.setProductMappings(pmaps);
        tc();

        HashSet<String> allowedIssuers = new HashSet<String>();
        allowedIssuers.add("CN=test1");
        allowedIssuers.add("CN=test2");
        HashSet<String> allowedCProfiles = new HashSet<String>();
        allowedCProfiles.add("cProfile1");
        HashSet<String> allowedTProfiles = new HashSet<String>();
        allowedTProfiles.add("tProfile1");

        TokenManager tm = new TokenManager(workerEntityManager, getAvailableTokenProfiles());
        ProductManager pm = new ProductManager(workerEntityManager);
        OrganizationManager om = new OrganizationManager(workerEntityManager, um, pm);
        OrganizationDataBean org1 = new OrganizationDataBean(OrganizationType.CUSTOMER, "testOrg1", "Test Org1", allowedIssuers, allowedCProfiles, allowedTProfiles);
        tb();
        om.editOrganization(org1);
        tc();
        OrganizationDataBean org2 = new OrganizationDataBean(OrganizationType.CUSTOMER, "testOrg2", "Test Org2", allowedIssuers, allowedCProfiles, allowedTProfiles);
        tb();
        om.editOrganization(org2);
        tc();

        OrganizationDataBean orgWithId = om.findOrganization("testOrg1");
        orgId1 = orgWithId.getId();

        ProductsInOrganizationDataBean piod1 = new ProductsInOrganizationDataBean("1234", "standard", "SEK");
        piod1.setOrganizationId(orgId1);
        tb();
        om.editProductInOrganization(piod1);
        tc();
        ProductsInOrganizationDataBean piod2 = new ProductsInOrganizationDataBean("2345", "budget", "SEK");
        piod2.setOrganizationId(orgId1);
        tb();
        om.editProductInOrganization(piod2);
        tc();

        tb();
        dbm.setRelatedProperty(WSRAConstants.DATABANKTYPE_ORGANIZATION, orgId1, "testkey1", "testvalue1");
        tc();
        tb();
        dbm.setRelatedProperty(WSRAConstants.DATABANKTYPE_ORGANIZATION, orgId1, "testkey2", "testvalue2");
        tc();

        HashSet<String> roles1 = new HashSet<String>();
        roles1.add(Roles.RAADMIN);
        roles1.add(Roles.MAINADMIN);
        UserDataBean ud = new UserDataBean("test1", "Test 1", roles1, orgId1);


        List<UserAliasDataBean> aliases = new ArrayList<UserAliasDataBean>();
        aliases.add(new UserAliasDataBean("type1", "test1alias1"));
        aliases.add(new UserAliasDataBean("type1", "test1alias2"));
        ud.setAliases(aliases);
        tb();
        um.editUser(ud);
        tc();

        ud = um.findUser("test1", orgId1);

        CertificateDataBean certData1 = new CertificateDataBean(cert1, "cProfile1");
        CertificateDataBean certData2 = new CertificateDataBean(cert2, "cProfile2");
        ArrayList<CertificateDataBean> certs = new ArrayList<CertificateDataBean>();
        certs.add(certData1);
        certs.add(certData2);


        TokenDataBean t1 = new TokenDataBean(orgId1, ud.getId(),
                JKSTokenProfile.PROFILEID,
                "12345");
        t1.setCertificates(certs);

        t1.setSensitiveData("test1".getBytes());

        TokenDataBean t2 = new TokenDataBean(orgId1, ud.getId(),
                JKSTokenProfile.PROFILEID,
                "12346");

        tb();
        tm.editToken(t1);
        tc();
        tb();
        tm.editToken(t2);
        tc();

        CertSNAuthType certSNAuthType = new CertSNAuthType();
        AuthDataBean adb1 = new AuthDataBean(certSNAuthType.getAuthType(), certSNAuthType.getMatchValue(cert1.getIssuerDN().toString(), cert1.getSerialNumber()), ud.getId());
        tb();
        um.editAuthData(adb1);
        tc();
    }
}
