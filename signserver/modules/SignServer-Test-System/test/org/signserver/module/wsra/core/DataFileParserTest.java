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

import java.io.ByteArrayInputStream;
import java.io.File;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import junit.framework.TestCase;

import org.bouncycastle.util.encoders.Base64;
import org.ejbca.util.CertTools;
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
import org.signserver.module.wsra.common.authtypes.CertSubjectAuthType;
import org.signserver.module.wsra.common.tokenprofiles.JKSTokenProfile;

/**
 * TODO: Document me!
 * 
 * @version $Id$
 */
public class DataFileParserTest extends TestCase {

    private String signserverhome;
    private String testfile;
    private X509Certificate cert;
    private static byte[] certbytes = Base64.decode(("MIIC5DCCAcygAwIBAgIIfZgsZqV8NDAwDQYJKoZIhvcNAQEFBQAwNzERMA8GA1UE"
            + "AxMIQWRtaW5DQTExFTATBgNVBAoTDEVKQkNBIFNhbXBsZTELMAkGA1UEBhMCU0Uw"
            + "HhcNMDYwNjAzMTUzMzM5WhcNMjYwNTI5MTU0MzM5WjA3MRYwFAYDVQQDEw10aW1l"
            + "c3RhbXB0ZXN0MR0wGwYDVQQKExRQcmltZUtleSBTb2x1dGlvbiBBQjCBnzANBgkq"
            + "hkiG9w0BAQEFAAOBjQAwgYkCgYEAhRCP0tmX/JlAeb1BKuD6j8iv4XZRCsRqYQvl"
            + "DfTuRL4CysH72YthmEVje+oijbVpmbEp209r93UwvS4TZiTPQvVAYnUw7la7H4Q4"
            + "rCiPT4mwj+eR8IxuAOZgrv2HXVERzuq6KfdTYrTCbm1cBoO6zxftlHCnjCbuA/62"
            + "WVRLhKsCAwEAAaN4MHYwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCBsAwFgYD"
            + "VR0lAQH/BAwwCgYIKwYBBQUHAwgwHQYDVR0OBBYEFOrxsQleE90vW4I2FC4cDim/"
            + "hKjhMB8GA1UdIwQYMBaAFNrdQb5Q2K3ZL/KD+leV040azuwPMA0GCSqGSIb3DQEB"
            + "BQUAA4IBAQB5WKwHfItwzbU3gdsszZ1V0yfnc9znP8De8fOjBHaGdgO3wxo2zB0G"
            + "JbgcyvVeJ5kecZRZcM+/bTNraWFGlCTkaqLD+1pMeVc1oBbtR5hevuykA+OR7RKS"
            + "mUZ7CadXnZjkDRgN8XsP5doDOpV2ZunLfrPCx61mJ3GxG6gvuMutOd7U2BN2vbMr"
            + "VMNxWOftXR/XyJAJxY0YOgplV8hOkW+Ky0MyAe2ktFnOOuMIMKhLgrN338ZeAXRs"
            + "2lhcc/p79imDL5QkPavZWrcnNZpT506DDyzn1cf68HpJNF1ICY57hWmx79gbIFhe"
            + "mJxVZp+eyws3H9Yb9o2pLs7EOS7n+X26").getBytes());

    protected void setUp() throws Exception {
        super.setUp();
        SignServerUtil.installBCProvider();
        signserverhome = System.getenv("SIGNSERVER_HOME");
        assertNotNull(signserverhome);

        testfile = signserverhome + "/tmp/testwsradump.xml";

        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
        cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certbytes));

    }

    public void testDataFileParser() throws Exception {

        Set<String> allowedIssuerDNs = new HashSet<String>();
        allowedIssuerDNs.add("CN=issuer1");
        allowedIssuerDNs.add("CN=issuer2");

        Set<String> allowedProfiles = new HashSet<String>();
        allowedProfiles.add("cProfile1");
        allowedProfiles.add("cProfile2");

        HashSet<String> allowedTProfiles = new HashSet<String>();
        allowedTProfiles.add("tProfile1");

        DataBankDataBean dbdb1 = new DataBankDataBean(WSRAConstants.DATABANKTYPE_PRICE, "testkey1", "testvalue");
        DataBankDataBean dbdb2 = new DataBankDataBean(WSRAConstants.DATABANKTYPE_GENERAL, "testkey2", "testvalue2");
        ArrayList<DataBankDataBean> databank = new ArrayList<DataBankDataBean>();
        databank.add(dbdb1);
        databank.add(dbdb2);

        OrganizationDataBean o1 = new OrganizationDataBean(OrganizationType.CUSTOMER, "testorg1", "Test Org1", allowedIssuerDNs, allowedProfiles, allowedTProfiles);

        CertificateDataBean cdb = new CertificateDataBean(cert, "cProfile1");
        ArrayList<CertificateDataBean> tokenCerts = new ArrayList<CertificateDataBean>();
        tokenCerts.add(cdb);

        TokenDataBean tdb = new TokenDataBean(JKSTokenProfile.PROFILEID, "TOKENSN123");
        tdb.setCertificates(tokenCerts);
        ArrayList<TokenDataBean> tokens = new ArrayList<TokenDataBean>();
        tokens.add(tdb);

        UserAliasDataBean alias = new UserAliasDataBean("type1", "alias1");
        ArrayList<UserAliasDataBean> aliases = new ArrayList<UserAliasDataBean>();
        aliases.add(alias);

        CertSubjectAuthType at = new CertSubjectAuthType();
        AuthDataBean authData = new AuthDataBean(at.getAuthType(), at.getMatchValue(CertTools.getIssuerDN(cert), CertTools.getSubjectDN(cert)));
        ArrayList<AuthDataBean> authDatas = new ArrayList<AuthDataBean>();
        authDatas.add(authData);

        Set<String> roles = new HashSet<String>();
        roles.add(Roles.SUPERADMIN);
        UserDataBean udb = new UserDataBean("user1", "User 1", roles, 1);
        udb.setTokens(tokens);
        udb.setAliases(aliases);
        udb.setAuthData(authDatas);
        List<UserDataBean> users = new ArrayList<UserDataBean>();
        users.add(udb);
        o1.setUsers(users);
        o1.setRelatedData(databank);

        OrganizationDataBean o2 = new OrganizationDataBean(OrganizationType.CUSTOMER, "testorg1", "Test Org1", allowedIssuerDNs, allowedProfiles, allowedTProfiles);

        ProductsInOrganizationDataBean piodb = new ProductsInOrganizationDataBean("1234", "standard", "SEK");
        List<ProductsInOrganizationDataBean> prio = new ArrayList<ProductsInOrganizationDataBean>();
        prio.add(piodb);
        o2.setProducts(prio);
        List<OrganizationDataBean> organizations = new ArrayList<OrganizationDataBean>();
        organizations.add(o1);
        organizations.add(o2);

        ProductDataBean pdb1 = new ProductDataBean("1234", "testprod1", "some test prod1");
        ProductDataBean pdb2 = new ProductDataBean("2345", "testprod2", "some test prod2");
        List<ProductDataBean> products = new ArrayList<ProductDataBean>();
        products.add(pdb1);
        products.add(pdb2);

        PricingDataBean prdb = new PricingDataBean("standard", "Standard price", (float) 1.0, "SEK");
        List<PricingDataBean> prices = new ArrayList<PricingDataBean>();
        prices.add(prdb);


        ArrayList<ProductMappingBean> pmaps = new ArrayList<ProductMappingBean>();
        pmaps.add(new ProductMappingBean("MAPPING1", "GENCERT", "TPROF1", "CPROF1", "Artnr1"));
        pmaps.add(new ProductMappingBean("MAPPING2", "*", "TPROF2", "*", "Artnr2"));
        pmaps.add(new ProductMappingBean("MAPPING3", "CHECKREV", "*", "*", "Artnr3"));

        BackupRestoreBean data = new BackupRestoreBean();
        data.setOrganizations(organizations);
        data.setProducts(products);
        data.setPricing(prices);
        data.setProductMappings(pmaps);



        DataFileParser parser = new DataFileParser(data);

        parser.dumpData(testfile);

        DataFileParser parser2 = new DataFileParser(testfile);

        BackupRestoreBean data2 = parser2.getData();
        assertTrue(data2.getOrganizations().size() == 2);
        OrganizationDataBean o3 = data2.getOrganizations().get(0);
        assertTrue(o3.getAllowedCProfiles().size() == 2);
        assertTrue(o3.getAllowedIssuers().size() == 2);
        UserDataBean udb2 = o3.getUsers().get(0);
        assertTrue(udb2.getUserName().equals(udb.getUserName()));
        TokenDataBean tdb2 = udb2.getTokens().iterator().next();
        assertTrue(tdb2.getSerialNumber().equals(tdb.getSerialNumber()));
        CertificateDataBean cdb2 = tdb2.getCertificates().iterator().next();
        assertTrue(cdb2.getIssuerDN().equals(CertTools.getIssuerDN(cert)));
        assertTrue(udb2.getAuthData().iterator().next().getAuthType() == at.getAuthType());
        assertTrue(udb2.getAliases().iterator().next().getAlias().equals(alias.getAlias()));
        assertTrue(o3.getRelatedData().get(0).getKey().equals(dbdb1.getKey()));
        OrganizationDataBean o4 = data2.getOrganizations().get(1);
        assertTrue(o4.getProducts().size() == 1);
        assertTrue(o4.getProducts().get(0).getCurrency().equals("SEK"));


        PricingDataBean pdb3 = data2.getPricing().get(0);
        assertTrue(pdb3.getCurrency().equals("SEK"));

        ProductDataBean pdb4 = data2.getProducts().get(0);
        assertTrue(pdb4.getProductNumber().equals("1234"));

        ProductMappingBean pmb2 = data2.getProductMappings().get(0);
        assertTrue(pmb2.getMappingName().equals("MAPPING1"));
    }

    protected void tearDown() throws Exception {
        super.tearDown();

        File f = new File(testfile);
        f.delete();
    }
}
