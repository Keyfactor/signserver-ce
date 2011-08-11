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

import org.ejbca.util.CertTools;
import org.ejbca.util.keystore.KeyTools;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerUtil;
import org.signserver.module.wsra.beans.AuthDataBean;
import org.signserver.module.wsra.beans.OrganizationDataBean;
import org.signserver.module.wsra.beans.UserAliasDataBean;
import org.signserver.module.wsra.beans.UserDataBean;
import org.signserver.module.wsra.common.Roles;
import org.signserver.module.wsra.common.WSRAConstants.OrganizationType;
import org.signserver.module.wsra.common.authtypes.CertSNAuthType;
import org.signserver.module.wsra.common.authtypes.CertSubjectAuthType;
import org.signserver.module.wsra.common.authtypes.SNinDNAuthType;

/**
 * TODO: Document me!
 * 
 * @version $Id$
 */
public class UserManagerTest extends CommonManagerT {

    private static UserManager um = null;
    private static Integer orgId;
    private static X509Certificate cert1 = null;
    private static X509Certificate cert2 = null;

    protected void setUp() throws Exception {
        super.setUp();
        if (um == null) {
            HashSet<Class<?>> availAuthTypes = new HashSet<Class<?>>();
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
    }

    public void test01BasicUserManager() throws Exception {
        ProductManager pm = new ProductManager(workerEntityManager);
        OrganizationManager om = new OrganizationManager(workerEntityManager, um, pm);
        OrganizationDataBean org = new OrganizationDataBean(OrganizationType.CUSTOMER, "testOrg", "Test Org", new HashSet<String>(), new HashSet<String>(), new HashSet<String>());
        tb();
        om.editOrganization(org);
        tc();
        OrganizationDataBean orgWithId = om.findOrganization("testOrg");
        orgId = orgWithId.getId();

        HashSet<String> roles1 = new HashSet<String>();
        roles1.add(Roles.RAADMIN);
        roles1.add(Roles.MAINADMIN);
        UserDataBean ud = new UserDataBean("test1", "Test 1", roles1, orgId);

        List<UserAliasDataBean> aliases = new ArrayList<UserAliasDataBean>();
        aliases.add(new UserAliasDataBean("type1", "test1alias1"));
        aliases.add(new UserAliasDataBean("type1", "test1alias2"));
        aliases.add(new UserAliasDataBean("type2", "test1alias1"));
        ud.setAliases(aliases);
        tb();
        um.editUser(ud);
        tc();

        UserDataBean result = um.findUser("test1", orgId);
        assertNotNull(result);
        assertTrue(result.getUserName().equals("test1"));
        assertTrue(result.getDisplayName().equals("Test 1"));
        assertTrue(result.getComment() == null);
        assertTrue(result.getAuthData().size() == 0);
        assertTrue(result.getTokens().size() == 0);
        assertNull(result.getPassword());
        assertTrue(result.isClearPassword());
        assertTrue(result.getOrganizationId() == orgId);
        assertTrue(result.getRoles().contains(Roles.MAINADMIN));
        assertTrue(result.getRoles().contains(Roles.RAADMIN));
        assertTrue(result.getAliases().size() == 3);
        for (UserAliasDataBean uad : result.getAliases()) {
            assertTrue(uad.getType().startsWith("type"));
            assertTrue(uad.getAlias().startsWith("test"));
            assertTrue(uad.getUserId() != 0);
        }


        UserAliasDataBean uadb = um.findUserAlias(result.getId(), "type1", "test1alias1");
        assertNotNull(uadb);
        assertTrue(uadb.getUserId() == result.getId());
        assertTrue(uadb.getType().equals("type1"));
        assertTrue(uadb.getAlias().equals("test1alias1"));

        List<UserDataBean> res = um.findUserByAlias(orgId, "type1", "test1alias1");
        assertNotNull(res);
        assertTrue(res.size() == 1);
        assertTrue(res.get(0).getUserName().equals("test1"));

        res = um.findUserByAlias(orgId, "type1", "test1alias3");
        assertTrue(res.size() == 0);

        res = um.findUserByAlias(orgId, "type3", "test1alias1");
        assertTrue(res.size() == 0);

        res = um.findUserLikeAlias(orgId, "type1", "alias");
        assertTrue(res.size() == 2);

        result = um.findUser(result.getId());
        assertNotNull(result);
        assertTrue(result.getUserName().equals("test1"));

        result.setComment("SomeComment");
        result.setClearPassword(false);
        result.setPassword("foo123");
        aliases = new ArrayList<UserAliasDataBean>();
        aliases.add(new UserAliasDataBean("type4", "test1alias1"));
        aliases.add(new UserAliasDataBean("type4", "test1alias2"));
        result.setAliases(aliases);
        tb();
        um.editUser(result);
        tc();

        res = um.findUserLikeAlias(orgId, "type4", "test1alias");
        assertTrue(res.size() == 2);

        result = um.findUser("test1", orgId);
        assertNotNull(result);
        assertTrue(result.getUserName().equals("test1"));
        assertTrue(result.getComment().equals("SomeComment"));
        assertFalse(result.isClearPassword());
        assertTrue(result.getPassword().startsWith("HASH:"));
        assertTrue(result.checkPassword("foo123"));
        assertFalse(result.checkPassword("foo124"));
        assertTrue(result.getAliases().size() == 2);

        result = um.findUser("test1", orgId + 1);
        assertNull(result);
        result = um.findUser("test2", orgId);
        assertNull(result);

        HashSet<String> roles2 = new HashSet<String>();
        roles2.add(Roles.RAADMIN);
        ud = new UserDataBean("test2", "Test 2", roles2, orgId);
        tb();
        um.editUser(ud);
        tc();

        res = um.listUsers(orgId, null);
        assertTrue(res.size() == 2);
        if (res.get(0).getUserName().equals("test1")) {
            assertTrue(res.get(1).getUserName().equals("test2"));
        } else {
            assertTrue(res.get(1).getUserName().equals("test1"));
        }

        res = um.listUsers(orgId, Roles.RAADMIN);
        assertTrue(res.size() == 2);
        if (res.get(0).getUserName().equals("test1")) {
            assertTrue(res.get(1).getUserName().equals("test2"));
        } else {
            assertTrue(res.get(1).getUserName().equals("test1"));
        }

        res = um.listUsers(orgId, Roles.MAINADMIN);
        assertTrue(res.size() == 1);
        assertTrue(res.get(0).getUserName().equals("test1"));



    }

    public void test02AuthData() throws Exception {
        UserDataBean result = um.findUser("test1", orgId);

        assertTrue(result.getAuthData().size() == 0);

        RequestContext rc = new RequestContext();
        rc.put(RequestContext.CLIENT_CERTIFICATE, cert1);

        CertSNAuthType certSNAuthType = new CertSNAuthType();
        AuthDataBean adb1 = new AuthDataBean(certSNAuthType.getAuthType(), certSNAuthType.getMatchValue(cert1.getIssuerDN().toString(), cert1.getSerialNumber()), result.getId());
        tb();
        um.editAuthData(adb1);
        tc();

        result = um.findUser("test1", orgId);
        assertTrue(result.getAuthData().size() == 1);
        AuthDataBean ad = result.getAuthData().iterator().next();
        assertTrue(ad.getAuthType() == certSNAuthType.getAuthType());
        assertTrue(ad.getAuthValue().equals(certSNAuthType.getMatchValue(rc)));

        tb();
        result = um.getAutorizedUser(rc);
        tc();
        assertNotNull(result);
        assertTrue(result.getUserName().equals("test1"));
        tb();
        result = um.getAutorizedUser(rc);
        tc();
        assertNotNull(result);
        assertTrue(result.getUserName().equals("test1"));
        assertTrue(result.getRoles().size() == 2);

        rc.put(RequestContext.CLIENT_CERTIFICATE, cert2);
        tb();
        result = um.getAutorizedUser(rc);
        tc();
        assertNotNull(result);
        assertTrue(result.equals(UserManager.NO_USER));
        assertTrue(result.getRoles().size() == 0);

        result = um.findUser("test2", orgId);
        SNinDNAuthType sNinDNAuthType = new SNinDNAuthType();
        AuthDataBean adb2 = new AuthDataBean(sNinDNAuthType.getAuthType(), sNinDNAuthType.getMatchValue(cert2.getIssuerDN().toString(), CertTools.getPartFromDN(CertTools.getSubjectDN(cert2), "SERIALNUMBER")), result.getId());
        tb();
        um.editAuthData(adb2);
        tc();

        result = um.getAutorizedUser(rc);
        assertNotNull(result);
        assertTrue(result.getUserName().equals("test2"));
        assertTrue(result.getRoles().size() == 1);

        tb();
        um.removeAuthData(adb1.getAuthType(), adb1.getAuthValue());
        tc();
        rc.put(RequestContext.CLIENT_CERTIFICATE, cert1);
        result = um.getAutorizedUser(rc);
        assertNotNull(result);
        assertTrue(result.equals(UserManager.NO_USER));
        assertTrue(result.getRoles().size() == 0);
        assertNull(um.findAuthData(certSNAuthType.getAuthType(), certSNAuthType.getMatchValue(cert1.getIssuerDN().toString(), cert1.getSerialNumber())));

        String orgValue = adb2.getAuthValue();
        adb2.setAuthValue("Test");
        tb();
        um.editAuthData(adb2);
        tc();

        adb2 = um.findAuthData(adb2.getAuthType(), "Test");
        assertNotNull(adb2);

        tb();
        um.removeAuthData(adb2.getAuthType(), adb2.getAuthValue());
        tc();

        adb2.setAuthValue(orgValue);

        tb();
        um.editAuthData(adb2);
        tc();

    }

    public void test03RemoveUser() throws Exception {
        UserDataBean result = um.findUser("test1", orgId);
        assertNotNull(result);
        assertTrue(result.getUserName().equals("test1"));


        tb();
        um.removeUser(result.getId());
        tc();
        result = um.findUser("test1", orgId);
        assertNull(result);

        result = um.findUser("test2", orgId);
        assertNotNull(result);
        assertTrue(result.getUserName().equals("test2"));
        tb();
        um.removeUser(result.getId());
        tc();
        result = um.findUser("test2", orgId);
        assertNull(result);

        SNinDNAuthType sNinDNAuthType = new SNinDNAuthType();
        AuthDataBean adb2 = um.findAuthData(sNinDNAuthType.getAuthType(), sNinDNAuthType.getMatchValue(cert2.getIssuerDN().toString(), CertTools.getPartFromDN(CertTools.getSubjectDN(cert2), "SERIALNUMBER")));
        assertNull(adb2);
    }
}
