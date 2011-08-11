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
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;

import org.ejbca.util.CertTools;
import org.ejbca.util.keystore.KeyTools;
import org.signserver.common.SignServerUtil;
import org.signserver.module.wsra.beans.CertificateDataBean;
import org.signserver.module.wsra.beans.OrganizationDataBean;
import org.signserver.module.wsra.beans.TokenDataBean;
import org.signserver.module.wsra.beans.UserDataBean;
import org.signserver.module.wsra.common.Roles;
import org.signserver.module.wsra.common.WSRAConstants;
import org.signserver.module.wsra.common.WSRAConstants.OrganizationType;
import org.signserver.module.wsra.common.authtypes.CertSNAuthType;
import org.signserver.module.wsra.common.authtypes.CertSubjectAuthType;
import org.signserver.module.wsra.common.authtypes.SNinDNAuthType;
import org.signserver.module.wsra.common.tokenprofiles.JKSTokenProfile;
import org.signserver.validationservice.common.X509Certificate;

/**
 * TODO: Document me!
 * 
 * @version $Id$
 */
public class TokenManagerTest extends CommonManagerT {

    private static UserManager um = null;
    private static TokenManager tm = null;
    private static Integer orgId;
    private static Integer userId1;
    private static X509Certificate cert1 = null;
    private static X509Certificate cert2 = null;
    private static PrivateKey privateKey = null;
    private static ArrayList<CertificateDataBean> certs;
    private static JKSTokenProfile jkstp;
    private static int userId2;

    protected void setUp() throws Exception {
        super.setUp();
        if (um == null) {
            jkstp = new JKSTokenProfile();

            HashSet<Class<?>> availAuthTypes = new HashSet<Class<?>>();
            availAuthTypes.add(CertSNAuthType.class);
            availAuthTypes.add(SNinDNAuthType.class);
            availAuthTypes.add(CertSubjectAuthType.class);

            SignServerUtil.installBCProvider();
            KeyPair keys = KeyTools.genKeys("512", "RSA");
            cert1 = X509Certificate.getInstance(CertTools.genSelfCert("CN=test1", 1, null, keys.getPrivate(), keys.getPublic(), "SHA1WithRSA", false));
            cert2 = X509Certificate.getInstance(CertTools.genSelfCert("CN=test2", 1, null, keys.getPrivate(), keys.getPublic(), "SHA1WithRSA", false));
            privateKey = keys.getPrivate();
            tm = new TokenManager(workerEntityManager, getAvailableTokenProfiles(), true, cert1, privateKey, "BC");
            um = new UserManager(workerEntityManager, availAuthTypes, tm);

        }
    }

    public void test01BasicTokenManager() throws Exception {

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

        tb();
        um.editUser(ud);
        tc();

        ud = um.findUser("test1", orgId);

        userId1 = ud.getId();

        HashSet<String> roles2 = new HashSet<String>();
        roles2.add(Roles.RAADMIN);
        ud = new UserDataBean("test2", "Test 2", roles2, orgId);
        tb();
        um.editUser(ud);
        tc();

        ud = um.findUser("test2", orgId);
        userId2 = ud.getId();


        CertificateDataBean certData1 = new CertificateDataBean(cert1, 0, "cProfile1");
        CertificateDataBean certData2 = new CertificateDataBean(cert2, 0, "cProfile2");
        certs = new ArrayList<CertificateDataBean>();
        certs.add(certData1);
        certs.add(certData2);


        TokenDataBean t1 = new TokenDataBean(orgId, userId1,
                jkstp.getProfileIdentifier(),
                "12345");
        t1.setCertificates(certs);

        t1.setSensitiveData("test1".getBytes());

        TokenDataBean t2 = new TokenDataBean(orgId, userId1,
                jkstp.getProfileIdentifier(),
                "12346");
        TokenDataBean t3 = new TokenDataBean(orgId, userId2,
                jkstp.getProfileIdentifier(),
                "22345");
        t3.setCertificates(certs);

        tb();
        tm.editToken(t1);
        tc();
        tb();
        tm.editToken(t2);
        tc();


        UserDataBean udres = um.findUser(userId1);
        assertTrue(udres.getTokens().size() == 2);
        Iterator<TokenDataBean> iter = udres.getTokens().iterator();
        while (iter.hasNext()) {
            TokenDataBean tr = iter.next();
            if (tr.getSerialNumber().equals("12345")) {
                assertTrue(tr.getProfile().equals(jkstp.getProfileIdentifier()));
                assertTrue(tr.getCopyOf() == 0);
                assertTrue(tr.getUserId() == userId1);
                assertTrue(tr.getOrganizationId() == orgId);
                assertTrue(tr.getCertificates().size() == 2);
                assertFalse(new String(tr.getSensitiveData()).equals("test1"));
                Iterator<CertificateDataBean> iter2 = tr.getCertificates().iterator();
                while (iter2.hasNext()) {
                    CertificateDataBean c = iter2.next();
                    if (c.getSubjectDN().equals("CN=test1")) {
                        assertTrue(c.getIssuerDN().equals("CN=test1"));
                        assertTrue(c.getFingerprint().equals(CertTools.getFingerprintAsString(cert1)));
                        assertTrue(c.getSerialNumber().equals(cert1.getSerialNumber().toString()));
                        assertTrue(c.getProfile().equals("cProfile1"));
                        assertTrue(c.getExpireDate().equals(cert1.getNotAfter()));
                        assertTrue(c.getStatus() == WSRAConstants.CERTSTATUS_ACTIVE);
                        assertNotNull(c.getCertificateData());
                        X509Certificate certRes = (X509Certificate) c.getCertificate();
                        assertTrue(CertTools.getFingerprintAsString(certRes).equals(CertTools.getFingerprintAsString(cert1)));
                    }
                }
            }
        }

        tb();
        tm.editToken(t3);
        tc();
        udres = um.findUser(userId2);
        assertTrue(udres.getTokens().size() == 1);

        TokenDataBean td = tm.findToken(orgId, "12345", true);
        assertTrue(td.getProfile().equals(jkstp.getProfileIdentifier()));
        assertTrue(td.getCopyOf() == 0);
        assertTrue(td.getUserId() == userId1);
        assertTrue(td.getOrganizationId() == orgId);
        assertTrue(td.getCertificates().size() == 0);
        assertTrue(new String(td.getSensitiveData()).equals("test1"));

        td.setComment("testtest");
        tb();
        tm.editToken(td);
        tc();
        td = tm.findToken(orgId, "12345", true);
        assertTrue(td.getComment().equals("testtest"));

        td = tm.findToken(orgId, "12345", false);
        assertNotNull(td);
        assertNull(td.getSensitiveData());

        td = tm.findToken(orgId + 100, "12345", false);
        assertNull(td);
        td = tm.findToken(orgId, "54321", false);
        assertNull(td);

        td = tm.findToken(orgId, "22345", false);
        assertNotNull(td);
        assertTrue(td.getCertificates().size() == 2);

    }

    public void test02CertificateData() throws Exception {
        TokenDataBean t3 = tm.findToken(orgId, "22345", false);

        CertificateDataBean c = tm.findCertificate(cert1.getSerialNumber().toString(), CertTools.getIssuerDN(cert1));
        assertNotNull(c);
        assertTrue(c.getSubjectDN().equals("CN=test1"));
        assertTrue(c.getIssuerDN().equals("CN=test1"));
        assertTrue(c.getFingerprint().equals(CertTools.getFingerprintAsString(cert1)));
        assertTrue(c.getSerialNumber().equals(cert1.getSerialNumber().toString()));
        assertTrue(c.getProfile().equals("cProfile1"));
        assertTrue(c.getExpireDate().equals(cert1.getNotAfter()));
        assertTrue(c.getStatus() == WSRAConstants.CERTSTATUS_ACTIVE);
        assertTrue(c.getTokenId() == t3.getId());
        assertNotNull(c.getCertificateData());
        X509Certificate certRes = (X509Certificate) c.getCertificate();
        assertTrue(CertTools.getFingerprintAsString(certRes).equals(CertTools.getFingerprintAsString(cert1)));

        c = tm.findCertificate(cert1.getSerialNumber().toString() + "123", CertTools.getIssuerDN(cert1));
        assertNull(c);
        c = tm.findCertificate(cert1.getSerialNumber().toString(), CertTools.getIssuerDN(cert1) + ",C=SE");
        assertNull(c);

        c = tm.findCertificateByFingerprint(CertTools.getFingerprintAsString(cert1));
        assertNotNull(c);
        assertTrue(c.getSubjectDN().equals("CN=test1"));
        assertTrue(c.getIssuerDN().equals("CN=test1"));
        assertTrue(c.getFingerprint().equals(CertTools.getFingerprintAsString(cert1)));
        assertTrue(c.getSerialNumber().equals(cert1.getSerialNumber().toString()));
        assertTrue(c.getProfile().equals("cProfile1"));
        assertTrue(c.getExpireDate().equals(cert1.getNotAfter()));
        assertTrue(c.getStatus() == WSRAConstants.CERTSTATUS_ACTIVE);
        assertNotNull(c.getCertificateData());
        certRes = (X509Certificate) c.getCertificate();
        assertTrue(CertTools.getFingerprintAsString(certRes).equals(CertTools.getFingerprintAsString(cert1)));

        c = tm.findCertificateByFingerprint(CertTools.getFingerprintAsString(cert1) + "123");
        assertNull(c);

        List<CertificateDataBean> result = tm.findCertificateBySubject(CertTools.getSubjectDN(cert1), CertTools.getIssuerDN(cert1));
        assertTrue(result.size() == 1);
        c = result.get(0);
        assertNotNull(c);
        assertTrue(c.getSubjectDN().equals("CN=test1"));
        assertTrue(c.getIssuerDN().equals("CN=test1"));
        assertTrue(c.getFingerprint().equals(CertTools.getFingerprintAsString(cert1)));
        assertTrue(c.getSerialNumber().equals(cert1.getSerialNumber().toString()));
        assertTrue(c.getProfile().equals("cProfile1"));
        assertTrue(c.getExpireDate().equals(cert1.getNotAfter()));
        assertTrue(c.getStatus() == WSRAConstants.CERTSTATUS_ACTIVE);
        assertNotNull(c.getCertificateData());
        certRes = (X509Certificate) c.getCertificate();
        assertTrue(CertTools.getFingerprintAsString(certRes).equals(CertTools.getFingerprintAsString(cert1)));

        result = tm.findCertificateBySubject("CN=testas", CertTools.getIssuerDN(cert1));
        assertTrue(result.size() == 0);
        result = tm.findCertificateBySubject(CertTools.getSubjectDN(cert1), "CN=testas");
        assertTrue(result.size() == 0);

        c = tm.findCertificateByFingerprint(CertTools.getFingerprintAsString(cert1));
        c.setComment("testtest");
        tb();
        tm.editCertificate(c);
        tc();
        c = tm.findCertificateByFingerprint(CertTools.getFingerprintAsString(cert1));
        assertTrue(c.getComment().equals("testtest"));
    }

    public void test03RemoveTokens() throws Exception {
        TokenDataBean t = tm.findToken(orgId, "12345", true);
        t.setCertificates(certs);
        tb();
        tm.editToken(t);
        tc();

        tb();
        um.removeUser(userId1);
        tc();

        assertNull(tm.findToken(orgId, "12345", false));
        assertNull(tm.findToken(orgId, "12346", false));

        TokenDataBean td = tm.findToken(orgId, "22345", false);
        assertNotNull(td);
        td.setCertificates(certs);
        tb();
        tm.editToken(td);
        tc();
        tb();
        tm.removeToken(td.getId());
        tc();
        assertNull(tm.findToken(1, "22345", false));

        assertNull(tm.findCertificateByFingerprint(CertTools.getFingerprintAsString(cert1)));
        assertNull(tm.findCertificateByFingerprint(CertTools.getFingerprintAsString(cert2)));

        TokenDataBean t1 = new TokenDataBean(orgId, userId2,
                jkstp.getProfileIdentifier(),
                "12345");

        tb();
        tm.editToken(t1);
        tc();

        t1 = tm.findToken(orgId, "12345", true);

        CertificateDataBean certData1 = new CertificateDataBean(cert1, t1.getId(), "cProfile1");

        tb();
        tm.editCertificate(certData1);
        tc();

        t1 = tm.findToken(orgId, "12345", true);

        assertTrue(t1.getCertificates().size() == 1);

        ArrayList<CertificateDataBean> certs2 = new ArrayList<CertificateDataBean>();
        CertificateDataBean certData2 = new CertificateDataBean(cert2, 0, "cProfile2");
        certs2.add(certData2);
        t1.setCertificates(certs2);
        tb();
        tm.editToken(t1);
        tc();

        t1 = tm.findToken(orgId, "12345", true);
        assertTrue(t1.getCertificates().size() == 2);
        CertificateDataBean res = tm.findCertificateByFingerprint(CertTools.getFingerprintAsString(cert1));
        assertNotNull(res);

        tb();
        tm.removeCertificate(res.getId());
        tc();
        assertNull(tm.findCertificateByFingerprint(CertTools.getFingerprintAsString(cert1)));
    }
}
