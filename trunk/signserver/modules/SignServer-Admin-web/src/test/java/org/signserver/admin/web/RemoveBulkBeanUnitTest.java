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
package org.signserver.admin.web;

import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;
import org.apache.log4j.Logger;
import org.junit.Test;
import static org.junit.Assert.*;
import org.signserver.admin.common.auth.AdminNotAuthorizedException;
import org.signserver.admin.web.ejb.AdminWebSessionBean;
import org.signserver.admin.web.ejb.NotLoggedInException;
import org.signserver.common.GlobalConfiguration;

/**
 * Unit tests for the RemoveBulkBeanTest class.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class RemoveBulkBeanUnitTest {

    private static final Logger LOG = Logger.getLogger(RemoveBulkBeanUnitTest.class);

    /**
     * Tests that the remove action calls reload after removing all properties.
     * @throws Exception in case of error
     */
    @Test
    public void testRemoveAction() throws Exception {
        LOG.info("testRemoveAction");
        // given
        Properties config = new Properties();
        config.setProperty("NAME", "MyWorker123");
        config.setProperty("PROPERTY", "Value");
        RemoveBulkBean.MyWorker worker = new RemoveBulkBean.MyWorker(123, true, "MyWorker123", config);

        MockedRemoveBulkBean instance = new MockedRemoveBulkBean();
        instance.setReloadCount(0);
        instance.setMyWorkers(Arrays.asList(worker));
        instance.setMySelectedWorkers(Arrays.asList(worker));

        // when
        instance.removeAction();

        // then
        assertEquals("reload called times", 1, instance.getReloadCount());
    }

    private static class MockedRemoveBulkBean extends RemoveBulkBean {
        private List<RemoveBulkBean.MyWorker> myWorkers;
        private List<RemoveBulkBean.MyWorker> mySelectedWorkers;
        private int reloadCount;

        @Override
        public AdminWebSessionBean getWorkerSessionBean() {
            return new AdminWebSessionBean() {

                {
                    init();
                }

                @Override
                public GlobalConfiguration getGlobalConfiguration(X509Certificate adminCertificate) throws AdminNotAuthorizedException {
                    Properties properties = new Properties();
                    return new GlobalConfiguration(properties, GlobalConfiguration.STATE_INSYNC, "1.0-beta3");
                }

                @Override
                public boolean removeWorkerProperty(X509Certificate adminCertificate, int workerId, String key) throws AdminNotAuthorizedException {
                    return true;
                }

                @Override
                public void reloadConfiguration(X509Certificate adminCertificate, Integer workerId) throws AdminNotAuthorizedException {
                    reloadCount++;
                }

            };
        }

        @Override
        public AuthenticationBean getAuthBean() {
            return new AuthenticationBean() {
                @Override
                public X509Certificate getAdminCertificate() throws NotLoggedInException {
                    return null;
                }
            };
        }

        @Override
        public List<MyWorker> getMyWorkers() throws AdminNotAuthorizedException {
            return myWorkers;
        }

        @Override
        public List<MyWorker> getMySelectedWorkers() throws AdminNotAuthorizedException {
            return mySelectedWorkers;
        }

        public void setMyWorkers(List<MyWorker> myWorkers) {
            this.myWorkers = myWorkers;
        }

        public void setMySelectedWorkers(List<MyWorker> mySelectedWorkers) {
            this.mySelectedWorkers = mySelectedWorkers;
        }

        public int getReloadCount() {
            return reloadCount;
        }

        public void setReloadCount(int reloadCount) {
            this.reloadCount = reloadCount;
        }

    }

}
