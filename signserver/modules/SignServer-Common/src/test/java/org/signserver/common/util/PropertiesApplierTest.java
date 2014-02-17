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
package org.signserver.common.util;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.signserver.common.AuthorizedClient;
import org.signserver.common.util.PropertiesApplier;
import org.signserver.common.util.PropertiesConstants;
import org.signserver.common.util.PropertiesParser.GlobalProperty;
import org.signserver.common.util.PropertiesParser.WorkerProperty;

import junit.framework.TestCase;

/**
 * Tests for the property applier used for loading configuration property files.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 *
 */
public class PropertiesApplierTest extends TestCase {

    private static class MockPropertiesApplier extends PropertiesApplier {

        private Map<GlobalProperty, String> globalProperties = new HashMap<GlobalProperty, String>();
        private Map<WorkerProperty, String> workerProperties = new HashMap<WorkerProperty, String>();
        
        public static int FIRST_GENERATED_ID = 1000;
        
        public String getWorkerProperty(final int workerId, final String key) {
            return workerProperties.get(new WorkerProperty(Integer.toString(workerId), key));
        }
        
        public String getGlobalProperty(final String scope, final String key) {
            return globalProperties.get(new GlobalProperty(scope, key));
        }
        
        @Override
        protected void setGlobalProperty(String scope, String key, String value) {
            globalProperties.put(new GlobalProperty(scope, key), value);
        }

        @Override
        protected void removeGlobalProperty(String scope, String key) {
            globalProperties.remove(new GlobalProperty(scope, key));
        }

        @Override
        protected void setWorkerProperty(int workerId, String key, String value) {
            workerProperties.put(new WorkerProperty(Integer.toString(workerId), key), value);
        }

        @Override
        protected void removeWorkerProperty(int workerId, String key) {
            workerProperties.remove(new WorkerProperty(Integer.toString(workerId), key));
        }

        @Override
        protected void uploadSignerCertificate(int workerId, byte[] signerCert) {
            // TODO Auto-generated method stub
            
        }

        @Override
        protected void uploadSignerCertificateChain(int workerId,
                List<byte[]> signerCertChain) {
            // TODO Auto-generated method stub
            
        }

        @Override
        protected void addAuthorizedClient(int workerId, AuthorizedClient ac) {
            // TODO Auto-generated method stub
            
        }

        @Override
        protected void removeAuthorizedClient(int workerId, AuthorizedClient ac) {
            // TODO Auto-generated method stub
            
        }

        @Override
        protected int genFreeWorkerId() throws PropertiesApplierException {
            return FIRST_GENERATED_ID;
        }

        @Override
        protected int getWorkerId(String workerName)
                throws PropertiesApplierException {
            for (final WorkerProperty prop : workerProperties.keySet()) {
                if (PropertiesConstants.NAME.equals(prop.getKey())) {
                    final String value = workerProperties.get(prop);
                    
                    if (workerName.equals(value)) {
                        return Integer.valueOf(prop.getWorkerIdOrName());
                    }
                }
            }
            
            throw new PropertiesApplierException("No such worker: " + workerName);
        }
        
    }
    
}
