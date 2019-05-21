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
package org.signserver.module.openpgp.signer;

import static junit.framework.TestCase.assertTrue;
import org.apache.log4j.Logger;
import org.junit.Test;
import org.signserver.common.AbstractCertReqData;
import org.signserver.common.PKCS10CertReqInfo;
import org.signserver.common.WorkerIdentifier;
import org.signserver.common.WorkerStatus;
import org.signserver.testutils.ModulesTestCase;

/**
 * System tests for the OpenPGPSigner.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public class OpenPGPSignerTest {
    /** Logger for this class */
    private static final Logger LOG = Logger.getLogger(OpenPGPSignerGpgComplianceTest.class);

    private final ModulesTestCase helper = new ModulesTestCase();
    
    /**
     * Test that generating a certification works both when generating
     * for DEFAULTKEY and for another key, with an existing certificate
     * set in PGPPUBLICKEY, installing the new public certificate and and
     * setting PGPPUBLICKEY to the new certificate and updating DEFAULTKEY.
     * The worker should be active in both cases.
     * 
     * @throws Exception 
     */
    @Test
    public void testGeneratePublicKeyForNoDefaultKey() throws Exception {
        final int workerId = 42;
        final String workerName = "OpenPGPSigner-gen-non-default";
        try {
            final WorkerIdentifier wi = new WorkerIdentifier(workerId);
            helper.addSigner("org.signserver.module.openpgp.signer.OpenPGPSigner",
                             workerId, workerName, true);
            helper.getWorkerSession().setWorkerProperty(workerId, "DEFAULTKEY",
                                                        "signer00001");
            helper.getWorkerSession().setWorkerProperty(workerId,
                                                        "DETACHEDSIGNATURE",
                                                        "true");
            helper.getWorkerSession().reloadConfiguration(workerId);

            PKCS10CertReqInfo certReqInfo =
                    new PKCS10CertReqInfo("SHA256withRSA", "User1", null);
            AbstractCertReqData requestData = (AbstractCertReqData)
                    helper.getWorkerSession().getCertificateRequest(wi,
                                                                    certReqInfo,
                                                                    false);
            
            String pgpPublicKey = requestData.toArmoredForm();
            helper.getWorkerSession().setWorkerProperty(workerId, "PGPPUBLICKEY",
                                                        pgpPublicKey);
            helper.getWorkerSession().reloadConfiguration(workerId);
            
            WorkerStatus status = helper.getWorkerSession().getStatus(wi);
            assertTrue("Worker active: " + status.getFatalErrors().toString(),
                       status.getFatalErrors().isEmpty());
            
            // generate certification for another key
            certReqInfo = new PKCS10CertReqInfo("SHA256withRSA", "User2", null);
            requestData = (AbstractCertReqData)
                    helper.getWorkerSession().getCertificateRequest(wi,
                                                                    certReqInfo,
                                                                    false,
                                                                    "signer00003");
            pgpPublicKey = requestData.toArmoredForm();
            helper.getWorkerSession().setWorkerProperty(workerId, "PGPPUBLICKEY",
                                                        pgpPublicKey);
            helper.getWorkerSession().setWorkerProperty(workerId, "DEFAULTKEY",
                                                        "signer00003");
            helper.getWorkerSession().reloadConfiguration(workerId);

            status = helper.getWorkerSession().getStatus(wi);
            assertTrue("Worker active: " + status.getFatalErrors().toString(),
                       status.getFatalErrors().isEmpty());
        } finally {
            helper.removeWorker(workerId);
        }
    }
}
