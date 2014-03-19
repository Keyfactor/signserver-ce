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
package org.signserver.server.signers;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.List;

import javax.persistence.EntityManager;

import junit.framework.TestCase;

import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.ProcessRequest;
import org.signserver.common.ProcessResponse;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.server.WorkerContext;
import org.signserver.server.signers.BaseSigner;

/**
 * Test cases for handling of the INCLUDE_CERTIFICATE_LEVELS
 * property in BaseSigner.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 *
 */
public class IncludeCertificateLevelsTest extends TestCase {
    private static final int DUMMY_ID = 1000;
    
    /**
     * Dummy signer initing the INCLUDE_CERTIFICATE_LEVELS property.
     */
    private static class DummySigner extends BaseSigner {
        @Override
        public ProcessResponse processData(
                ProcessRequest signRequest,
                RequestContext requestContext)
                throws IllegalRequestException,
                CryptoTokenOfflineException, SignServerException {
            return null;
        }

        @Override
        public void init(int workerId, WorkerConfig config,
                WorkerContext workerContext, EntityManager workerEM) {
            super.init(workerId, config, workerContext, workerEM);
            initIncludeCertificateLevels();
        }
    };
    
    /**
     * Dummy implementation of Certificate just keeping track of the certificate's
     * index in a list.
     */
    private static class DummyCert extends Certificate {

        private int index;

        /**
         * Constructs a dummy certificate with an index.
         * 
         * @param index Index to be used in the certificate list
         */
        public DummyCert(final int index) {
            super("X.509");
            this.index = index;
        }
        
        @Override
        public byte[] getEncoded() throws CertificateEncodingException {
            return null;
        }

        @Override
        public PublicKey getPublicKey() {
            return null;
        }

        @Override
        public String toString() {
            return null;
        }

        @Override
        public void verify(PublicKey key) throws CertificateException,
                NoSuchAlgorithmException, InvalidKeyException,
                NoSuchProviderException, SignatureException {
        }

        @Override
        public void verify(PublicKey key, String sigProvider)
                throws CertificateException, NoSuchAlgorithmException,
                InvalidKeyException, NoSuchProviderException,
                SignatureException {
        }
        
        public int getIndex() {
            return index;
        }
        
    }
    
    private DummySigner dummySigner = new DummySigner();
    
    /**
     * Test the INCLUDE_CERTIFICATE_LEVELS property with a valid value.
     * 
     * @throws Exception
     */
    public void test01InitWithValidLevels() throws Exception {
        final WorkerConfig config = new WorkerConfig();
        
        config.setProperty(WorkerConfig.PROPERTY_INCLUDE_CERTIFICATE_LEVELS, "2");
        dummySigner.init(DUMMY_ID, config, null, null);
                
        // a dummy list (content is not important)
        final List<Certificate> certs = Arrays.asList((Certificate) new DummyCert(0), new DummyCert(1), new DummyCert(2));
        final List<Certificate> includedCerts = dummySigner.includedCertificates(certs);
        assertEquals("Number of included certificates", 2, includedCerts.size());
        assertEquals("Certificate index", 0, ((DummyCert) includedCerts.get(0)).getIndex());
        assertEquals("Certificate index", 1, ((DummyCert) includedCerts.get(1)).getIndex());
    }
    
    /**
     * Test with a list shorter than the (maximum) to-be-included certs.
     *
     * @throws Exception
     */
    public void test02InitWithValidLevelsAdditionalCerts() throws Exception {
        final WorkerConfig config = new WorkerConfig();
        
        config.setProperty(WorkerConfig.PROPERTY_INCLUDE_CERTIFICATE_LEVELS, "2");
        dummySigner.init(DUMMY_ID, config, null, null);
                
        // a dummy list (content is not important)
        final List<Certificate> certs = Arrays.asList((Certificate) new DummyCert(0));
        final List<Certificate> includedCerts = dummySigner.includedCertificates(certs);
        assertEquals("Number of included certificates", 1, includedCerts.size());
        assertEquals("Certificate index", 0, ((DummyCert) includedCerts.get(0)).getIndex());
    }
    
    /**
     * Test that the default is one included certificate.
     * 
     * @throws Exception
     */
    public void test03DefaultValue() throws Exception {
        final WorkerConfig config = new WorkerConfig();
        
        dummySigner.init(DUMMY_ID, config, null, null);
                
        // a dummy list (content is not important)
        final List<Certificate> certs = Arrays.asList((Certificate) new DummyCert(0), new DummyCert(1), new DummyCert(2));
        final List<Certificate> includedCerts = dummySigner.includedCertificates(certs);
        assertEquals("Number of included certificates", 1, includedCerts.size());
        assertEquals("Certificate index", 0, ((DummyCert) includedCerts.get(0)).getIndex());
    }
    
}
