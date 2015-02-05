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
package org.signserver.module.xmlvalidator;

import java.math.BigInteger;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import org.signserver.common.ArchiveDataVO;
import org.signserver.common.ArchiveMetadata;
import org.signserver.common.AuthorizedClient;
import org.signserver.common.CryptoTokenAuthenticationFailureException;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.ICertReqData;
import org.signserver.common.ISignerCertReqInfo;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.KeyTestResult;
import org.signserver.common.OperationUnsupportedException;
import org.signserver.common.ProcessRequest;
import org.signserver.common.ProcessResponse;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerStatus;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.validationservice.common.ValidateRequest;
import org.signserver.validationservice.common.ValidateResponse;
import org.signserver.validationservice.common.Validation;
import org.signserver.validationservice.common.ValidationServiceConstants;

/**
 * Mocked version of WorkerSession only implementing the process method
 * and using a CertValidator.
 *
 * @author Markus Kilås
 * @version $Id: MockedXAdESSigner.java 4704 2014-05-16 12:38:10Z netmackan $
 */
public class MockedWorkerSession implements IWorkerSession {

    @Override
    public ProcessResponse process(int workerId, ProcessRequest request, RequestContext requestContext) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException {
        ValidateRequest vr = (ValidateRequest) request;
        String[] validPurposes = new String[] { ValidationServiceConstants.CERTPURPOSE_ELECTRONIC_SIGNATURE };

        Certificate icert = vr.getCertificate();
        List<Certificate> chain = Arrays.asList(icert);

        return new ValidateResponse(new Validation(icert, chain, Validation.Status.VALID, "Certificate is valid"), validPurposes);
    }

    @Override
    public WorkerStatus getStatus(int workerId) throws InvalidWorkerIdException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public int getWorkerId(String workerName) {
        return 1236; // Any worker id
    }

    @Override
    public void reloadConfiguration(int workerId) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public void activateSigner(int signerId, String authenticationCode) throws CryptoTokenAuthenticationFailureException, CryptoTokenOfflineException, InvalidWorkerIdException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public boolean deactivateSigner(int signerId) throws CryptoTokenOfflineException, InvalidWorkerIdException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public WorkerConfig getCurrentWorkerConfig(int signerId) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public void setWorkerProperty(int workerId, String key, String value) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public boolean removeWorkerProperty(int workerId, String key) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public Collection<AuthorizedClient> getAuthorizedClients(int signerId) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public void addAuthorizedClient(int signerId, AuthorizedClient authClient) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public boolean removeAuthorizedClient(int signerId, AuthorizedClient authClient) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public ICertReqData getCertificateRequest(int signerId, ISignerCertReqInfo certReqInfo, boolean explicitEccParameters) throws CryptoTokenOfflineException, InvalidWorkerIdException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public ICertReqData getCertificateRequest(int signerId, ISignerCertReqInfo certReqInfo, boolean explicitEccParameters, boolean defaultKey) throws CryptoTokenOfflineException, InvalidWorkerIdException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public ICertReqData getCertificateRequest(int signerId, ISignerCertReqInfo certReqInfo, boolean explicitEccParameters, String keyAlias) throws CryptoTokenOfflineException, InvalidWorkerIdException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public Certificate getSignerCertificate(int signerId) throws CryptoTokenOfflineException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public byte[] getSignerCertificateBytes(int signerId) throws CryptoTokenOfflineException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public List<Certificate> getSignerCertificateChain(int signerId) throws CryptoTokenOfflineException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public List<byte[]> getSignerCertificateChainBytes(int signerId) throws CryptoTokenOfflineException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public Date getSigningValidityNotAfter(int workerId) throws CryptoTokenOfflineException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public Date getSigningValidityNotBefore(int workerId) throws CryptoTokenOfflineException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public long getKeyUsageCounterValue(int workerId) throws CryptoTokenOfflineException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public boolean removeKey(int signerId, String alias) throws CryptoTokenOfflineException, InvalidWorkerIdException, KeyStoreException, SignServerException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public String generateSignerKey(int signerId, String keyAlgorithm, String keySpec, String alias, char[] authCode) throws CryptoTokenOfflineException, InvalidWorkerIdException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public Collection<KeyTestResult> testKey(int signerId, String alias, char[] authCode) throws CryptoTokenOfflineException, InvalidWorkerIdException, KeyStoreException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public void uploadSignerCertificate(int signerId, byte[] signerCert, String scope) throws CertificateException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public void uploadSignerCertificateChain(int signerId, Collection<byte[]> signerCerts, String scope) throws CertificateException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public int genFreeWorkerId() {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public List<ArchiveDataVO> findArchiveDataFromArchiveId(int signerId, String archiveId) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public List<ArchiveDataVO> findArchiveDatasFromRequestIP(int signerId, String requestIP) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public List<ArchiveDataVO> findArchiveDatasFromRequestCertificate(int signerId, BigInteger serialNumber, String issuerDN) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public List<ArchiveMetadata> searchArchive(int startIndex, int max, org.cesecore.util.query.QueryCriteria criteria, boolean includeData) throws org.cesecore.authorization.AuthorizationDeniedException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public List<ArchiveMetadata> searchArchiveWithIds(List<String> uniqueIds, boolean includeData) throws org.cesecore.authorization.AuthorizationDeniedException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public List<Integer> getWorkers(int workerType) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public void importCertificateChain(int signerId, List<byte[]> signerCerts, String alias, char[] athenticationCode) throws CryptoTokenOfflineException, CertificateException, OperationUnsupportedException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public List<Certificate> getSignerCertificateChain(int signerId, String alias) throws CryptoTokenOfflineException {
        throw new UnsupportedOperationException("Not supported yet.");
    }
    
    
}
