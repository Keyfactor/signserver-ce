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
package org.signserver.module.renewal.worker;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import javax.jws.WebService;
import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Base64;
import org.ejbca.core.protocol.IRequestMessage;
import org.ejbca.util.RequestMessageUtils;
import org.signserver.module.renewal
        .ejbcaws.gen.AlreadyRevokedException_Exception;
import org.signserver.module.renewal.ejbcaws.gen.ApprovalException_Exception;
import org.signserver.module.renewal
        .ejbcaws.gen.ApprovalRequestExecutionException_Exception;
import org.signserver.module.renewal
        .ejbcaws.gen.ApprovalRequestExpiredException_Exception;
import org.signserver.module.renewal.ejbcaws.gen.AuthorizationDeniedException;
import org.signserver.module.renewal
        .ejbcaws.gen.AuthorizationDeniedException_Exception;
import org.signserver.module.renewal
        .ejbcaws.gen.CADoesntExistsException_Exception;
import org.signserver.module.renewal.ejbcaws.gen.Certificate;
import org.signserver.module.renewal
        .ejbcaws.gen.CertificateExpiredException_Exception;
import org.signserver.module.renewal.ejbcaws.gen.CertificateResponse;
import org.signserver.module.renewal.ejbcaws.gen.EjbcaException;
import org.signserver.module.renewal.ejbcaws.gen.EjbcaException_Exception;
import org.signserver.module.renewal.ejbcaws.gen.ErrorCode;
import org.signserver.module.renewal.ejbcaws.gen.HardTokenDataWS;
import org.signserver.module.renewal
        .ejbcaws.gen.HardTokenDoesntExistsException_Exception;
import org.signserver.module.renewal
        .ejbcaws.gen.HardTokenExistsException_Exception;
import org.signserver.module.renewal
        .ejbcaws.gen.IllegalQueryException_Exception;
import org.signserver.module.renewal.ejbcaws.gen.KeyStore;
import org.signserver.module.renewal
        .ejbcaws.gen.MultipleMatchException_Exception;
import org.signserver.module.renewal.ejbcaws.gen.NameAndId;
import org.signserver.module.renewal.ejbcaws.gen.NotFoundException_Exception;
import org.signserver.module.renewal.ejbcaws.gen.PublisherException_Exception;
import org.signserver.module.renewal.ejbcaws.gen.RevokeStatus;
import org.signserver.module.renewal.ejbcaws.gen.SignRequestException_Exception;
import org.signserver.module.renewal.ejbcaws.gen.TokenCertificateRequestWS;
import org.signserver.module.renewal.ejbcaws.gen.TokenCertificateResponseWS;
import org.signserver.module.renewal
        .ejbcaws.gen.UserDataSourceException_Exception;
import org.signserver.module.renewal.ejbcaws.gen.UserDataSourceVOWS;
import org.signserver.module.renewal.ejbcaws.gen.UserDataVOWS;
import org.signserver.module.renewal
        .ejbcaws.gen.UserDoesntFullfillEndEntityProfile_Exception;
import org.signserver.module.renewal.ejbcaws.gen.UserMatch;
import org.signserver.module.renewal
        .ejbcaws.gen.WaitingForApprovalException_Exception;

/**
 * Mock implementation of the EJBCA Web Service.
 *
 * @author Markus Kilås
 * @version $Id$
 */
@WebService(serviceName="EjbcaWSService", portName="EjbcaWSPort", 
    targetNamespace="http://ws.protocol.core.ejbca.org/",
    endpointInterface="org.signserver.module.renewal.ejbcaws.gen.EjbcaWS")
public class MockEjbcaWS {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(MockEjbcaWS.class);

    private boolean findUserCalled;
    private boolean editUserCalled;
    private boolean pkcs10RequestCalled;
    private boolean authenticationFail;
    
    private Map<UserMatchEq,List<UserDataVOWS>> findUserResults
            = Collections.emptyMap();

    private MockCA ca
            = MockCA.createMockCA("CN=MockupRootCA,O=SignServer Testing,C=SE");

    // From CertificateHelper:
    /**
     * Indicates that the requester want a BASE64 encoded certificate in the CertificateResponse object.
     */
    //private static String RESPONSETYPE_CERTIFICATE    = "CERTIFICATE";
    /**
     * Indicates that the requester want a BASE64 encoded pkcs7 in the CertificateResponse object.
     */
    //private static String RESPONSETYPE_PKCS7          = "PKCS7";
    /**
     * Indicates that the requester want a BASE64 encoded pkcs7 with the complete chain in the CertificateResponse object.
     */
    private static String RESPONSETYPE_PKCS7WITHCHAIN = "PKCS7WITHCHAIN";
    
    public Certificate getCertificate(String arg0, String arg1) throws 
            AuthorizationDeniedException_Exception,
            CADoesntExistsException_Exception, EjbcaException_Exception {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    
    public boolean isAuthorized(String arg0) throws EjbcaException_Exception {
        System.out.println("arg0: " + arg0);
        return !authenticationFail;
    }

    
    public int isApproved(int arg0) throws ApprovalException_Exception, 
            ApprovalRequestExpiredException_Exception,
            EjbcaException_Exception {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    
    public boolean existsHardToken(String arg0)
            throws EjbcaException_Exception {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    
    public List<NameAndId> getAvailableCAs() 
            throws AuthorizationDeniedException_Exception,
            EjbcaException_Exception {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    
    public void revokeUser(String arg0, int arg1, boolean arg2) 
            throws AlreadyRevokedException_Exception,
            ApprovalException_Exception, AuthorizationDeniedException_Exception,
            CADoesntExistsException_Exception, EjbcaException_Exception,
            NotFoundException_Exception, WaitingForApprovalException_Exception {
        checkAuth();
        throw new UnsupportedOperationException("Not supported yet.");
    }

    
    public void revokeCert(String arg0, String arg1, int arg2) 
            throws AlreadyRevokedException_Exception,
            ApprovalException_Exception, AuthorizationDeniedException_Exception,
            CADoesntExistsException_Exception, EjbcaException_Exception,
            NotFoundException_Exception, WaitingForApprovalException_Exception {
        checkAuth();
        throw new UnsupportedOperationException("Not supported yet.");
    }

    
    public List<UserDataVOWS> findUser(UserMatch arg0) 
            throws AuthorizationDeniedException_Exception,
            EjbcaException_Exception, IllegalQueryException_Exception {
        checkAuth();
        List<UserDataVOWS> result = findUserResults.get(new UserMatchEq(arg0));
        return result;
    }

    
    public void createCRL(String arg0) throws ApprovalException_Exception, 
            ApprovalRequestExpiredException_Exception,
            CADoesntExistsException_Exception, EjbcaException_Exception {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public void editUser(UserDataVOWS arg0) throws ApprovalException_Exception, 
            AuthorizationDeniedException_Exception,
            CADoesntExistsException_Exception, EjbcaException_Exception,
            UserDoesntFullfillEndEntityProfile_Exception,
            WaitingForApprovalException_Exception {
        checkAuth();
        System.out.println("editUser(" + arg0 + ")");
        editUserCalled = true;
    }

    
    public List<Certificate> findCerts(String arg0, boolean arg1) 
            throws AuthorizationDeniedException_Exception,
            EjbcaException_Exception {
        checkAuth();
        throw new UnsupportedOperationException("Not supported yet.");
    }

    
    public List<Certificate> getLastCertChain(String arg0) 
            throws AuthorizationDeniedException_Exception,
            EjbcaException_Exception {
        checkAuth();
        throw new UnsupportedOperationException("Not supported yet.");
    }

    
    public CertificateResponse crmfRequest(String arg0, String arg1, 
            String arg2, String arg3, String arg4)
            throws AuthorizationDeniedException_Exception,
            CADoesntExistsException_Exception, EjbcaException_Exception,
            NotFoundException_Exception {
        checkAuth();
        throw new UnsupportedOperationException("Not supported yet.");
    }

    
    public CertificateResponse spkacRequest(String arg0, String arg1, 
            String arg2, String arg3, String arg4)
            throws AuthorizationDeniedException_Exception,
            CADoesntExistsException_Exception, EjbcaException_Exception,
            NotFoundException_Exception {
        checkAuth();
        throw new UnsupportedOperationException("Not supported yet.");
    }

    
    public List<Certificate> cvcRequest(String arg0, String arg1, String arg2)
            throws ApprovalException_Exception,
            AuthorizationDeniedException_Exception,
            CADoesntExistsException_Exception,
            CertificateExpiredException_Exception, EjbcaException_Exception,
            NotFoundException_Exception, SignRequestException_Exception,
            UserDoesntFullfillEndEntityProfile_Exception,
            WaitingForApprovalException_Exception {
        checkAuth();
        throw new UnsupportedOperationException("Not supported yet.");
    }

    
    public byte[] caRenewCertRequest(String arg0, List<byte[]> arg1,
            boolean arg2, boolean arg3, boolean arg4, String arg5)
            throws ApprovalException_Exception,
            AuthorizationDeniedException_Exception,
            CADoesntExistsException_Exception, EjbcaException_Exception,
            WaitingForApprovalException_Exception {
        checkAuth();
        throw new UnsupportedOperationException("Not supported yet.");
    }

    
    public void caCertResponse(String arg0, byte[] arg1, List<byte[]> arg2, 
            String arg3) throws ApprovalException_Exception,
            AuthorizationDeniedException_Exception,
            CADoesntExistsException_Exception, EjbcaException_Exception,
            WaitingForApprovalException_Exception {
        checkAuth();
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public CertificateResponse pkcs10Request(String username, String password, 
            String pkcs10, String hardTokenSN, String responseType)
            throws AuthorizationDeniedException_Exception,
            CADoesntExistsException_Exception, EjbcaException_Exception,
            NotFoundException_Exception {
        checkAuth();
        System.out.println(">certificateRequest");
        pkcs10RequestCalled = true;
        final CertificateResponse result = new CertificateResponse();
        LOG.debug("PKCS10 from user '"+username+"'.");
	result.setResponseType(responseType);
        result.setData(Base64.encode(processCertReq(username, password, pkcs10,
                0, hardTokenSN, responseType)));
        return result;
    }

    private byte[] processCertReq(String username, String password, String req, 
            int reqType, String hardTokenSN, String responseType)
            throws EjbcaException_Exception,
            AuthorizationDeniedException_Exception {
        try {
            byte[] retval = null;
            
            UserDataVOWS userdata = findUser(username);
            if (userdata == null) {
                EjbcaException ex = new EjbcaException();
                ErrorCode code = new ErrorCode();
                //            code.setInternalErrorCode(todo)
                ex.setErrorCode(code);
                throw new EjbcaException_Exception("User not found: "
                        + username, ex);
            }
            //String caName = userdata.getCaName();
            IRequestMessage pkcs10req
                    = RequestMessageUtils.genPKCS10RequestMessage(
                        req.getBytes());
            PublicKey pubKey = pkcs10req.getRequestPublicKey();
            //IRequestMessage imsg = new SimpleRequestMessage(pubKey, username,
            //        password);

            X509Certificate cert = ca.issueCertificate(userdata.getSubjectDN(),
                    5, "SHA1withRSA", pubKey);
            if (RESPONSETYPE_PKCS7WITHCHAIN.equals(responseType)) {
                retval = ca.createPKCS7(cert, true);
            } else {
                retval = cert.getEncoded();
                throw new UnsupportedOperationException("Not supported yet");
            }

            // Set to generated
            userdata.setStatus(40);
            
            return retval;
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }    

    private UserDataVOWS findUser(final String username) 
            throws AuthorizationDeniedException_Exception,
            EjbcaException_Exception {
        try {
            final UserMatchEq match1 = new UserMatchEq();
            match1.setMatchwith(RenewalWorkerTest.MATCH_WITH_USERNAME);
            match1.setMatchtype(RenewalWorkerTest.MATCH_TYPE_EQUALS);
            match1.setMatchvalue(username);
            List<UserDataVOWS> users = findUser(match1);
            if (users.size() < 1) {
                return null;
            } else {
                return users.get(0);
            }
        } catch (IllegalQueryException_Exception ex) {
            throw new RuntimeException(ex);
        }
    }
    
    public KeyStore pkcs12Req(String arg0, String arg1, String arg2, 
            String arg3, String arg4)
            throws AuthorizationDeniedException_Exception,
            CADoesntExistsException_Exception, EjbcaException_Exception,
            NotFoundException_Exception {
        checkAuth();
        throw new UnsupportedOperationException("Not supported yet.");
    }
    
    public void keyRecoverNewest(String arg0) throws ApprovalException_Exception,
            AuthorizationDeniedException_Exception,
            CADoesntExistsException_Exception, EjbcaException_Exception,
            NotFoundException_Exception, WaitingForApprovalException_Exception {
        checkAuth();
        throw new UnsupportedOperationException("Not supported yet.");
    }
    
    public void revokeToken(String arg0, int arg1) throws 
            AlreadyRevokedException_Exception, ApprovalException_Exception,
            AuthorizationDeniedException_Exception,
            CADoesntExistsException_Exception, EjbcaException_Exception,
            NotFoundException_Exception, WaitingForApprovalException_Exception {
        checkAuth();
        throw new UnsupportedOperationException("Not supported yet.");
    }
    
    public RevokeStatus checkRevokationStatus(String arg0, String arg1) throws 
            AuthorizationDeniedException_Exception,
            CADoesntExistsException_Exception, EjbcaException_Exception {
        checkAuth();
        throw new UnsupportedOperationException("Not supported yet.");
    }
    
    public List<UserDataSourceVOWS> fetchUserData(List<String> arg0, 
            String arg1) throws AuthorizationDeniedException_Exception,
            EjbcaException_Exception, UserDataSourceException_Exception {
        checkAuth();
        throw new UnsupportedOperationException("Not supported yet.");
    }
    
    public List<TokenCertificateResponseWS> genTokenCertificates(
            UserDataVOWS arg0, List<TokenCertificateRequestWS> arg1,
            HardTokenDataWS arg2, boolean arg3, boolean arg4) throws
            ApprovalException_Exception,
            ApprovalRequestExecutionException_Exception,
            ApprovalRequestExpiredException_Exception,
            AuthorizationDeniedException_Exception,
            CADoesntExistsException_Exception, EjbcaException_Exception,
            HardTokenExistsException_Exception,
            UserDoesntFullfillEndEntityProfile_Exception,
            WaitingForApprovalException_Exception {
        checkAuth();
        throw new UnsupportedOperationException("Not supported yet.");
    }
    
    public HardTokenDataWS getHardTokenData(String arg0, boolean arg1, 
            boolean arg2) throws ApprovalRequestExecutionException_Exception,
            ApprovalRequestExpiredException_Exception,
            AuthorizationDeniedException_Exception,
            CADoesntExistsException_Exception, EjbcaException_Exception,
            HardTokenDoesntExistsException_Exception,
            NotFoundException_Exception, WaitingForApprovalException_Exception {
        checkAuth();
        throw new UnsupportedOperationException("Not supported yet.");
    }
    
    public List<HardTokenDataWS> getHardTokenDatas(String arg0, boolean arg1, 
            boolean arg2) throws AuthorizationDeniedException_Exception,
            CADoesntExistsException_Exception, EjbcaException_Exception {
        checkAuth();
        throw new UnsupportedOperationException("Not supported yet.");
    }
    
    public void republishCertificate(String arg0, String arg1) throws
            AuthorizationDeniedException_Exception,
            CADoesntExistsException_Exception, EjbcaException_Exception,
            PublisherException_Exception {
        checkAuth();
        throw new UnsupportedOperationException("Not supported yet.");
    }
    
    public void customLog(int arg0, String arg1, String arg2, String arg3,
            Certificate arg4, String arg5) throws
            AuthorizationDeniedException_Exception,
            CADoesntExistsException_Exception, EjbcaException_Exception {
        checkAuth();
        throw new UnsupportedOperationException("Not supported yet.");
    }
    
    public boolean deleteUserDataFromSource(List<String> arg0, String arg1,
            boolean arg2) throws AuthorizationDeniedException_Exception,
            EjbcaException_Exception, MultipleMatchException_Exception,
            UserDataSourceException_Exception {
        checkAuth();
        throw new UnsupportedOperationException("Not supported yet.");
    }
    
    public List<NameAndId> getAuthorizedEndEntityProfiles() throws
            AuthorizationDeniedException_Exception, EjbcaException_Exception {
        checkAuth();
        throw new UnsupportedOperationException("Not supported yet.");
    }
    
    public List<NameAndId> getAvailableCertificateProfiles(int arg0) throws
            AuthorizationDeniedException_Exception, EjbcaException_Exception {
        checkAuth();
        throw new UnsupportedOperationException("Not supported yet.");
    }
    
    public List<NameAndId> getAvailableCAsInProfile(int arg0) throws
            AuthorizationDeniedException_Exception, EjbcaException_Exception {
        checkAuth();
        throw new UnsupportedOperationException("Not supported yet.");
    }
    
    public String getEjbcaVersion() {
        throw new UnsupportedOperationException("Not supported yet.");
    }
    
    public int getPublisherQueueLength(String arg0) throws
            EjbcaException_Exception {
        throw new UnsupportedOperationException("Not supported yet.");
    }
    
    public CertificateResponse certificateRequest(UserDataVOWS arg0, 
            String arg1, int arg2, String arg3, String arg4) throws
            ApprovalException_Exception, AuthorizationDeniedException_Exception,
            CADoesntExistsException_Exception, EjbcaException_Exception,
            NotFoundException_Exception,
            UserDoesntFullfillEndEntityProfile_Exception,
            WaitingForApprovalException_Exception {
        checkAuth();
        throw new UnsupportedOperationException("Not supported yet.");
    }
    
    public KeyStore softTokenRequest(UserDataVOWS arg0, String arg1, 
            String arg2, String arg3) throws ApprovalException_Exception,
            AuthorizationDeniedException_Exception,
            CADoesntExistsException_Exception, EjbcaException_Exception,
            NotFoundException_Exception,
            UserDoesntFullfillEndEntityProfile_Exception,
            WaitingForApprovalException_Exception {
        checkAuth();
        throw new UnsupportedOperationException("Not supported yet.");
    }

    //////////////////////////////////////////////////////////////////////////
    // Methods for controlling the mockup

    private void resetCalls() {
        editUserCalled = false;
        pkcs10RequestCalled = false;
    }

    public boolean isFindUserCalled() {
        return findUserCalled;
    }

    public boolean isPkcs10RequestCalled() {
        return pkcs10RequestCalled;
    }

    public boolean isEditUserCalled() {
        return editUserCalled;
    }

    public void setFindUserResults(Map<UserMatchEq,
            List<UserDataVOWS>> findUserResults) {
        this.findUserResults = findUserResults;
    }

    public void setAuthenticationFail(final boolean authenticationFail) {
        this.authenticationFail = authenticationFail;
    }

    private void checkAuth() throws AuthorizationDeniedException_Exception {
        if (authenticationFail) {
            AuthorizationDeniedException fault = new AuthorizationDeniedException();
            fault.setMessage("Administrator not authorized to resource");
            throw new AuthorizationDeniedException_Exception(
                    "Administrator not authorized to resource", fault);
        }
    }

}
