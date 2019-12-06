/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.onetime.common;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.List;
import javax.jws.WebService;
import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Base64;
import org.cesecore.certificates.certificate.request.PKCS10RequestMessage;
import org.cesecore.certificates.certificate.request.RequestMessageUtils;
import org.signserver.module.renewal.ejbcaws.gen.AlreadyRevokedException_Exception;
import org.signserver.module.renewal.ejbcaws.gen.ApprovalException_Exception;
import org.signserver.module.renewal.ejbcaws.gen.ApprovalRequestExecutionException_Exception;
import org.signserver.module.renewal.ejbcaws.gen.ApprovalRequestExpiredException_Exception;
import org.signserver.module.renewal.ejbcaws.gen.AuthorizationDeniedException_Exception;
import org.signserver.module.renewal.ejbcaws.gen.CADoesntExistsException_Exception;
import org.signserver.module.renewal.ejbcaws.gen.Certificate;
import org.signserver.module.renewal.ejbcaws.gen.CertificateExpiredException_Exception;
import org.signserver.module.renewal.ejbcaws.gen.CertificateResponse;
import org.signserver.module.renewal.ejbcaws.gen.EjbcaException_Exception;
import org.signserver.module.renewal.ejbcaws.gen.HardTokenDataWS;
import org.signserver.module.renewal.ejbcaws.gen.HardTokenDoesntExistsException_Exception;
import org.signserver.module.renewal.ejbcaws.gen.HardTokenExistsException_Exception;
import org.signserver.module.renewal.ejbcaws.gen.IllegalQueryException_Exception;
import org.signserver.module.renewal.ejbcaws.gen.KeyStore;
import org.signserver.module.renewal.ejbcaws.gen.MultipleMatchException_Exception;
import org.signserver.module.renewal.ejbcaws.gen.NameAndId;
import org.signserver.module.renewal.ejbcaws.gen.NotFoundException_Exception;
import org.signserver.module.renewal.ejbcaws.gen.PublisherException_Exception;
import org.signserver.module.renewal.ejbcaws.gen.RevokeStatus;
import org.signserver.module.renewal.ejbcaws.gen.SignRequestException_Exception;
import org.signserver.module.renewal.ejbcaws.gen.TokenCertificateRequestWS;
import org.signserver.module.renewal.ejbcaws.gen.TokenCertificateResponseWS;
import org.signserver.module.renewal.ejbcaws.gen.UserDataSourceException_Exception;
import org.signserver.module.renewal.ejbcaws.gen.UserDataSourceVOWS;
import org.signserver.module.renewal.ejbcaws.gen.UserDataVOWS;
import org.signserver.module.renewal.ejbcaws.gen.UserDoesntFullfillEndEntityProfile_Exception;
import org.signserver.module.renewal.ejbcaws.gen.UserMatch;
import org.signserver.module.renewal.ejbcaws.gen.WaitingForApprovalException_Exception;

/**
 * Mock implementation of the EJBCA Web Service.
 *
 * @author Vinay Singh
 * @version $Id$
 */
@WebService(serviceName = "EjbcaWSService", portName = "EjbcaWSPort",
        targetNamespace = "http://ws.protocol.core.ejbca.org/",
        endpointInterface = "org.signserver.module.renewal.ejbcaws.gen.EjbcaWS")
public class MockEjbcaWS {

    /**
     * Logger for this class.
     */
    private static final Logger LOG = Logger.getLogger(MockEjbcaWS.class);

    private boolean pkcs10RequestCalled;

    private MockCA ca
            = MockCA.createMockCA("CN=MockupRootCA,O=SignServer Testing,C=SE");

    private PKCS10RequestMessage pkcs10req;

    /**
     * Indicates that the requester want a BASE64 encoded pkcs7 with the
     * complete chain in the CertificateResponse object.
     */
    private static final String RESPONSETYPE_PKCS7WITHCHAIN = "PKCS7WITHCHAIN";

    public CertificateResponse pkcs10Request(String username, String password,
            String pkcs10, String hardTokenSN, String responseType)
            throws AuthorizationDeniedException_Exception,
            CADoesntExistsException_Exception, EjbcaException_Exception,
            NotFoundException_Exception {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    private byte[] processCertReq(UserDataVOWS userdata, String req, //NOPMD
            int reqType, String hardTokenSN, String responseType) //NOPMD
    {
        try {

            final byte[] retval;

            pkcs10req = RequestMessageUtils.genPKCS10RequestMessage(req.getBytes());
            PublicKey pubKey = pkcs10req.getRequestPublicKey();

            X509Certificate cert = ca.issueCertificate(userdata.getSubjectDN(),
                    5, "SHA1withRSA", pubKey);
            if (RESPONSETYPE_PKCS7WITHCHAIN.equals(responseType)) {
                retval = ca.createPKCS7(cert, true);
            } else {
                //retval = cert.getEncoded();
                throw new UnsupportedOperationException("Not supported yet");
            }

            return retval;
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    public Certificate getCertificate(String arg0, String arg1) throws
            AuthorizationDeniedException_Exception,
            CADoesntExistsException_Exception, EjbcaException_Exception {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public boolean isAuthorized(String arg0) throws EjbcaException_Exception {
        System.out.println("arg0: " + arg0);
        throw new UnsupportedOperationException("Not supported yet.");
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
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public void revokeCert(String arg0, String arg1, int arg2)
            throws AlreadyRevokedException_Exception,
            ApprovalException_Exception, AuthorizationDeniedException_Exception,
            CADoesntExistsException_Exception, EjbcaException_Exception,
            NotFoundException_Exception, WaitingForApprovalException_Exception {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public List<UserDataVOWS> findUser(UserMatch arg0)
            throws AuthorizationDeniedException_Exception,
            EjbcaException_Exception, IllegalQueryException_Exception {
        throw new UnsupportedOperationException("Not supported yet.");
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
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public List<Certificate> findCerts(String arg0, boolean arg1)
            throws AuthorizationDeniedException_Exception,
            EjbcaException_Exception {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public List<Certificate> getLastCertChain(String arg0)
            throws AuthorizationDeniedException_Exception,
            EjbcaException_Exception {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public CertificateResponse crmfRequest(String arg0, String arg1,
            String arg2, String arg3, String arg4)
            throws AuthorizationDeniedException_Exception,
            CADoesntExistsException_Exception, EjbcaException_Exception,
            NotFoundException_Exception {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public CertificateResponse spkacRequest(String arg0, String arg1,
            String arg2, String arg3, String arg4)
            throws AuthorizationDeniedException_Exception,
            CADoesntExistsException_Exception, EjbcaException_Exception,
            NotFoundException_Exception {
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
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public byte[] caRenewCertRequest(String arg0, List<byte[]> arg1,
            boolean arg2, boolean arg3, boolean arg4, String arg5)
            throws ApprovalException_Exception,
            AuthorizationDeniedException_Exception,
            CADoesntExistsException_Exception, EjbcaException_Exception,
            WaitingForApprovalException_Exception {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public void caCertResponse(String arg0, byte[] arg1, List<byte[]> arg2,
            String arg3) throws ApprovalException_Exception,
            AuthorizationDeniedException_Exception,
            CADoesntExistsException_Exception, EjbcaException_Exception,
            WaitingForApprovalException_Exception {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public KeyStore pkcs12Req(String arg0, String arg1, String arg2,
            String arg3, String arg4)
            throws AuthorizationDeniedException_Exception,
            CADoesntExistsException_Exception, EjbcaException_Exception,
            NotFoundException_Exception {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public void keyRecoverNewest(String arg0) throws ApprovalException_Exception,
            AuthorizationDeniedException_Exception,
            CADoesntExistsException_Exception, EjbcaException_Exception,
            NotFoundException_Exception, WaitingForApprovalException_Exception {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public void revokeToken(String arg0, int arg1) throws
            AlreadyRevokedException_Exception, ApprovalException_Exception,
            AuthorizationDeniedException_Exception,
            CADoesntExistsException_Exception, EjbcaException_Exception,
            NotFoundException_Exception, WaitingForApprovalException_Exception {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public RevokeStatus checkRevokationStatus(String arg0, String arg1) throws
            AuthorizationDeniedException_Exception,
            CADoesntExistsException_Exception, EjbcaException_Exception {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public List<UserDataSourceVOWS> fetchUserData(List<String> arg0,
            String arg1) throws AuthorizationDeniedException_Exception,
            EjbcaException_Exception, UserDataSourceException_Exception {
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
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public HardTokenDataWS getHardTokenData(String arg0, boolean arg1,
            boolean arg2) throws ApprovalRequestExecutionException_Exception,
            ApprovalRequestExpiredException_Exception,
            AuthorizationDeniedException_Exception,
            CADoesntExistsException_Exception, EjbcaException_Exception,
            HardTokenDoesntExistsException_Exception,
            NotFoundException_Exception, WaitingForApprovalException_Exception {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public List<HardTokenDataWS> getHardTokenDatas(String arg0, boolean arg1,
            boolean arg2) throws AuthorizationDeniedException_Exception,
            CADoesntExistsException_Exception, EjbcaException_Exception {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public void republishCertificate(String arg0, String arg1) throws
            AuthorizationDeniedException_Exception,
            CADoesntExistsException_Exception, EjbcaException_Exception,
            PublisherException_Exception {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public void customLog(int arg0, String arg1, String arg2, String arg3,
            Certificate arg4, String arg5) throws
            AuthorizationDeniedException_Exception,
            CADoesntExistsException_Exception, EjbcaException_Exception {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public boolean deleteUserDataFromSource(List<String> arg0, String arg1,
            boolean arg2) throws AuthorizationDeniedException_Exception,
            EjbcaException_Exception, MultipleMatchException_Exception,
            UserDataSourceException_Exception {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public List<NameAndId> getAuthorizedEndEntityProfiles() throws
            AuthorizationDeniedException_Exception, EjbcaException_Exception {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public List<NameAndId> getAvailableCertificateProfiles(int arg0) throws
            AuthorizationDeniedException_Exception, EjbcaException_Exception {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public List<NameAndId> getAvailableCAsInProfile(int arg0) throws
            AuthorizationDeniedException_Exception, EjbcaException_Exception {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public String getEjbcaVersion() {
        return "dummyEJBCAVersion";
    }

    public int getPublisherQueueLength(String arg0) throws
            EjbcaException_Exception {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public CertificateResponse certificateRequest(UserDataVOWS userdata,
            String pkcs10, int var, String hardTokenSN, String responseType) throws
            ApprovalException_Exception, AuthorizationDeniedException_Exception,
            CADoesntExistsException_Exception, EjbcaException_Exception,
            NotFoundException_Exception,
            UserDoesntFullfillEndEntityProfile_Exception,
            WaitingForApprovalException_Exception {
        LOG.info(">certificateRequest");
        pkcs10RequestCalled = true;
        final CertificateResponse result = new CertificateResponse();
        LOG.debug("PKCS10 from user '" + userdata + "'.");
        result.setResponseType(responseType);
        result.setData(Base64.encode(processCertReq(userdata, pkcs10,
                0, hardTokenSN, responseType)));
        return result;
    }

    public KeyStore softTokenRequest(UserDataVOWS arg0, String arg1,
            String arg2, String arg3) throws ApprovalException_Exception,
            AuthorizationDeniedException_Exception,
            CADoesntExistsException_Exception, EjbcaException_Exception,
            NotFoundException_Exception,
            UserDoesntFullfillEndEntityProfile_Exception,
            WaitingForApprovalException_Exception {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public boolean isPkcs10RequestCalled() {
        return pkcs10RequestCalled;
    }

    public PKCS10RequestMessage getLastPKCS10() {
        return pkcs10req;
    }

}
