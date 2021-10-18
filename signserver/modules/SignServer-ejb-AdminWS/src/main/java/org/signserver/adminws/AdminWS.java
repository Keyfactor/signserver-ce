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
package org.signserver.adminws;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStoreException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.LinkedList;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import javax.annotation.PostConstruct;

import javax.annotation.Resource;
import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.jws.WebMethod;
import javax.jws.WebParam;
import javax.jws.WebService;
import javax.servlet.http.HttpServletRequest;
import javax.xml.ws.WebServiceContext;
import javax.xml.ws.handler.MessageContext;
import org.apache.commons.fileupload.FileUploadBase;
import org.apache.commons.fileupload.FileUploadException;

import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Base64;
import org.cesecore.audit.AuditLogEntry;
import org.cesecore.audit.audit.SecurityEventsAuditorSessionLocal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.util.query.Elem;
import org.cesecore.util.query.QueryCriteria;
import org.cesecore.util.query.clauses.Order;
import org.signserver.admin.common.auth.AdminAuthHelper;
import org.signserver.admin.common.query.QueryOrdering;
import org.signserver.admin.common.query.QueryCondition;
import org.signserver.admin.common.query.QueryUtil;
import org.signserver.common.*;
import org.signserver.common.data.CertificateValidationRequest;
import org.signserver.common.data.CertificateValidationResponse;
import org.signserver.common.data.DocumentValidationRequest;
import org.signserver.common.data.DocumentValidationResponse;
import org.signserver.common.data.LegacyRequest;
import org.signserver.common.data.LegacyResponse;
import org.signserver.common.data.Request;
import org.signserver.common.data.Response;
import org.signserver.common.data.SODRequest;
import org.signserver.common.data.SODResponse;
import org.signserver.common.data.SignatureRequest;
import org.signserver.common.data.SignatureResponse;
import org.signserver.ejb.interfaces.ProcessSessionLocal;
import org.signserver.server.CertificateClientCredential;
import org.signserver.server.IClientCredential;
import org.signserver.server.UsernamePasswordClientCredential;
import org.signserver.server.log.AdminInfo;
import org.signserver.ejb.interfaces.WorkerSessionLocal;
import org.signserver.ejb.interfaces.GlobalConfigurationSessionLocal;
import org.signserver.server.data.impl.CloseableReadableData;
import org.signserver.server.data.impl.CloseableWritableData;
import org.signserver.server.data.impl.DataFactory;
import org.signserver.server.data.impl.DataUtils;
import org.signserver.server.data.impl.UploadConfig;
import org.signserver.validationservice.common.ValidateRequest;
import org.signserver.validationservice.common.ValidateResponse;
import static org.signserver.common.SignServerConstants.TOKEN_ENTRY_FIELDS_ALIAS;
import static org.signserver.common.SignServerConstants.TOKEN_ENTRY_FIELDS_KEY_ALIAS;

/**
 * SignServer Administration Web Services (AdminWS) interface.
 *
 * @author Markus Kilås
 * @version $Id$
 */
@WebService(serviceName = "AdminWSService")
@Stateless
public class AdminWS {

    private static final Logger LOG = Logger.getLogger(AdminWS.class);

    private static final String HTTP_AUTH_BASIC_AUTHORIZATION = "Authorization";

    @Resource
    private WebServiceContext wsContext;

    @EJB
    private WorkerSessionLocal worker;

    @EJB
    private ProcessSessionLocal processSession;

    @EJB
    private GlobalConfigurationSessionLocal global;

    @EJB
    private SecurityEventsAuditorSessionLocal auditor;

    private DataFactory dataFactory;

    private AdminWSAuthHelper auth;

    @PostConstruct
    protected void init() {
        dataFactory = DataUtils.createDataFactory();
        auth = new AdminWSAuthHelper(new AdminAuthHelper(global));
    }

    /**
     * Get the ID of a worker given a name.
     *
     * @param workerName of the worker, cannot be null
     * @return The ID of a named worker or 0 if no such name exists
     * @throws AdminNotAuthorizedException If the admin is not authorized
     */
    @WebMethod(operationName = "getWorkerId")
    public int getWorkerId(
            @WebParam(name = "workerName") final String workerName )
            throws AdminNotAuthorizedException {
        auth.requireAdminAuthorization(getCertificate(), "getWorkerId", workerName);

        try {
            return worker.getWorkerId(workerName);
        } catch (InvalidWorkerIdException ex) {
            return 0;
        }
    }

    /**
     * Get the current status of a worker.
     *
     * @param workerId of the worker
     * @return a WorkerStatus class
     * @throws InvalidWorkerIdException If the worker ID is invalid
     * @throws AdminNotAuthorizedException If the admin is not authorized
     */
    @WebMethod(operationName = "getStatus")
    public WSWorkerStatus getStatus(
            @WebParam(name = "workerId") final int workerId)
            throws InvalidWorkerIdException, AdminNotAuthorizedException {
        auth.requireAdminAuthorization(getCertificate(), "getStatus", String.valueOf(workerId));

        final WSWorkerStatus result;
        final WorkerStatus status = worker.getStatus(new WorkerIdentifier(workerId));
        if (status == null) {
            result = null;
        } else {
            result = new WSWorkerStatus();
            result.setActiveConfig(status.getActiveSignerConfig().getProperties());
            result.setHostname(status.getHostname());
            result.setOk(status.getFatalErrors().isEmpty() ? null : "offline");
            result.setWorkerId(workerId);

            final ByteArrayOutputStream bout1 = new ByteArrayOutputStream();
            status.displayStatus(new PrintStream(bout1), false);
            result.setStatusText(bout1.toString());

            final ByteArrayOutputStream bout2 = new ByteArrayOutputStream();
            status.displayStatus(new PrintStream(bout2), true);
            result.setCompleteStatusText(bout2.toString());
        }
        return result;
    }

    /**
     * Reload the configuration from the database so the latest version gets used.
     *
     * Needs to be called after a configuration change to start use it.
     *
     * @param workerId of the worker that should be reloaded, or 0 to reload reload of all available workers
     * @throws AdminNotAuthorizedException If the admin is not authorized
     */
    @WebMethod(operationName = "reloadConfiguration")
    public void reloadConfiguration(
            @WebParam(name = "workerId") int workerId)
            throws AdminNotAuthorizedException {
        final AdminInfo adminInfo = auth.requireAdminAuthorization(getCertificate(), "reloadConfiguration",
                String.valueOf(workerId));

        worker.reloadConfiguration(adminInfo, workerId);
    }

    /**
     * Activate the crypto token of the worker.
     *
     * @param signerId ID of the worker
     * @param authenticationCode (PIN) for logging in to the token.
     * @throws CryptoTokenOfflineException if the crypto token is offline
     * @throws CryptoTokenAuthenticationFailureException if the crypto token refused authentication
     * @throws InvalidWorkerIdException If the worker ID is invalid
     * @throws AdminNotAuthorizedException If the admin is not authorized
     */
    @WebMethod(operationName = "activateSigner")
    public void activateSigner(
            @WebParam(name = "signerId") int signerId,
            @WebParam(name = "authenticationCode") String authenticationCode)
            throws CryptoTokenAuthenticationFailureException, CryptoTokenOfflineException, InvalidWorkerIdException,
            AdminNotAuthorizedException {
        auth.requireAdminAuthorization(getCertificate(), "activateSigner", String.valueOf(signerId));

        worker.activateSigner(new WorkerIdentifier(signerId), authenticationCode);
    }

    /**
     * Deactivate (logout) the crypto token of the worker.
     *
     * @param signerId ID of the worker
     * @return true if deactivation (logout) was successful
     * @throws CryptoTokenOfflineException if the crypto token is offline
     * @throws InvalidWorkerIdException If the worker ID is invalid
     * @throws AdminNotAuthorizedException If the admin is not authorized
     */
    @WebMethod(operationName = "deactivateSigner")
    public boolean deactivateSigner(
            @WebParam(name = "signerId") int signerId)
            throws CryptoTokenOfflineException, InvalidWorkerIdException, AdminNotAuthorizedException {
        auth.requireAdminAuthorization(getCertificate(), "deactivateSigner", String.valueOf(signerId));

        return worker.deactivateSigner(new WorkerIdentifier(signerId));
    }

    /**
     * Returns the current configuration of a worker.
     *
     * Observe that this configuration might not be active until a reload command has been executed.
     *
     * @param workerId ID of worker
     * @return the current (not necessarily active) configuration
     * @throws AdminNotAuthorizedException If the admin is not authorized
     */
    @WebMethod(operationName = "getCurrentWorkerConfig")
    public WSWorkerConfig getCurrentWorkerConfig(
            @WebParam(name = "workerId") final int workerId) throws AdminNotAuthorizedException {
        auth.requireAdminAuthorization(getCertificate(), "getCurrentWorkerConfig",
                String.valueOf(workerId));

        return new WSWorkerConfig(worker.exportWorkerConfig(workerId));
    }

    /**
     * Set a worker property.
     *
     * Observe that the worker isn't activated with this configuration until a reload is performed.
     *
     * @param workerId ID of worker
     * @param key worker property name
     * @param value worker property value
     * @throws AdminNotAuthorizedException If the admin is not authorized
     */
    @WebMethod(operationName = "setWorkerProperty")
    public void setWorkerProperty(
            @WebParam(name = "workerId") final int workerId,
            @WebParam(name = "key") final String key,
            @WebParam(name = "value") final String value) throws AdminNotAuthorizedException {
        final AdminInfo adminInfo = auth.requireAdminAuthorization(getCertificate(), "setWorkerProperty",
                String.valueOf(workerId), key);

        worker.setWorkerProperty(adminInfo, workerId, key, value);
    }

    /**
     * Remove a worker property.
     *
     * Observe that the worker isn't activated with this configuration until a reload is performed.
     *
     * @param workerId ID of worker
     * @param key worker property name
     * @return true if the property did exist and was removed otherwise false
     * @throws AdminNotAuthorizedException If the admin is not authorized
     */
    @WebMethod(operationName = "removeWorkerProperty")
    public boolean removeWorkerProperty(
            @WebParam(name = "workerId") final int workerId,
            @WebParam(name = "key") final String key) throws AdminNotAuthorizedException {
        final AdminInfo adminInfo = auth.requireAdminAuthorization(getCertificate(), "removeWorkerProperty",
                String.valueOf(workerId), key);

        return worker.removeWorkerProperty(adminInfo, workerId, key);
    }

    /**
     * Get a collection of all authorized client certificate serial numbers and issuer DN:s accepted by the worker.
     *
     * @param workerId ID of worker
     * @return Sorted collection of authorized clients
     * @throws AdminNotAuthorizedException If the admin is not authorized
     */
    @WebMethod(operationName = "getAuthorizedClients")
    public Collection<AuthorizedClient> getAuthorizedClients(
            @WebParam(name = "workerId") final int workerId) throws AdminNotAuthorizedException {
        auth.requireAdminAuthorization(getCertificate(), "getAuthorizedClients",
                String.valueOf(workerId));

        return worker.getAuthorizedClients(workerId);
    }

    /**
     * Add an authorized client to the worker.

     * @param workerId ID of worker
     * @param authClient Authorized client to add
     * @throws AdminNotAuthorizedException If the admin is not authorized
     */
    @WebMethod(operationName = "addAuthorizedClient")
    public void addAuthorizedClient(
            @WebParam(name = "workerId") final int workerId,
            @WebParam(name = "authClient") final AuthorizedClient authClient) throws AdminNotAuthorizedException {
        final AdminInfo adminInfo = auth.requireAdminAuthorization(getCertificate(), "addAuthorizedClient",
                String.valueOf(workerId), authClient.getCertSN(),
                authClient.getIssuerDN());

        worker.addAuthorizedClient(adminInfo, workerId, authClient);
    }

    /**
     * Remove an authorized client from the worker.
     *
     * @param workerId ID of worker
     * @param authClient Authorized client to be removed
     * @return True if the authorized client was removed, false otherwise.
     * @throws AdminNotAuthorizedException If the admin is not authorized
     */
    @WebMethod(operationName = "removeAuthorizedClient")
    public boolean removeAuthorizedClient(
            @WebParam(name = "workerId") final int workerId,
            @WebParam(name = "authClient") final AuthorizedClient authClient) throws AdminNotAuthorizedException {
        final AdminInfo adminInfo = auth.requireAdminAuthorization(getCertificate(), "removeAuthorizedClient",
                String.valueOf(workerId), authClient.getCertSN(),
                authClient.getIssuerDN());

        return worker.removeAuthorizedClient(adminInfo, workerId, authClient);
    }

    /**
     * Generate a PKCS#10 certificate signing request.
     *
     * @param signerId ID of worker
     * @param certReqInfo information used by the worker to create the request
     * @param explicitEccParameters false should be default and will use
     * NamedCurve encoding of ECC public keys (IETF recommendation), use true
     * to include all parameters explicitly (ICAO ePassport requirement).
     * @return Base64 encoded certificate signing request
     * @throws CryptoTokenOfflineException if the crypto token is offline
     * @throws InvalidWorkerIdException If the worker ID is invalid
     * @throws AdminNotAuthorizedException If the admin is not authorized
     */
    @WebMethod(operationName = "getPKCS10CertificateRequest")
    public Base64SignerCertReqData getPKCS10CertificateRequest(
            @WebParam(name = "signerId") final int signerId,
            @WebParam(name = "certReqInfo") final PKCS10CertReqInfo certReqInfo,
            @WebParam(name = "explicitEccParameters") final boolean explicitEccParameters)
            throws CryptoTokenOfflineException, InvalidWorkerIdException, AdminNotAuthorizedException {
        final AdminInfo adminInfo = auth.requireAdminAuthorization(getCertificate(), "getPKCS10CertificateRequest",
                String.valueOf(signerId));

        final ICertReqData data = worker.getCertificateRequest(adminInfo, new WorkerIdentifier(signerId),
                certReqInfo, explicitEccParameters);
        if (data instanceof AbstractCertReqData) {
            try {
                return new Base64SignerCertReqData(Base64.encode(((AbstractCertReqData) data).toBinaryForm()));
            } catch (IOException ex) {
                throw new RuntimeException("Unable to encode cert req data", ex);
            }
        } else if (data instanceof Base64SignerCertReqData) {
            return (Base64SignerCertReqData) data;
        } else {
            throw new RuntimeException("Unsupported cert req data");
        }
    }

    /**
     * Legacy operation to generate a PKCS#10 certificate signing request
     * either for the current key or the next key.
     *
     * Note: Legacy operation. This operation is kept for backwards compatibility
     * but new implementations are recommended to use the newer
     * <i>getPKCS10CertificateRequestForKey2</i> operation which returns a
     * structure supporting other formats than PKCS#10.
     *
     * @param signerId ID of worker
     * @param certReqInfo information used by the worker to create the request
     * @param explicitEccParameters false should be default and will use NamedCurve encoding of ECC public keys
     *                              (IETF recommendation), use true to include all parameters explicitly
     *                              (ICAO ePassport requirement).
     * @param defaultKey true if the default key should be used otherwise for instance use next key.
     * @return Base64 encoded certificate signing request
     * @throws CryptoTokenOfflineException if the crypto token is offline
     * @throws InvalidWorkerIdException if a worker with the Id is not existing
     * @throws AdminNotAuthorizedException If the admin is not authorized
     */
    @WebMethod(operationName = "getPKCS10CertificateRequestForKey")
    public Base64SignerCertReqData getPKCS10CertificateRequestForKey(
            @WebParam(name = "signerId") final int signerId,
            @WebParam(name = "certReqInfo") final PKCS10CertReqInfo certReqInfo,
            @WebParam(name = "explicitEccParameters") final boolean explicitEccParameters,
            @WebParam(name = "defaultKey") final boolean defaultKey)
            throws CryptoTokenOfflineException, InvalidWorkerIdException, AdminNotAuthorizedException {
        final AdminInfo adminInfo = auth.requireAdminAuthorization(getCertificate(), "getPKCS10CertificateRequestForKey",
                String.valueOf(signerId));

        final ICertReqData data = worker.getCertificateRequest(adminInfo, new WorkerIdentifier(signerId),
                certReqInfo, explicitEccParameters, defaultKey);
        if (data instanceof AbstractCertReqData) {
            try {
                return new Base64SignerCertReqData(Base64.encode(((AbstractCertReqData) data).toBinaryForm()));
            } catch (IOException ex) {
                throw new RuntimeException("Unable to encode cert req data", ex);
            }
        } else if (data instanceof Base64SignerCertReqData) {
            return (Base64SignerCertReqData) data;
        } else {
            throw new RuntimeException("Unsupported cert req data");
        }
    }

    /**
     * Generate a certificate signing request (or similar) either for the
     * current key or the next key.
     *
     * Note: This operation is recommended over the legacy operation
     * <i>getPKCS10CertificateRequestForKey</i> which only supported PKCS#10.
     * Specifically when generating a certification signature or a revocation
     * certificate for OpenPGP this newer operation should be used.
     *
     * @param signerId id of the signer
     * @param certReqInfo information used by the worker to create the request
     * @param explicitEccParameters false should be default and will use
     * NamedCurve encoding of ECC public keys (IETF recommendation), use true
     * to include all parameters explicitly (ICAO ePassport requirement).
     * @param defaultKey true if the default key should be used otherwise for
     * instance use next key.
     * @return A structure containing a certificate signing request (or similar)
     * data in a form where it can be read both in binary or in PEM/armored form
     * @throws CryptoTokenOfflineException if the crypto token is offline
     * @throws InvalidWorkerIdException if a worker with the Id is not existing
     * @throws AdminNotAuthorizedException If the admin is not authorized
     */
    @WebMethod(operationName = "getPKCS10CertificateRequestForKey2")
    public CertReqData getPKCS10CertificateRequestForKey2(
            @WebParam(name = "signerId") final int signerId,
            @WebParam(name = "certReqInfo") final PKCS10CertReqInfo certReqInfo,
            @WebParam(name = "explicitEccParameters")
            final boolean explicitEccParameters,
            @WebParam(name = "defaultKey") final boolean defaultKey)
            throws CryptoTokenOfflineException, InvalidWorkerIdException,
            AdminNotAuthorizedException {
        final AdminInfo adminInfo = auth.requireAdminAuthorization(getCertificate(), "getPKCS10CertificateRequestForKey",
                String.valueOf(signerId));

        ICertReqData data = worker.getCertificateRequest(adminInfo, new WorkerIdentifier(signerId),
                certReqInfo, explicitEccParameters, defaultKey);

        if (!(data instanceof AbstractCertReqData)) {
            throw new RuntimeException("Unsupported cert req data");
        }

        try {
            CertReqData fullData = new CertReqData();
            fullData.setBinary(((AbstractCertReqData) data).toBinaryForm());
            fullData.setArmored(((AbstractCertReqData) data).toArmoredForm());
            return fullData;
        } catch (IOException ex) {
            throw new RuntimeException("Unable to encode cert req data", ex);
        }
    }

    /**
     * Legacy operation to generate a PKCS#10 certificate signing request for
     * the specified key alias.
     *
     * Note: Legacy operation. This operation is kept for backwards compatibility
     * but new implementations are recommended to use the newer
     * <i>getPKCS10CertificateRequestForAlias2</i> operation which returns a
     * structure supporting other formats than PKCS#10.
     *
     * @param signerId ID of worker
     * @param certReqInfo information used by the worker to create the request
     * @param explicitEccParameters false should be default and will use
     * NamedCurve encoding of ECC public keys (IETF recommendation), use true
     * to include all parameters explicitly (ICAO ePassport requirement).
     * @param keyAlias to generate the request for
     * @return Base64 encoded certificate signing request
     * @throws CryptoTokenOfflineException if the crypto token is offline
     * @throws InvalidWorkerIdException If the worker ID is invalid
     * @throws AdminNotAuthorizedException If the admin is not authorized
     */
    @WebMethod(operationName = "getPKCS10CertificateRequestForAlias")
    public Base64SignerCertReqData getPKCS10CertificateRequestForAlias(
            @WebParam(name = "signerId") final int signerId,
            @WebParam(name = "certReqInfo") final PKCS10CertReqInfo certReqInfo,
            @WebParam(name = "explicitEccParameters")
            final boolean explicitEccParameters,
            @WebParam(name = "keyAlias") final String keyAlias)
            throws CryptoTokenOfflineException, InvalidWorkerIdException,
            AdminNotAuthorizedException {

        final AdminInfo adminInfo = auth.requireAdminAuthorization(getCertificate(), "getPKCS10CertificateRequestForKey",
                String.valueOf(signerId));

        final ICertReqData data = worker.getCertificateRequest(adminInfo, new WorkerIdentifier(signerId),
                certReqInfo, explicitEccParameters, keyAlias);
        if (data instanceof AbstractCertReqData) {
            try {
                return new Base64SignerCertReqData(Base64.encode(((AbstractCertReqData) data).toBinaryForm()));
            } catch (IOException ex) {
                throw new RuntimeException("Unable to encode cert req data", ex);
            }
        } else if (data instanceof Base64SignerCertReqData) {
            return (Base64SignerCertReqData) data;
        } else {
            throw new RuntimeException("Unsupported cert req data");
        }
    }

    /**
     * Generate a certificate signing request (or similar) for the specified key
     * alias.
     *
     * Note: This operation is recommended over the legacy operation
     * <i>getPKCS10CertificateRequestForAlias2</i> which only supported PKCS#10.
     * Specifically when generating a certification signature or a revocation
     * certificate for OpenPGP this newer operation should be used.
     *
     * @param signerId ID of worker
     * @param certReqInfo information used by the worker to create the request
     * @param explicitEccParameters false should be default and will use
     * NamedCurve encoding of ECC public keys (IETF recommendation), use true
     * to include all parameters explicitly (ICAO ePassport requirement).
     * @param keyAlias to generate the request for
     * @return A structure containing a certificate signing request (or similar)
     * data in a form where it can be read both in binary or in PEM/armored form
     * @throws CryptoTokenOfflineException if the crypto token is offline
     * @throws InvalidWorkerIdException If the worker ID is invalid
     * @throws AdminNotAuthorizedException If the admin is not authorized
     */
    @WebMethod(operationName = "getPKCS10CertificateRequestForAlias2")
    public CertReqData getPKCS10CertificateRequestForAlias2(
            @WebParam(name = "signerId") final int signerId,
            @WebParam(name = "certReqInfo") final PKCS10CertReqInfo certReqInfo,
            @WebParam(name = "explicitEccParameters")
            final boolean explicitEccParameters,
            @WebParam(name = "keyAlias") final String keyAlias)
            throws CryptoTokenOfflineException, InvalidWorkerIdException,
            AdminNotAuthorizedException {

        final AdminInfo adminInfo = auth.requireAdminAuthorization(getCertificate(), "getPKCS10CertificateRequestForKey",
                String.valueOf(signerId));

        final ICertReqData data = worker.getCertificateRequest(adminInfo, new WorkerIdentifier(signerId),
                certReqInfo, explicitEccParameters, keyAlias);
        if (!(data instanceof AbstractCertReqData)) {
            throw new RuntimeException("Unsupported cert req data");
        }

        try {
            CertReqData fullData = new CertReqData();
            fullData.setBinary(((AbstractCertReqData) data).toBinaryForm());
            fullData.setArmored(((AbstractCertReqData) data).toArmoredForm());
            return fullData;
        } catch (IOException ex) {
            throw new RuntimeException("Unable to encode cert req data", ex);
        }
    }

    /**
     * Get the current signer certificate for the signer.
     * @param signerId Id of signer
     * @return Current signing certificate if the worker is a signer and it has
     * been configured. Otherwise null or an exception is thrown.
     * @throws CryptoTokenOfflineException if the crypto token is offline
     * @throws AdminNotAuthorizedException If the admin is not authorized
     */
    @WebMethod(operationName = "getSignerCertificate")
    public byte[] getSignerCertificate(
            @WebParam(name = "signerId") final int signerId)
            throws CryptoTokenOfflineException, AdminNotAuthorizedException {
        auth.requireAdminAuthorization(getCertificate(), "getSignerCertificate",
                String.valueOf(signerId));

        return worker.getSignerCertificateBytes(new WorkerIdentifier(signerId));
    }

    /**
     * Get the current signer certificate chain for the signer.
     * @param signerId Id of signer
     * @return Current signing certificate chain if the worker is a signer and it
     * has been configured. Otherwise null or an exception is thrown.
     * @throws CryptoTokenOfflineException if the crypto token is offline
     * @throws AdminNotAuthorizedException If the admin is not authorized
     */
    @WebMethod(operationName = "getSignerCertificateChain")
    public List<byte[]> getSignerCertificateChain(
            @WebParam(name = "signerId") final int signerId)
            throws CryptoTokenOfflineException, AdminNotAuthorizedException {
        auth.requireAdminAuthorization(getCertificate(), "getSignerCertificateChain",
                String.valueOf(signerId));

        return worker.getSignerCertificateChainBytes(new WorkerIdentifier(signerId));
    }

    /**
     * Get the last date the specified worker can perform signings.
     * @param workerId Id of worker to check.
     * @return The last date or null if no last date (=unlimited).
     * @throws CryptoTokenOfflineException if the crypto token is offline
     * @throws AdminNotAuthorizedException If the admin is not authorized
     */
    @WebMethod(operationName = "getSigningValidityNotAfter")
    public Date getSigningValidityNotAfter(
            @WebParam(name = "workerId") final int workerId)
            throws CryptoTokenOfflineException, AdminNotAuthorizedException {
        auth.requireAdminAuthorization(getCertificate(), "getSigningValidityNotAfter",
                String.valueOf(workerId));

        return worker.getSigningValidityNotAfter(new WorkerIdentifier(workerId));
    }

    /**
     * Get the first date the specified worker can perform signings.
     * @param workerId Id of worker to check.
     * @return The first date or null if no last date (=unlimited).
     * @throws CryptoTokenOfflineException if the crypto token is offline
     * @throws AdminNotAuthorizedException If the admin is not authorized
     */
    @WebMethod(operationName = "getSigningValidityNotBefore")
    public Date getSigningValidityNotBefore(
            @WebParam(name = "workerId") final int workerId)
            throws CryptoTokenOfflineException, AdminNotAuthorizedException {
        auth.requireAdminAuthorization(getCertificate(), "getSigningValidityNotBefore",
                String.valueOf(workerId));

        return worker.getSigningValidityNotBefore(new WorkerIdentifier(workerId));
    }

    /**
     * Get the value of the key usage counter for the given worker.
     * If no certificate is configured for the worker or the current key does
     * not yet have a counter in the database, -1 is returned.
     * @param workerId of worker
     * @return Value of the key usage counter or -1
     * @throws CryptoTokenOfflineException if the crypto token is offline
     * @throws AdminNotAuthorizedException If the admin is not authorized
     */
    @WebMethod(operationName = "getKeyUsageCounterValue")
    public long getKeyUsageCounterValue(
            @WebParam(name = "workerId") final int workerId)
            throws CryptoTokenOfflineException, AdminNotAuthorizedException {
        auth.requireAdminAuthorization(getCertificate(), "getKeyUsageCounterValue",
                String.valueOf(workerId));

        return worker.getKeyUsageCounterValue(new WorkerIdentifier(workerId));
    }

    /**
     * Legacy operation for removing a key.
     *
     * @param signerId ID of the worker
     * @param purpose on of ICryptoTokenV4.PURPOSE_ constants
     * @return true if removal was successful.
     * @throws InvalidWorkerIdException If the worker ID is invalid
     * @throws AdminNotAuthorizedException If the admin is not authorized
     * @deprecated Use removeKey instead
     */
    @WebMethod(operationName = "destroyKey")
    public boolean destroyKey(@WebParam(name = "signerId") final int signerId,
                              @WebParam(name = "purpose") final int purpose)
            throws InvalidWorkerIdException, AdminNotAuthorizedException {
        auth.requireAdminAuthorization(getCertificate(), "destroyKey", String.valueOf(signerId));

        // destroyKey has been replaced with removeKey operation
        LOG.warn("Operation destroyKey no longer supported. Use removeKey instead.");
        return false;
    }

    /**
     * Generate a new key pair.
     * @param signerId ID of worker
     * @param keyAlgorithm Key algorithm, i.e. "RSA" or "ECDSA"
     * @param keySpec Key specification as bit length or elliptic curve name, i.e. "3078" or "secp256r1"
     * @param alias Name of the new key
     * @param authCode Authorization code of the token
     * @return Key alias of generated key
     * @throws CryptoTokenOfflineException if the crypto token is offline
     * @throws InvalidWorkerIdException If the worker ID is invalid
     * @throws AdminNotAuthorizedException If the admin is not authorized
     * @throws IllegalArgumentException in case of invalid input
     */
    @WebMethod(operationName = "generateSignerKey")
    public String generateSignerKey(
            @WebParam(name = "signerId") final int signerId,
            @WebParam(name = "keyAlgorithm") final String keyAlgorithm,
            @WebParam(name = "keySpec") final String keySpec,
            @WebParam(name = "alias") final String alias,
            @WebParam(name = "authCode") final String authCode)
            throws CryptoTokenOfflineException, InvalidWorkerIdException,
            AdminNotAuthorizedException {
        final AdminInfo adminInfo = auth.requireAdminAuthorization(getCertificate(), "generateSignerKey", String.valueOf(signerId),
                keyAlgorithm, keySpec, alias);

        return worker.generateSignerKey(adminInfo, new WorkerIdentifier(signerId), keyAlgorithm, keySpec, alias,
                authCode == null ? null : authCode.toCharArray());
    }

    /**
     * Perform a test signing with the key identified by alias or all keys
     * if alias "all" specified.
     *
     * @param signerId ID of worker
     * @param alias Name of key to test or "all" to test all available
     * @param authCode Authorization code of token
     * @return Collection with test results for each key
     * @throws CryptoTokenOfflineException if the crypto token is offline
     * @throws InvalidWorkerIdException If the worker ID is invalid
     * @throws KeyStoreException in case of key store problem
     * @throws AdminNotAuthorizedException If the admin is not authorized
     */
    @WebMethod(operationName = "testKey")
    @SuppressWarnings("deprecation") // We support the old KeyTestResult class as well
    public Collection<KeyTestResult> testKey(
            @WebParam(name = "signerId") final int signerId,
            @WebParam(name = "alias") final String alias,
            @WebParam(name = "authCode") final String authCode)
            throws CryptoTokenOfflineException,
            InvalidWorkerIdException, KeyStoreException,
            AdminNotAuthorizedException {
        final AdminInfo adminInfo = auth.requireAdminAuthorization(getCertificate(), "testKey", String.valueOf(signerId), alias);

        // Workaround for KeyTestResult first placed in wrong package
        final Collection<KeyTestResult> results;
        Collection<?> res = worker.testKey(adminInfo, new WorkerIdentifier(signerId), alias, authCode == null ? null : authCode.toCharArray());
        if (res.size() < 1) {
            results = new LinkedList<>();
        } else {
            results = new LinkedList<>();
            for (Object o : res) {
                if (o instanceof KeyTestResult) {
                    results.add((KeyTestResult) o);
                }
            }
        }

        return results;
    }

    /**
     * Remove a key pair from the crypto token used by the worker.
     *
     * @param signerId ID of worker
     * @param alias key alias of key to remove
     * @return True if the key existed and then was successfully removed.
     * @throws CryptoTokenOfflineException if the crypto token is offline
     * @throws InvalidWorkerIdException if the specified worker id does not
     * exist
     * @throws KeyStoreException for keystore related errors
     * @throws SignServerException for other errors including trying to remove 
     * a non-existing key (i.e "No such alias in token")
     * @throws AdminNotAuthorizedException If the admin is not authorized
     */
    @WebMethod(operationName = "removeKey")
    public boolean removeKey(
            @WebParam(name = "signerId") final int signerId,
            @WebParam(name = "alias") final String alias)
            throws CryptoTokenOfflineException,
            InvalidWorkerIdException, KeyStoreException,
            SignServerException, AdminNotAuthorizedException {
        final AdminInfo adminInfo = auth.requireAdminAuthorization(getCertificate(), "removeKey", String.valueOf(signerId), alias);

        return worker.removeKey(adminInfo, new WorkerIdentifier(signerId), alias);
    }

    /**
     * Set the signer certificate worker property of a worker.
     *
     * @param signerId ID of the worker
     * @param signerCert the certificate to set
     * @param scope one of GlobalConfiguration.SCOPE_ constants
     * @throws IllegalRequestException in case of invalid input.
     * @throws AdminNotAuthorizedException If the admin is not authorized
     */
    @WebMethod(operationName = "uploadSignerCertificate")
    public void uploadSignerCertificate(
            @WebParam(name = "signerId") final int signerId,
            @WebParam(name = "signerCert") final byte[] signerCert,
            @WebParam(name = "scope") final String scope)
            throws IllegalRequestException, AdminNotAuthorizedException {
        final AdminInfo adminInfo = auth.requireAdminAuthorization(getCertificate(), "uploadSignerCertificate",
                String.valueOf(signerId));

        try {
            worker.uploadSignerCertificate(adminInfo, signerId, signerCert, scope);
        } catch (CertificateException ex) {
            // Log stacktrace and only pass on description to client
            LOG.error("Unable to parse certificate", ex);
            throw new IllegalRequestException("Unable to parse certificate");
        }
    }

    /**
     * Set the signer certificate chain worker property of a worker.
     *
     * @param signerId ID of the worker
     * @param signerCerts the certificate chain
     * @param scope one of GlobalConfiguration.SCOPE_ constants
     * @throws IllegalRequestException in case of invalid input.
     * @throws AdminNotAuthorizedException If the admin is not authorized
     */
    @WebMethod(operationName = "uploadSignerCertificateChain")
    public void uploadSignerCertificateChain(
            @WebParam(name = "signerId") final int signerId,
            @WebParam(name = "signerCerts") final List<byte[]> signerCerts,
            @WebParam(name = "scope") final String scope)
            throws IllegalRequestException, AdminNotAuthorizedException {
        final AdminInfo adminInfo = auth.requireAdminAuthorization(getCertificate(), "uploadSignerCertificateChain",
                String.valueOf(signerId));

        try {
            worker.uploadSignerCertificateChain(adminInfo, signerId, signerCerts, scope);
        } catch (CertificateException ex) {
            // Log stacktrace and only pass on description to client
            LOG.error("Unable to parse certificate", ex);
            throw new IllegalRequestException("Unable to parse certificate");
        }
    }

    /**
     * Set a global configuration property.
     *
     * @param scope one of the GlobalConfiguration.SCOPE_ constants
     * @param key of the property should not have any scope prefix, never null
     * @param value the value, never null.
     * @throws AdminNotAuthorizedException If the admin is not authorized
     */
    @WebMethod(operationName = "setGlobalProperty")
    public void setGlobalProperty(
            @WebParam(name = "scope") final String scope,
            @WebParam(name = "key") final String key,
            @WebParam(name = "value") final String value)
            throws AdminNotAuthorizedException {
        final AdminInfo adminInfo = auth.requireAdminAuthorization(getCertificate(), "setGlobalProperty", key);

        global.setProperty(adminInfo, scope, key, value);
    }

    /**
     * Remove a global configuration property.
     *
     * @param scope one of the GlobalConfiguration.SCOPE_ constants
     * @param key of the property should start with either glob. or node.,
     * never null
     * @return true if removal was successful, otherwise false.
     * @throws AdminNotAuthorizedException If the admin is not authorized
     */
    @WebMethod(operationName = "removeGlobalProperty")
    public boolean removeGlobalProperty(
            @WebParam(name = "scope") final String scope,
            @WebParam(name = "key") final String key)
            throws AdminNotAuthorizedException {
        final AdminInfo adminInfo = auth.requireAdminAuthorization(getCertificate(), "removeGlobalProperty", key);

        return global.removeProperty(adminInfo, scope, key);
    }

    /**
     * Get all the global configuration properties with Global Scope and Node
     * scopes properties for this node.
     * @return A GlobalConfiguration Object, never null
     * @throws AdminNotAuthorizedException If the admin is not authorized
     */
    @WebMethod(operationName = "getGlobalConfiguration")
    public WSGlobalConfiguration getGlobalConfiguration()
            throws AdminNotAuthorizedException {
        auth.requireAdminAuthorization(getCertificate(), "getGlobalConfiguration");

        final WSGlobalConfiguration result;
        final GlobalConfiguration config = global.getGlobalConfiguration();
        if (config == null) {
            result = null;
        } else {
            result = new WSGlobalConfiguration();
            final Properties props = new Properties();
            final Enumeration<String> en = config.getKeyEnumeration();
            while (en.hasMoreElements()) {
                final String key = en.nextElement();
                props.setProperty(key, config.getProperty(key));
            }
            result.setConfig(props);
            result.setState(config.getState());
            result.setAppVersion(config.getAppVersion());
            result.setClusterClassLoaderEnabled(false);
            result.setRequireSigning(false);
            result.setUseClassVersions(false);
        }
        return result;
    }

    /**
     * Get all worker ID:s of workers with the specified worker type.
     *
     * <ul>
     *    <li>1 = WorkerConfig.WORKERTYPE_ALL</li>
     *    <li>2 = WorkerType.PROCESSABLE</li>
     *    <li>3 = WorkerType.TIMED_SERVICE</li>
     *    <li>10 = WorkerType.SPECIAL</li>
     *    <li>11 = WorkerType.CRYPTO_WORKER</li>
     * </ul>
     *
     * @param workerType to get the worker ID:s for
     * @return A List if worker ID:s
     * @throws AdminNotAuthorizedException If the admin is not authorized
     */
    @WebMethod(operationName = "getWorkers")
    public List<Integer> getWorkers(
            @WebParam(name = "workerType") final int workerType)
            throws AdminNotAuthorizedException {
        auth.requireAdminAuthorization(getCertificate(), "getWorkers", String.valueOf(workerType));

        if (workerType == WorkerConfig.WORKERTYPE_ALL) {
            return worker.getAllWorkers();
        } else {
            return worker.getWorkers(WorkerType.fromType(workerType));
        }
    }

    /**
     * Method that is used after a database crash to restore all cached data to
     * database.
     * @throws ResyncException if resync was unsuccessful
     * @throws AdminNotAuthorizedException If the admin is not authorized
     * @deprecated Unclear if this is supported or not
     */
    @WebMethod(operationName = "globalResync")
    public void globalResync() throws ResyncException, AdminNotAuthorizedException {
        final AdminInfo adminInfo = auth.requireAdminAuthorization(getCertificate(), "globalResync");

        global.resync(adminInfo);
    }

    /**
     * Flushes all cached worker configurations and the global configuration so
     * they will have to be read in from the database again.
     *
     * @throws AdminNotAuthorizedException If the admin is not authorized
     */
    @WebMethod(operationName = "globalReload")
    public void globalReload() throws AdminNotAuthorizedException {
        final AdminInfo adminInfo = auth.requireAdminAuthorization(getCertificate(), "globalReload");

        global.reload(adminInfo);
    }

    /**
     * Request a collection of requests to be processed by the specified worker.
     *
     * @param workerIdOrName Name or ID of the worker who should process the
     * request
     * @param requests Collection of serialized (binary) requests.
     * @return Collection of response data
     * @throws InvalidWorkerIdException If the worker ID is invalid
     * @throws IllegalRequestException in case of invalid input.
     * @throws CryptoTokenOfflineException if the crypto token is offline
     * @throws SignServerException general exception
     * @throws AdminNotAuthorizedException If the admin is not authorized
     *
     * @see RequestAndResponseManager#serializeProcessRequest(org.signserver.common.ProcessRequest)
     * @see RequestAndResponseManager#parseProcessRequest(byte[])
     */
    @WebMethod(operationName = "process")
    public Collection<byte[]> process(
            @WebParam(name = "workerIdOrName") final String workerIdOrName,
            @WebParam(name = "processRequest") Collection<byte[]> requests)
            throws InvalidWorkerIdException, IllegalRequestException,
            CryptoTokenOfflineException, SignServerException,
            AdminNotAuthorizedException {
        final AdminInfo adminInfo = auth.requireAdminAuthorization(getCertificate(), "process", workerIdOrName);

        final Collection<byte[]> result = new LinkedList<>();

        final X509Certificate[] clientCerts = getClientCertificates();
        final X509Certificate clientCertificate;
        if (clientCerts != null && clientCerts.length > 0) {
            clientCertificate = clientCerts[0];
        } else {
            clientCertificate = null;
        }
        // Requests from authenticated administrators are considered to come
        // from the local host and is set to null. This is also the same as
        // when requests are over EJB calls.
        final String ipAddress = null;

        final RequestContext requestContext = new RequestContext(
                clientCertificate, ipAddress);

        IClientCredential credential;
        if (clientCertificate instanceof X509Certificate) {
            final X509Certificate cert = (X509Certificate) clientCertificate;
            LOG.debug("Authentication: certificate");
            credential = new CertificateClientCredential(
                    cert.getSerialNumber().toString(16),
                    cert.getIssuerDN().getName());
        } else {
            final HttpServletRequest servletRequest =
                    (HttpServletRequest) wsContext.getMessageContext()
                            .get(MessageContext.SERVLET_REQUEST);
            // Check is client supplied basic-credentials
            final String authorization = servletRequest.getHeader(
                    HTTP_AUTH_BASIC_AUTHORIZATION);
            if (authorization != null) {
                LOG.debug("Authentication: password");

                final String decoded[] = new String(Base64.decode(
                        authorization.split("\\s")[1])).split(":", 2);

                credential = new UsernamePasswordClientCredential(
                        decoded[0], decoded[1]);
            } else {
                LOG.debug("Authentication: none");
                credential = null;
            }
        }
        requestContext.put(RequestContext.CLIENT_CREDENTIAL, credential);

        for (byte[] requestBytes : requests) {
            final ProcessRequest req;
            try {
                req = RequestAndResponseManager.parseProcessRequest(
                        requestBytes);
            } catch (IOException ex) {
                LOG.error("Error parsing process request", ex);
                throw new IllegalRequestException(
                        "Error parsing process request", ex);
            }

            // TODO: Duplicated in SignServerWS, AdminWS, ProcessSessionBean (remote)
            CloseableReadableData requestData = null;
            CloseableWritableData responseData = null;
            try {
                final Request req2;
                boolean propertiesRequest = false;

                // Use the new request types with large file support for
                // GenericSignRequest and GenericValidationRequest
                if (req instanceof GenericSignRequest) {
                    byte[] data = ((GenericSignRequest) req).getRequestData();
                    int requestID = ((GenericSignRequest) req).getRequestID();

                    // Upload handling (Note: close in finally clause)
                    UploadConfig uploadConfig = UploadConfig.create(global);
                    requestData = dataFactory.createReadableData(data, uploadConfig.getMaxUploadSize(), uploadConfig.getRepository());
                    responseData = dataFactory.createWritableData(requestData, uploadConfig.getRepository());
                    req2 = new SignatureRequest(requestID, requestData, responseData);
                } else if (req instanceof GenericValidationRequest) {
                    byte[] data = ((GenericValidationRequest) req).getRequestData();
                    int requestID = ((GenericValidationRequest) req).getRequestID();

                    // Upload handling (Note: close in finally clause)
                    UploadConfig uploadConfig = UploadConfig.create(global);
                    requestData = dataFactory.createReadableData(data, uploadConfig.getMaxUploadSize(), uploadConfig.getRepository());
                    req2 = new DocumentValidationRequest(requestID, requestData);
                } else if (req instanceof ValidateRequest) {
                    ValidateRequest vr = (ValidateRequest) req;
                    req2 = new CertificateValidationRequest(vr.getCertificate(), vr.getCertPurposesString());
                } else if (req instanceof SODSignRequest) {
                    SODSignRequest sodReq = (SODSignRequest) req;
                    req2 = new SODRequest(sodReq.getRequestID(), sodReq.getDataGroupHashes(), sodReq.getLdsVersion(), sodReq.getUnicodeVersion(), responseData);
                } else if (req instanceof GenericPropertiesRequest) {
                    GenericPropertiesRequest propReq = (GenericPropertiesRequest) req;
                    propertiesRequest = true;

                    // Upload handling (Note: close in finally clause)
                    UploadConfig uploadConfig = UploadConfig.create(global);
                    ByteArrayOutputStream bout = new ByteArrayOutputStream();
                    propReq.getProperties().store(bout, null);
                    requestData = dataFactory.createReadableData(bout.toByteArray(), uploadConfig.getMaxUploadSize(), uploadConfig.getRepository());
                    responseData = dataFactory.createWritableData(requestData, uploadConfig.getRepository());
                    req2 = new SignatureRequest(propReq.hashCode(), requestData, responseData);
                } else {
                    // Passthrough for all legacy requests
                    req2 = new LegacyRequest(req);
                }

                Response resp = processSession.process(adminInfo, WorkerIdentifier.createFromIdOrName(workerIdOrName), req2, requestContext);

                ProcessResponse processResponse;
                if (resp instanceof SignatureResponse) {
                    SignatureResponse sigResp = (SignatureResponse) resp;
                    if (propertiesRequest) {
                        Properties properties = new Properties();
                        properties.load(responseData.toReadableData().getAsInputStream());
                        processResponse = new GenericPropertiesResponse(properties);
                    } else {
                        processResponse = new GenericSignResponse(sigResp.getRequestID(), responseData.toReadableData().getAsByteArray(), sigResp.getSignerCertificate(), sigResp.getArchiveId(), sigResp.getArchivables());
                    }
                } else if (resp instanceof DocumentValidationResponse) {
                    DocumentValidationResponse docResp = (DocumentValidationResponse) resp;
                    processResponse = new GenericValidationResponse(docResp.getRequestID(), docResp.isValid(), convert(docResp.getCertificateValidationResponse()), responseData.toReadableData().getAsByteArray());
                } else if (resp instanceof CertificateValidationResponse) {
                    CertificateValidationResponse certResp = (CertificateValidationResponse) resp;
                    processResponse = new ValidateResponse(certResp.getValidation(), certResp.getValidCertificatePurposes());
                } else if (resp instanceof SODResponse) {
                    SODResponse sodResp = (SODResponse) resp;
                    processResponse = new SODSignResponse(sodResp.getRequestID(), responseData.toReadableData().getAsByteArray(), sodResp.getSignerCertificate(), sodResp.getArchiveId(), sodResp.getArchivables());
                } else if (resp instanceof LegacyResponse) {
                    processResponse = ((LegacyResponse) resp).getLegacyResponse();
                } else {
                    throw new SignServerException("Unexpected response type: " + resp);
                }

                try {
                    result.add(RequestAndResponseManager.serializeProcessResponse(processResponse));
                } catch (IOException ex) {
                    LOG.error("Error serializing process response", ex);
                    throw new IllegalRequestException(
                            "Error serializing process response", ex);
                }
            } catch (FileUploadBase.SizeLimitExceededException ex) {
                LOG.error("Maximum content length exceeded: " + ex.getLocalizedMessage());
                throw new IllegalRequestException("Maximum content length exceeded");
            } catch (FileUploadException ex) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Upload failed", ex);
                }
                throw new IllegalRequestException("Upload failed: " + ex.getLocalizedMessage());
            } catch (IOException ex) {
                throw new SignServerException("IO error", ex);
            } finally {
                if (requestData != null) {
                    try {
                        requestData.close();
                    } catch (IOException ex) {
                        LOG.error("Unable to remove temporary upload file: " + ex.getLocalizedMessage());
                    }
                }
                if (responseData != null) {
                    try {
                        responseData.close();
                    } catch (IOException ex) {
                        LOG.error("Unable to remove temporary response file: " + ex.getLocalizedMessage());
                    }
                }
            }
        }
        return result;
    }

    /**
     * Import a certificate chain in to a crypto token.
     *
     * Note that this operation stores the certificates in the token. Compare
     * with the uploadSignerCertificate and uploadSignerCertificateChain which
     * stores the certificates in the worker configuration.
     *
     * @param workerId ID of (crypto)worker
     * @param certChain Certificate chain to import
     * @param alias Alias of entry in the crypto token to store the certificate(s) for
     * @param authCode Set if the alias is protected by an individual authentication
     *                 code. If null, uses the authentication code used when activating
     *                 the token
     * @throws CryptoTokenOfflineException if the crypto token is offline
     * @throws CertificateException in case of certificate problems.
     * @throws OperationUnsupportedException requested operation is not supported/implemented.
     * @throws AdminNotAuthorizedException If the admin is not authorized
     */
    @WebMethod(operationName = "importCertificateChain")
    public void importCertificateChain(
            @WebParam(name="workerId") final int workerId,
            @WebParam(name="certificateChain") final List<byte[]> certChain,
            @WebParam(name="alias") final String alias,
            @WebParam(name="authenticationCode") final String authCode)
            throws CryptoTokenOfflineException, CertificateException,
            OperationUnsupportedException, AdminNotAuthorizedException {
        final AdminInfo adminInfo =
                auth.requireAdminAuthorization(getCertificate(), "importCertificateChain",
                        String.valueOf(workerId), String.valueOf(alias));
        worker.importCertificateChain(adminInfo, new WorkerIdentifier(workerId), certChain, alias,
                authCode == null ? null : authCode.toCharArray());
    }


    /**
     * Query the audit log.
     *
     * @param startIndex Index where select will start. Set to 0 to start from the beginning.
     * @param max maximum number of results to be returned.
     * @param conditions List of conditions defining the subset of logs to be selected.
     * @param orderings List of ordering conditions for ordering the result.
     * @return List of log entries
     * @throws SignServerException In case of internal failures
     * @throws AdminNotAuthorizedException If the admin is not authorized
     */
    @WebMethod(operationName="queryAuditLog")
    public List<WSAuditLogEntry> queryAuditLog(@WebParam(name="startIndex") int startIndex, @WebParam(name="max") int max, @WebParam(name="condition") final List<QueryCondition> conditions, @WebParam(name="ordering") final List<QueryOrdering> orderings) throws SignServerException, AdminNotAuthorizedException {
        final AdminInfo adminInfo = auth.requireAuditorAuthorization(getCertificate(), "queryAuditLog", String.valueOf(startIndex), String.valueOf(max));

        // For now we only query one of the available audit devices
        Set<String> devices = auditor.getQuerySupportingLogDevices();
        if (devices.isEmpty()) {
            throw new SignServerException("No log devices available for querying");
        }
        final String device = devices.iterator().next();

        final List<Elem> elements = QueryUtil.toElements(conditions);
        final QueryCriteria qc = QueryCriteria.create();

        if (orderings != null) {
            for (QueryOrdering order : orderings) {
                qc.add(new Order(order.getColumn(), Order.Value.valueOf(order.getOrder().name())));
            }
        }

        if (!elements.isEmpty()) {
            qc.add(QueryUtil.andAll(elements, 0));
        }

        try {
            return toLogEntries(worker.selectAuditLogs(adminInfo, startIndex, max, qc, device));
        } catch (AuthorizationDeniedException ex) {
            throw new AdminNotAuthorizedException(ex.getMessage());
        }
    }

    /**
     * Convert to WS model LogEntry:s.
     */
    private List<WSAuditLogEntry> toLogEntries(final List<? extends AuditLogEntry> entries) {
        final List<WSAuditLogEntry> results = new LinkedList<>();
        for (AuditLogEntry entry : entries) {
            results.add(WSAuditLogEntry.fromAuditLogEntry(entry));
        }
        return results;
    }

    /**
     * Query the archive.
     *
     * @param startIndex Index where select will start. Set to 0 to start from the beginning.
     * @param max maximum number of results to be returned.
     * @param conditions List of conditions defining the subset of the archive to be presented.
     * @param orderings List of ordering conditions for ordering the result.
     * @param includeData Set to true if archive data should be included in the result set
     * @return List of archive entries (the archive data is not included).
     * @throws SignServerException general exception
     * @throws AdminNotAuthorizedException If the admin is not authorized
     */
    @WebMethod(operationName="queryArchive")
    public List<WSArchiveMetadata> queryArchive(@WebParam(name="startIndex") int startIndex,
                                                @WebParam(name="max") int max, @WebParam(name="condition") final List<QueryCondition> conditions,
                                                @WebParam(name="ordering") final List<QueryOrdering> orderings,
                                                @WebParam(name="includeData") final boolean includeData)
            throws SignServerException, AdminNotAuthorizedException {
        final AdminInfo adminInfo = auth.requireArchiveAuditorAuthorization(getCertificate(), "queryArchive", String.valueOf(startIndex), String.valueOf(max));

        final List<Elem> elements = QueryUtil.toElements(conditions);
        final QueryCriteria qc = QueryCriteria.create();

        for (QueryOrdering order : orderings) {
            qc.add(new Order(order.getColumn(), Order.Value.valueOf(order.getOrder().name())));
        }

        if (!elements.isEmpty()) {
            qc.add(QueryUtil.andAll(elements, 0));
        }

        try {
            return toArchiveEntries(worker.searchArchive(adminInfo, startIndex,
                    max, qc, includeData));
        } catch (AuthorizationDeniedException ex) {
            throw new AdminNotAuthorizedException(ex.getMessage());
        }
    }

    /**
     * Query the archive based on unique IDs.
     *
     * @param uniqueIds to query for
     * @param includeData true if the archive data should be included in the response
     * @return list of archive metadata optionally including the data
     * @throws SignServerException general exception
     * @throws AdminNotAuthorizedException If the admin is not authorized
     */
    @WebMethod(operationName="queryArchiveWithIds")
    public List<WSArchiveMetadata> queryArchiveWithIds(@WebParam(name="uniqueIds") List<String> uniqueIds,
                                                       @WebParam(name="includeData") boolean includeData)
            throws SignServerException, AdminNotAuthorizedException {
        final AdminInfo adminInfo =
                auth.requireArchiveAuditorAuthorization(getCertificate(), "queryArchiveWithIds");

        try {
            return toArchiveEntries(worker.searchArchiveWithIds(adminInfo, uniqueIds, includeData));
        } catch (AuthorizationDeniedException ex) {
            throw new AdminNotAuthorizedException(ex.getMessage());
        }
    }

    /**
     * Query entries in a crypto token.
     *
     * @param workerId (crypto)worker ID
     * @param startIndex Index where select will start. Set to 0 to start from the beginning.
     * @param max maximum number of results to be returned.
     * @param conditions List of conditions defining the subset of the list to be presented.
     * @param orderings List of ordering conditions for ordering the result.
     * @param includeData If 'false' only the alias and key type is included, otherwise all information available is returned
     * @return the query search result
     * @throws OperationUnsupportedException requested operation is not supported/implemented.
     * @throws CryptoTokenOfflineException if the crypto token is offline
     * @throws QueryException input query
     * @throws InvalidWorkerIdException If the worker ID is invalid
     * @throws AuthorizationDeniedException If the admin is not authorized
     * @throws SignServerException general exception
     * @throws AdminNotAuthorizedException If the admin is not authorized
     */
    @WebMethod(operationName="queryTokenEntries")
    public WSTokenSearchResults queryTokenEntries(@WebParam(name="workerId") int workerId, @WebParam(name="startIndex") int startIndex, @WebParam(name="max") int max, @WebParam(name="condition") final List<QueryCondition> conditions, @WebParam(name="ordering") final List<QueryOrdering> orderings, @WebParam(name="includeData") boolean includeData) throws OperationUnsupportedException, CryptoTokenOfflineException, QueryException, InvalidWorkerIdException, AuthorizationDeniedException, SignServerException, AdminNotAuthorizedException {
        try {
            final AdminInfo adminInfo = auth.requireAdminAuthorization(getCertificate(), "queryTokenEntries", String.valueOf(workerId), String.valueOf(startIndex), String.valueOf(max));
            final List<Elem> elements = QueryUtil.toElements(conditions);
            final QueryCriteria qc = QueryCriteria.create();
            if (orderings != null) {
                for (QueryOrdering order : orderings) {
                    if (order.getColumn().equals(TOKEN_ENTRY_FIELDS_ALIAS)) {
                        order.setColumn(TOKEN_ENTRY_FIELDS_KEY_ALIAS);
                    }
                    qc.add(new Order(order.getColumn(), Order.Value.valueOf(order.getOrder().name())));
                }
            }
            if (!elements.isEmpty()) {
                qc.add(QueryUtil.andAll(elements, 0));
            }

            return WSTokenSearchResults.fromTokenSearchResults(worker.searchTokenEntries(adminInfo, new WorkerIdentifier(workerId), startIndex, max, qc, includeData, Collections.<String, Object>emptyMap()));
        } catch (InvalidAlgorithmParameterException ex) {
            throw new SignServerException("Crypto token expects supported parameters", ex);
        } catch (UnsupportedCryptoTokenParameter ex) {
            throw new SignServerException("Crypto token expects parameters", ex);
        }
    }

    /**
     * Convert to WS model ArchiveEntry.
     *
     * @param entries list of archive entries.
     * @return list of archive meta entries.
     */
    private List<WSArchiveMetadata> toArchiveEntries(final List<? extends ArchiveMetadata> entries) {
        final List<WSArchiveMetadata> results = new LinkedList<>();

        for (final ArchiveMetadata entry : entries) {
            results.add(WSArchiveMetadata.fromArchiveMetadata(entry));
        }

        return results;
    }

    private X509Certificate[] getClientCertificates() {
        final HttpServletRequest req =
                (HttpServletRequest) wsContext.getMessageContext()
                        .get(MessageContext.SERVLET_REQUEST);
        final X509Certificate[] certificates =
                (X509Certificate[]) req.getAttribute(
                        "javax.servlet.request.X509Certificate");
        return certificates;
    }

    private X509Certificate getCertificate() throws AdminNotAuthorizedException {
        final X509Certificate[] certificates = getClientCertificates();
        if (certificates == null || certificates.length == 0) {
            throw new AdminNotAuthorizedException(
                    "Auditor not authorized to resource. "
                            + "Client certificate authentication required.");
        }
        return certificates[0];
    }

    private ValidateResponse convert(CertificateValidationResponse from) {
        return new ValidateResponse(from.getValidation(), from.getValidCertificatePurposes());
    }

}
