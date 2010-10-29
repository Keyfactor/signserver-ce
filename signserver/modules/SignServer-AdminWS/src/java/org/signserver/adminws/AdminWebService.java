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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.jws.WebMethod;
import javax.jws.WebParam;
import javax.jws.WebService;
import javax.naming.NamingException;
import org.signserver.common.*;
import org.signserver.ejb.interfaces.IWorkerSession;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.KeyStoreException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Properties;
import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import javax.xml.ws.WebServiceContext;
import javax.xml.ws.handler.MessageContext;
import org.apache.log4j.Logger;
import org.signserver.ejb.interfaces.IGlobalConfigurationSession;

/**
 * Class implementing the Admin WS interface.
 *
 * This class contains web service implementations for almost all EJB methods.
 * @author markus
 * @version $Id$
 */
@WebService()
public class AdminWebService {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(AdminWebService.class);

    @Resource
    WebServiceContext wsContext;

    @EJB
    private IWorkerSession.IRemote worker;

    @EJB
    private IGlobalConfigurationSession.IRemote global;

    @PostConstruct
    private void postConstruct() {
        if (worker == null) {
            try {
                worker = ServiceLocator.getInstance().lookupRemote(
                        IWorkerSession.IRemote.class);
            } catch (NamingException ex) {
                LOG.error("Error looking up WorkerSession", ex);
            }
        }
        if (global == null) {
            try {
                global = ServiceLocator.getInstance().lookupRemote(
                        IGlobalConfigurationSession.IRemote.class);
            } catch (NamingException ex) {
                LOG.error("Error looking up GlobalConfigurationSession", ex);
            }
        }
    }

//    /**
//     * The Worker Beans main method. Takes  requests processes them
//     * and returns a response.
//     *
//     * @param workerId id of worker who should process the request
//     * @param request the request
//     * @param context context of the request
//     * @throws CryptoTokenOfflineException if the signers token isn't activated.
//     * @throws IllegalRequestException if illegal request is sent to the method
//     * @throws SignServerException if some other error occurred server side
//     * during process.
//     */
//    @WebMethod(operationName = "processData")
//    public ProcessResponse processData(@WebParam(name = "workerId") int workerId,
//            @WebParam(name = "request") ProcessRequest request,
//            @WebParam(name = "context") RequestContext context)
//            throws IllegalRequestException, CryptoTokenOfflineException,
//            SignServerException {
//        return worker.process(workerId, request, context);
//    }

    /**
     * Returns the Id of a worker given a name
     *
     * @param workerName of the worker, cannot be null
     * @return The Id of a named worker or 0 if no such name exists
     */
    @WebMethod(operationName = "getWorkerId")
    public int getWorkerId(
            @WebParam(name = "workerName") final String workerName)
            throws AdminNotAuthorizedException {
        requireAdminAuthorization("getWorkerId", workerName);

        return worker.getWorkerId(workerName);
    }

    /**
     * Returns the current status of a processalbe.
     *
     * Should be used with the cmd-line status command.
     * @param workerId of the signer
     * @return a WorkerStatus class
     */
    @WebMethod(operationName = "getStatus")
    public WSWorkerStatus getStatus(
            @WebParam(name = "workerId") final int workerId)
            throws InvalidWorkerIdException, AdminNotAuthorizedException {
        requireAdminAuthorization("getStatus", String.valueOf(workerId));

        final WSWorkerStatus result;
        final WorkerStatus status = worker.getStatus(workerId);
        if (status == null) {
            result = null;
        } else {
            result = new WSWorkerStatus();
            result.setActiveConfig(status.getActiveSignerConfig()
                    .getProperties());
            result.setHostname(status.getHostname());
            result.setOk(status.isOK());
            result.setWorkerId(workerId);

            final ByteArrayOutputStream bout1 = new ByteArrayOutputStream();
            status.displayStatus(workerId, new PrintStream(bout1), false);
            result.setStatusText(bout1.toString());

            final ByteArrayOutputStream bout2 = new ByteArrayOutputStream();
            status.displayStatus(workerId, new PrintStream(bout2), true);
            result.setCompleteStatusText(bout2.toString());
        }
        return result;
    }


    /**
     * Method used when a configuration have been updated. And should be
     * called from the commandline.
     *
     * @param workerId of the worker that should be reloaded, or 0 to reload
     * reload of all available workers
     */
    @WebMethod(operationName = "reloadConfiguration")
    public void reloadConfiguration(@WebParam(name = "workerId") int workerId)
            throws AdminNotAuthorizedException {
        requireAdminAuthorization("reloadConfiguration",
                String.valueOf(workerId));
        
        worker.reloadConfiguration(workerId);
    }

    /**
     * Method used to activate the signtoken of a signer.
     * Should be called from the command line.
     *
     * @param signerId of the signer
     * @param authenticationCode (PIN) used to activate the token.
     * @throws CryptoTokenOfflineException
     * @throws CryptoTokenAuthenticationFailureException
     */
    @WebMethod(operationName = "activateSigner")
    public void activateSigner(@WebParam(name = "signerId") int signerId,
            @WebParam(name = "authenticationCode") String authenticationCode)
            throws CryptoTokenAuthenticationFailureException,
            CryptoTokenOfflineException, InvalidWorkerIdException,
            AdminNotAuthorizedException {
        requireAdminAuthorization("activateSigner", String.valueOf(signerId));
        
        worker.activateSigner(signerId, authenticationCode);
    }

    /**
     * Method used to deactivate the signtoken of a signer.
     * Should be called from the command line.
     *
     * @param signerId of the signer
     * @return true if deactivation was successful
     * @throws CryptoTokenOfflineException
     * @throws CryptoTokenAuthenticationFailureException
     */
    @WebMethod(operationName = "deactivateSigner")
    public boolean deactivateSigner(@WebParam(name = "signerId") int signerId)
                throws CryptoTokenOfflineException,
            InvalidWorkerIdException, AdminNotAuthorizedException {
        requireAdminAuthorization("deactivateSigner", String.valueOf(signerId));
        
        return worker.deactivateSigner(signerId);
    }

/////////////////////////////////////////////////////////////////////////////////

    /**
     * Returns the current configuration of a worker.
     *
     * Observe that this config might not be active until a reload command
     * has been excecuted.
     *
     * @param signerId
     * @return the current (not always active) configuration
     */
    @WebMethod(operationName = "getCurrentWorkerConfig")
    public WSWorkerConfig getCurrentWorkerConfig(
            @WebParam(name = "workerId") final int workerId)
            throws AdminNotAuthorizedException {
        requireAdminAuthorization("getCurrentWorkerConfig",
                String.valueOf(workerId));
        
        return new WSWorkerConfig(worker.getCurrentWorkerConfig(workerId)
                .getProperties());
    }

    /**
     * Sets a parameter in a workers configuration.
     *
     * Observe that the worker isn't activated with this config until reload
     * is performed.
     *
     * @param workerId
     * @param key
     * @param value
     */
    @WebMethod(operationName = "setWorkerProperty")
    public void setWorkerProperty(
            @WebParam(name = "workerId") final int workerId,
            @WebParam(name = "key") final String key,
            @WebParam(name = "value") final String value)
            throws AdminNotAuthorizedException {
        requireAdminAuthorization("setWorkerProperty",
                String.valueOf(workerId), key);

        worker.setWorkerProperty(workerId, key, value);
    }

    /**
     * Removes a given worker's property.
     *
     * @param workerId
     * @param key
     * @return true if the property did exist and was removed othervise false
     */
    @WebMethod(operationName = "removeWorkerProperty")
    public boolean removeWorkerProperty(
            @WebParam(name = "workerId") final int workerId,
            @WebParam(name = "key") final String key)
            throws AdminNotAuthorizedException {
        requireAdminAuthorization("removeWorkerProperty",
                String.valueOf(workerId), key);
        
        return worker.removeWorkerProperty(workerId, key);
    }

    /**
     * Method that returns a collection of AuthorizedClient of
     * client certificate sn and issuerid accepted for a given signer.
     *
     * @param signerId
     * @return Sorted collection of authorized clients
     */
    @WebMethod(operationName = "getAuthorizedClients")
    public Collection<AuthorizedClient> getAuthorizedClients(
            @WebParam(name = "workerId") final int workerId)
            throws AdminNotAuthorizedException {
        requireAdminAuthorization("getAuthorizedClients",
                String.valueOf(workerId));
        
        return worker.getAuthorizedClients(workerId);
    }

    /**
     * Method adding an authorized client to a signer.

     * @param signerId
     * @param authClient
     */
    @WebMethod(operationName = "addAuthorizedClient")
    public void addAuthorizedClient(@WebParam(name = "workerId") final int workerId,
            @WebParam(name = "authClient") final AuthorizedClient authClient)
            throws AdminNotAuthorizedException {
        requireAdminAuthorization("addAuthorizedClient", 
                String.valueOf(workerId), authClient.getCertSN(),
                authClient.getIssuerDN());
        
        worker.addAuthorizedClient(workerId, authClient);
    }

    /**
     * Removes an authorized client from a signer.
     *
     * @param signerId
     * @param authClient
     */
    @WebMethod(operationName = "removeAuthorizedClient")
    public boolean removeAuthorizedClient(
            @WebParam(name = "workerId") final int workerId,
            @WebParam(name = "authClient") final AuthorizedClient authClient) 
            throws AdminNotAuthorizedException {
        requireAdminAuthorization("removeAuthorizedClient",
                String.valueOf(workerId), authClient.getCertSN(),
                authClient.getIssuerDN());
        
        return worker.removeAuthorizedClient(workerId, authClient);
    }

    /**
     * Method used to let a signer generate a certificate request
     * using the signers own genCertificateRequest method.
     *
     * @param signerId id of the signer
     * @param certReqInfo information used by the signer to create the request
     */
    @WebMethod(operationName = "getPKCS10CertificateRequest")
    public Base64SignerCertReqData getPKCS10CertificateRequest(
            @WebParam(name = "signerId") final int signerId,
            @WebParam(name = "certReqInfo") final PKCS10CertReqInfo certReqInfo)
            throws CryptoTokenOfflineException,
            InvalidWorkerIdException, AdminNotAuthorizedException {
        requireAdminAuthorization("getPKCS10CertificateRequest",
                String.valueOf(signerId));
        
        final ICertReqData data = worker.getCertificateRequest(signerId,
                certReqInfo);
        if (!(data instanceof Base64SignerCertReqData)) {
            throw new RuntimeException("Unsupported cert req data");
        }
        return (Base64SignerCertReqData) data;
    }

    /**
     * Method used to let a signer generate a certificate request
     * using the signers own genCertificateRequest method.
     *
     * @param signerId id of the signer
     * @param certReqInfo information used by the signer to create the request
     * @param defaultKey true if the default key should be used otherwise for
     * instance use next key.
     */
    @WebMethod(operationName = "getPKCS10CertificateRequestForKey")
    public Base64SignerCertReqData getPKCS10CertificateRequestForKey(
            @WebParam(name = "signerId") final int signerId,
            @WebParam(name = "certReqInfo") final PKCS10CertReqInfo certReqInfo,
            @WebParam(name = "defaultKey") final boolean defaultKey)
                throws CryptoTokenOfflineException, InvalidWorkerIdException,
                AdminNotAuthorizedException {
        requireAdminAuthorization("getPKCS10CertificateRequestForKey",
                String.valueOf(signerId));
        
        final ICertReqData data = worker.getCertificateRequest(signerId,
                certReqInfo, defaultKey);
        if (!(data instanceof Base64SignerCertReqData)) {
            throw new RuntimeException("Unsupported cert req data");
        }
        return (Base64SignerCertReqData) data;
    }

    /**
     * Method returning the current signing certificate for the signer.
     * @param signerId Id of signer
     * @return Current signing certificate if the worker is a signer and it has
     * been configured. Otherwise null or an exception is thrown.
     * @throws CryptoTokenOfflineException In case the crypto token or the worker
     * is not active
     */
    @WebMethod(operationName = "getSignerCertificate")
    public byte[] getSignerCertificate(
            @WebParam(name = "signerId") final int signerId)
            throws CryptoTokenOfflineException, AdminNotAuthorizedException {
        requireAdminAuthorization("getSignerCertificate",
                String.valueOf(signerId));
        
        return getEncoded(worker.getSignerCertificate(signerId));
    }

    private byte[] getEncoded(final Certificate certificate) {
        byte[] result = null;
        try {
            if (certificate != null) {
                result = certificate.getEncoded();
            }
        } catch (CertificateEncodingException ex) {
            LOG.error("Certificate encoding error", ex);
        }
        return result;
    }

    /**
     * Method returning the current signing certificate chain for the signer.
     * @param signerId Id of signer
     * @return Current signing certificate chain if the worker is a signer and it
     * has been configured. Otherwise null or an exception is thrown.
     * @throws CryptoTokenOfflineException In case the crypto token or the worker
     * is not active
     */
    @WebMethod(operationName = "getSignerCertificateChain")
    public List<byte[]> getSignerCertificateChain(
            @WebParam(name = "signerId") final int signerId)
            throws CryptoTokenOfflineException, AdminNotAuthorizedException {
        requireAdminAuthorization("getSignerCertificateChain",
                String.valueOf(signerId));
        
        final List<byte[]> result;
        final List<Certificate> certs
                = worker.getSignerCertificateChain(signerId);
        if (certs == null || certs.size() < 1) {
            result = null;
        } else {
            result = new LinkedList<byte[]>();
            for (Certificate cert : certs) {
                result.add(getEncoded(cert));
            }
        }
        return result;
    }

    /**
     * Gets the last date the specified worker can do signings.
     * @param workerId Id of worker to check.
     * @return The last date or null if no last date (=unlimited).
     * @throws CryptoTokenOfflineException In case the cryptotoken is offline
     * for some reason.
     */
    @WebMethod(operationName = "getSigningValidityNotAfter")
    public Date getSigningValidityNotAfter(
            @WebParam(name = "workerId") final int workerId)
            throws CryptoTokenOfflineException, AdminNotAuthorizedException {
        requireAdminAuthorization("getSigningValidityNotAfter",
                String.valueOf(workerId));
        
        return worker.getSigningValidityNotAfter(workerId);
    }

    /**
     * Gets the first date the specified worker can do signings.
     * @param workerId Id of worker to check.
     * @return The first date or null if no last date (=unlimited).
     * @throws CryptoTokenOfflineException In case the cryptotoken is offline
     * for some reason.
     */
    @WebMethod(operationName = "getSigningValidityNotBefore")
    public Date getSigningValidityNotBefore(
            @WebParam(name = "workerId") final int workerId)
            throws CryptoTokenOfflineException, AdminNotAuthorizedException {
        requireAdminAuthorization("getSigningValidityNotBefore", 
                String.valueOf(workerId));
        
        return worker.getSigningValidityNotBefore(workerId);
    }

    /**
     * Method used to remove a key from a signer.
     *
     * @param signerId id of the signer
     * @param purpose on of ICryptoToken.PURPOSE_ constants
     * @return true if removal was successful.
     */
    @WebMethod(operationName = "destroyKey")
    public boolean destroyKey(@WebParam(name = "signerId") final int signerId,
            @WebParam(name = "purpose") final int purpose)
            throws InvalidWorkerIdException, AdminNotAuthorizedException {
        requireAdminAuthorization("destroyKey", String.valueOf(signerId));
        
        return worker.destroyKey(signerId, purpose);
    }

    /**
     * Generate a new keypair.
     * @param signerId Id of signer
     * @param keyAlgorithm Key algorithm
     * @param keySpec Key specification
     * @param alias Name of the new key
     * @param authCode Authorization code
     * @throws CryptoTokenOfflineException
     * @throws IllegalArgumentException
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
        requireAdminAuthorization("generateSignerKey", String.valueOf(signerId),
                keyAlgorithm, keySpec, alias);
        
        return worker.generateSignerKey(signerId, keyAlgorithm, keySpec, alias,
                authCode.toCharArray());
    }

    /**
     * Tests the key identified by alias or all keys if "all" specified.
     *
     * @param signerId Id of signer
     * @param alias Name of key to test or "all" to test all available
     * @param authCode Authorization code
     * @return Collection with test results for each key
     * @throws CryptoTokenOfflineException
     * @throws KeyStoreException
     */
    @WebMethod(operationName = "testKey")
    public Collection<KeyTestResult> testKey(
            @WebParam(name = "signerId") final int signerId,
            @WebParam(name = "alias") final String alias,
            @WebParam(name = "authCode") final String authCode)
            throws CryptoTokenOfflineException,
            InvalidWorkerIdException, KeyStoreException,
            AdminNotAuthorizedException {
        requireAdminAuthorization("testKey", String.valueOf(signerId), alias);

        // Workaround for KeyTestResult first placed in wrong package
        final Collection<KeyTestResult> results;
	Collection<?> res = worker.testKey(signerId, alias, authCode.toCharArray());
	if (res.size() < 1) {
            results = new LinkedList<KeyTestResult>();
        } else {
            if (res.iterator().next() instanceof org.signserver.server.KeyTestResult) {
                results = new LinkedList<KeyTestResult>();
                for (Object res0 : res) {
                    final org.signserver.server.KeyTestResult res1
                            = (org.signserver.server.KeyTestResult) res0;
                    final KeyTestResult res2 = new KeyTestResult(
                            res1.getAlias(), res1.isSuccess(),
                            res1.getStatus(), res1.getPublicKeyHash());
                    results.add(res2);
                }
            } else {
                results = (Collection<KeyTestResult>) res;
            }
        }

        return results;
    }

    /**
     * Method used to upload a certificate to a signers active configuration.
     *
     * @param signerId id of the signer
     * @param signerCert the certificate used to sign signature requests
     * @param scope one of GlobalConfiguration.SCOPE_ constants
     */
    @WebMethod(operationName = "uploadSignerCertificate")
    public void uploadSignerCertificate(
            @WebParam(name = "signerId") final int signerId,
            @WebParam(name = "signerCert") final byte[] signerCert,
            @WebParam(name = "scope") final String scope)
            throws IllegalRequestException, AdminNotAuthorizedException {
        requireAdminAuthorization("uploadSignerCertificate",
                String.valueOf(signerId));
        
        try {
            final X509Certificate cert = getX509Certificate(signerCert);
            worker.uploadSignerCertificate(signerId, cert, scope);
        } catch (CertificateException ex) {
            // Log stacktrace and only pass on description to client
            LOG.error("Unable to parse certificate", ex);
            throw new IllegalRequestException("Unable to parse certificate");
        }
    }

    private X509Certificate getX509Certificate(byte[] certbytes)
            throws CertificateException {
        final X509Certificate result;
        if (certbytes == null || certbytes.length == 0) {
            result = null;
        } else {
            try {
                final CertificateFactory cf
                        = CertificateFactory.getInstance("X.509", "BC");
                result = (X509Certificate) cf.generateCertificate(
                        new ByteArrayInputStream(certbytes));
            } catch (NoSuchProviderException ex) {
                // Log stacktrace and only pass on description to client
                LOG.error("Error with provider", ex);
                throw new RuntimeException("Internal error");
            }
        }
        return result;
    }

    /**
     * Method used to upload a complete certificate chain to a configuration
     *
     * @param signerId id of the signer
     * @param signerCerts the certificate chain used to sign signature requests
     * @param scope one of GlobalConfiguration.SCOPE_ constants
     */
    @WebMethod(operationName = "uploadSignerCertificateChain")
    public void uploadSignerCertificateChain(
            @WebParam(name = "signerId") final int signerId,
            @WebParam(name = "signerCerts") final List<byte[]> signerCerts,
            @WebParam(name = "scope") final String scope)
                throws IllegalRequestException, AdminNotAuthorizedException {
        requireAdminAuthorization("uploadSignerCertificateChain",
                String.valueOf(signerId));
        
        try {
            final List<Certificate> certs = new LinkedList<Certificate>();

            for (byte[] signerCert : signerCerts) {
                final Certificate cert;
                if (signerCert == null || signerCert.length == 0) {
                    cert = null;
                } else {
                    cert = getX509Certificate(signerCert);
                }
                certs.add(cert);
            }
            worker.uploadSignerCertificateChain(signerId, certs, scope);
        } catch (CertificateException ex) {
            // Log stacktrace and only pass on description to client
            LOG.error("Unable to parse certificate", ex);
            throw new IllegalRequestException("Unable to parse certificate");
        }
    }

    /**
     * Method setting a global configuration property. For node. prefix will the
     * node id be appended.
     * @param scope one of the GlobalConfiguration.SCOPE_ constants
     * @param key of the property should not have any scope prefix, never null
     * @param value the value, never null.
     */
    @WebMethod(operationName = "setGlobalProperty")
    public void setGlobalProperty(
            @WebParam(name = "scope") final String scope,
            @WebParam(name = "key") final String key,
            @WebParam(name = "value") final String value)
            throws AdminNotAuthorizedException {
        requireAdminAuthorization("setGlobalProperty", key);
        
        global.setProperty(scope, key, value);
    }

    /**
     * Method used to remove a property from the global configuration.
     * @param scope one of the GlobalConfiguration.SCOPE_ constants
     * @param key of the property should start with either glob. or node.,
     * never null
     * @return true if removal was successful, othervise false.
     */
    @WebMethod(operationName = "removeGlobalProperty")
    public boolean removeGlobalProperty(
            @WebParam(name = "scope") final String scope,
            @WebParam(name = "key") final String key)
            throws AdminNotAuthorizedException {
        requireAdminAuthorization("removeGlobalProperty", key);
        
        return global.removeProperty(scope, key);
    }

    /**
     * Method that returns all the global properties with Global Scope and Node
     * scopes properties for this node.
     * @return A GlobalConfiguration Object, never null
     */
    @WebMethod(operationName = "getGlobalConfiguration")
    public WSGlobalConfiguration getGlobalConfiguration()
            throws AdminNotAuthorizedException {
        requireAdminAuthorization("getGlobalConfiguration");
        
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
            result.setClusterClassLoaderEnabled(
                    GlobalConfiguration.isClusterClassLoaderEnabled());
            result.setRequireSigning(GlobalConfiguration.isRequireSigning());
            result.setUseClassVersions(GlobalConfiguration.isUseClassVersions());
        }
        return result;
    }

    /**
     * Help method that returns all worker, either signers or services defined
     * in the global configuration.
     * @param workerType can either be GlobalConfiguration.WORKERTYPE_ALL,
     * _SIGNERS or _SERVICES
     * @return A List if Integers of worker Ids, never null.
     */
    @WebMethod(operationName = "getWorkers")
    public List<Integer> getWorkers(
            @WebParam(name = "workerType") final int workerType)
                throws AdminNotAuthorizedException {
        requireAdminAuthorization("getWorkers", String.valueOf(workerType));
        
        return global.getWorkers(workerType);
    }

    /**
     * Method that is used after a database crash to restore all cached data to
     * database.
     * @throws ResyncException if resync was unsuccessfull
     */
    @WebMethod(operationName = "globalResync")
    public void globalResync() throws ResyncException, AdminNotAuthorizedException {
        requireAdminAuthorization("globalResync");
        
        global.resync();
    }

    /**
     * Method to reload all data from database.
     */
    @WebMethod(operationName = "globalReload")
    public void globalReload() throws AdminNotAuthorizedException {
        requireAdminAuthorization("globalReload");
        
        global.reload();
    }

    private void requireAdminAuthorization(final String operation,
            final String... args) throws AdminNotAuthorizedException {
        LOG.debug(">requireAdminAuthorization");

        final HttpServletRequest req =
                (HttpServletRequest) wsContext.getMessageContext()
                .get(MessageContext.SERVLET_REQUEST);
        final X509Certificate[] certificates =
                (X509Certificate[]) req.getAttribute(
                    "javax.servlet.request.X509Certificate");
        if (certificates == null || certificates.length == 0) {
            throw new AdminNotAuthorizedException(
                    "Administrator not authorized to resource. "
                    + "Client certificate authentication required.");
        } else {
           final boolean authorized = isAdminAuthorized(certificates[0],
                   operation);

           log(certificates[0], authorized, operation, args);

           if (!authorized) {
               throw new AdminNotAuthorizedException(
                       "Administrator not authorized to resource.");
           }
        }
    }

    private void log(final X509Certificate certificate, 
            final boolean authorized, final String operation,
            final String... args) {
        final StringBuilder line = new StringBuilder()
                .append("ADMIN OPERATION")
                .append("; ")
                
                .append("subjectDN=")
                .append(certificate.getSubjectDN().getName())
                .append("; ")
                
                .append("serialNumber=")
                .append(certificate.getSerialNumber().toString(16))
                .append("; ")
                
                .append("issuerDN=")
                .append(certificate.getIssuerDN().getName())
                .append("; ")
                
                .append("authorized=")
                .append(authorized)
                .append("; ")
                
                .append("operation=")
                .append(operation)
                .append("; ")
                
                .append("arguments=");
        for (String arg : args) {
            line.append(arg.replace(";", "\\;").replace("=", "\\="));
            line.append(",");
        }
        line.append(";");
        LOG.info(line.toString());
    }

    private boolean isAdminAuthorized(final X509Certificate cert,
            final String operation) {
        boolean authorized = false;
        final String admins = global.getGlobalConfiguration().getProperty(
                GlobalConfiguration.SCOPE_GLOBAL, "WSADMINS");
        final String admin = cert.getSerialNumber().toString(16) + "," +
                cert.getIssuerDN();

        if (LOG.isDebugEnabled()) {
            LOG.debug("admin: " + admin + ", admins: " + admins);
        }

        if (admins == null) {
            LOG.warn("No WSADMINS global property set");
        } else {
            for (String entry : admins.split(";")) {
                if (entry.trim().equalsIgnoreCase(admin)) {
                    authorized = true;
                    break;
                }
            }
        }
        return authorized;
    }

    // "Insert Code > Add Web Service Operation")
}
