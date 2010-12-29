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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.Socket;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Enumeration;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import javax.ejb.EJB;
import javax.naming.NamingException;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509KeyManager;

import javax.persistence.EntityManager;
import javax.xml.namespace.QName;

import org.apache.log4j.Logger;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.x509.X509CertStoreSelector;
import org.ejbca.util.CertTools;
import org.signserver.common.Base64SignerCertReqData;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.GenericPropertiesRequest;
import org.signserver.common.GenericPropertiesResponse;
import org.signserver.common.GenericServletRequest;
import org.signserver.common.GenericServletResponse;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.GenericSignResponse;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.KeyTestResult;
import org.signserver.common.PKCS10CertReqInfo;
import org.signserver.common.ProcessRequest;
import org.signserver.common.ProcessResponse;
import org.signserver.common.RequestContext;
import org.signserver.common.ServiceLocator;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.common.util.RandomPasswordGenerator;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.module.renewal.common.RenewalWorkerProperties;
import org.signserver.module.renewal.ejbcaws.gen.CertificateResponse;
import org.signserver.module.renewal.ejbcaws.gen.EjbcaWS;
import org.signserver.module.renewal.ejbcaws.gen.EjbcaWSService;
import org.signserver.module.renewal.ejbcaws.gen.UserDataVOWS;
import org.signserver.module.renewal.ejbcaws.gen.UserMatch;
import org.signserver.server.WorkerContext;
import org.signserver.server.log.IWorkerLogger;
import org.signserver.server.signers.BaseSigner;

/**
 * Worker renewing certificate (and optionally keys) for a signer by sending
 * a certificate signing request using the EJBCA Web Service interface.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class RenewalWorker extends BaseSigner {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(RenewalWorker.class);

    public static final String PROPERTY_RENEWENDENTITY = "RENEWENDENTITY";
    public static final String PROPERTY_REQUESTDN = "REQUESTDN";
    public static final String PROPERTY_SIGNATUREALGORITHM
            = "SIGNATUREALGORITHM";
    public static final String PROPERTY_KEYALG = "KEYALG";
    public static final String PROPERTY_KEYSPEC = "KEYSPEC";
    public static final String PROPERTY_EXPLICITECC = "EXPLICITECC";
    private static final String NEXTCERTSIGNKEY = "NEXTCERTSIGNKEY";

    WorkerConfig config;
    private static final String TRUSTSTORE_TYPE_PEM = "PEM";
    private static final String TRUSTSTORE_TYPE_KEYSTORE = "JKS";

    private static final String WS_PATH = "/ejbcaws/ejbcaws?wsdl";

    private static final int MATCH_WITH_USERNAME = 0;
    private static final int MATCH_TYPE_EQUALS = 0;
    private static final int STATUS_NEW = 10;

    // From CertificateHelper:
    /**
     * Indicates that the requester want a BASE64 encoded certificate in the
     * CertificateResponse object.
     */
    private static String RESPONSETYPE_CERTIFICATE    = "CERTIFICATE";
    /**
     * Indicates that the requester want a BASE64 encoded pkcs7 in the
     * CertificateResponse object.
     */
    private static String RESPONSETYPE_PKCS7          = "PKCS7";
    /**
     * Indicates that the requester want a BASE64 encoded pkcs7 with the
     * complete chain in the CertificateResponse object.
     */
    private static String RESPONSETYPE_PKCS7WITHCHAIN = "PKCS7WITHCHAIN";

    /** Workersession. */
    @EJB
    private IWorkerSession.IRemote workerSession;

    @Override
    public void init(final int workerId, final WorkerConfig config,
            final WorkerContext workerContext, final EntityManager workerEM) {
        super.init(workerId, config, workerContext, workerEM);
        this.config = config;
        getWorkerSession();
    }

    public ProcessResponse processData(final ProcessRequest request,
            final RequestContext requestContext) throws IllegalRequestException,
            CryptoTokenOfflineException, SignServerException {

        final ProcessResponse ret;
        final Properties requestData, responseData;


        // Check that the request contains a valid request
        if (request instanceof GenericPropertiesRequest) {
            requestData = ((GenericPropertiesRequest) request).getProperties();
        } else if (request instanceof GenericSignRequest) {
            requestData = new Properties();
            try {
                requestData.load(new ByteArrayInputStream(
                    ((GenericSignRequest) request).getRequestData()));
            } catch (IOException ex) {
                LOG.error("Error in request: "
                        + requestContext.get(RequestContext.TRANSACTION_ID),
                        ex);
                throw new IllegalRequestException("Error parsing request. "
                        + "See server log for information.");
            }
        } else {
            throw new IllegalRequestException(
                "Recieved request was not of expected type.");
        }

        // Log values
        final Map<String, String> logMap =
                (Map<String, String>) requestContext.get(RequestContext.LOGMAP);

        responseData = process(requestData, logMap);

        // Log result
        logMap.put(RenewalWorkerProperties.LOG_RESPONSE_RESULT,
                responseData.getProperty(RenewalWorkerProperties
                    .RESPONSE_RESULT));
        logMap.put(RenewalWorkerProperties.LOG_RESPONSE_MESSAGE,
                responseData.getProperty(RenewalWorkerProperties
                    .RESPONSE_MESSAGE));

        if (request instanceof GenericSignRequest) {
            final GenericSignRequest signRequest =
                    (GenericServletRequest) request;
            try {
                final ByteArrayOutputStream bout = new ByteArrayOutputStream();
                responseData.store(bout, null);
                if (request instanceof GenericServletRequest) {
                    ret = new GenericServletResponse(signRequest.getRequestID(),
                        bout.toByteArray(), null, null, null, "text/plain");
                } else {
                    ret = new GenericSignResponse(signRequest.getRequestID(),
                        signRequest.getRequestData(), null, null, null);
                }
            } catch (IOException ex) {
                LOG.error("Error constructing response for request: "
                        + requestContext.get(RequestContext.TRANSACTION_ID),
                        ex);
                throw new SignServerException("Error constructing response."
                        + "See server log for information.");
            }
        } else {
            ret = new GenericPropertiesResponse(responseData);
        }

        return ret;
    }

    /**
     * Processes the request.
     * @param requestData
     * @return
     * @throws IllegalRequestException
     * @throws CryptoTokenOfflineException
     * @throws SignServerException
     */
    private Properties process(final Properties requestData,
                final Map<String, String> logMap)
            throws IllegalRequestException, CryptoTokenOfflineException,
            SignServerException {
        final String workerName = requestData.getProperty(
                RenewalWorkerProperties.REQUEST_WORKER);

        final Properties responseData;
        final ProcessResponse ret;

        if (workerName == null) {
            throw new IllegalRequestException("No worker name in request.");
        }

        responseData = new Properties();

        // Log renewee
        logMap.put(RenewalWorkerProperties.LOG_RENEWEE, workerName);

        try {
            final int reneweeId = getWorkerSession().getWorkerId(workerName);

            // Get the worker config
            final WorkerConfig workerConfig
                    = getWorkerSession().getCurrentWorkerConfig(reneweeId);
            final String sigAlg = workerConfig.getProperty(
                    PROPERTY_SIGNATUREALGORITHM);
            final String subjectDN = workerConfig.getProperty(
                    PROPERTY_REQUESTDN);
            final String endEntity = workerConfig.getProperty(
                    PROPERTY_RENEWENDENTITY);
            final String keyAlg = workerConfig.getProperty(
                    PROPERTY_KEYALG);
            final String keySpec = workerConfig.getProperty(
                    PROPERTY_KEYSPEC);
            final String explicitEccParameters = workerConfig.getProperty(
                    PROPERTY_EXPLICITECC, String.valueOf(false));
            String nextCertSignKey
                    = workerConfig.getProperty(NEXTCERTSIGNKEY);

            // If we should use the default key (instead of nextKey,
            // if existing) can be specified in the request (but only if we
            // don't generate a new key)
            final String forDefaultKeyValue = requestData.getProperty(
                    RenewalWorkerProperties.REQUEST_FORDEFAULTKEY,
                    Boolean.FALSE.toString());
            boolean requestForDefaultKey = false;
            if (forDefaultKeyValue != null && !forDefaultKeyValue.isEmpty()) {
                requestForDefaultKey = Boolean.parseBoolean(forDefaultKeyValue);
            }

            final boolean renewKey = !requestForDefaultKey 
                    && nextCertSignKey == null;

            final String authCode = requestData.getProperty(
                    RenewalWorkerProperties.REQUEST_AUTHCODE);

            if (LOG.isDebugEnabled()) {
                final StringBuilder buff = new StringBuilder();
                buff.append("Renewer");
                buff.append("[");
                buff.append(workerId);
                buff.append("]: ");
                buff.append("Got request for renewal of Worker");
                buff.append("[");
                buff.append(reneweeId);
                buff.append("]: ");
                buff.append("\n");

                buff.append("Transaction:");
                buff.append("\n\t");
                buff.append("LOG_ID: ");
                buff.append(logMap.get(IWorkerLogger.LOG_ID));
                buff.append("\n");
                
                buff.append("Renewee config:");
                buff.append("\n\t");

                buff.append(PROPERTY_SIGNATUREALGORITHM);
                buff.append("=");
                buff.append(sigAlg);
                buff.append("\n\t");

                buff.append(PROPERTY_REQUESTDN);
                buff.append("=");
                buff.append(subjectDN);
                buff.append("\n\t");

                buff.append(PROPERTY_KEYALG);
                buff.append("=");
                buff.append(keyAlg);
                buff.append("\n\t");

                buff.append(PROPERTY_KEYSPEC);
                buff.append("=");
                buff.append(keySpec);
                buff.append("\n\t");

                buff.append(PROPERTY_EXPLICITECC);
                buff.append("=");
                buff.append(explicitEccParameters);
                buff.append("\n\t");

                buff.append(PROPERTY_RENEWENDENTITY);
                buff.append("=");
                buff.append(endEntity);
                buff.append("\n");

                buff.append("Request config:");
                buff.append("\n\t");

                buff.append(RenewalWorkerProperties.REQUEST_FORDEFAULTKEY);
                buff.append("=");
                buff.append(requestForDefaultKey);
                buff.append("\n\t");

                buff.append(RenewalWorkerProperties.REQUEST_AUTHCODE);
                buff.append("=");
                if (authCode == null) {
                    buff.append("null");
                } else {
                    final char[] masked = new char[authCode.length()];
                    Arrays.fill(masked, '*');
                    buff.append(new String(masked));
                }

                LOG.debug(buff.toString());
            }

            if (endEntity == null || endEntity.isEmpty()) {
                renewalFailure(responseData,
                        "Property ENDENTITY not specified for worker: "
                        + workerName);
            } else if (subjectDN == null || subjectDN.isEmpty()) {
                renewalFailure(responseData,
                        "Property REQUESTDN not specified for worker: "
                        + workerName);
            } else if (sigAlg == null || sigAlg.isEmpty()) {
                renewalFailure(responseData,
                        "Property SIGNATUREALGORITHM not specified for worker: "
                        + workerName);
            } else if (renewKey && (keyAlg == null || keyAlg.isEmpty())) {
                renewalFailure(responseData,
                        "Property KEYALG not specified for worker: "
                        + workerName);
            } else if (renewKey && (keySpec == null || keySpec.isEmpty())) {
                renewalFailure(responseData,
                        "Property KEYSPEC not specified for worker: "
                        + workerName);
            } else {
                final boolean defaultKey;

                // (Renew key if specified in request)
                // OR (if specified in worker but not denied in request)
                if (renewKey) {
                    // If we renew the key then we want to use that key
                    defaultKey = false;
                    LOG.debug("Will renew key");

                    // Renew the key
                    nextCertSignKey = renewKey(reneweeId, keyAlg, keySpec,
                            authCode == null ? null : authCode.toCharArray(),
                            logMap);
                } else {
                    // Request might say that we should use the default key
                    defaultKey = requestForDefaultKey;
                    LOG.debug("Use default key: " + defaultKey);
                }

                // Renew worker
                renewWorker(reneweeId, sigAlg, keyAlg, endEntity,
                        Boolean.valueOf(explicitEccParameters),
                        defaultKey, nextCertSignKey, authCode.toCharArray(),
                        logMap);

                responseData.setProperty(
                        RenewalWorkerProperties.RESPONSE_RESULT,
                        RenewalWorkerProperties.RESPONSE_RESULT_OK);
            }

        } catch (Exception ex) {
            renewalFailure(responseData, ex.getMessage(), ex);
        }

        return responseData;
    }

    private String renewKey(final int workerId, final String keyAlg,
           final String keySpec, final char[] authcode,
           final Map<String, String> logMap) throws Exception {
        LOG.debug("<renewKey");

        if (authcode == null) {
            throw new IllegalArgumentException("Missing authcode in request");
        }

        final String newAlias = getWorkerSession().generateSignerKey(workerId,
                keyAlg, keySpec, null, authcode);

        // Log
        logMap.put(RenewalWorkerProperties.LOG_GENERATEDKEYALIAS, newAlias);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Generated new key: " + newAlias);
        }

        final Collection<KeyTestResult> results = getWorkerSession().testKey(
                workerId, newAlias, authcode);
        if (results.size() != 1) {
            throw new CryptoTokenOfflineException("Key testing failed: "
                    + "No result");
        }

        final KeyTestResult result = results.iterator().next();
        if (LOG.isDebugEnabled()) {
            LOG.debug("Key test result: " + result);
        }
        if (result.isSuccess()) {
            // Log
            logMap.put(RenewalWorkerProperties.LOG_GENERATEDKEYHASH, 
                    result.getPublicKeyHash());

            getWorkerSession().setWorkerProperty(workerId, NEXTCERTSIGNKEY,
                    newAlias);
            getWorkerSession().reloadConfiguration(workerId);

            LOG.debug("Key generated, tested and set");

            getWorkerSession().activateSigner(workerId,
                    String.valueOf(authcode));

            LOG.debug("Worker activated");
            LOG.debug(">renewKey");
            return newAlias;
        } else {
            throw new CryptoTokenOfflineException("Key testing failed: "
                    + result.getStatus());
        }
    }

    private void renewWorker(final int workerId, 
            final String sigAlg, final String subjectDN, final String endEntity,
            final boolean explicitEccParameters,
            final boolean defaultKey, final String nextCertSignKey, 
            final char[] authCode, final Map<String, String> logMap)
            throws Exception {

        final String pkcs10
                = createRequestPEM(workerId, sigAlg, subjectDN, 
                explicitEccParameters, defaultKey);

        if (LOG.isDebugEnabled()) {
            LOG.debug("PKCS10: " + pkcs10);
        }

        // Connect to EjbcaWS
        final String alias = config.getProperty("DEFAULTKEY");
//        if (alias == null) {
//            throw new IllegalArgumentException(
//                    "Missing DEFAULTKEY property");
//        }

        final String truststoreType = config.getProperty("TRUSTSTORETYPE");
        if (truststoreType == null) {
            throw new IllegalArgumentException(
                    "Missing TRUSTSTORETYPE property");
        }
        final String truststorePath = config.getProperty("TRUSTSTOREPATH");
        if (truststorePath == null) {
            throw new IllegalArgumentException(
                    "Missing TRUSTSTOREPATH property");
        }

        final String truststorePass = config.getProperty("TRUSTSTOREPASSWORD");
        if (truststorePass == null) {
            throw new IllegalArgumentException(
                    "Missing TRUSTSTOREPASSWORD property");
        }

        final String ejbcaWsUrl = config.getProperty("EJBCAWSURL");
        if (ejbcaWsUrl == null) {
            throw new IllegalArgumentException("Missing EJBCAWSURL property");
        }
        final EjbcaWS ejbcaws = getEjbcaWS(ejbcaWsUrl,
                alias, truststoreType, truststorePath, truststorePass, authCode);

        if (ejbcaws == null) {
            LOG.debug("Could not get EjbcaWS");
        } else {
            LOG.debug("Got EjbcaWS");

            final UserMatch usermatch = new UserMatch();
            usermatch.setMatchwith(MATCH_WITH_USERNAME);
            usermatch.setMatchtype(MATCH_TYPE_EQUALS);
            usermatch.setMatchvalue(endEntity);
            final List<UserDataVOWS> result = ejbcaws.findUser(usermatch);
            if (LOG.isDebugEnabled()) {
                LOG.debug("Got users: " + result);
            }
            if (result.isEmpty()) {
                throw new IllegalArgumentException(
                        "End entity not found in EJBCA: " + endEntity);
            } else {
                // Update user with status and new password
                final UserDataVOWS user1 = result.get(0);
                final char[] password = RandomPasswordGenerator
                        .getInstance().generate(20);
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Changing to status to NEW from "
                            + user1.getStatus()
                            + " for end entity " + endEntity + ".");
                }
                user1.setStatus(STATUS_NEW);
                user1.setPassword(new String(password));
                ejbcaws.editUser(user1);

                // Send request to CA
                final CertificateResponse resp
                        = ejbcaws.pkcs10Request(endEntity, new String(password),
                        pkcs10, null, RESPONSETYPE_PKCS7WITHCHAIN);

                RandomPasswordGenerator.getInstance().fill(password);

                final String b64Cert = new String(resp.getData());
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Got PKCS7: " + b64Cert);
                }

                final CMSSignedData signedData = new CMSSignedData(
                        Base64.decode(b64Cert));
                final CertStore certStore
                        = signedData.getCertificatesAndCRLs("Collection", "BC");

                final List<Certificate> certChain
                        = getCertificateChain(certStore.getCertificates(
                            new X509CertStoreSelector()));
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Got certificates: " + certChain);
                }

                final X509Certificate signerCert
                        = getEndEntityCertificate(certChain);
                if (LOG.isDebugEnabled()) {
                    LOG.debug("New certificate subject DN: "
                            + signerCert.getSubjectDN());
                }

                // Log
                logMap.put(RenewalWorkerProperties.LOG_NEWCERTISSUERDN,
                        signerCert.getIssuerDN().getName());
                logMap.put(RenewalWorkerProperties.LOG_NEWCERTSERIALNO,
                        signerCert.getSerialNumber().toString(16));
                logMap.put(RenewalWorkerProperties.LOG_NEWCERTSUBJECTDN,
                        signerCert.getSubjectDN().getName());

                // TODO: Check the certificate
                    // Public key should match

                // Update worker to use the new certificate
                getWorkerSession().uploadSignerCertificate(workerId,
                        signerCert.getEncoded(),
                        GlobalConfiguration.SCOPE_GLOBAL);
                getWorkerSession().uploadSignerCertificateChain(workerId,
                        getCertificateChainBytes(certChain),
                        GlobalConfiguration.SCOPE_GLOBAL);

                // If not the default key we need to promote the key
                // Set DEFAULTKEY to NEXTCERTSIGNKEY
                if (defaultKey) {
                    LOG.debug("Uploaded was for DEFAULTKEY");
                } else if (!defaultKey && nextCertSignKey != null) {
                    LOG.debug("Uploaded was for NEXTCERTSIGNKEY");

                   getWorkerSession().setWorkerProperty(workerId, "DEFAULTKEY",
                           nextCertSignKey);
                   getWorkerSession().removeWorkerProperty(workerId,
                           NEXTCERTSIGNKEY);
                }

                getWorkerSession().reloadConfiguration(workerId);
                LOG.debug("New configuration applied");
            }
        }
    }

    private IWorkerSession.IRemote getWorkerSession() {
        if (workerSession == null) {
            try {
                workerSession = ServiceLocator.getInstance().lookupRemote(
                    IWorkerSession.IRemote.class);
            } catch (NamingException ex) {
                throw new RuntimeException("Unable to lookup worker session",
                        ex);
            }
        }
        return workerSession;
    }

    private String createRequestPEM(int workerId, final String sigAlg, 
            final String subjectDN, final boolean explicitEccParameters,
            final boolean defaultKey)
            throws CryptoTokenOfflineException, InvalidWorkerIdException {
        final PKCS10CertReqInfo certReqInfo = new PKCS10CertReqInfo(sigAlg,
                subjectDN, null);
        final Base64SignerCertReqData reqData
                = (Base64SignerCertReqData) getWorkerSession()
                .getCertificateRequest(workerId, certReqInfo, explicitEccParameters, defaultKey);
        if (reqData == null) {
            throw new RuntimeException(
                    "Base64SignerCertReqData returned was null."
                    + " Unable to generate certificate request.");
        }

        final StringBuilder buff = new StringBuilder();
        buff.append("-----BEGIN CERTIFICATE REQUEST-----\n");
        buff.append(new String(reqData.getBase64CertReq()));
        buff.append("\n-----END CERTIFICATE REQUEST-----\n");
        return buff.toString();
    }

    private EjbcaWS getEjbcaWS(final String ejbcaUrl, final String alias,
            final String truststoreType, final String truststorePath,
            final String truststorePass, final char[] authcode) throws CryptoTokenOfflineException,
            NoSuchAlgorithmException, KeyStoreException,
            UnrecoverableKeyException, IOException, CertificateException,
            NoSuchProviderException, KeyManagementException {

        EjbcaWS result = null;

        final String urlstr = ejbcaUrl + WS_PATH;

        final KeyStore keystore = getCryptoToken().getKeyStore();

        // TODO: Check that keystore contains key with the specified alias
        LOG.info("aliases in keystore follows:");
        Enumeration<String> e = keystore.aliases();
        while(e.hasMoreElements()) {
            LOG.info("alias: " + e.nextElement());
        }

        final KeyManagerFactory kKeyManagerFactory
                = KeyManagerFactory.getInstance("SunX509");
        kKeyManagerFactory.init(keystore, null);
        final KeyStore keystoreTrusted;

        if (TRUSTSTORE_TYPE_PEM.equals(truststoreType)) {
            keystoreTrusted = KeyStore.getInstance("JKS");
            keystoreTrusted.load(null, null);
            final Collection certs = CertTools.getCertsFromPEM(
                    new FileInputStream(truststorePath));
            int i = 0;
            for (Object o : certs) {
                if (o instanceof Certificate) {
                    keystoreTrusted.setCertificateEntry("cert-" + i,
                            (Certificate) o);
                    i++;
                }
            }
            if (LOG.isDebugEnabled()) {
                LOG.debug("Loaded " + i + " certs to truststore");
            }
        } else {
            keystoreTrusted = KeyStore.getInstance(truststoreType, "BC");
            keystoreTrusted.load(new FileInputStream(truststorePath),
                    truststorePass.toCharArray());
        }
        final TrustManagerFactory tTrustManagerFactory
                = TrustManagerFactory.getInstance("SunX509");
        tTrustManagerFactory.init(keystoreTrusted);
        KeyManager[] keyManagers = kKeyManagerFactory.getKeyManagers();
        for (int i = 0; i < keyManagers.length; i++) {
            if (keyManagers[i] instanceof X509KeyManager) {
                keyManagers[i] = new AliasKeyManager(
                        (X509KeyManager) keyManagers[i], alias);
            }
        }
        // Now construct a SSLContext using these (possibly wrapped)
        // KeyManagers, and the TrustManagers. We still use a null
        // SecureRandom, indicating that the defaults should be used.
        final SSLContext context = SSLContext.getInstance("TLS");
        context.init(keyManagers, tTrustManagerFactory.getTrustManagers(),
                new SecureRandom());
        // Finally, we get a SocketFactory, and pass it to SimpleSSLClient.
        SSLSocketFactory factory = context.getSocketFactory();
        HttpsURLConnection.setDefaultSSLSocketFactory(factory); // TODO: This could if multiple renewal workers are used
        LOG.info("Getting WS");
        EjbcaWSService service = new EjbcaWSService(new URL(urlstr), 
                new QName("http://ws.protocol.core.ejbca.org/",
                "EjbcaWSService"));
        result = service.getEjbcaWSPort();

        return result;
    }

    // TODO: We are assuming here that a CA certificate is not used for signing
    private static X509Certificate getEndEntityCertificate(
            final Collection<? extends Certificate> certs) {
        X509Certificate result = null;
        for (Certificate cert : certs) {
            if (cert instanceof X509Certificate) {
                final X509Certificate x509 = (X509Certificate) cert;
                // If not CA certificate
                if (x509.getBasicConstraints() == -1) {
                    result = x509;
                    break;
                }
            }
        }
        return result;
    }

    // TODO: We are not ordering this chain and assumes that is not important
    private static List<Certificate> getCertificateChain(
            final Collection<? extends Certificate> certs) {
        final LinkedList<Certificate> result = new LinkedList<Certificate>();
        for (Certificate cert : certs) {
            result.add(cert);
        }
        return result;
    }

    private static List<byte[]> getCertificateChainBytes(
            final Collection<? extends Certificate> certs)
            throws CertificateEncodingException {
        final LinkedList<byte[]> result = new LinkedList<byte[]>();
        for (Certificate cert : certs) {
            result.add(cert.getEncoded());
        }
        return result;
    }

    private String getPEMCerts(Collection<? extends Certificate> certs)
            throws CertificateEncodingException {
        final StringBuilder buff = new StringBuilder();
        for (Certificate cert : certs) {
            buff.append(CertTools.BEGIN_CERTIFICATE);
            buff.append(new String(Base64.encode(cert.getEncoded())));
            buff.append(CertTools.END_CERTIFICATE);
        }
        return buff.toString();
    }

    private void renewalFailure(final Properties responseData,
            final String message) {
        renewalFailure(responseData, message, null);
    }

    private void renewalFailure(final Properties responseData,
            final String message, final Throwable ex) {
        LOG.error(message, ex);
        responseData.setProperty(RenewalWorkerProperties.RESPONSE_RESULT,
                RenewalWorkerProperties.RESPONSE_RESULT_FAILURE);
        responseData.setProperty(RenewalWorkerProperties.RESPONSE_MESSAGE,
                message);
    }

    class AliasKeyManager implements X509KeyManager {

        private final X509KeyManager base;
        private final String alias;

        public AliasKeyManager(final X509KeyManager base, final String alias) {
            this.base = base;
            this.alias = alias;
        }

        public String[] getClientAliases(String string, Principal[] prncpls) {
            return base.getClientAliases(string, prncpls);
        }

        public String chooseClientAlias(String[] keyType, Principal[] issuers,
                Socket socket) {
            return alias;
        }

        public String[] getServerAliases(String string, Principal[] prncpls) {
            return base.getClientAliases(string, prncpls);
        }

        public String chooseServerAlias(String string, Principal[] prncpls,
                Socket socket) {
            return base.chooseServerAlias(string, prncpls, socket);
        }

        public X509Certificate[] getCertificateChain(String string) {
            try {
                return getSigningCertificateChain().toArray(new X509Certificate[0]);
            } catch (CryptoTokenOfflineException ex) {
                LOG.error("Offline getting chain", ex);
                return new X509Certificate[0];
            }
        }

        public PrivateKey getPrivateKey(String string) {
            final PrivateKey key = base.getPrivateKey(string);
            return key;
        }
    }
}
