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
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.Properties;
import javax.net.ssl.*;
import javax.persistence.EntityManager;
import javax.xml.namespace.QName;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.util.Selector;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Base64;
import org.cesecore.util.CertTools;
import org.signserver.common.*;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.data.ReadableData;
import org.signserver.common.data.Request;
import org.signserver.common.data.Response;
import org.signserver.common.data.SignatureRequest;
import org.signserver.common.data.SignatureResponse;
import org.signserver.common.data.WritableData;
import org.signserver.common.util.RandomPasswordGenerator;
import org.signserver.ejb.interfaces.WorkerSessionLocal;
import org.signserver.module.renewal.common.RenewalWorkerProperties;
import org.signserver.module.renewal.ejbcaws.gen.CertificateResponse;
import org.signserver.module.renewal.ejbcaws.gen.EjbcaWS;
import org.signserver.module.renewal.ejbcaws.gen.EjbcaWSService;
import org.signserver.module.renewal.ejbcaws.gen.UserDataVOWS;
import org.signserver.module.renewal.ejbcaws.gen.UserMatch;
import org.signserver.server.IServices;
import org.signserver.server.WorkerContext;
import org.signserver.server.cryptotokens.KeystoreCryptoToken;
import org.signserver.server.log.IWorkerLogger;
import org.signserver.server.log.LogMap;
import org.signserver.server.signers.BaseSigner;
import org.signserver.server.log.Loggable;

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

    private static final String NEXTCERTSIGNKEY = "NEXTCERTSIGNKEY";

    public static final String TRUSTSTORE_TYPE_PEM = "PEM";
    public static final String TRUSTSTORE_TYPE_JKS = "JKS";

    private static final String WS_PATH = "/ejbcaws/ejbcaws?wsdl";

    private static final int MATCH_WITH_USERNAME = 0;
    private static final int MATCH_TYPE_EQUALS = 0;
    private static final int STATUS_NEW = 10;
    
    // From CertificateHelper:
    /**
     * Indicates that the requester want a BASE64 encoded certificate in the
     * CertificateResponse object.
     */
    //private static String RESPONSETYPE_CERTIFICATE    = "CERTIFICATE";
    /**
     * Indicates that the requester want a BASE64 encoded pkcs7 in the
     * CertificateResponse object.
     */
    //private static String RESPONSETYPE_PKCS7          = "PKCS7";
    /**
     * Indicates that the requester want a BASE64 encoded pkcs7 with the
     * complete chain in the CertificateResponse object.
     */
    private static final String RESPONSETYPE_PKCS7WITHCHAIN = "PKCS7WITHCHAIN";

    private List<String> fatalErrors;
    
    /** Configuration parameters. */
    private String alias;
    private String truststoreValue;
    private String truststoreType;
    private String truststorePath;
    private String truststorePass;
    private String ejbcaWsUrl;


    @Override
    public void init(final int workerId, final WorkerConfig config,
            final WorkerContext workerContext, final EntityManager workerEM) {
        initInternal(workerId, config, workerContext, workerEM);
    }
    
    /**
     * Internal init method used by the unit test to initialize configuration
     * without looking up the worker session.
     */
    void initInternal(final int workerId, final WorkerConfig config,
            final WorkerContext workerContext, final EntityManager workerEM) {
        super.init(workerId, config, workerContext, workerEM);
        
        fatalErrors = new LinkedList<>();
        setupConfig();
    }
    
    /**
     * Setup configuration and update fatal errors.
     */
    private void setupConfig() {
        alias = config.getProperty("DEFAULTKEY");
        if (alias == null) {
            fatalErrors.add("Missing DEFAULTKEY property");
        }

        truststoreType = config.getProperty("TRUSTSTORETYPE");
        if (truststoreType == null) {
            fatalErrors.add("Missing TRUSTSTORETYPE property");
        }
        
        truststorePath = config.getProperty("TRUSTSTOREPATH");
        truststoreValue = config.getProperty(TRUSTSTOREVALUE);
        if (truststorePath == null && truststoreValue == null) {
            fatalErrors.add("Missing TRUSTSTOREPATH or TRUSTSTOREVALUE property");
        }
        if (truststorePath != null && truststoreValue != null) {
            fatalErrors.add("Can not specify both TRUSTSTOREPATH and TRUSTSTOREVALUE property");
        }

        truststorePass = config.getProperty("TRUSTSTOREPASSWORD");
        if (truststorePass == null && !TRUSTSTORE_TYPE_PEM.equals(truststoreType)) {
            fatalErrors.add("Missing TRUSTSTOREPASSWORD property");
        }
        
        ejbcaWsUrl = config.getProperty("EJBCAWSURL");
        if (ejbcaWsUrl == null) {
            fatalErrors.add("Missing EJBCAWSURL property");
        }
    }

    @Override
    public Response processData(final Request signRequest,
            final RequestContext requestContext) throws IllegalRequestException,
            CryptoTokenOfflineException, SignServerException {

        // Check that the request contains a valid request
        if (!(signRequest instanceof SignatureRequest)) {
            throw new IllegalRequestException(
                "Received request was not of expected type.");
        }
        final SignatureRequest request = (SignatureRequest) signRequest;
        final ReadableData requestData = request.getRequestData();
        final WritableData responseData = request.getResponseData();
        
        final Properties requestProperties, propertiesResponse;

        requestProperties = new Properties();
        try (InputStream in = requestData.getAsInputStream()) {
            requestProperties.load(in);
        } catch (IOException ex) {
            LOG.error("Error in request: "
                    + requestContext.get(RequestContext.TRANSACTION_ID),
                    ex);
            throw new IllegalRequestException("Error parsing request. "
                    + "See server log for information.");
        }

        // Log values
        final LogMap logMap = LogMap.getInstance(requestContext);

        propertiesResponse = process(requestProperties, logMap, requestContext);

        // Log result
        logMap.put(RenewalWorkerProperties.LOG_RESPONSE_RESULT,
                   new Loggable() {
                        @Override
                        public String toString() {
                            return propertiesResponse.getProperty(RenewalWorkerProperties
                                                            .RESPONSE_RESULT);
                        }
                    }); 

        logMap.put(RenewalWorkerProperties.LOG_RESPONSE_MESSAGE,
                   new Loggable() {
                       @Override
                       public String toString() {
                           return propertiesResponse.getProperty(RenewalWorkerProperties
                                                            .RESPONSE_MESSAGE);
                       }
                   });



        try (OutputStream out = responseData.getAsOutputStream()) {
            propertiesResponse.store(out, null);
        } catch (IOException ex) {
            LOG.error("Error constructing response for request: "
                    + requestContext.get(RequestContext.TRANSACTION_ID),
                    ex);
            throw new SignServerException("Error constructing response."
                    + "See server log for information.");
        }

        return new SignatureResponse(request.getRequestID(),
                    responseData, null, null, null, "text/plain");
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
                final LogMap logMap, final RequestContext requestContext)
            throws IllegalRequestException, CryptoTokenOfflineException,
            SignServerException {
        final String workerName = requestData.getProperty(
                RenewalWorkerProperties.REQUEST_WORKER);

        final Properties responseData;

        if (workerName == null) {
            throw new IllegalRequestException("No worker name in request.");
        }

        responseData = new Properties();

        // Log renewee
        logMap.put(RenewalWorkerProperties.LOG_RENEWEE,
                   new Loggable() {
                       @Override
                       public String toString() {
                           return workerName;
                       }
                   });

        final WorkerSessionLocal workerSession = getWorkerSession(requestContext.getServices());
        
        try {
            int reneweeId;
            try {
                reneweeId = Integer.parseInt(workerName);
            } catch (NumberFormatException ex) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Not a workerId, maybe workerName: " + workerName);
                }
                reneweeId = workerSession.getWorkerId(workerName);
            }
            
            // Get the worker config
            final WorkerConfig workerConfig
                    = workerSession.getCurrentWorkerConfig(reneweeId);
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
                    WorkerConfig.PROPERTY_EXPLICITECC, String.valueOf(false));
            String nextCertSignKey
                    = workerConfig.getProperty(NEXTCERTSIGNKEY);

            // If we should use the default key (instead of nextKey,
            // if existing) can be specified in the request (but only if we
            // don't generate a new key)
            final String forDefaultKeyValue = requestData.getProperty(
                    RenewalWorkerProperties.REQUEST_FORDEFAULTKEY,
                    Boolean.FALSE.toString());
            final boolean requestForDefaultKey =
                    Boolean.TRUE.toString().equalsIgnoreCase(forDefaultKeyValue);

            final boolean renewKey = !requestForDefaultKey 
                    && nextCertSignKey == null;

            final String authCode = requestData.getProperty(
                    RenewalWorkerProperties.REQUEST_AUTHCODE);

            if (LOG.isDebugEnabled()) {
                final StringBuilder buff = new StringBuilder();
                buff.append("Renewer[").append(workerId)
                    .append("]: Got request for renewal of Worker[").append(reneweeId)
                    .append("]: \n");

                buff.append("Transaction:\n\t")
                    .append("LOG_ID: ").append(logMap.get(IWorkerLogger.LOG_ID)).append("\n");
                
                buff.append("Renewee config:\n\t")
                    .append(PROPERTY_SIGNATUREALGORITHM).append("=").append(sigAlg).append("\n\t")
                    .append(PROPERTY_REQUESTDN).append("=").append(subjectDN).append("\n\t")
                    .append(PROPERTY_KEYALG).append("=").append(keyAlg).append("\n\t")
                    .append(PROPERTY_KEYSPEC).append("=").append(keySpec).append("\n\t")
                    .append(WorkerConfig.PROPERTY_EXPLICITECC).append("=").append(explicitEccParameters).append("\n\t")
                    .append(PROPERTY_RENEWENDENTITY).append("=").append(endEntity).append("\n");

                buff.append("Request config:\n\t");
                buff.append(RenewalWorkerProperties.REQUEST_FORDEFAULTKEY)
                    .append("=").append(requestForDefaultKey).append("\n\t");

                buff.append(RenewalWorkerProperties.REQUEST_AUTHCODE)
                    .append("=");
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
                        "Property " + PROPERTY_RENEWENDENTITY + " not specified for worker: "
                        + workerName);
            } else if (subjectDN == null || subjectDN.isEmpty()) {
                renewalFailure(responseData,
                        "Property " + PROPERTY_REQUESTDN + " not specified for worker: "
                        + workerName);
            } else if (sigAlg == null || sigAlg.isEmpty()) {
                renewalFailure(responseData,
                        "Property " + PROPERTY_SIGNATUREALGORITHM + " not specified for worker: "
                        + workerName);
            } else if (renewKey && (keyAlg == null || keyAlg.isEmpty())) {
                renewalFailure(responseData,
                        "Property " + PROPERTY_KEYALG + " not specified for worker: "
                        + workerName);
            } else if (renewKey && (keySpec == null || keySpec.isEmpty())) {
                renewalFailure(responseData,
                        "Property " + PROPERTY_KEYSPEC + " not specified for worker: "
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
                            logMap, workerSession);
                } else {
                    // Request might say that we should use the default key
                    defaultKey = requestForDefaultKey;
                    LOG.debug("Use default key: " + defaultKey);
                }

                // Renew worker
                renewWorker(reneweeId, sigAlg, subjectDN, endEntity,
                        Boolean.valueOf(explicitEccParameters),
                        defaultKey, nextCertSignKey,
                        logMap, workerSession, requestContext.getServices());

                responseData.setProperty(
                        RenewalWorkerProperties.RESPONSE_RESULT,
                        RenewalWorkerProperties.RESPONSE_RESULT_OK);
                
                // The client can be charged for the request
                requestContext.setRequestFulfilledByWorker(true);
            }

        } catch (Exception ex) {
            renewalFailure(responseData, ex.getMessage(), ex);
        }

        return responseData;
    }

    private String renewKey(final int workerId, final String keyAlg,
           final String keySpec, final char[] authcode,
           final LogMap logMap, final WorkerSessionLocal workerSession) throws Exception {
        if (LOG.isDebugEnabled()) {
            LOG.debug("<renewKey");
        }
            
        final String newAlias = workerSession.generateSignerKey(new WorkerIdentifier(workerId),
                keyAlg, keySpec, null, authcode);

        // Log
        logMap.put(RenewalWorkerProperties.LOG_GENERATEDKEYALIAS,
                   new Loggable() {
                       @Override
                       public String toString() {
                           return newAlias;
                       }
                   });
        if (LOG.isDebugEnabled()) {
            LOG.debug("Generated new key: " + newAlias);
        }

        final Collection<KeyTestResult> results = workerSession.testKey(
                new WorkerIdentifier(workerId), newAlias, authcode);
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
                       new Loggable() {
                           @Override
                           public String toString() {
                               return result.getPublicKeyHash();
                           }
                       });

            workerSession.setWorkerProperty(workerId, NEXTCERTSIGNKEY,
                    newAlias);
            workerSession.reloadConfiguration(workerId);

            if (LOG.isDebugEnabled()) {
                LOG.debug("Key generated, tested and set");
            }

            if (authcode != null) {
                workerSession.activateSigner(new WorkerIdentifier(workerId),
                        String.valueOf(authcode));

                if (LOG.isDebugEnabled()) {
                    LOG.debug("Worker activated");
                }
            }
            
            if (LOG.isDebugEnabled()) {
                LOG.debug(">renewKey");
            }
            
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
            final LogMap logMap, final WorkerSessionLocal workerSession,
            final IServices services)
            throws Exception {

        final String pkcs10
                = createRequestPEM(workerId, sigAlg, subjectDN, 
                explicitEccParameters, defaultKey, workerSession);

        if (LOG.isDebugEnabled()) {
            LOG.debug("PKCS10: " + pkcs10);
        }

        // Connect to EjbcaWS
        final EjbcaWS ejbcaws = getEjbcaWS(ejbcaWsUrl,
                alias, truststoreType, truststorePath, truststoreValue, truststorePass, services);

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
                
                final Store certStore = signedData.getCertificates();
                final List<X509CertificateHolder> certChain = getCertificateChain(certStore.getMatches(new RenewalWorker.AllSelector()));
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Got certificates: " + certChain);
                }

                final X509CertificateHolder signerCert
                        = getEndEntityCertificate(certChain);
                if (LOG.isDebugEnabled()) {
                    LOG.debug("New certificate subject DN: "
                            + signerCert.getSubject());
                }

                // Log
                logMap.put(RenewalWorkerProperties.LOG_NEWCERTISSUERDN,
                           new Loggable() {
                               @Override
                               public String toString() {
                                   return signerCert.getIssuer().toString();
                               }
                           });
                logMap.put(RenewalWorkerProperties.LOG_NEWCERTSERIALNO,
                           new Loggable() {
                               @Override
                               public String toString() {
                                   return signerCert.getSerialNumber().toString(16);
                               }
                           });
                logMap.put(RenewalWorkerProperties.LOG_NEWCERTSUBJECTDN,
                           new Loggable() {
                               @Override
                               public String toString() {
                                   return signerCert.getSubject().toString();
                               }
                           });

                // TODO: Check the certificate
                    // Public key should match

                // Update worker to use the new certificate
                workerSession.uploadSignerCertificate(workerId,
                        signerCert.getEncoded(),
                        GlobalConfiguration.SCOPE_GLOBAL);
                workerSession.uploadSignerCertificateChain(workerId,
                        getCertificateChainBytes(certChain),
                        GlobalConfiguration.SCOPE_GLOBAL);

                // If not the default key we need to promote the key
                // Set DEFAULTKEY to NEXTCERTSIGNKEY
                if (defaultKey) {
                    LOG.debug("Uploaded was for DEFAULTKEY");
                } else if (!defaultKey && nextCertSignKey != null) {
                    LOG.debug("Uploaded was for NEXTCERTSIGNKEY");

                   workerSession.setWorkerProperty(workerId, "DEFAULTKEY",
                           nextCertSignKey);
                   workerSession.removeWorkerProperty(workerId,
                           NEXTCERTSIGNKEY);
                }

                workerSession.reloadConfiguration(workerId);
                LOG.debug("New configuration applied");
            }
        }
    }
    public static final String TRUSTSTOREVALUE = "TRUSTSTOREVALUE";

    protected WorkerSessionLocal getWorkerSession(IServices services) {
        return services.get(WorkerSessionLocal.class);
    }

    private String createRequestPEM(int workerId, final String sigAlg, 
            final String subjectDN, final boolean explicitEccParameters,
            final boolean defaultKey, final WorkerSessionLocal workerSession)
            throws CryptoTokenOfflineException, InvalidWorkerIdException, IOException {
        final PKCS10CertReqInfo certReqInfo = new PKCS10CertReqInfo(sigAlg,
                subjectDN, null);
        final AbstractCertReqData reqData
                = (AbstractCertReqData) workerSession
                .getCertificateRequest(new WorkerIdentifier(workerId), certReqInfo, explicitEccParameters, defaultKey);
        if (reqData == null) {
            throw new RuntimeException(
                    "CSR returned was null."
                    + " Unable to generate certificate request.");
        }

        return reqData.toArmoredForm();
    }

    private EjbcaWS getEjbcaWS(final String ejbcaUrl, final String alias,
            final String truststoreType, final String truststorePath,
            final String truststoreValue, final String truststorePass,
            final IServices services) throws CryptoTokenOfflineException,
            NoSuchAlgorithmException, KeyStoreException,
            UnrecoverableKeyException, IOException, CertificateException,
            NoSuchProviderException, KeyManagementException, SignServerException {

        EjbcaWS result;

        final String urlstr = ejbcaUrl + WS_PATH;

        final KeyStore keystore = getCryptoToken(services).getKeyStore();

        // Check that the key is there
        if (!keystore.containsAlias(alias)) {
            LOG.error("RenewalWorker[" + workerId + "] is missing its key: " + alias);
        } else {
            if (LOG.isDebugEnabled()) {
                LOG.debug("RenewalWorker[" + workerId + "] will use its key: " + alias);
            }
        }

        final String keystorePassword = getConfig().getProperty(KeystoreCryptoToken.KEYSTOREPASSWORD);
        final KeyManagerFactory kKeyManagerFactory = KeyManagerFactory.getInstance("SunX509");
        kKeyManagerFactory.init(keystore,
                keystorePassword != null ? keystorePassword.toCharArray() : null);
                
        final KeyStore keystoreTrusted;

        if (truststoreValue != null) {
            if (TRUSTSTORE_TYPE_PEM.equals(truststoreType)) {
                keystoreTrusted = KeyStore.getInstance("JKS");
                keystoreTrusted.load(null, null);
                final Collection certs = CertTools.getCertsFromPEM(new ByteArrayInputStream(truststoreValue.getBytes(StandardCharsets.UTF_8)));
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
                if (TRUSTSTORE_TYPE_JKS.equals(truststoreType)) {
                    keystoreTrusted = KeyStore.getInstance(truststoreType);
                    if (!truststoreValue.isEmpty()) {
                        keystoreTrusted.load(new ByteArrayInputStream(Base64.decode(truststoreValue)), truststorePass.toCharArray());
                    }
                } else {
                    keystoreTrusted = KeyStore.getInstance(truststoreType, "BC");
                    if (!truststoreValue.isEmpty()) {
                        keystoreTrusted.load(new ByteArrayInputStream(Base64.decode(truststoreValue)), truststorePass.toCharArray());
                    }
                }
            }
        } else {
            FileInputStream in = null;
            try {
                in = new FileInputStream(truststorePath);

                if (TRUSTSTORE_TYPE_PEM.equals(truststoreType)) {
                    keystoreTrusted = KeyStore.getInstance("JKS");
                    keystoreTrusted.load(null, null);
                    final Collection certs = CertTools.getCertsFromPEM(in);
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
                } else if (TRUSTSTORE_TYPE_JKS.equals(truststoreType)) {
                    keystoreTrusted = KeyStore.getInstance(truststoreType);
                    keystoreTrusted.load(in, truststorePass.toCharArray());
                } else {
                    keystoreTrusted = KeyStore.getInstance(truststoreType, "BC");
                    keystoreTrusted.load(in, truststorePass.toCharArray());
                }
            } finally {
                if (in != null) {
                    try {
                        in.close();
                    } catch (IOException ignored) {} // NOPMD
                }
            }
        }
        final TrustManagerFactory tTrustManagerFactory
                = TrustManagerFactory.getInstance("SunX509");
        tTrustManagerFactory.init(keystoreTrusted);
        KeyManager[] keyManagers = kKeyManagerFactory.getKeyManagers();
        for (int i = 0; i < keyManagers.length; i++) {
            if (keyManagers[i] instanceof X509KeyManager) {
                keyManagers[i] = new AliasKeyManager(
                        (X509KeyManager) keyManagers[i], alias, getCertificateChain(alias, keystore));
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
    private static X509CertificateHolder getEndEntityCertificate(
            final Collection<? extends X509CertificateHolder> certs) {
        X509CertificateHolder result = null;
        for (X509CertificateHolder cert : certs) {
            Extension extension = cert.getExtension(Extension.basicConstraints);
            if (extension == null) {
                result = cert;
                break;
            } else {
                BasicConstraints bc = BasicConstraints.getInstance(extension.getParsedValue());
                if (!bc.isCA()) {
                    result = cert;
                    break;
                }
            }
        }
        return result;
    }

    // TODO: We are not ordering this chain and assumes that is not important
    private static List<X509CertificateHolder> getCertificateChain(
            final Collection certs) {
        final LinkedList<X509CertificateHolder> result = new LinkedList<>();
        for (Object cert : certs) {
            if (cert instanceof X509CertificateHolder) {
                result.add((X509CertificateHolder) cert);
            }
        }
        return result;
    }

    private static List<byte[]> getCertificateChainBytes(
            final Collection<? extends X509CertificateHolder> certs)
            throws CertificateEncodingException, IOException {
        final LinkedList<byte[]> result = new LinkedList<>();
        for (X509CertificateHolder cert : certs) {
            result.add(cert.getEncoded());
        }
        return result;
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
                message == null ? "" : message);
    }

    private X509Certificate[] getCertificateChain(final String alias, final KeyStore keystore) throws KeyStoreException {
        X509Certificate[] result;
        
        List<Certificate> chain = config.getSignerCertificateChain();
        
        if (chain == null) {
            Certificate[] ch = keystore.getCertificateChain(alias);
            if (ch == null) {
                result = new X509Certificate[0];
            } else {
                result = new X509Certificate[ch.length];
                for (int i = 0; i < ch.length; i++) {
                    result[i] = (X509Certificate) ch[i];
                }
            }
        } else {
            result = chain.toArray(new X509Certificate[chain.size()]);
        }

        return result;
    }
  
    public static class AliasKeyManager implements X509KeyManager {

        private final X509KeyManager base;
        private final String alias;
        private final X509Certificate[] chain;

        public AliasKeyManager(final X509KeyManager base, final String alias, final X509Certificate[] chain) {
            this.base = base;
            this.alias = alias;
            this.chain = chain;
        }

        @Override
        public String[] getClientAliases(String string, Principal[] prncpls) {
            return base.getClientAliases(string, prncpls);
        }

        @Override
        public String chooseClientAlias(String[] keyType, Principal[] issuers,
                Socket socket) {
            return alias;
        }

        @Override
        public String[] getServerAliases(String string, Principal[] prncpls) {
            return base.getClientAliases(string, prncpls);
        }

        @Override
        public String chooseServerAlias(String string, Principal[] prncpls,
                Socket socket) {
            return base.chooseServerAlias(string, prncpls, socket);
        }

        @Override
        public X509Certificate[] getCertificateChain(String string) {
            return chain;
        }

        @Override
        public PrivateKey getPrivateKey(String string) {
            final PrivateKey key = base.getPrivateKey(string);
            return key;
        }
    }
    
    /**
     * Simply matches true on all objects found.
     */
    public static class AllSelector implements Selector {
        @Override
        public boolean match(Object obj) {
            return true;
        }

        @Override
        public Object clone() {
            return new RenewalWorker.AllSelector();
        }
    }

    @Override
    protected List<String> getFatalErrors(final IServices services) {
        final List<String> errors = super.getFatalErrors(services);
        
        errors.addAll(getLocalFatalErrors());
        return errors;
    }
    
    /**
     * Internal method used by the unit test to get locally
     * added fatal errors, bypassing the token setup in BaseProcessable.
     * 
     * @return List of fatal errors added in this class.
     */
    List<String> getLocalFatalErrors() {
        return fatalErrors;
    }
}
