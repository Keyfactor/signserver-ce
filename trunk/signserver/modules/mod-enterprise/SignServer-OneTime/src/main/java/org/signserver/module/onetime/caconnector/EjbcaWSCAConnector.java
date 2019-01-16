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
package org.signserver.module.onetime.caconnector;

import org.signserver.module.onetime.cryptoworker.OneTimeCryptoWorker;
import java.io.ByteArrayInputStream;
import java.io.EOFException;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509KeyManager;
import javax.xml.namespace.QName;
import javax.xml.ws.WebServiceException;
import org.apache.commons.lang.text.StrLookup;
import org.apache.commons.lang.text.StrSubstitutor;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.StoreException;
import org.bouncycastle.util.encoders.Base64;
import org.cesecore.util.CertTools;
import org.signserver.common.Base64SignerCertReqData;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.NoSuchAliasException;
import org.signserver.common.PKCS10CertReqInfo;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.ejb.interfaces.WorkerSessionLocal;
import org.signserver.module.renewal.common.RenewalWorkerProperties;
import org.signserver.module.renewal.ejbcaws.gen.ApprovalException_Exception;
import org.signserver.module.renewal.ejbcaws.gen.AuthorizationDeniedException_Exception;
import org.signserver.module.renewal.ejbcaws.gen.CADoesntExistsException_Exception;
import org.signserver.module.renewal.ejbcaws.gen.CertificateResponse;
import org.signserver.module.renewal.ejbcaws.gen.EjbcaException_Exception;
import org.signserver.module.renewal.ejbcaws.gen.EjbcaWS;
import org.signserver.module.renewal.ejbcaws.gen.EjbcaWSService;
import org.signserver.module.renewal.ejbcaws.gen.NotFoundException_Exception;
import org.signserver.module.renewal.ejbcaws.gen.UserDataVOWS;
import org.signserver.module.renewal.ejbcaws.gen.UserDoesntFullfillEndEntityProfile_Exception;
import org.signserver.module.renewal.ejbcaws.gen.WaitingForApprovalException_Exception;
import org.signserver.module.renewal.worker.RenewalWorker;
import static org.signserver.module.renewal.worker.RenewalWorker.TRUSTSTORE_TYPE_JKS;
import static org.signserver.module.renewal.worker.RenewalWorker.TRUSTSTORE_TYPE_PEM;
import org.signserver.server.ExceptionUtil;
import org.signserver.server.IAuthorizer;
import org.signserver.server.IServices;
import org.signserver.server.SignServerContext;
import org.signserver.server.cryptotokens.CryptoTokenHelper;
import org.signserver.server.cryptotokens.ICryptoTokenV4;
import org.signserver.server.log.LogMap;
import org.signserver.server.log.Loggable;
import static org.signserver.common.SignServerConstants.DEFAULT_NULL;
import org.signserver.common.WorkerConfig;

/**
 * CAConnector using EjbcaWS.
 *
 * @author Markus Kilås
 * @version $Id: EjbcaWSCAConnector.java 9470 2018-08-07 09:59:52Z vinays $
 */
public class EjbcaWSCAConnector implements ICAConnector {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(OneTimeCryptoWorker.class);

    // Worker properties
    public static final String PROPERTY_CANAME = "CANAME";
    public static final String PROPERTY_ENDENTITYPROFILE = "ENDENTITYPROFILE";
    public static final String PROPERTY_CERTIFICATEPROFILE = "CERTIFICATEPROFILE";
    public static final String PROPERTY_CERTIFICATESTARTTIME = "CERTIFICATESTARTTIME";
    public static final String PROPERTY_CERTIFICATEENDTIME = "CERTIFICATEENDTIME";
    public static final String PROPERTY_TRUSTSTOREVALUE = "TRUSTSTOREVALUE";
    public static final String PROPERTY_TRUSTSTORETYPE = "TRUSTSTORETYPE";
    public static final String PROPERTY_TRUSTSTOREPATH = "TRUSTSTOREPATH";
    public static final String PROPERTY_TRUSTSTOREPASSWORD = "TRUSTSTOREPASSWORD";
    public static final String PROPERTY_CERTSIGNATUREALGORITHM = "CERTSIGNATUREALGORITHM";
    public static final String PROPERTY_EJBCAWSURL = "EJBCAWSURL";
    public static final String PROPERTY_USERNAME_PATTERN = "USERNAME_PATTERN";
    public static final String PROPERTY_SUBJECTDN_PATTERN = "SUBJECTDN_PATTERN";
    public static final String PROPERTY_SUBJECTALTNAME_PATTERN = "SUBJECTALTNAME_PATTERN";

    private static final int CERT_REQ_TYPE_PKCS10 = 0;
    
    /**
     * Indicates that the requester want a BASE64 encoded pkcs7 with the
     * complete chain in the CertificateResponse object.
     */
    private static final String RESPONSETYPE_PKCS7WITHCHAIN = "PKCS7WITHCHAIN";

    private static final String WS_PATH = "/ejbcaws/ejbcaws?wsdl";

    // Configuration errors
    private final LinkedList<String> configErrors = new LinkedList<>();

    // Configuration values
    private WorkerConfig config;
    private String tlsClientKeyAlias;
    private String truststoreValue;
    private String truststoreType;
    private String truststorePath;
    private String truststorePass;
    private String certSignatureAlgorithm;
    private String ejbcaWsUrl;
    private String caName;
    private String endentityProfile;
    private String certificateProfile;
    
    private String usernamePattern;
    private String subjectDNPattern;
    private String subjectAltNamePattern;
    
    private String certificateStartTime;
    private String certificateEndTime;    

    @Override
    public void init(WorkerConfig config, SignServerContext context) {        
        this.config = config;
        
        tlsClientKeyAlias = config.getProperty("TLSCLIENTKEY", DEFAULT_NULL);
        if (tlsClientKeyAlias == null) {
            configErrors.add("Missing TLSCLIENTKEY property");
        }

        truststoreType = config.getProperty(PROPERTY_TRUSTSTORETYPE, DEFAULT_NULL);
        if (truststoreType == null) {
            configErrors.add("Missing TRUSTSTORETYPE property");
        }
        
        if (truststoreType != null && !(truststoreType.equals(TRUSTSTORE_TYPE_PEM) || truststoreType.equals(TRUSTSTORE_TYPE_JKS))) {
            configErrors.add("Invalid TRUSTSTORETYPE property");
        }
        
        truststorePath = config.getProperty(PROPERTY_TRUSTSTOREPATH, DEFAULT_NULL);
        truststoreValue = config.getProperty(PROPERTY_TRUSTSTOREVALUE, DEFAULT_NULL);
        if (truststorePath == null && truststoreValue == null) {
            configErrors.add("Missing TRUSTSTOREPATH or TRUSTSTOREVALUE property");
        }
        if (truststorePath != null && truststoreValue != null) {
            configErrors.add("Can not specify both TRUSTSTOREPATH and TRUSTSTOREVALUE property");
        }

        // TRUSTSTOREPASSWORD could be empty?
        truststorePass = config.getPropertyThatCouldBeEmpty(PROPERTY_TRUSTSTOREPASSWORD);
        if (truststorePass == null && truststoreType != null && !TRUSTSTORE_TYPE_PEM.equals(truststoreType)) {
            configErrors.add("Missing TRUSTSTOREPASSWORD property");
        }
        
        certSignatureAlgorithm = config.getProperty(PROPERTY_CERTSIGNATUREALGORITHM, DEFAULT_NULL);
        if (certSignatureAlgorithm == null) {
            configErrors.add("Missing CERTSIGNATUREALGORITHM property");
        }
        
        ejbcaWsUrl = config.getProperty(PROPERTY_EJBCAWSURL, DEFAULT_NULL);
        if (ejbcaWsUrl == null) {
            configErrors.add("Missing EJBCAWSURL property");
        }
        
        caName = config.getProperty(PROPERTY_CANAME, DEFAULT_NULL);
        if (caName == null) {
            configErrors.add("Missing CANME property");
        }
        
        endentityProfile = config.getProperty(PROPERTY_ENDENTITYPROFILE, DEFAULT_NULL);
        if (endentityProfile == null) {
            configErrors.add("Missing " + PROPERTY_ENDENTITYPROFILE + " property");
        }
        
        certificateProfile = config.getProperty(PROPERTY_CERTIFICATEPROFILE, DEFAULT_NULL);
        if (certificateProfile == null) {
            configErrors.add("Missing " + PROPERTY_CERTIFICATEPROFILE + " property");
        }
        
        
        usernamePattern = config.getProperty(PROPERTY_USERNAME_PATTERN, DEFAULT_NULL);
        if (usernamePattern == null) {
            configErrors.add("Missing USERNAME_PATTERN property");
        }
        subjectDNPattern = config.getProperty("SUBJECTDN_PATTERN", DEFAULT_NULL);
        if (subjectDNPattern == null) {
            configErrors.add("Missing SUBJECTDN_PATTERN property");
        }
        
        // Optional property SUBJECTALTNAME_PATTERN
        subjectAltNamePattern = config.getProperty(PROPERTY_SUBJECTALTNAME_PATTERN, DEFAULT_NULL);
        
        // Optional property CERTIFICATESTARTTIME
        certificateStartTime = config.getProperty(PROPERTY_CERTIFICATESTARTTIME, DEFAULT_NULL);

        // Optional property CERTIFICATEENDTIME
        certificateEndTime = config.getProperty(PROPERTY_CERTIFICATEENDTIME, DEFAULT_NULL);
    }

    @Override
    public List<String> getFatalErrors(ICryptoTokenV4 backingToken, IServices services) {
        // Add our errors to the list of errors
        final LinkedList<String> errors = new LinkedList<>(configErrors);
        
        // TODO: Make check configurable
        if (configErrors.isEmpty()) {
            try {
                if (backingToken == null) {
                    errors.add("No crypto token available for CA Connector");
                } else {
                    final EjbcaWS ca = getEjbcaWS(ejbcaWsUrl, tlsClientKeyAlias, truststoreType, truststorePath, truststoreValue, truststorePass, backingToken);
                    final String version = ca.getEjbcaVersion();
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Connected with EJBCA version: " + version);
                    }
                }
            } catch (NoSuchAliasException ex) {
                errors.add("Connection test failed: TLS key not fund");
            } catch (IOException | KeyManagementException | KeyStoreException |
                     NoSuchAlgorithmException | NoSuchProviderException |
                     UnrecoverableKeyException | CertificateException |
                     CryptoTokenOfflineException | SignServerException | WebServiceException | IllegalArgumentException ex) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Connection test failed", ex);
                }
                
                // Get all error messages
                final String causes = ExceptionUtil.getCauseMessages(ex).toString();
                
                // Try to provide nicer error message for known cases
                if (causes.contains("FileNotFoundException")) {
                    errors.add("Connection test failed: File not found");
                } else if(causes.contains("Connection refused")) {
                    errors.add("Connection test failed: Connection refused");
                } else if (causes.contains("FileInputStream") ||
                           causes.contains("Invalid keystore format") ||
                           ex instanceof EOFException) {
                    errors.add("Connection test failed: Failed to read truststore");
                } else {
                    errors.add("Connection test failed: " + causes);
                }
            }
        }

        return errors;
    }
    
    @Override
    public CAResponse requestCertificate(ICryptoTokenV4 backingToken, String keyAlias, PrivateKey privateKey, PublicKey publicKey, String provider, RequestContext context) throws CAException {
        try {
            if (!configErrors.isEmpty()) {
                throw new CAException(new IllegalStateException("Misconfigured"));
            }
            
            final UserDataVOWS userData = createUserData(keyAlias, context);
            
            final String pkcs10
                    = createRequestPEM(userData.getSubjectDN(), privateKey, publicKey, provider);
            
            if (LOG.isDebugEnabled()) {
                LOG.debug("PKCS10: " + pkcs10);
            }

            // Connect to EjbcaWS
            final EjbcaWS ejbcaws = getEjbcaWS(ejbcaWsUrl,
                    tlsClientKeyAlias, truststoreType, truststorePath, truststoreValue, truststorePass, backingToken);

            if (ejbcaws == null) {
                throw new CAException("Could not get EjbcaWS");
            } else {
                LOG.debug("Got EjbcaWS");

                CertificateResponse resp = ejbcaws.certificateRequest(userData, pkcs10, CERT_REQ_TYPE_PKCS10, null, RESPONSETYPE_PKCS7WITHCHAIN);

                final String b64Cert = new String(resp.getData());
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Got PKCS7: " + b64Cert);
                }

                final CMSSignedData signedData = new CMSSignedData(Base64.decode(b64Cert));

                final Store certStore = signedData.getCertificates();
                Collection certs = certStore.getMatches(new RenewalWorker.AllSelector());
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Got certificates: " + certs);
                }

                final X509CertificateHolder signerCert = getEndEntityCertificate(certs);
                if (LOG.isDebugEnabled()) {
                    LOG.debug("New certificate subject DN: " + signerCert.getSubject());
                }

                // Log
                LogMap logMap = LogMap.getInstance(context);
                logMap.put(RenewalWorkerProperties.LOG_NEWCERTISSUERDN, new Loggable() {
                    @Override
                    public String toString() {
                        return signerCert.getIssuer().toString();
                    }
                });
                logMap.put(RenewalWorkerProperties.LOG_NEWCERTSERIALNO, new Loggable() {
                    @Override
                    public String toString() {
                        return signerCert.getSerialNumber().toString(16);
                    }
                });
                logMap.put(RenewalWorkerProperties.LOG_NEWCERTSUBJECTDN, new Loggable() {
                    @Override
                    public String toString() {
                        return signerCert.getSubject().toString();
                    }
                });

                // TODO: Check the certificate
                // Public key should match

                return new CAResponse(signerCert, new ArrayList(certs));
            }
        } catch (NoSuchAliasException ex) {
            return new CAResponse(ex.getLocalizedMessage());
        } catch (WebServiceException ex) {
            final String causes = ExceptionUtil.getCauseMessages(ex).toString();
            LOG.error("CA connection error", ex);
            return new CAResponse("CA connection error: " + causes);
        } catch (CAException | CryptoTokenOfflineException | NoSuchAlgorithmException | KeyStoreException | UnrecoverableKeyException | IOException | CertificateException | NoSuchProviderException | KeyManagementException | SignServerException | ApprovalException_Exception | AuthorizationDeniedException_Exception | CADoesntExistsException_Exception | EjbcaException_Exception | NotFoundException_Exception | UserDoesntFullfillEndEntityProfile_Exception | WaitingForApprovalException_Exception | CMSException | StoreException | IllegalArgumentException ex) {
            final String causes = ExceptionUtil.getCauseMessages(ex).toString();
            LOG.error("CA error", ex);
            return new CAResponse(causes);
        }
    }

    protected WorkerSessionLocal getWorkerSession(IServices services) {
        return services.get(WorkerSessionLocal.class);
    }

    private String createRequestPEM(String subjectDN, PrivateKey privateKey, PublicKey publicKey, String provider) {
        final PKCS10CertReqInfo certReqInfo = new PKCS10CertReqInfo(certSignatureAlgorithm, subjectDN, null);
        
        Base64SignerCertReqData reqData = (Base64SignerCertReqData) CryptoTokenHelper.genCertificateRequest(certReqInfo, privateKey, provider, publicKey, false);

        final StringBuilder buff = new StringBuilder();
        buff.append("-----BEGIN CERTIFICATE REQUEST-----\n");
        buff.append(new String(reqData.getBase64CertReq()));
        buff.append("\n-----END CERTIFICATE REQUEST-----\n");
        return buff.toString();
    }

    private EjbcaWS getEjbcaWS(final String ejbcaUrl, final String alias,
            final String truststoreType, final String truststorePath,
            final String truststoreValue, final String truststorePass,
            final ICryptoTokenV4 backingToken)
        throws CryptoTokenOfflineException,
            NoSuchAlgorithmException, KeyStoreException,
            UnrecoverableKeyException, IOException, CertificateException,
            NoSuchProviderException, KeyManagementException, SignServerException, NoSuchAliasException {

        final EjbcaWS result;
        final String urlstr = ejbcaUrl + WS_PATH;        
        final KeyStore keystore = backingToken.getKeyStore();
        
        final KeyManagerFactory kKeyManagerFactory = KeyManagerFactory.getInstance("SunX509");
        kKeyManagerFactory.init(keystore, null);

        final KeyStore keystoreTrusted;

        if (truststoreValue != null) {
            if (TRUSTSTORE_TYPE_PEM.equals(truststoreType)) {
                keystoreTrusted = KeyStore.getInstance("JKS");
                keystoreTrusted.load(null, null);
                final List<Certificate> certs = CertTools.getCertsFromPEM(new ByteArrayInputStream(truststoreValue.getBytes(StandardCharsets.UTF_8)),
                                                                   Certificate.class);
                int i = 0;
                for (final Certificate cert : certs) {
                    keystoreTrusted.setCertificateEntry("cert-" + i, cert);
                    i++;
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
            try (FileInputStream in = new FileInputStream(truststorePath)) {
                if (truststoreType == null) {
                    keystoreTrusted = KeyStore.getInstance(truststoreType, "BC");
                    keystoreTrusted.load(in, truststorePass.toCharArray());
                } else {
                    if (TRUSTSTORE_TYPE_PEM.equals(truststoreType)) {
                        keystoreTrusted = KeyStore.getInstance("JKS");
                        keystoreTrusted.load(null, null);
                        final List<Certificate> certs = CertTools.getCertsFromPEM(in, Certificate.class);
                        int i = 0;
                        for (final Certificate cert : certs) {
                            keystoreTrusted.setCertificateEntry("cert-" + i,
                                    cert);
                            i++;      
                        }
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("Loaded " + i + " certs to truststore");
                        }
                    } else {
                        keystoreTrusted = KeyStore.getInstance(truststoreType);
                        keystoreTrusted.load(in, truststorePass.toCharArray());
                    }
                }
            }
        }
        final TrustManagerFactory tTrustManagerFactory
                = TrustManagerFactory.getInstance("SunX509");
        tTrustManagerFactory.init(keystoreTrusted);
        KeyManager[] keyManagers = kKeyManagerFactory.getKeyManagers();
        for (int i = 0; i < keyManagers.length; i++) {
            if (keyManagers[i] instanceof X509KeyManager) {
                Certificate[] ch = keystore.getCertificateChain(alias);
                if (ch == null) {
                    throw new NoSuchAliasException("Missing key " + alias);
                }
                X509Certificate[] xcert = new X509Certificate[ch.length];
                for (int j = 0; j < ch.length; j++) {
                    xcert[j] = (X509Certificate) ch[j];
                }
                keyManagers[i] = new RenewalWorker.AliasKeyManager((X509KeyManager) keyManagers[i], alias, xcert);
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

    protected UserDataVOWS createUserData(final String keyAlias, final RequestContext context) {
        final UserDataVOWS result = new UserDataVOWS();
        // Construct fields
        final LogMap logMap = LogMap.getInstance(context);
        
        StrSubstitutor subst = new StrSubstitutor(new StrLookup() {
            @Override
            public String lookup(String key) {
                final String result;
                switch (key) {
                    case "username":
                        result = String.valueOf(logMap.get(IAuthorizer.LOG_USERNAME));
                        break;
                    //        remoteAddress
                    case "keyAlias":
                        result = keyAlias;
                        break;
                    //        cert.subject
                    //        cert.subject.[CN,O,C,1.2.3,...]
                    //        cert.issuer.[CN,O,C,1.2.3,…]
                    //        cert.subjectAltName
                    //        cert.subjectAltName.[dnsName,email,1.2.3...][.0,.1,…,.first,.last]
                    //        transactionId
                    case "transactionId":
                        result = String.valueOf(context.get(RequestContext.TRANSACTION_ID));
                        break;
                    //        metadata.X
                    default:
                        result = null;
                }
                return result;
            }
        });

        // Do the replacements
        final String endEntity = subst.replace(usernamePattern);
        final String subjectDN = subst.replace(subjectDNPattern);
        
        // Set subjectAltNamePattern only if provided otherwise ignore
        if (subjectAltNamePattern != null) {
            final String subjectAltName = subst.replace(subjectAltNamePattern);
            result.setSubjectAltName(subjectAltName);
        }

        result.setUsername(endEntity);
        result.setEndEntityProfileName(endentityProfile);
        result.setCertificateProfileName(certificateProfile);
        result.setCaName(caName);
        result.setSubjectDN(subjectDN);        
        
        if (certificateStartTime != null) {
            result.setStartTime(certificateStartTime);
        }
        if (certificateEndTime != null) {
            result.setEndTime(certificateEndTime);
        }

        return result;
    }
}
