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
package org.signserver.module.xades.signer;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchProviderException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import javax.persistence.EntityManager;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.server.signers.BaseSigner;
import org.apache.log4j.Logger;
import org.apache.xml.security.algorithms.MessageDigestAlgorithm;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerIdentifier;
import org.signserver.ejb.interfaces.InternalProcessSessionLocal;
import org.signserver.server.IServices;
import org.signserver.server.UsernamePasswordClientCredential;
import org.signserver.server.WorkerContext;
import org.signserver.server.archive.Archivable;
import org.signserver.server.archive.DefaultArchivable;
import org.signserver.server.cryptotokens.ICryptoInstance;
import org.signserver.server.cryptotokens.ICryptoTokenV4;
import org.signserver.common.data.Request;
import org.signserver.common.data.Response;
import org.signserver.common.data.SignatureRequest;
import org.signserver.common.data.SignatureResponse;
import org.signserver.common.data.WritableData;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.xml.sax.SAXException;

import xades4j.UnsupportedAlgorithmException;
import xades4j.XAdES4jException;
import xades4j.algorithms.Algorithm;
import xades4j.algorithms.GenericAlgorithm;
import xades4j.production.EnvelopedXmlObject;
import xades4j.production.SignedDataObjects;
import xades4j.production.XadesBesSigningProfile;
import xades4j.production.XadesSigner;
import xades4j.production.XadesSigningProfile;
import xades4j.production.XadesTSigningProfile;
import xades4j.properties.AllDataObjsCommitmentTypeProperty;
import xades4j.properties.SignerRoleProperty;
import xades4j.providers.KeyInfoCertificatesProvider;
import xades4j.providers.KeyingDataProvider;
import xades4j.providers.SignaturePropertiesCollector;
import xades4j.providers.SigningCertChainException;
import xades4j.providers.TimeStampTokenProvider;
import xades4j.utils.XadesProfileResolutionException;
import xades4j.providers.impl.DefaultAlgorithmsProviderEx;
import xades4j.providers.impl.DefaultMessageDigestProvider;
import xades4j.providers.impl.DefaultSignaturePropertiesProvider;
import xades4j.providers.impl.ExtendedTimeStampTokenProvider;
import xades4j.verification.UnexpectedJCAException;
import static org.signserver.common.SignServerConstants.DEFAULT_NULL;
import org.signserver.common.data.ReadableData;

/**
 * A Signer using XAdES to createSigner XML documents.
 * 
 * Based on patch contributed by Luis Maia &lt;lmaia@dcc.fc.up.pt&gt;.
 * 
 * @author Luis Maia <lmaia@dcc.fc.up.pt>
 * @version $Id$
 */
public class XAdESSigner extends BaseSigner {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(XAdESSigner.class);
    
    /** Worker property: XADESFORM. */
    public static final String PROPERTY_XADESFORM = "XADESFORM";
    
    /** Worker property: TSA_URL. */
    public static final String PROPERTY_TSA_URL = "TSA_URL";
    
    /** Worker property: TSA_USERNAME. */
    public static final String PROPERTY_TSA_USERNAME = "TSA_USERNAME";
    
    /** Worker property: TSA_PASSWORD. */
    public static final String PROPERTY_TSA_PASSWORD = "TSA_PASSWORD";

    /** Worker property: TSA_WORKER. */
    public static final String PROPERTY_TSA_WORKER = "TSA_WORKER";

    /** Worker property: COMMITMENT_TYPES. */
    public static final String PROPERTY_COMMITMENT_TYPES = "COMMITMENT_TYPES";
    public static final String COMMITMENT_TYPES_NONE = "NONE";

    /** Worker property: SIGNATUREALGORITHM */
    public static final String SIGNATUREALGORITHM = "SIGNATUREALGORITHM";
   
    /** Worker property: CLAIMED_ROLE. */
    public static final String CLAIMED_ROLE = "CLAIMED_ROLE";
    public static final String CLAIMED_ROLE_FROM_USERNAME = "CLAIMED_ROLE_FROM_USERNAME";

    /** Default value to use if the worker property XADESFORM has not been set. */
    private static final String DEFAULT_XADESFORM = "BES";
    
    private static final String DEFAULT_TSA_DIGEST_ALGORITHM = "SHA256";
    
    /** Worker property: TSA_DIGEST_ALGORITHM. */
    private static final String TSA_DIGESTALGORITHM = "TSA_DIGESTALGORITHM";
    
    private static final String CONTENT_TYPE = "text/xml";
    
    private LinkedList<String> configErrors;
    private XAdESSignerParameters parameters;
    
    private Collection<AllDataObjsCommitmentTypeProperty> commitmentTypes;
    
    private String signatureAlgorithm;
    private String tsaDigestAlgorithm;
    
    private String claimedRoleDefault;
    private boolean claimedRoleFromUsername;
    
    /**
     * Addional signature methods not yet covered by
     * javax.xml.dsig.SignatureMethod
     * 
     * Defined in RFC 4051 {@link http://www.ietf.org/rfc/rfc4051.txt}
     */
    static final String SIGNATURE_METHOD_RSA_SHA256 =
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    static final String SIGNATURE_METHOD_RSA_SHA384 =
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384";
    static final String SIGNATURE_METHOD_RSA_SHA512 =
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";
    static final String SIGNATURE_METHOD_ECDSA_SHA1 =
            "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1";
    static final String SIGNATURE_METHOD_ECDSA_SHA256 =
            "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";
    static final String SIGNATURE_METHOD_ECDSA_SHA384 =
            "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384";
    static final String SIGNATURE_METHOD_ECDSA_SHA512 =
            "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512";
    
    /**
     * The default time stamp token implementation, can be overridden by the unit tests.
     */
    private Class<? extends TimeStampTokenProvider> timeStampTokenProviderImplementation =
            ExtendedTimeStampTokenProvider.class;
    
    private TimeStampTokenProvider internalTimeStampTokenProvider;
    private InternalProcessSessionLocal workerSession;
    private WorkerIdentifier tsaWorker;
    private DefaultMessageDigestProvider mdProvider;
    private String tsaUrl;
    private String tsaUsername;
    private String tsaPassword;
    
    /** 
     * Electronic signature forms defined in ETSI TS 101 903 V1.4.1 (2009-06)
     * section 4.4.
     */
    public enum Profiles {
        BES,
        C,
        EPES,
        T
    }
    
    
    /**
     * Commitment types defined in ETSI TS 101 903 V1.4.1 (2009-06).
     * section 7.2.6.
     * @see xades4j.properties.AllDataObjsCommitmentTypeProperty
     */
    public enum CommitmentTypes {
        PROOF_OF_APPROVAL(AllDataObjsCommitmentTypeProperty.proofOfApproval()),
        PROOF_OF_CREATION(AllDataObjsCommitmentTypeProperty.proofOfCreation()),
        PROOF_OF_DELIVERY(AllDataObjsCommitmentTypeProperty.proofOfDelivery()),
        PROOF_OF_ORIGIN(AllDataObjsCommitmentTypeProperty.proofOfOrigin()),
        PROOF_OF_RECEIPT(AllDataObjsCommitmentTypeProperty.proofOfReceipt()),
        PROOF_OF_SENDER(AllDataObjsCommitmentTypeProperty.proofOfSender());
        
        CommitmentTypes(AllDataObjsCommitmentTypeProperty commitmentType) {
            prop = commitmentType;
        }
        
        AllDataObjsCommitmentTypeProperty getProp() {
            return prop;
        }
        
        AllDataObjsCommitmentTypeProperty prop;
    }

    @Override
    public void init(final int signerId, final WorkerConfig config, final WorkerContext workerContext, final EntityManager em) {
        super.init(signerId, config, workerContext, em);
        LOG.trace(">init");
        
        // Configuration errors
        configErrors = new LinkedList<>();
        
        // PROPERTY_XADESFORM
        Profiles form = null;
        final String xadesForm = config.getProperty(PROPERTY_XADESFORM, XAdESSigner.DEFAULT_XADESFORM);
        try {
            form = Profiles.valueOf(xadesForm);
        } catch (IllegalArgumentException ex) {
            configErrors.add("Incorrect value for property " + PROPERTY_XADESFORM + ": \"" + xadesForm + "\"");
        }
        
        // PROPERTY_TSA_URL, PROPERTY_TSA_USERNAME, PROPERTY_TSA_PASSWORD, PROPERTY_TSA_WORKER
        TSAParameters tsa = null;
        if (form == Profiles.T) {
            tsaUrl = config.getProperty(PROPERTY_TSA_URL, DEFAULT_NULL);
            tsaUsername = config.getProperty(PROPERTY_TSA_USERNAME, DEFAULT_NULL);
            tsaPassword = config.getPropertyThatCouldBeEmpty(PROPERTY_TSA_PASSWORD);
            final String tsaWorkerName = config.getProperty(PROPERTY_TSA_WORKER, DEFAULT_NULL);
            
            if (tsaUrl == null && tsaWorkerName == null) {
                configErrors.add("Property " + PROPERTY_TSA_URL + " or " + PROPERTY_TSA_WORKER + " are required when " + PROPERTY_XADESFORM + " is " + Profiles.T);
            } else {
                if (tsaUrl != null) {
                    // Use URL to external TSA
                    tsa = new TSAParameters(tsaUrl, tsaUsername, tsaPassword);
                } else {
                    // Use worker name/ID of internal TSA
                    this.tsaWorker = WorkerIdentifier.createFromIdOrName(tsaWorkerName.trim());
                    try {
                        this.mdProvider = new DefaultMessageDigestProvider("BC");
                    } catch (NoSuchProviderException ex) {
                        configErrors.add("No such message digest provider: " + ex.getMessage());
                    }
                }
            }
        }
      
        // check that TSA_URL and TSA_WORKER is not set at the same time
        if (config.getProperty(PROPERTY_TSA_URL, DEFAULT_NULL) != null && config.getProperty(PROPERTY_TSA_WORKER, DEFAULT_NULL) != null) {
            configErrors.add("Can not specify " + PROPERTY_TSA_URL + " and " + PROPERTY_TSA_WORKER + " at the same time.");
        }

        // TODO: Other configuration options
        final String commitmentTypesProperty = config.getProperties().getProperty(PROPERTY_COMMITMENT_TYPES);

        commitmentTypes = new LinkedList<>();
        
        if (commitmentTypesProperty != null) {
            if ("".equals(commitmentTypesProperty)) {
                configErrors.add("Commitment types can not be empty");
            } else if (!COMMITMENT_TYPES_NONE.equals(commitmentTypesProperty)) {
                for (final String part : commitmentTypesProperty.split(",")) {
                    final String type = part.trim();

                    try {
                        commitmentTypes.add(CommitmentTypes.valueOf(type).getProp());
                    } catch (IllegalArgumentException e) {
                        configErrors.add("Unknown commitment type: " + type);
                    }
                }
            }
        }

        parameters = new XAdESSignerParameters(form, tsa);
        
        // Get the signature algorithm
        signatureAlgorithm = config.getProperty(SIGNATUREALGORITHM, DEFAULT_NULL);
        
        // Get the TSA digest algorithm
        tsaDigestAlgorithm = config.getProperty(TSA_DIGESTALGORITHM, DEFAULT_TSA_DIGEST_ALGORITHM);
                
        claimedRoleDefault = config.getProperty(CLAIMED_ROLE, DEFAULT_NULL);
        claimedRoleFromUsername =
                Boolean.parseBoolean(config.getProperty(CLAIMED_ROLE_FROM_USERNAME, Boolean.FALSE.toString()));

        // additionally check that at least one certificate is included.
        // (initIncludeCertificateLevels already checks non-negative values)
        if (hasSetIncludeCertificateLevels && includeCertificateLevels == 0) {
            configErrors.add("Illegal value for property " + WorkerConfig.PROPERTY_INCLUDE_CERTIFICATE_LEVELS + ". Only numbers >= 1 supported.");
        }
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("Worker " + workerId + " configured: " + parameters);
            if (!configErrors.isEmpty()) {
                LOG.error("Worker " + workerId + " configuration error(s): " + configErrors);
            }
        }
        
        LOG.trace("<init");
    }

    @Override
    public Response processData(Request signRequest, RequestContext requestContext) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException {

        // Check that the request contains a valid GenericSignRequest object
        // with a byte[].
        if (!(signRequest instanceof SignatureRequest)) {
            throw new IllegalRequestException(
                    "Received request wasn't an expected GenericSignRequest.");
        }
        final SignatureRequest sReq = (SignatureRequest) signRequest;

        if (!configErrors.isEmpty()) {
            throw new SignServerException("Worker is misconfigured");
        }

        final String archiveId = createArchiveId(new byte[0], (String) requestContext.get(RequestContext.TRANSACTION_ID));
        final byte[] signedbytes;
       
        // take role from request user name in first hand when CLAIMED_ROLE_FROM_USERNAME
        // is true, otherwise take it from the CLAIMED_ROLE property
        UsernamePasswordClientCredential cred = null;
        final Object o = requestContext.get(RequestContext.CLIENT_CREDENTIAL);
        
        if (o instanceof UsernamePasswordClientCredential) {
            cred = (UsernamePasswordClientCredential) o;
        }

        final String username = cred != null ? cred.getUsername() : null;
        final String claimedRole =
                username != null && claimedRoleFromUsername ? username : claimedRoleDefault;
       
        // if CLAIMED_ROLE_FROM_USERNAME is true and there was no supplied user name
        // and no value from CLAIMED_ROLE consider this a fatal error
        if (claimedRoleFromUsername && claimedRoleDefault == null && username == null) {
            throw new SignServerException("Received a request with no user name set, while configured to get claimed role from user name and no default value for claimed role is set.");
        }
        
        final WritableData responseData = sReq.getResponseData();
        final ReadableData requestData = sReq.getRequestData();
        Certificate cert = null;
        ICryptoInstance crypto = null;
        try (
                InputStream in = requestData.getAsInputStream();
                OutputStream out = responseData.getAsOutputStream()
            ) {
            crypto = acquireCryptoInstance(ICryptoTokenV4.PURPOSE_SIGN, signRequest, requestContext);

            // Parse
            final XadesSigner signer =
                    createSigner(crypto, parameters, claimedRole, signRequest, requestContext);
            cert = getSigningCertificate(crypto);
            final DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);

            // Xerces 1 - http://xerces.apache.org/xerces-j/features.html#external-general-entities
            // Xerces 2 - http://xerces.apache.org/xerces2-j/features.html#external-general-entities
            dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);

            // Xerces 1 - http://xerces.apache.org/xerces-j/features.html#external-parameter-entities
            // Xerces 2 - http://xerces.apache.org/xerces2-j/features.html#external-parameter-entities
            dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);

            // Xerces 2 only - http://xerces.apache.org/xerces2-j/features.html#disallow-doctype-decl
            dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);

            final DocumentBuilder builder = dbf.newDocumentBuilder();
            final Document doc = builder.parse(in);

            // Sign
            final Node node = doc.getDocumentElement();
            SignedDataObjects dataObjs = new SignedDataObjects(new EnvelopedXmlObject(node));

            for (final AllDataObjsCommitmentTypeProperty commitmentType : commitmentTypes) {
                dataObjs = dataObjs.withCommitmentType(commitmentType);
            }

            signer.sign(dataObjs, doc);
            
            // Render result
            TransformerFactory tf = TransformerFactory.newInstance();
            Transformer trans = tf.newTransformer();
            trans.transform(new DOMSource(doc), new StreamResult(out));
        } catch (SAXException ex) {
            throw new IllegalRequestException("Document parsing error", ex);
        } catch (IOException | ParserConfigurationException ex) {
            throw new SignServerException("Document parsing error", ex);
        } catch (XadesProfileResolutionException ex) {
            throw new SignServerException("Exception in XAdES profile resolution", ex);
        } catch (XAdES4jException ex) {
            throw new SignServerException("Exception signing document", ex);
        } catch (TransformerException ex) {
            throw new SignServerException("Transformation failure", ex);
        } finally {
            releaseCryptoInstance(crypto, requestContext);
        }
        
        // Response
        final Collection<? extends Archivable> archivables = Arrays.asList(
                    new DefaultArchivable(Archivable.TYPE_REQUEST, CONTENT_TYPE, requestData, archiveId), 
                    new DefaultArchivable(Archivable.TYPE_RESPONSE, CONTENT_TYPE, responseData.toReadableData(), archiveId));

        // The client can be charged for the request
        requestContext.setRequestFulfilledByWorker(true);
        
        return new SignatureResponse(sReq.getRequestID(), responseData,
                    cert, archiveId, archivables, CONTENT_TYPE);
    }

    /**
     * Creates the signer implementation given the parameters.
     *
     * @param crypto instance
     * @param params Parameters such as XAdES form and TSA properties.
     * @param claimedRole
     * @param request Signing request
     * @param context Request context
     * @return The signer implementation
     * @throws SignServerException In case an unsupported XAdES form was specified
     * @throws XadesProfileResolutionException if the dependencies of the signer cannot be resolved
     * @throws CryptoTokenOfflineException If the private key is not available
     */
    private XadesSigner createSigner(final ICryptoInstance crypto,
                                    final XAdESSignerParameters params,
                                    final String claimedRole,
                                    final Request request,
                                    final RequestContext context)
            throws SignServerException, XadesProfileResolutionException,
                   CryptoTokenOfflineException, IllegalRequestException {
        // Setup key and certificiates
        final List<X509Certificate> xchain = new LinkedList<>();
        final List<Certificate> chain = this.getSigningCertificateChain(crypto);
        if (chain == null) {
            throw new CryptoTokenOfflineException("No certificate chain");
        }
        for (Certificate cert : chain) {
            if (cert instanceof X509Certificate) {
                xchain.add((X509Certificate) cert);
            }
        }
        final KeyingDataProvider kdp =
                new CertificateAndChainKeyingDataProvider(xchain, crypto.getPrivateKey());
        
        // Signing profile
        XadesSigningProfile xsp;                   
        
        switch (params.getXadesForm()) {
            case BES:
                xsp = new XadesBesSigningProfile(kdp);
                break;
            case T:
                // add timestamp token provider
                xsp = new XadesTSigningProfile(kdp);
                if (tsaUrl != null) {
                    // Use URL to external TSA
                    xsp = xsp.withTimeStampTokenProvider(timeStampTokenProviderImplementation)
                            .withBinding(TSAParameters.class, params.getTsaParameters());
                } else {
                    // Use internal TSA
                    xsp = xsp.withTimeStampTokenProvider(new InternalTimeStampTokenProvider(mdProvider, context.getServices().get(InternalProcessSessionLocal.class), tsaWorker, tsaUsername, tsaPassword));
                }

                break;
            case C:
            case EPES:
            default:
                throw new SignServerException("Unsupported XAdES profile configured");
        }
        
        xsp = xsp.withAlgorithmsProviderEx(new AlgorithmsProvider());
        
        if (claimedRole != null) {
            xsp = xsp.withSignaturePropertiesProvider(new SignaturePropertiesProvider(claimedRole));
        }
        
        // Include the configured number of certificates in the KeyInfo
        xsp.withKeyInfoCertificatesProvider(new KeyInfoCertificatesProvider() {
            @Override
            public List<X509Certificate> getCertificates(List<X509Certificate> list) throws SigningCertChainException, UnexpectedJCAException {
                return includedX509Certificates(list);
            }
        });
   
        return (XadesSigner) xsp.newSigner();
    }

    @Override
    protected List<String> getFatalErrors(final IServices services) {
        final LinkedList<String> errors = new LinkedList<>(super.getFatalErrors(services));
        errors.addAll(configErrors);
        return errors;
    }

    public XAdESSignerParameters getParameters() {
        return parameters;
    }
    
    /**
     * Used by the unit test to override the time stamp token provider.
     * 
     * @param implementation
     */
    public void setTimeStampTokenProviderImplementation(final Class<? extends TimeStampTokenProvider> implementation) {
        timeStampTokenProviderImplementation = implementation;
    }

    /**
     * Implementation of {@link xades4j.providers.AlgorithmsProviderEx} using the
     * signature algorithm configured for the worker (or the default values).
     */
    private class AlgorithmsProvider extends DefaultAlgorithmsProviderEx {

        @Override
        public Algorithm getSignatureAlgorithm(String keyAlgorithmName)
                throws UnsupportedAlgorithmException {
            if (signatureAlgorithm == null) {
                if ("EC".equals(keyAlgorithmName)) {
                    // DefaultAlgorithmsProviderEx only handles RSA and DSA
                    return new GenericAlgorithm(SIGNATURE_METHOD_ECDSA_SHA256);
                }
                // use default xades4j behavior when not configured for the worker
                return super.getSignatureAlgorithm(keyAlgorithmName);
            }
            
            if ("SHA1withRSA".equals(signatureAlgorithm)) {
                return new GenericAlgorithm(SignatureMethod.RSA_SHA1);
            } else if ("SHA256withRSA".equals(signatureAlgorithm)) {
                return new GenericAlgorithm(SIGNATURE_METHOD_RSA_SHA256);
            } else if ("SHA384withRSA".equals(signatureAlgorithm)) {
                return new GenericAlgorithm(SIGNATURE_METHOD_RSA_SHA384); 
            } else if ("SHA512withRSA".equals(signatureAlgorithm)) {
                return new GenericAlgorithm(SIGNATURE_METHOD_RSA_SHA512);
            } else if ("SHA1withDSA".equals(signatureAlgorithm)) {
                return new GenericAlgorithm(SignatureMethod.DSA_SHA1);
            } else if ("SHA1withECDSA".equals(signatureAlgorithm)) {
                return new GenericAlgorithm(SIGNATURE_METHOD_ECDSA_SHA1);
            } else if ("SHA256withECDSA".equals(signatureAlgorithm)) {
                return new GenericAlgorithm(SIGNATURE_METHOD_ECDSA_SHA256);
            } else if ("SHA384withECDSA".equals(signatureAlgorithm)) {
                return new GenericAlgorithm(SIGNATURE_METHOD_ECDSA_SHA384);
            } else if ("SHA512withECDSA".equals(signatureAlgorithm)) {
                return new GenericAlgorithm(SIGNATURE_METHOD_ECDSA_SHA512);
            } else {
                throw new UnsupportedAlgorithmException("Unsupported signature algorithm", signatureAlgorithm);
            }
        }

        @Override
        public String getDigestAlgorithmForTimeStampProperties() {
            String result;

            switch (tsaDigestAlgorithm) {
                case "MD5":
                case "MD-5":
                    result = MessageDigestAlgorithm.ALGO_ID_DIGEST_NOT_RECOMMENDED_MD5;
                    break;
                case "SHA1":
                case "SHA-1":
                    result = MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA1;
                    break;
                case "SHA224":
                case "SHA-224":
                    result = MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA224;
                    break;
                case "SHA256":
                case "SHA-256":
                    result = MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA256;
                    break;
                case "SHA384":
                case "SHA-384":
                    result = MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA384;
                    break;
                case "SHA512":
                case "SHA-512":
                    result = MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA512;
                    break;
                case "RIPEMD160":
                case "RIPEMD-160":
                    result = MessageDigestAlgorithm.ALGO_ID_DIGEST_RIPEMD160;
                    break;
                default:
                    throw new IllegalArgumentException("Unsupported TSA digest algorithm: " + tsaDigestAlgorithm);
            }
            return result;
        }
        
    }
    
    /**
     * SignaturePropertiesProvider adding signer role property.
     *
     */
    private class SignaturePropertiesProvider extends DefaultSignaturePropertiesProvider {

        private String claimedRole;
        
        public SignaturePropertiesProvider(final String claimedRole) {
            this.claimedRole = claimedRole;
        }
        
        @Override
        public void provideProperties(
                SignaturePropertiesCollector signaturePropsCol) {
            super.provideProperties(signaturePropsCol);
            signaturePropsCol.setSignerRole(new SignerRoleProperty(claimedRole));
        }

    }

    /**
     * Utility method to extract certificate chain from list of X509Certificate.
     * This will use the default of 1 certificate if the INCLUDE_CERTIFICATE_LEVELS
     * propery has not been set.
     * 
     * @param certs List of certificates to extract chain from
     * @return The certificate chain, including the configured number of certificates
     */
    protected List<X509Certificate> includedX509Certificates(List<X509Certificate> certs) {
        if (hasSetIncludeCertificateLevels) {
            return certs.subList(0, Math.min(includeCertificateLevels, certs.size()));
        } else {
            // there should always be at least one cert in the chain
            return certs.subList(0, 1);
        }
    }

    protected InternalProcessSessionLocal getProcessSession(RequestContext requestContext) {
        return requestContext.getServices().get(InternalProcessSessionLocal.class);
    }
}
