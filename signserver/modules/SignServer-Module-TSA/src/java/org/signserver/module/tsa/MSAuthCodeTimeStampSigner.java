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
package org.signserver.module.tsa;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.util.*;

import javax.persistence.EntityManager;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BEROctetString;
import org.bouncycastle.asn1.BERSet;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.asn1.ess.ESSCertID;
import org.bouncycastle.asn1.ess.SigningCertificate;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Attribute;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuerSerial;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.SignerInfoGeneratorBuilder;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.*;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.TeeOutputStream;
import org.ejbca.util.Base64;
import org.signserver.common.*;
import org.signserver.server.ITimeSource;
import org.signserver.server.WorkerContext;
import org.signserver.server.archive.Archivable;
import org.signserver.server.archive.DefaultArchivable;
import org.signserver.server.cryptotokens.ICryptoToken;
import org.signserver.server.log.LogMap;
import org.signserver.server.signers.BaseSigner;


/**
 * A Signer signing Time-stamp request compatible with Microsoft Authenticode
 *
 * Implements a ISigner and have the following properties:
 *
 * <table border="1">
 *  <tr>
 *      <td>TIMESOURCE</td>
 *      <td>
 *          property containing the classpath to the ITimeSource implementation
 *          that should be used. (default LocalComputerTimeSource)
 *      </td>
 *  </tr>
 *
 * </table>
 * 
 * Specifying a signer certificate (normally the SIGNERCERT property) is required 
 * as information from that certificate will be used to indicate which signer
 * signed the time-stamp token.
 * 
 * The SIGNERCERTCHAIN property contains all certificates included in the token 
 * if the client requests the certificates. The RFC specified that the signer 
 * certificate MUST be included in the list returned.
 * 
 *
 * @author Marcus Lundblad
 * @version $Id$
 */
public class MSAuthCodeTimeStampSigner extends BaseSigner {

    /** Log4j instance for actual implementation class. */
    private static final Logger LOG = Logger.getLogger(MSAuthCodeTimeStampSigner.class);

    /** Random generator algorithm. */
    private static String algorithm = "SHA1PRNG";

    /** Random generator. */
    private transient SecureRandom random;

    private static final BigInteger LOWEST =
            new BigInteger("0080000000000000", 16);

    private static final BigInteger HIGHEST =
            new BigInteger("7FFFFFFFFFFFFFFF", 16);

    //Private Property constants
    public static final String TIMESOURCE = "TIMESOURCE";
    public static final String SIGNATUREALGORITHM = "SIGNATUREALGORITHM";
    public static final String ACCEPTEDALGORITHMS = "ACCEPTEDALGORITHMS";
    public static final String ACCEPTEDPOLICIES = "ACCEPTEDPOLICIES";
    public static final String ACCEPTEDEXTENSIONS = "ACCEPTEDEXTENSIONS";
    //public static final String DEFAULTDIGESTOID    = "DEFAULTDIGESTOID";
    public static final String DEFAULTTSAPOLICYOID = "DEFAULTTSAPOLICYOID";
    public static final String ACCURACYMICROS = "ACCURACYMICROS";
    public static final String ACCURACYMILLIS = "ACCURACYMILLIS";
    public static final String ACCURACYSECONDS = "ACCURACYSECONDS";
    public static final String ORDERING = "ORDERING";
    public static final String TSA = "TSA";
    public static final String REQUIREVALIDCHAIN = "REQUIREVALIDCHAIN";
    public static final String INCLUDE_SIGNING_CERTIFICATE_ATTRIBUTE = "INCLUDE_SIGNING_CERTIFICATE_ATTRIBUTE";
    
    private static final String dataOID = "1.2.840.113549.1.7.1";
    private static final String msOID = "1.3.6.1.4.1.311.3.2.1";

    private static final String DEFAULT_WORKERLOGGER =
            DefaultTimeStampLogger.class.getName();

    private static final String DEFAULT_TIMESOURCE =
            "org.signserver.server.LocalComputerTimeSource";
    
    private static final String DEFAULT_SIGNATUREALGORITHM = "SHA1withRSA";
    
    /** MIME type for the request data. **/
    private static final String REQUEST_CONTENT_TYPE = "application/octect-stream";
    
    /** MIME type for the response data. **/
    private static final String RESPONSE_CONTENT_TYPE = "application/octet-stream";

    private ITimeSource timeSource = null;
    private String signatureAlgo;
    
    private boolean validChain = true;
    
    private boolean includeSigningCertificateAttribute;
    
    @Override
    public void init(final int signerId, final WorkerConfig config,
            final WorkerContext workerContext,
            final EntityManager workerEntityManager) {
        super.init(signerId, config, workerContext, workerEntityManager);

        // Overrides the default worker logger to be this worker
        //  implementation's default instead of the WorkerSessionBean's
        if (config.getProperty("WORKERLOGGER") == null) {
            config.setProperty("WORKERLOGGER", DEFAULT_WORKERLOGGER);
        }

        // Check that the timestamp server is properly configured
        try {
            timeSource = getTimeSource();
            if (timeSource == null) {
                final String error = "Error: Timestamp signer :" + signerId +
                    " has a malconfigured timesource.";
                LOG.error(error);
            } else {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("TimeStampSigner[" + signerId + "]: "
                            + "Using TimeSource: "
                            + timeSource.getClass().getName());
                }
            }
            
            signatureAlgo = config.getProperty(SIGNATUREALGORITHM);
            
            if (signatureAlgo == null) {
            	signatureAlgo = DEFAULT_SIGNATUREALGORITHM;
            }
        } catch (SignServerException e) {
            LOG.error("Could not create time source: " + e.getMessage());
        }
   
        if (LOG.isDebugEnabled()) {
            LOG.debug("bctsp version: " + TimeStampResponseGenerator.class
                .getPackage().getImplementationVersion() + ", "
                + TimeStampRequest.class.getPackage()
                    .getImplementationVersion());
        }
        
        // Validate certificates in signer certificate chain
        final String requireValidChain = config.getProperty(REQUIREVALIDCHAIN, Boolean.FALSE.toString());
        if (Boolean.parseBoolean(requireValidChain)) {
            validChain = validateChain();
        }
        
        includeSigningCertificateAttribute =
                Boolean.parseBoolean(config.getProperty(INCLUDE_SIGNING_CERTIFICATE_ATTRIBUTE, "false"));
    }

    /**
     * The main method performing the actual timestamp operation.
     * Expects the signRequest to be a GenericSignRequest contining a
     * TimeStampRequest
     *
     * @param signRequest
     * @param requestContext
     * @return the sign response
     * @see org.signserver.server.IProcessable#processData(org.signserver.common.ProcessRequest, org.signserver.common.RequestContext)
     */
    public ProcessResponse processData(final ProcessRequest signRequest,
            final RequestContext requestContext) throws
                IllegalRequestException,
                CryptoTokenOfflineException,
                SignServerException {

    	// Log values
		final LogMap logMap = LogMap.getInstance(requestContext);
    	
    	try {
            final ISignRequest sReq = (ISignRequest) signRequest;
            final byte[] requestbytes = (byte[]) sReq.getRequestData();

            if (requestbytes == null || requestbytes.length == 0) {
                LOG.error("Request must contain data");
                throw new IllegalRequestException("Request must contain data");
            }
            
            // Check that the request contains a valid TimeStampRequest object.
            if (!(signRequest instanceof GenericSignRequest)) {
                    final IllegalRequestException exception =
                                    new IllegalRequestException(
                                                    "Recieved request wasn't an expected GenericSignRequest. ");
                    LOG.error("Received request wasn't an expected GenericSignRequest");
                    throw exception;
            }

            if (!((sReq.getRequestData() instanceof TimeStampRequest)
            || (sReq.getRequestData() instanceof byte[]))) {
                    final IllegalRequestException exception =
                                    new IllegalRequestException(
                                                    "Recieved request data wasn't an expected TimeStampRequest. ");
                    LOG.error("Received request data wasn't an expected TimeStampRequest");
                    throw exception;
            }

            if (!validChain) {
                    LOG.error("Certificate chain not correctly configured");
                    throw new CryptoTokenOfflineException("Certificate chain not correctly configured");
            }

            ASN1Primitive asn1obj = ASN1Primitive.fromByteArray(Base64.decode(requestbytes));
            ASN1Sequence asn1seq = ASN1Sequence.getInstance(asn1obj);

            if (asn1seq.size() != 2) {
                    LOG.error("Wrong structure, should be an ASN1Sequence with 2 elements");
                    throw new IllegalRequestException("Wrong structure, should be an ASN1Sequence with 2 elements");
            }

            ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.getInstance(asn1seq.getObjectAt(0));
            ASN1Sequence asn1seq1 = ASN1Sequence.getInstance(asn1seq.getObjectAt(1));

            final ContentInfo ci = new ContentInfo(asn1seq1);
            
            if (!oid.getId().equals(msOID)) {
                    LOG.error("Invalid OID in request: " + oid.getId());
                    throw new IllegalRequestException("Invalid OID in request: " + oid.getId());
            }

            if (asn1seq1.size() != 2) {
                    LOG.error("Wrong structure, should be an ASN1Sequence with 2 elements as the value of element 0 in the outer ASN1Sequence");
                    throw new IllegalRequestException("Wrong structure, should be an ASN1Sequence with 2 elements as the value of element 0 in the outer ASN1Sequence");
            } 

            oid = ASN1ObjectIdentifier.getInstance(asn1seq1.getObjectAt(0));

            if (!oid.getId().equals(dataOID)) {
                    throw new IllegalRequestException("Wrong contentType OID: " + oid.getId());
            }

            ASN1TaggedObject tag = ASN1TaggedObject.getInstance(asn1seq1.getObjectAt(1));

            if (tag.getTagNo() != 0) {
                    throw new IllegalRequestException("Wrong tag no (should be 0): " + tag.getTagNo());
            } 

            ASN1OctetString octets = ASN1OctetString.getInstance(tag.getObject());
            byte[] content = octets.getOctets();
           
            // get signing cert certificate chain and private key
            List<Certificate> certList = this.getSigningCertificateChain();
            if (certList == null) {
                throw new SignServerException(
                        "Null certificate chain. This signer needs a certificate.");
            }

            Certificate[] certs = (Certificate[]) certList.toArray(new Certificate[0]);
            PrivateKey pk = this.getCryptoToken().getPrivateKey(
                    ICryptoToken.PURPOSE_SIGN);

            // Sign
            X509Certificate x509cert = (X509Certificate) certs[0]; 
            List<X509Certificate> certL = new ArrayList<X509Certificate>();

            for (final Certificate cert : certs) {
                    certL.add((X509Certificate) cert);
            }
            
            final Date date = getTimeSource().getGenTime();
            
            if (date == null) {
                throw new ServiceUnavailableException("Time source is not available");
            }
            
            ASN1EncodableVector signedAttributes = new ASN1EncodableVector();
            signedAttributes.add(new Attribute(CMSAttributes.signingTime, new DERSet(new Time(date))));
            
            if (includeSigningCertificateAttribute) {
                try {
                    final DERInteger serial = new DERInteger(x509cert.getSerialNumber());
                    final X509CertificateHolder certHolder =
                            new X509CertificateHolder(x509cert.getEncoded());
                    final X500Name issuer = certHolder.getIssuer();                   
                    final GeneralName name = new GeneralName(issuer);
                    final GeneralNames names = new GeneralNames(name);
                    final IssuerSerial is = new IssuerSerial(names, ASN1Integer.getInstance(serial));

                    final ESSCertID essCertid =
                            new ESSCertID(MessageDigest.getInstance("SHA-1").digest(x509cert.getEncoded()), is);
                    signedAttributes.add(new Attribute(PKCSObjectIdentifiers.id_aa_signingCertificate,
                            new DERSet(new SigningCertificate(essCertid))));
                } catch (NoSuchAlgorithmException e) {
                    LOG.error("Can't find SHA-1 implementation: " + e.getMessage());
                    throw new SignServerException("Can't find SHA-1 implementation", e);
                }
            }

            AttributeTable signedAttributesTable = new AttributeTable(signedAttributes);
            DefaultSignedAttributeTableGenerator signedAttributeGenerator = new DefaultSignedAttributeTableGenerator(signedAttributesTable);

            
            final String provider = cryptoToken.getProvider(ICryptoToken.PROVIDERUSAGE_SIGN);
            
            SignerInfoGeneratorBuilder signerInfoBuilder =
                    new SignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider("BC").build());
            signerInfoBuilder.setSignedAttributeGenerator(signedAttributeGenerator);

            JcaContentSignerBuilder contentSigner = new JcaContentSignerBuilder(signatureAlgo);
            contentSigner.setProvider(provider);

            final SignerInfoGenerator sig = signerInfoBuilder.build(contentSigner.build(pk), new X509CertificateHolder(x509cert.getEncoded()));

            JcaCertStore cs = new JcaCertStore(certList);
            
            CMSTypedData cmspba = new CMSProcessableByteArray(content);
            CMSSignedData cmssd = MSAuthCodeCMSUtils.generate(cmspba, true, Arrays.asList(sig),
                    MSAuthCodeCMSUtils.getCertificatesFromStore(cs), Collections.emptyList(), ci);

            byte[] der = ASN1Primitive.fromByteArray(cmssd.getEncoded()).getEncoded(); 

  
            // Log values
            logMap.put(ITimeStampLogger.LOG_TSA_TIME, date == null ? null
                : String.valueOf(date.getTime()));
            
            final String archiveId = createArchiveId(requestbytes, (String) requestContext.get(RequestContext.TRANSACTION_ID));

            GenericSignResponse signResponse = null;
            byte[] signedbytes = Base64.encode(der);
            
            logMap.put(ITimeStampLogger.LOG_TSA_TIMESTAMPRESPONSE_ENCODED,
                    new String(signedbytes));
        	
            
            final Collection<? extends Archivable> archivables = Arrays.asList(
                    new DefaultArchivable(Archivable.TYPE_REQUEST, REQUEST_CONTENT_TYPE, requestbytes, archiveId),
                    new DefaultArchivable(Archivable.TYPE_RESPONSE, RESPONSE_CONTENT_TYPE, signedbytes, archiveId));

            
            if (signRequest instanceof GenericServletRequest) {
                signResponse = new GenericServletResponse(sReq.getRequestID(),
                        		signedbytes,
                                    getSigningCertificate(),
                                    archiveId,
                                    archivables,
                                    RESPONSE_CONTENT_TYPE);
            } else {
                signResponse = new GenericSignResponse(sReq.getRequestID(),
                        signedbytes,
                        getSigningCertificate(),
                        archiveId,
                        archivables);
            }
        
        	return signResponse;

        } catch (IOException e) {
            final IllegalRequestException exception =
                    new IllegalRequestException(
                    "IOException: " + e.getMessage(), e);
            LOG.error("IOException: ", e);
            logMap.put(ITimeStampLogger.LOG_TSA_EXCEPTION,
                    exception.getMessage());
            throw exception;
        } catch (CMSException e) {
        	final SignServerException exception =
        			new SignServerException(e.getMessage(), e);
        	LOG.error("CMSException: ", e);
        	logMap.put(ITimeStampLogger.LOG_TSA_EXCEPTION,
        			exception.getMessage());
        	throw exception;
        } catch (OperatorCreationException e) {
            final SignServerException exception =
                new SignServerException(e.getMessage(), e);
            LOG.error("OperatorCreationException: ", e);
            logMap.put(ITimeStampLogger.LOG_TSA_EXCEPTION,
        	exception.getMessage());
            throw exception;
        } catch (CertificateEncodingException e) {
            final SignServerException exception =
                new SignServerException(e.getMessage(), e);
            LOG.error("CertificateEncodingException: ", e);
            logMap.put(ITimeStampLogger.LOG_TSA_EXCEPTION,
        	exception.getMessage());
            throw exception;
        } catch (ArrayIndexOutOfBoundsException e) {
            // the BC base64 decoder doesn't check the the base64 input length...
            final IllegalRequestException exception =
                    new IllegalRequestException(
                    "ArrayIndexOutOfBoundsException: " + e.getMessage(), e);
            LOG.error("ArrayIndexOutOfBoundsException: ", e);
            logMap.put(ITimeStampLogger.LOG_TSA_EXCEPTION,
                    exception.getMessage());
            throw exception;
        }
    }

    /**
     * @return a time source interface expected to provide accurate time
     */
    private ITimeSource getTimeSource() throws SignServerException {
        if (timeSource == null) {
            try {
                String classpath =
                        this.config.getProperties().getProperty(TIMESOURCE);
                if (classpath == null) {
                    classpath = DEFAULT_TIMESOURCE;
                }

                final Class<?> implClass = Class.forName(classpath);
                final Object obj = implClass.newInstance();
                timeSource = (ITimeSource) obj;
                timeSource.init(config.getProperties());

            } catch (ClassNotFoundException e) {
                throw new SignServerException("Class not found", e);
            } catch (IllegalAccessException iae) {
                throw new SignServerException("Illegal access", iae);
            } catch (InstantiationException ie) {
                throw new SignServerException("Instantiation error", ie);
            }
        }

        return timeSource;
    }


    /** Generates a number of serial number bytes. The number returned should
     * be a positive number.
     *
     * @return a BigInteger with a new random serial number.
     */
    public BigInteger getSerno() {
        if (random == null) {
            try {
                random = SecureRandom.getInstance(algorithm);
            } catch (NoSuchAlgorithmException e) {
                LOG.error(e);
            }
        }

        final byte[] sernobytes = new byte[8];
        boolean ok = false;
        BigInteger serno = null;
        while (!ok) {
            random.nextBytes(sernobytes);
            serno = new BigInteger(sernobytes).abs();

            // Must be within the range 0080000000000000 - 7FFFFFFFFFFFFFFF
            if ((serno.compareTo(LOWEST) >= 0)
                    && (serno.compareTo(HIGHEST) <= 0)) {
                ok = true;
            }
        }
        return serno;
    }

    /**
     * @return True if each certificate in the certificate chain can be verified 
     * by the next certificate (if any). This does not check that the last 
     * certificate is a trusted certificate as the root certificate is normally 
     * not included.
     */
    private boolean validateChain() {
        boolean result = true;
        try {
            Collection<Certificate> signingCertificateChain = getSigningCertificateChain();
            if (signingCertificateChain instanceof List) {
                List<Certificate> chain = (List<Certificate>) signingCertificateChain;
                for (int i = 0; i < chain.size(); i++) {
                    Certificate subject = chain.get(i);
                    
                    // If we have the issuer we can validate the certificate
                    if (chain.size() > i + 1) {
                        Certificate issuer = chain.get(i + 1);
                        try {
                            subject.verify(issuer.getPublicKey(), "BC");
                        } catch (CertificateException ex) {
                            if (LOG.isDebugEnabled()) {
                                LOG.debug("Certificate could not be verified: " + ex.getMessage() + ": " + subject);
                            }
                            result = false;
                        } catch (NoSuchAlgorithmException ex) {
                            if (LOG.isDebugEnabled()) {
                                LOG.debug("Certificate could not be verified: " + ex.getMessage() + ": " + subject);
                            }
                            result = false;
                        } catch (InvalidKeyException ex) {
                            if (LOG.isDebugEnabled()) {
                                LOG.debug("Certificate could not be verified: " + ex.getMessage() + ": " + subject);
                            }
                            result = false;
                        } catch (NoSuchProviderException ex) {
                            if (LOG.isDebugEnabled()) {
                                LOG.debug("Certificate could not be verified: " + ex.getMessage() + ": " + subject);
                            }
                            result = false;
                        } catch (SignatureException ex) {
                            if (LOG.isDebugEnabled()) {
                                LOG.debug("Certificate could not be verified: " + ex.getMessage() + ": " + subject);
                            }
                            result = false;
                        }
                    }
                }
            } else {
                // This would be a bug
                LOG.error("Certificate chain was not an list!");
                result = false;
            }
        } catch (CryptoTokenOfflineException ex) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Unable to get signer certificate or chain: " + ex.getMessage());
            }
            result = false;
        }
        return result;
    }

    @Override
    protected List<String> getFatalErrors() {
        final List<String> result = new LinkedList<String>();
        result.addAll(super.getFatalErrors());
        
        try {
            // Check signer certificate chain if required
            if (!validChain) {
                result.add("Not strictly valid chain and " + REQUIREVALIDCHAIN + " specified");
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Signer " + workerId + ": " + REQUIREVALIDCHAIN + " specified but the chain was not found valid");
                }
            }

            // Check if certificat has the required EKU
            final Certificate certificate = getSigningCertificate();
            try {
                if (certificate instanceof X509Certificate) {
                    final X509Certificate cert = (X509Certificate) certificate;
                    if (cert.getExtendedKeyUsage() == null 
                            || !cert.getExtendedKeyUsage().contains(KeyPurposeId.id_kp_timeStamping.getId())) {
                        result.add("Missing extended key usage timeStamping");
                    }
                    if (cert.getCriticalExtensionOIDs() == null 
                            || !cert.getCriticalExtensionOIDs().contains(org.bouncycastle.asn1.x509.X509Extension.extendedKeyUsage.getId())) {
                        result.add("The extended key usage extension must be present and marked as critical");
                    }
                } else {
                    result.add("Unsupported certificate type");
                }
            } catch (CertificateParsingException ex) {
                result.add("Unable to parse certificate");
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Signer " + workerId + ": Unable to parse certificate: " + ex.getMessage());
                }
            }
        } catch (CryptoTokenOfflineException ex) {
            result.add("No signer certificate available");
            if (LOG.isDebugEnabled()) {
                LOG.debug("Signer " + workerId + ": Could not get signer certificate: " + ex.getMessage());
            }
        } 
        
        // check time source
        if (timeSource.getGenTime() == null) {
        	result.add("Time source not available");
        	if (LOG.isDebugEnabled()) {
        		LOG.debug("Signer " + workerId + ": time source not available");
        	}
        }

        return result;
    }
    


}
