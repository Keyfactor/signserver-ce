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

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.ejb.EJBException;
import javax.persistence.EntityManager;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;
import org.signserver.server.tsa.org.bouncycastle.tsp.TimeStampResponseGenerator;
import org.bouncycastle.tsp.TimeStampTokenGenerator;
import org.ejbca.util.Base64;
import org.signserver.common.ArchiveData;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.GenericServletRequest;
import org.signserver.common.GenericServletResponse;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.GenericSignResponse;
import org.signserver.common.ISignRequest;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.ProcessRequest;
import org.signserver.common.ProcessResponse;
import org.signserver.common.RequestContext;
import org.signserver.common.WorkerConfig;
import org.signserver.server.ITimeSource;
import org.signserver.server.IWorkerLogger;
import org.signserver.server.WorkerContext;
import org.signserver.server.cryptotokens.ICryptoToken;
import org.signserver.server.signers.BaseSigner;

/**
 * A Signer signing Time-stamp request according to RFC 3161 using the
 * BouncyCastle TimeStamp API.
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
 *  <tr>
 *      <td>ACCEPTEDALGORITHMS</td>
 *      <td>
 *          A ';' separated string containing accepted algorithms, can be null
 *          if it shouldn't be used. (OPTIONAL)
 *      </td>
 *  </tr>
 *  <tr>
 *      <td>ACCEPTEDPOLICIES</td>
 *      <td>
 *          A ';' separated string containing accepted policies, can be null if
 *          it shouldn't be used. (OPTIONAL)
 *      </td>
 * </tr>
 *  <tr>
 *      <td>ACCEPTEDEXTENSIONS</td>
 *      <td>
 *          A ';' separated string containing accepted extensions, can be null
 *          if it shouldn't be used. (OPTIONAL)
 *      </td>
 * </tr>
 *  <tr>
 *      <td>DIGESTOID</td>
 *      <td>
 *          The Digenst OID to be used in the timestamp
 *      </td>
 * </tr>
 *  <tr>
 *      <td>DEFAULTTSAPOLICYOID</td>
 *      <td>
 *          The default policy ID of the time stamp authority
 *      </td>
 * </tr>
 *  <tr>
 *      <td>ACCURACYMICROS</td>
 *      <td>
 *          Accuraty in micro seconds, Only decimal number format, only one of
 *          the accuracy properties should be set (OPTIONAL)
 *      </td>
 * </tr>
 *  <tr>
 *      <td>ACCURACYMILLIS</td>
 *      <td>
 *          Accuraty in milli seconds, Only decimal number format, only one of
 *          the accuracy properties should be set (OPTIONAL)
 *      </td>
 * </tr>
 *  <tr>
 *      <td>ACCURACYSECONDS</td>
 *      <td>
 *          Accuraty in seconds. Only decimal number format, only one of the
 *          accuracy properties should be set (OPTIONAL)
 *      </td>
 * </tr>
 *  <tr>
 *      <td>ORDERING</td>
 *      <td>
 *          The ordering (OPTIONAL), default false.
 *      </td>
 * </tr>
 *  <tr>
 *      <td>TSA</td>
 *      <td>
 *          General name of the Time Stamp Authority.
 *      </td>
 *  </tr>
 *
 *
 * </table>
 *
 * @author philip
 * $Id$
 */
public class TimeStampSigner extends BaseSigner {

    /** Log4j instance for actual implementation class. */
    private static final Logger LOG = Logger.getLogger(TimeStampSigner.class);

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

    private static final String DEFAULT_WORKERLOGGER =
            DefaultTimeStampLogger.class.getName();

    private static final String DEFAULT_TIMESOURCE =
            "org.signserver.server.LocalComputerTimeSource";
    
    private static final String[] ACCEPTEDALGORITHMSNAMES = {
        "GOST3411",
        "MD5",
        "SHA1",
        "SHA224",
        "SHA256",
        "SHA384",
        "SHA512",
        "RIPEMD128",
        "RIPEMD160",
        "RIPEMD256"
    };
    
    private static final String[] ACCEPTEDALGORITHMSOIDS = {
        TSPAlgorithms.GOST3411,
        TSPAlgorithms.MD5,
        TSPAlgorithms.SHA1,
        TSPAlgorithms.SHA224,
        TSPAlgorithms.SHA256,
        TSPAlgorithms.SHA384,
        TSPAlgorithms.SHA512,
        TSPAlgorithms.RIPEMD128,
        TSPAlgorithms.RIPEMD160,
        TSPAlgorithms.RIPEMD256
    };

    private static final HashMap<String, String> ACCEPTEDALGORITHMSMAP =
            new HashMap<String, String>();

    static {
        for (int i = 0; i < ACCEPTEDALGORITHMSNAMES.length; i++) {
            ACCEPTEDALGORITHMSMAP.put(ACCEPTEDALGORITHMSNAMES[i],
                    ACCEPTEDALGORITHMSOIDS[i]);
        }
    }

    private static final String DEFAULT_ORDERING = "FALSE";
    //private static final String DEFAULT_DIGESTOID   = TSPAlgorithms.SHA1;

    private ITimeSource timeSource = null;
    private Set<String> acceptedAlgorithms = null;
    private Set<String> acceptedPolicies = null;
    private Set<String> acceptedExtensions = null;

    //private String defaultDigestOID = null;
    private String defaultTSAPolicyOID = null;

    
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

        /* defaultDigestOID =
            config.getProperties().getProperty(DEFAULTDIGESTOID);
        if (defaultDigestOID == null) {
            defaultDigestOID = DEFAULT_DIGESTOID;
        }*/

        defaultTSAPolicyOID =
                config.getProperties().getProperty(DEFAULTTSAPOLICYOID);
        if (defaultTSAPolicyOID == null) {
            LOG.error("Error: No default TSA Policy OID have been configured");
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("bctsp version: " + TimeStampResponseGenerator.class
                .getPackage().getImplementationVersion() + ", "
                + TimeStampRequest.class.getPackage()
                    .getImplementationVersion());
        }
    }

    /**
     * The main method performing the actual timestamp operation.
     * Expects the signRequest to be a GenericSignRequest contining a
     * TimeStampRequest
     *
     * @param signRequest
     * @param requestContext
     * @return the sign response
     * @see org.signserver.server.signers.IProcessable#signData(
     *  org.signserver.common.ProcessRequest,
     *  java.security.cert.X509Certificate)
     */
    public ProcessResponse processData(final ProcessRequest signRequest,
            final RequestContext requestContext) throws
                IllegalRequestException,
                CryptoTokenOfflineException {

        // Log values
        final Map<String, String> logMap =
                (Map<String, String>) requestContext.get(RequestContext.LOGMAP);

        final ISignRequest sReq = (ISignRequest) signRequest;

        // Check that the request contains a valid TimeStampRequest object.
        if (!(signRequest instanceof GenericSignRequest)) {
            final IllegalRequestException exception =
                    new IllegalRequestException(
                    "Recieved request wasn't a expected GenericSignRequest. ");
            throw exception;
        }

        if (!((sReq.getRequestData() instanceof TimeStampRequest)
                || (sReq.getRequestData() instanceof byte[]))) {
            final IllegalRequestException exception =
                    new IllegalRequestException(
                "Recieved request data wasn't a expected TimeStampRequest. ");
            throw exception;
        }

        final Date date = getTimeSource().getGenTime();
        final BigInteger serialNumber = getSerialNumber();

        // Log values
        logMap.put(ITimeStampLogger.LOG_TSA_TIME, date == null ? null
                : String.valueOf(date.getTime()));
        logMap.put(ITimeStampLogger.LOG_TSA_SERIALNUMBER,
                serialNumber.toString(16));


        GenericSignResponse signResponse;
        try {
            final TimeStampRequest timeStampRequest =
                    new TimeStampRequest((byte[]) sReq.getRequestData());

            // Log values for timestamp request
            logMap.put(ITimeStampLogger.LOG_TSA_TIMESTAMPREQUEST_CERTREQ,
                    String.valueOf(timeStampRequest.getCertReq()));
            logMap.put(ITimeStampLogger.LOG_TSA_TIMESTAMPREQUEST_CRITEXTOIDS,
                    String.valueOf(timeStampRequest.getCriticalExtensionOIDs()));
            logMap.put(ITimeStampLogger.LOG_TSA_TIMESTAMPREQUEST_ENCODED,
                    new String(Base64.encode(timeStampRequest.getEncoded())));
            logMap.put(ITimeStampLogger.LOG_TSA_TIMESTAMPREQUEST_NONCRITEXTOIDS,
                    String.valueOf(timeStampRequest.getNonCriticalExtensionOIDs()));
            logMap.put(ITimeStampLogger.LOG_TSA_TIMESTAMPREQUEST_NOUNCE,
                    String.valueOf(timeStampRequest.getNonce()));
            logMap.put(ITimeStampLogger.LOG_TSA_TIMESTAMPREQUEST_VERSION,
                    String.valueOf(timeStampRequest.getVersion()));
            logMap.put(ITimeStampLogger
                        .LOG_TSA_TIMESTAMPREQUEST_MESSAGEIMPRINTALGOID,
                    timeStampRequest.getMessageImprintAlgOID());
            logMap.put(ITimeStampLogger
                        .LOG_TSA_TIMESTAMPREQUEST_MESSAGEIMPRINTDIGEST,
                    new String(Base64.encode(
                        timeStampRequest.getMessageImprintDigest())));

            final TimeStampTokenGenerator timeStampTokenGen =
                    getTimeStampTokenGenerator(timeStampRequest, logMap);

            final TimeStampResponseGenerator timeStampResponseGen =
                    getTimeStampResponseGenerator(timeStampTokenGen);

            final TimeStampResponse timeStampResponse =
                    timeStampResponseGen.generate(timeStampRequest,
                    serialNumber,
                    date,
                    getCryptoToken().getProvider(
                        ICryptoToken.PROVIDERUSAGE_SIGN));

            final TimeStampToken token = timeStampResponse.getTimeStampToken();

            // Log values for timestamp response
            if (LOG.isDebugEnabled()) {
                LOG.debug("Time stamp response status: "
                        + timeStampResponse.getStatus() + ": "
                        + timeStampResponse.getStatusString());
            }
            logMap.put(ITimeStampLogger.LOG_TSA_PKISTATUS,
                    String.valueOf(timeStampResponse.getStatus()));
            if (timeStampResponse.getFailInfo() != null) {
                logMap.put(ITimeStampLogger.LOG_TSA_PKIFAILUREINFO, 
                        String.valueOf(
                            timeStampResponse.getFailInfo().intValue()));
            }
            logMap.put(ITimeStampLogger.LOG_TSA_TIMESTAMPRESPONSE_ENCODED,
                    new String(Base64.encode(timeStampResponse.getEncoded())));
            logMap.put(ITimeStampLogger.LOG_TSA_PKISTATUS_STRING,
                    timeStampResponse.getStatusString());
            
            final String archiveId;
            if (token == null) {
                archiveId = serialNumber.toString(16);
            } else {
                archiveId = token.getTimeStampInfo().getSerialNumber()
                                        .toString(16);
            }

            if (signRequest instanceof GenericServletRequest) {
                signResponse = new GenericServletResponse(sReq.getRequestID(),
                        timeStampResponse.getEncoded(),
                                    getSigningCertificate(),
                                    archiveId,
                                    new ArchiveData(
                                        timeStampResponse.getEncoded()),
                                        "application/timestamp-reply");
            } else {
                signResponse = new GenericSignResponse(sReq.getRequestID(),
                        timeStampResponse.getEncoded(),
                        getSigningCertificate(),
                        archiveId,
                        new ArchiveData(timeStampResponse.getEncoded()));
            }

            // Put in log values
            if (date == null) {
                logMap.put(ITimeStampLogger.LOG_TSA_EXCEPTION,
                        "timeSourceNotAvailable");
            }

            // We were able to fulfill the request so the worker session bean
            // can go on and charge the client
            if (timeStampResponse.getStatus() == PKIStatus.GRANTED) {
                requestContext.put(RequestContext.WORKER_FULFILLED_REQUEST,
                        true);
            }

        } catch (InvalidAlgorithmParameterException e) {
            final IllegalRequestException exception =
                    new IllegalRequestException(
                    "InvalidAlgorithmParameterException: " + e.getMessage(), e);
            LOG.error("InvalidAlgorithmParameterException: ", e);
            logMap.put(ITimeStampLogger.LOG_TSA_EXCEPTION,
                    exception.getMessage());
            throw exception;
        } catch (NoSuchAlgorithmException e) {
            final IllegalRequestException exception =
                    new IllegalRequestException(
                        "NoSuchAlgorithmException: " + e.getMessage(), e);
            LOG.error("NoSuchAlgorithmException: ", e);
            logMap.put(ITimeStampLogger.LOG_TSA_EXCEPTION,
                    exception.getMessage());
            throw exception;
        } catch (NoSuchProviderException e) {
            final IllegalRequestException exception =
                    new IllegalRequestException(
                    "NoSuchProviderException: " + e.getMessage(), e);
            LOG.error("NoSuchProviderException: ", e);
            logMap.put(ITimeStampLogger.LOG_TSA_EXCEPTION,
                    exception.getMessage());
            throw exception;
        } catch (CertStoreException e) {
            final IllegalRequestException exception =
                    new IllegalRequestException("CertStoreException: "
                    + e.getMessage(), e);
            LOG.error("CertStoreException: ", e);
            logMap.put(ITimeStampLogger.LOG_TSA_EXCEPTION,
                    exception.getMessage());
            throw exception;
        } catch (IOException e) {
            final IllegalRequestException exception =
                    new IllegalRequestException(
                    "IOException: " + e.getMessage(), e);
            LOG.error("IOException: ", e);
            logMap.put(ITimeStampLogger.LOG_TSA_EXCEPTION,
                    exception.getMessage());
            throw exception;
        } catch (TSPException e) {
            final IllegalRequestException exception =
                    new IllegalRequestException(e.getMessage(), e);
            LOG.error("TSPException: ", e);
            logMap.put(ITimeStampLogger.LOG_TSA_EXCEPTION,
                    exception.getMessage());
            throw exception;
        }

        return signResponse;
    }

    /**
     * @return a time source interface expected to provide accurate time
     */
    private ITimeSource getTimeSource() {
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
                throw new EJBException(e);
            } catch (IllegalAccessException iae) {
                throw new EJBException(iae);
            } catch (InstantiationException ie) {
                throw new EJBException(ie);
            }
        }

        return timeSource;
    }

    @SuppressWarnings("unchecked")
    private Set<String> getAcceptedAlgorithms() {
        if (acceptedAlgorithms == null) {
            final String nonParsedAcceptedAlgorihms =
                    this.config.getProperties().getProperty(ACCEPTEDALGORITHMS);
            if (nonParsedAcceptedAlgorihms == null) {
                acceptedAlgorithms = TSPAlgorithms.ALLOWED;
            } else {
                final String[] subStrings =
                        nonParsedAcceptedAlgorihms.split(";");
                if (subStrings.length > 0) {
                    acceptedAlgorithms = new HashSet();
                    for (int i = 0; i < subStrings.length; i++) {
                        final String algorithm =
                            (String) ACCEPTEDALGORITHMSMAP.get(subStrings[i]);
                        if (algorithm != null) {
                            acceptedAlgorithms.add(algorithm);
                        } else {
                            LOG.error("Error, signer " + workerId
                                    + " configured with incompatible acceptable algorithm : "
                                    + subStrings[i]);
                        }
                    }
                }
            }
        }

        return acceptedAlgorithms;
    }

    private Set<String> getAcceptedPolicies() {
        if (acceptedPolicies == null) {
            final String nonParsedAcceptedPolicies =
                    this.config.getProperties().getProperty(ACCEPTEDPOLICIES);
            acceptedPolicies = makeSetOfProperty(nonParsedAcceptedPolicies);
        }

        return acceptedPolicies;

    }

    private Set<String> getAcceptedExtensions() {
        if (acceptedExtensions == null) {
            final String nonParsedAcceptedExtensions =
                    this.config.getProperties().getProperty(ACCEPTEDEXTENSIONS);
            acceptedExtensions = makeSetOfProperty(nonParsedAcceptedExtensions);
        }

        return acceptedExtensions;
    }

    /**
     * Help method taking a string and creating a java.util.Set of the
     * strings using ';' as a delimiter.
     * If null is used as and argument then will null be returned by the method.
     * @param nonParsedPropery Semicolon separated strings
     * @return Set of Strings
     */
    private Set<String> makeSetOfProperty(final String nonParsedPropery) {
        Set<String> retval = null;
        if (nonParsedPropery != null) {
            final String[] subStrings = nonParsedPropery.split(";");
            if (subStrings.length > 0) {
                retval = new HashSet<String>();
                for (int i = 0; i < subStrings.length; i++) {
                    retval.add(subStrings[i]);
                }
            }
        }
        return retval;
    }

    private TimeStampTokenGenerator getTimeStampTokenGenerator(
            final TimeStampRequest timeStampRequest,
            final Map<String, String> logMap) throws
                IllegalRequestException,
                CryptoTokenOfflineException,
                InvalidAlgorithmParameterException,
                NoSuchAlgorithmException,
                NoSuchProviderException,
                CertStoreException {

        TimeStampTokenGenerator timeStampTokenGen = null;
        try {
            final String digestOID = timeStampRequest.getMessageImprintAlgOID();
            
            /*if (digestOID == null) {
                digestOID = defaultDigestOID;
            }*/

            String tSAPolicyOID = timeStampRequest.getReqPolicy();
            if (tSAPolicyOID == null) {
                tSAPolicyOID = defaultTSAPolicyOID;
            }
            logMap.put(ITimeStampLogger.LOG_TSA_POLICYID, tSAPolicyOID);

            final X509Certificate signingCert
                    = (X509Certificate) getSigningCertificate();
            if (signingCert == null) {
                throw new CryptoTokenOfflineException(
                        "No certificate for this signer");
            }

            timeStampTokenGen = new TimeStampTokenGenerator(
                    this.getCryptoToken().getPrivateKey(
                        ICryptoToken.PURPOSE_SIGN),
                    signingCert,
                    digestOID,
                    tSAPolicyOID);


            if (config.getProperties().getProperty(ACCURACYMICROS) != null) {
                timeStampTokenGen.setAccuracyMicros(Integer.parseInt(
                        config.getProperties().getProperty(ACCURACYMICROS)));
            }

            if (config.getProperties().getProperty(ACCURACYMILLIS) != null) {
                timeStampTokenGen.setAccuracyMillis(Integer.parseInt(
                        config.getProperties().getProperty(ACCURACYMILLIS)));
            }

            if (config.getProperties().getProperty(ACCURACYSECONDS) != null) {
                timeStampTokenGen.setAccuracySeconds(Integer.parseInt(
                        config.getProperties().getProperty(ACCURACYSECONDS)));
            }

            if (config.getProperties().getProperty(ORDERING) != null) {
                timeStampTokenGen.setOrdering(
                        config.getProperties().getProperty(ORDERING,
                            DEFAULT_ORDERING).equalsIgnoreCase("TRUE"));
            }

            if (config.getProperties().getProperty(TSA) != null) {
                final X509Name x509Name = new X509Name(config.getProperties()
                            .getProperty(TSA));
                timeStampTokenGen.setTSA(new GeneralName(x509Name));
            }

            final CertStore certStore = CertStore.getInstance("Collection",
                    new CollectionCertStoreParameters(
                        getSigningCertificateChain()), "BC");
            timeStampTokenGen.setCertificatesAndCRLs(certStore);

        } catch (IllegalArgumentException e) {
            LOG.error("IllegalArgumentException: ", e);
            throw new IllegalRequestException(e.getMessage());
        } catch (TSPException e) {
            LOG.error("TSPException: ", e);
            throw new IllegalRequestException(e.getMessage());
        }
        return timeStampTokenGen;
    }

    private TimeStampResponseGenerator getTimeStampResponseGenerator(
            TimeStampTokenGenerator timeStampTokenGen) {
        
        return new TimeStampResponseGenerator(timeStampTokenGen,
                this.getAcceptedAlgorithms(),
                this.getAcceptedPolicies(),
                this.getAcceptedExtensions());
    }

    /**
     * Help method that generates a serial number using SecureRandom
     */
    private BigInteger getSerialNumber() {
        BigInteger serialNumber = null;
        try {
            serialNumber = getSerno();
        } catch (Exception e) {
            LOG.error("Error initiating Serial Number generator, SEVERE ERROR.",
                    e);
        }
        return serialNumber;
    }

    /**
     * Generates a number of serial number bytes. The number returned should
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
}
