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
package org.signserver.module.sample.workers;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import java.util.Properties;
import javax.persistence.EntityManager;
import org.apache.log4j.Logger;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.util.encoders.Base64;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.RequestContext;
import org.signserver.common.RequestMetadata;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.server.IServices;
import org.signserver.server.WorkerContext;
import org.signserver.server.archive.Archivable;
import org.signserver.server.archive.DefaultArchivable;
import org.signserver.server.cryptotokens.ICryptoInstance;
import org.signserver.server.cryptotokens.ICryptoTokenV4;
import org.signserver.common.data.ReadableData;
import org.signserver.common.data.Request;
import org.signserver.common.data.Response;
import org.signserver.common.data.SignatureRequest;
import org.signserver.common.data.SignatureResponse;
import org.signserver.common.data.WritableData;
import org.signserver.server.log.LogMap;
import org.signserver.server.log.Loggable;
import org.signserver.server.signers.BaseSigner;

/**
 * Sample signer for a made up format "Text Signature" which for demonstration
 * purposes only signs text files.
 *
 * Note 1: This is not a standardized signature format and should not be used in
 * production. The purpose is only to demonstrate how one can implement a 
 * signer in SignServer.
 * 
 * Note 2: This signer does not yet properly handle large files as it reads all
 * data into memory. A future version could be changed to read the data from
 * an InputStream and write the results to an OutputStream.
 *
 * <p>
 * The signer has the following worker properties:
 * </p>
 * <ul>
 *    <li>
 *       <b>DIGESTALGORITHM</b> = Algorithm for hashing the content
 *       (Optional, default: "SHA-256")
 *    </li>
 *    <li>
 *       <b>SIGNATUREALGORITHM</b> = Algorithm for signing the attributes
 *       (Optional, default: "SHA256withRSA")
 *    </li>
 *    <li>
 *       <b>LOCATION</b> = Attribute to indicate the geographical location
 *       (Optional, default: not included)
 *    </li>
 *    <li>
 *       <b>ALLOW_LOCATION_OVERIDE</b> = True if the location attribute could
 *          be taken from the request (Optional, default: "False")
 *    </li>
 * </ul>
 * <p>
 *    The signer accepts the following request properties:
 * </p>
 * <ul>
 *    <li>
 *        <b>LOCATION</b> = To use as the location attributes
 *           (Optional, requires ALLOW_LOCATION_OVERRIDE to be configured)
 *    </li>
 * </ul>
 * <p>
 *    Example signed text:
 * </p>
 * <pre>
 * ----- BEGIN SIGNED TEXT -----
 * This is the original document.
 * It can contain multiple lines.  
 * ----- BEGIN TEXT SIGNATURE -----
 * signature=...base64 encoded signature...
 * 
 * location=Stockholm
 * 
 * signingTime=Fri Mar 20 10\:55\:01 CET 2015
 * 
 * certificates=...PEM encoded certificates...
 *
 * contentDigest=...base64 encoded digest...
 *
 * contentDigestAlgorithm=SHA-256
 * 
 * signatureAlgorithm=SHA256withRSA
 * ----- END TEXT SIGNATURE -----
 * </pre>
 * <p>
 * Where:
 * </p>
 * <ul>
 *    <li>
 *        The text between BEGIN SIGNED TEXT and BEGIN TEXT SIGNATURE
 *        ("the content") is the original document but with a line endings
 *        using "\n" instead of "\r" or "\r\n".
 *    </li>
 *    <li>
 *        The text between BEGIN TEXT SIGNATURE and END TEXT SIGNATURE is
 *        using the Java Properties file format.
 *    </li>
 *    <li>
 *        contentDigest is the hash of the content using the algorithm specified
 *        in contentDigestAlgorithm.
 *    </li>
 *    <li>
 *        contentDigestAlgorithm is the algorithm to use to hash the content.
 *    </li>
 *    <li>
 *        Certificates is the PEM encoded signer certificate followed by any
 *        intermediate CA certificates.
 *    </li>
 *    <li>
 *        signature is the output from the signing function. Input to the
 *        signature function is each other attributes with the name followed
 *        by a equals sign followed by the value followed by a newline. Ie:<br/>
 *        attributeName + "=" + attributeValue + "\n".
 *        The attributes are to be taken sorted on the attributeName.
 *    </li>
 *    <li>
 *        signatureAlgorithm is the algorithm to use for the signature.
 *    </li>
 *    <li>
 *        Other attributes could be included as well.
 *    </li>
 * </ul>
 * 
 * @author Markus Kilås
 * @version $Id$
 */
public class TextSigner extends BaseSigner {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(TextSigner.class);

    // Worker properties
    public static final String PROPERTY_DIGESTALGORITHM
            = "DIGESTALGORITHM";
    public static final String PROPERTY_SIGNATUREALGORITHM
            = "SIGNATUREALGORITHM";
    public static final String PROPERTY_LOCATION
            = "LOCATION";
    public static final String PROPERTY_ALLOW_LOCATION_OVERRIDE
            = "ALLOW_LOCATION_OVERRIDE";

    // Log fields
    public static final String LOG_REQUESTED_LOCATION = "REQUESTED_LOCATION";
    public static final String LOG_REQUESTED_LOCATION_BASE64 =
            "REQUESTED_LOCATION_BASE64";

    // Default values
    private static final String DEFAULT_DIGESTALGORITHM = "SHA-256";
    private static final String DEFAULT_SIGNATUREALGORITHM = "SHA256withRSA";
    private static final String DEFAULT_LOCATION = null;
    private static final boolean DEFAULT_ALLOW_LOCATION_OVERRIDE = false;

    // Content types
    private static final String REQUEST_CONTENT_TYPE = "text/plain";
    private static final String RESPONSE_CONTENT_TYPE = "text/plain";

    // Configuration errors
    private final LinkedList<String> configErrors = new LinkedList<>();

    // Configuration values
    private String digestAlgorithm;
    private String signatureAlgorithm;
    private String location;
    private boolean allowLocationOverride;

    @Override
    public void init(int workerId, WorkerConfig config,
            WorkerContext workerContext, EntityManager workerEM) {
        super.init(workerId, config, workerContext, workerEM);

        // Optional property DIGESTALGORITHM
        digestAlgorithm = config.getProperty(PROPERTY_DIGESTALGORITHM);
        if (digestAlgorithm == null || digestAlgorithm.trim().isEmpty()) {
            digestAlgorithm = DEFAULT_DIGESTALGORITHM;
        }

        // Optional property SIGNATUREALGORITHM
        signatureAlgorithm = config.getProperty(PROPERTY_SIGNATUREALGORITHM);
        if (signatureAlgorithm == null || signatureAlgorithm.trim().isEmpty()) {
            signatureAlgorithm = DEFAULT_SIGNATUREALGORITHM;
        }
        
        // Optional property LOCATION
        location = config.getProperty(PROPERTY_LOCATION);
        if (location == null || location.trim().isEmpty()) {
            location = DEFAULT_LOCATION;
        }
        
        // Optional property ALLOW_LOCATION_OVERRIDE
        final String value = config.getProperty(
                PROPERTY_ALLOW_LOCATION_OVERRIDE);
        if (value == null || value.trim().isEmpty()) {
            allowLocationOverride = DEFAULT_ALLOW_LOCATION_OVERRIDE;
        } else if (Boolean.TRUE.toString().equalsIgnoreCase(value.trim())) {
            allowLocationOverride = true;
        } else if (Boolean.FALSE.toString().equalsIgnoreCase(value.trim())) {
            allowLocationOverride = false;
        } else {
            configErrors.add("Incorrect value for property "
                    + PROPERTY_ALLOW_LOCATION_OVERRIDE);
        }

        // Check that at least one certificate is included.
        if (hasSetIncludeCertificateLevels && includeCertificateLevels < 1) {
            configErrors.add("Illegal value for property "
                    + WorkerConfig.PROPERTY_INCLUDE_CERTIFICATE_LEVELS
                    + ". Only numbers >= 1 supported.");
        }
    }

    @Override
    public Response processData(Request signRequest,
            RequestContext requestContext) throws IllegalRequestException,
            CryptoTokenOfflineException, SignServerException {
        try {
            if (!configErrors.isEmpty()) {
                throw new SignServerException("Worker is misconfigured");
            }
            if (!(signRequest instanceof SignatureRequest)) {
                throw new IllegalRequestException("Unexpected request type");
            }
            final SignatureRequest request = (SignatureRequest) signRequest;

            // Get the data from request
            final ReadableData requestData = request.getRequestData();
            final WritableData responseData = request.getResponseData();
            final byte[] data = requestData.getAsByteArray();
            final String text = canonicalize(data);
            final String requestedLocation = RequestMetadata.getInstance(
                    requestContext).get(PROPERTY_LOCATION);
            
            // Log anything interesting from the request to the worker logger
            final LogMap logMap = LogMap.getInstance(requestContext);
            
            logMap.put(LOG_REQUESTED_LOCATION, requestedLocation);
            // log using lazy evaluation (the log value will be computed only
            // the logger in use requests it) something that required some
            // computation
            if (requestedLocation != null) {
                logMap.put(LOG_REQUESTED_LOCATION_BASE64, new Loggable() {
                    @Override
                    public String toString() {
                        return Base64.toBase64String(requestedLocation.getBytes());
                    }
                });
            }

            // Produce the result, ie doing the work
            Properties attributes = new Properties();
            
            // Content digest
            final MessageDigest md = MessageDigest.getInstance(digestAlgorithm);
            final byte[] contentDigest = md.digest(
                    text.getBytes(StandardCharsets.UTF_8));
            attributes.setProperty("contentDigest",
                    Base64.toBase64String(contentDigest));
            attributes.setProperty("contentDigestAlgorithm", digestAlgorithm);
            
            // time
            attributes.setProperty("signingTime", new Date().toString());
            
            // location
            if (LOG.isDebugEnabled()) {
                LOG.debug("Configured location:    " + location
                          + "\nRequested location: " + requestedLocation);
            }
            final String effectiveLocation;
            if (requestedLocation == null) {
                // No location in request so use the configured one
                effectiveLocation = location;
            } else {
                // Location in request
                if (allowLocationOverride) {
                    effectiveLocation = requestedLocation;
                } else {
                    // Client error
                    throw new IllegalRequestException("Requesting "
                            + PROPERTY_LOCATION + " not allowed.");
                }
            }
            // Set the location value if we have one
            if (effectiveLocation != null) {
                attributes.setProperty("location", effectiveLocation);
            }
            
            Certificate signerCert = null;
            ICryptoInstance cryptoInstance = null;
            try (OutputStream out = responseData.getAsOutputStream()) {
                cryptoInstance = acquireCryptoInstance(ICryptoTokenV4.PURPOSE_SIGN,
                        request, requestContext);

                // certifiates
                ByteArrayOutputStream bout0 = new ByteArrayOutputStream();
                PEMWriter pemWriter = new PEMWriter(
                        new OutputStreamWriter(bout0));
                for (Certificate cert : includedCertificates(
                        getSigningCertificateChain(cryptoInstance))) {
                    pemWriter.writeObject(cert);
                }
                pemWriter.flush();
                attributes.setProperty("certificates", bout0.toString(StandardCharsets.UTF_8.name()));

                // signature algorithm
                attributes.setProperty("signatureAlgorithm",
                        signatureAlgorithm);

                // signature value
                final Signature signature = Signature.getInstance(
                        signatureAlgorithm, cryptoInstance.getProvider());
                signature.initSign(cryptoInstance.getPrivateKey());

                final String[] attributeNames = attributes.stringPropertyNames()
                        .toArray(new String[0]);
                // Sort as specified
                Arrays.sort(attributeNames);
                for (String attr : attributeNames) {
                    String attribute
                            = attr + "=" + attributes.getProperty(attr) + "\n";
                    signature.update(attribute.getBytes(StandardCharsets.UTF_8));
                }
                byte[] signatureBytes = signature.sign();
                attributes.setProperty("signature",
                        Base64.toBase64String(signatureBytes));
                
                // Render the result
                final StringBuilder sb = new StringBuilder();
                sb.append("----- BEGIN SIGNED TEXT -----\n");
                sb.append(text);
                sb.append("----- BEGIN TEXT SIGNATURE -----\n");
                sb.append(renderProperties(attributes));
                sb.append("----- END TEXT SIGNATURE -----\n");

                final String result = sb.toString();
                out.write(result.getBytes(StandardCharsets.UTF_8));
            } finally {
                releaseCryptoInstance(cryptoInstance, requestContext);
            }

            // Create the archivables (request and response)
            final String archiveId = createArchiveId(data,
                    (String) requestContext.get(RequestContext.TRANSACTION_ID));
            final Collection<? extends Archivable> archivables = Arrays.asList(
                    new DefaultArchivable(Archivable.TYPE_REQUEST,
                            REQUEST_CONTENT_TYPE, requestData, archiveId), 
                    new DefaultArchivable(Archivable.TYPE_RESPONSE,
                            RESPONSE_CONTENT_TYPE, 
                            responseData.toReadableData(), archiveId));

            // Suggest new file name
            final Object fileNameOriginal = requestContext.get(
                    RequestContext.FILENAME);
            if (fileNameOriginal instanceof String) {
                requestContext.put(RequestContext.RESPONSE_FILENAME,
                        fileNameOriginal + "");
            }

            // As everyting went well, the client can be charged for the request
            requestContext.setRequestFulfilledByWorker(true);

            // Return the response
            return new SignatureResponse(
                    request.getRequestID(), responseData, signerCert, archiveId,
                    archivables, RESPONSE_CONTENT_TYPE);
        } catch (IOException ex) {
            throw new SignServerException("Encoding error", ex);
        } catch (NoSuchAlgorithmException ex) {
            throw new SignServerException("Configured algorithm not supported",
                    ex);
        } catch (InvalidKeyException | SignatureException ex) {
            throw new SignServerException("Error signing", ex);
        }
    }

    @Override
    protected List<String> getFatalErrors(final IServices services) {
        // Add our errors to the list of errors
        final LinkedList<String> errors = new LinkedList<>(
                super.getFatalErrors(services));
        errors.addAll(configErrors);
        return errors;
    }

    /**
     * Improve the readability of the Properties output.
     * - Skipping the first line with Properties comment
     * - Make encoded newlines follow by a Properties new line
     * - Introduce line breaks
     */
    private String renderProperties(Properties properties) throws IOException {
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        properties.store(bout, null);
        String s = bout.toString(StandardCharsets.UTF_8.name());
        
        final StringBuilder sb = new StringBuilder();
        
        BufferedReader sr = new BufferedReader(new StringReader(s));
        sr.readLine(); // Skipping first line
        String line; 
        while ((line = sr.readLine()) != null) {
            line = line.replace("\\n", "\\n\\\n");
            
            // Check if (the new lines) need wrapping
            BufferedReader sr2 = new BufferedReader(new StringReader(line));
            String line3;
            while ((line3 = sr2.readLine()) != null) {
                while (line3.length() > 80) {
                    String line2 = line3.substring(0, 80);
                    sb.append(line2).append("\\\n");
                    line3 = line3.substring(80, line3.length());
                }
                sb.append(line3).append("\n");
            }
            sb.append("\n");
        }
        return sb.toString();
    }

    /**
     * Change line endings to platform neutral "\n" as specified.
     * 
     * @param data Data to canonicalize
     * @return Canonicalized string
     * @throws UnsupportedEncodingException In case the data is not UTF-8-encoded
     */
    public static String canonicalize(byte[] data) throws IOException {
        final StringBuilder sb = new StringBuilder();
        final BufferedReader in = new BufferedReader(new InputStreamReader(
                new ByteArrayInputStream(data), StandardCharsets.UTF_8));
        String line;
        while ((line = in.readLine()) != null) {
            sb.append(line).append("\n");
        }
        return sb.toString();
    }
}
