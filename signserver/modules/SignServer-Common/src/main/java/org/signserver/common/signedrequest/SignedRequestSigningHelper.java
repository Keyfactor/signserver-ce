/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.signserver.common.signedrequest;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import org.apache.log4j.Logger;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.signserver.common.RequestContext;

/**
 * Helper doing as much of the stuff for the signed request as possible.
 * 
 * Current spec for the format:
 * Request metadata property named "SIGNED_REQUEST"
 * - Value: base64 encoded  CMS SignedData structure with
 *          encapsulated content: SHA-256 hash of requestData
 * 
 * TODO: Spec does not cover hashing of workerName/workerId and request metadata etc.
 *
 * @author user
 */
public class SignedRequestSigningHelper {
    
    private static final Logger LOG = Logger.getLogger(SignedRequestSigningHelper.class);
    
    public static final String METADATA_PROPERTY_SIGNED_REQUEST = "SIGNED_REQUEST";
    
    private static final String DIGEST_ALGORITHM = "SHA-256"; // XXX hardcoded, but should use what's in the request signature

    /**
     * Constructs the SIGNED_REQUEST request metadata property value.
     *
     * @param requestDataDigest
     * @param metadata
     * @param signKey
     * @param provider
     * @param certificateChain 
     * @return  
     * @throws org.signserver.common.signedrequest.SignedRequestException  
     */
    public static String createSignedRequest(byte[] requestDataDigest, Map<String, String> metadata, String fileName, String workerName, Integer workerId, PrivateKey signKey, Provider provider, List<Certificate> certificateChain) throws SignedRequestException {
        try {
            LOG.error(">createSignedRequest");
            final String result;
            
            final CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
            final ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withRSA")/*.setProvider(provider)*/.build(signKey);
            final JcaSignerInfoGeneratorBuilder siBuilder = new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider("BC").build());
            final SignerInfoGenerator sig = siBuilder.build(contentSigner, (X509Certificate) certificateChain.get(0));
            
            generator.addSignerInfoGenerator(sig);
            generator.addCertificates(new JcaCertStore(certificateChain));
            
            // Generate the signature
            CMSSignedData signedData = generator.generate(new CMSProcessableByteArray(createContentToBeSigned(requestDataDigest, metadata, fileName, workerName, workerId)), true);
            
            result = Base64.toBase64String(signedData.getEncoded());
            LOG.error("Created signed request: " + result);
            return result;
        } catch (OperatorCreationException | CMSException | CertificateEncodingException | NoSuchAlgorithmException | NoSuchProviderException | IOException ex) {
            throw new SignedRequestException("Failed to sign signature request", ex);
        }
    }

    private static byte[] createContentToBeSigned(byte[] requestDataDigest, Map<String, String> metadata, String fileName, String workerName, Integer workerId) throws IOException, NoSuchAlgorithmException, NoSuchProviderException {
        Properties properties = new Properties();
       
        properties.put("data", Hex.toHexString(requestDataDigest));
        ArrayList<String> metaKeys = new ArrayList<>(metadata.keySet());
        for (String metaKey : metaKeys) {
            if (!metaKey.equals(METADATA_PROPERTY_SIGNED_REQUEST)) {
                properties.put("meta." + metaKey, Hex.toHexString(hash(metadata.get(metaKey))));
            }
        }
        if (fileName != null) {
            properties.put(RequestContext.FILENAME, Hex.toHexString(hash(fileName)));
        }

        if (workerName != null) {
            properties.put("workerName", Hex.toHexString(hash(workerName)));
        }
        if (workerId != null) {
            properties.put("workerId", Hex.toHexString(hash(String.valueOf(workerId))));
        }
        
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        properties.store(bout, null);
        return bout.toByteArray();
    }
    
    public static byte[] hash(String value) throws NoSuchAlgorithmException, NoSuchProviderException {
        MessageDigest md = MessageDigest.getInstance(DIGEST_ALGORITHM, "BC");
        
        return md.digest(value == null ? new byte[0] : value.getBytes(StandardCharsets.UTF_8));
    }

}
