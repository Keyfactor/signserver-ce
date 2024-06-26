package org.signserver.testutils;

import java.io.File;
import java.io.FileOutputStream;
import java.security.KeyStore;
import org.apache.commons.io.IOUtils;
import org.json.simple.JSONObject;
import org.signserver.server.cryptotokens.KeystoreCryptoToken;

/**
 * Class containing utility methods used to simplify MANAGEDREST api testing.
 *
 */
public class ManagedRestTestUtils {
    
    protected static final String pin = "foo123";
    private static final String SIGN_KEY_ALIAS = "p12signkey1234";
    private File keystoreFile;

    /**
     * Generate a test Json Object with sample data, metaData in it.
     */
    public JSONObject createPostProcessRequestJsonBody() {
        JSONObject metaData = new JSONObject();
        metaData.put("name1", "value1");
        metaData.put("name2", "value2");

        JSONObject postRequestJsonBody = new JSONObject();
        postRequestJsonBody.put("metaData", metaData);
        postRequestJsonBody.put("data", "Sample Text!");

        return postRequestJsonBody;
    }

    /**
     * Generate a test Json Object with cryptotoken.
     */
    public JSONObject createPostProcessRequestJsonBodyWithCryptotoken() {
        JSONObject metaData = new JSONObject();
        metaData.put("name1", "value1");
        metaData.put("name2", "value2");
        metaData.put("CRYPTOTOKEN", "SIGNUM_CryptoTokenP12");

        JSONObject postRequestJsonBody = new JSONObject();
        postRequestJsonBody.put("metaData", metaData);
        postRequestJsonBody.put("data", "Sample Text!");

        return postRequestJsonBody;
    }

    /**
     * Generate a test Json Object with sample data, metaData with defaultkey in
     * it.
     */
    public JSONObject createPostProcessRequestWithKey() {
        JSONObject metaData = new JSONObject();
        metaData.put("DEFAULTKEY", "signer00003");
        metaData.put("CRYPTOTOKEN", "SIGNUM_CryptoTokenP12");

        JSONObject postRequestJsonBody = new JSONObject();
        postRequestJsonBody.put("metaData", metaData);
        postRequestJsonBody.put("data", "Sample Text!");

        return postRequestJsonBody;
    }

    /**
     * Generate a test Json Object with sample data, metaData with signature
     * algorithm in it.
     */
    public JSONObject createPostProcessRequestWithSignatureAlgorithm() {
        JSONObject metaData = new JSONObject();
        metaData.put("SIGNATUREALGORITHM", "SHA256withRSA");
        metaData.put("CRYPTOTOKEN", "SIGNUM_CryptoTokenP12");

        JSONObject postRequestJsonBody = new JSONObject();
        postRequestJsonBody.put("metaData", metaData);
        postRequestJsonBody.put("data", "Sample Text!");

        return postRequestJsonBody;
    }

    /**
     * Generate a test Json Object with sample data, metaData with defaultkey
     * and signature algorithm in it.
     */
    public JSONObject createPostProcessRequestWithKeyAndSignatureAlgorithm() {
        JSONObject metaData = new JSONObject();
        metaData.put("DEFAULTKEY", "signer00003");
        metaData.put("SIGNATUREALGORITHM", "SHA256withRSA");
        metaData.put("CRYPTOTOKEN", "SIGNUM_CryptoTokenP12");

        JSONObject postRequestJsonBody = new JSONObject();
        postRequestJsonBody.put("metaData", metaData);
        postRequestJsonBody.put("data", "Sample Text!");

        return postRequestJsonBody;
    }

    /**
     * Generate a test Json Object with sample data, metaData with defaultkey
     * and incorrect signature algorithm in it.
     */
    public JSONObject createPostProcessRequestWithKeyAndSignatureAlgorithmFailing() {
        JSONObject metaData = new JSONObject();
        metaData.put("DEFAULTKEY", "signer00003"); // RSA key
        metaData.put("SIGNATUREALGORITHM", "SHA256withECDSA"); // missmatch with provided key
        metaData.put("CRYPTOTOKEN", "SIGNUM_CryptoTokenP12");

        JSONObject postRequestJsonBody = new JSONObject();
        postRequestJsonBody.put("metaData", metaData);
        postRequestJsonBody.put("data", "Sample Text!");

        return postRequestJsonBody;
    }

    public JSONObject createPostWorkerAddRequestJsonBody(final String workerName) {
        JSONObject properties = new JSONObject();
        properties.put("NAME", workerName);
        properties.put("TYPE", "PROCESSABLE");
        properties.put("AUTHTYPE", "NOAUTH");
        properties.put("GREETING", "Hi");
        properties.put("IMPLEMENTATION_CLASS", "org.signserver.module.sample.workers.HelloWorker");

        JSONObject patchRequestJsonBody = new JSONObject();
        patchRequestJsonBody.put("properties", properties);

        return patchRequestJsonBody;
    }
    
    public JSONObject createPostCryptoWorkerAddRequestJsonBody(final String workerName) throws Exception {
        // Create keystore
        keystoreFile = File.createTempFile("testkeystore", ".p12");
        FileOutputStream out = null;
        try {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(null, null);
            out = new FileOutputStream(keystoreFile);
            ks.store(out, pin.toCharArray());
        } finally {
            IOUtils.closeQuietly(out);
        }
        
        // Setup crypto token    
        JSONObject properties = new JSONObject();
        properties.put("NAME", workerName);
        properties.put("TYPE", "CRYPTO_WORKER");
        properties.put("KEYSTORETYPE", "PKCS12");
        properties.put("IMPLEMENTATION_CLASS", "org.signserver.server.signers.CryptoWorker");
        properties.put("CRYPTOTOKEN_IMPLEMENTATION_CLASS", KeystoreCryptoToken.class.getName());
        properties.put("KEYSTOREPATH", keystoreFile.getAbsolutePath());
        properties.put("DEFAULTKEY", SIGN_KEY_ALIAS);
        properties.put("KEYSTOREPASSWORD", pin);

        JSONObject patchRequestJsonBody = new JSONObject();
        patchRequestJsonBody.put("properties", properties);

        return patchRequestJsonBody;
    }
}
