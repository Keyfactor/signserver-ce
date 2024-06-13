package org.signserver.testutils;

import org.json.simple.JSONObject;

/**
 * Class containing utility methods used to simplify MANAGEDREST api testing.
 *
 */
public class ManagedRestTestUtils {

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
     * Generate a test Json Object with sample data, metaData with defaultkey in
     * it.
     */
    public JSONObject createPostProcessRequestWithKey() {
        JSONObject metaData = new JSONObject();
        metaData.put("DEFAULTKEY", "signer00003");

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
}
