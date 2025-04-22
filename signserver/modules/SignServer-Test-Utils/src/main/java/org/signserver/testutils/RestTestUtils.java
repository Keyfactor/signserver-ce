package org.signserver.testutils;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.util.encoders.Base64;
import org.json.simple.JSONObject;
import org.signserver.common.util.PathUtil;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;

/**
 * Class containing utility methods used to simplify REST api testing.
 *
 * @version $Id$
 */
public class RestTestUtils {

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

    public JSONObject createPatchWorkerEditRequestJsonBody() {
        JSONObject properties = new JSONObject();
        properties.put("property1", "value1");
        properties.put("-GREETING", "");

        JSONObject patchRequestJsonBody = new JSONObject();
        patchRequestJsonBody.put("properties", properties);

        return patchRequestJsonBody;
    }


    public JSONObject createPutWorkerReplaceRequestJsonBody(final String workerName) {
        JSONObject properties = new JSONObject();
        properties.put("NAME", workerName);
        properties.put("TYPE", "PROCESSABLE");
        properties.put("GREETING", "Properties Replaced!");
        properties.put("IMPLEMENTATION_CLASS", "org.signserver.module.sample.workers.HelloWorker");

        JSONObject patchRequestJsonBody = new JSONObject();
        patchRequestJsonBody.put("properties", properties);

        return patchRequestJsonBody;
    }

    /**
     * Generate a test Json Object from a sample PDF file, metaData and encoding base64 in it.
     *
     * @throws IOException in case of error
     */
    public JSONObject createPostRequestJsonBodyPDF() throws IOException {

        File home;
        home = PathUtil.getAppHome();
        File samplePdf = new File(home, "res/test/pdf/sample.pdf");
        String base64DataString = Base64.toBase64String(FileUtils.readFileToByteArray(samplePdf));

        JSONObject metaData = new JSONObject();
        metaData.put("name1", "value1");
        metaData.put("name2", "value2");

        JSONObject postRequestJsonBody = new JSONObject();
        postRequestJsonBody.put("encoding", "BASE64");
        postRequestJsonBody.put("metaData", metaData);
        postRequestJsonBody.put("data", base64DataString);

        return postRequestJsonBody;
    }

    /**
     * Generate a multipart/form-data object for file upload testing.
     */
    public File createPostRequestFormDataBody(String filePath) throws FileNotFoundException {
        File home;
        home = PathUtil.getAppHome();
        File samplePdf = new File(home, filePath);
        return samplePdf;
    }
}
