/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.signserver.server.data.impl;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import org.apache.commons.fileupload.FileUploadException;
import org.apache.commons.fileupload.disk.DiskFileItem;
import org.apache.commons.fileupload.disk.DiskFileItemFactory;
import org.apache.log4j.Logger;

/**
 *
 * @author user
 */
public class UploadUtil {
    
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(UploadUtil.class);

    public static CloseableReadableData handleUpload(UploadConfig uploadConfig, byte[] data) throws FileUploadException {
        final DiskFileItemFactory factory = new DiskFileItemFactory();
        factory.setSizeThreshold(uploadConfig.getSizeThreshold());
        factory.setRepository(uploadConfig.getRepository());

        final BinaryFileUpload upload = new BinaryFileUpload(new ByteArrayInputStream(data), "application/octet-stream", factory);
        upload.setSizeMax(uploadConfig.getMaxUploadSize());

        return new DiskFileItemReadableData((DiskFileItem) upload.parseTheRequest());
    }

    /*public static void cleanUp(DiskFileItemReadableData requestData, ResponseDataImpl responseData) {
        // Clean up request data
        // Remove the temporary file (if any)
        if (requestData != null) {
            try {
                requestData.remove();
            } catch (IOException ex) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Unable to remove temporary upload file", ex);
                }
                LOG.error("Unable to remove temporary upload file: " + ex.getLocalizedMessage());
            }
        }

        // Clean up response data
        if (responseData != null) {
            try {
                responseData.remove();
            } catch (IOException ex) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Unable to remove temporary response file", ex);
                }
                LOG.error("Unable to remove temporary response file: " + ex.getLocalizedMessage());
            }
        }
    }*/
    
    // TODO: Move out of this class!
    public static byte[] digest(InputStream input, MessageDigest md) throws IOException {
        final byte[] buffer = new byte[4096]; 
        int n = 0;
        while (-1 != (n = input.read(buffer))) {
            md.update(buffer, 0, n);
        }
        return md.digest();
    }
    
}
