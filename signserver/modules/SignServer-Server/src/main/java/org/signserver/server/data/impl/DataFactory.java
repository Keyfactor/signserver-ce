/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.signserver.server.data.impl;

import java.io.File;
import org.apache.commons.fileupload.FileItem;
import org.apache.commons.fileupload.FileUploadException;
import org.signserver.common.data.ReadableData;

/**
 *
 * @author user
 */
public interface DataFactory {

    CloseableReadableData createReadableData(byte[] data, long maxSize, File repository) throws FileUploadException;
    CloseableReadableData createReadableData(FileItem item, File repository);
    CloseableWritableData createWritableData(ReadableData readableData, File repository);
    CloseableWritableData createWritableData(boolean defaultToDisk, File repository);
}
