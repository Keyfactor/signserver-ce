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
package org.signserver.server.enterprise.data.impl;

import java.io.File;
import org.apache.commons.fileupload.FileItem;
import org.apache.commons.fileupload.disk.DiskFileItem;
import org.apache.log4j.Logger;
import org.signserver.server.data.impl.CloseableReadableData;
import org.signserver.server.data.impl.DataFactory;
import org.signserver.server.data.impl.DefaultDataFactory;

/**
 * Implementation of the DataFactory with support for large files.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class LargeFileDataFactory extends DefaultDataFactory implements DataFactory {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(LargeFileDataFactory.class);

    
    public LargeFileDataFactory() {
        LOG.info("Loading large file support");
    }

    @Override
    public CloseableReadableData createReadableData(FileItem item, File repository) {
        return new DiskFileItemReadableData((DiskFileItem) item, repository);
    }

}
