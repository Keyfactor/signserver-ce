/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
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
