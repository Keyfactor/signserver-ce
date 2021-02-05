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
package org.signserver.admin.cli.defaultimpl.archive;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import org.signserver.common.ArchiveDataVO;

/**
 * Utility methods used by the different Achiving commands.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class ArchiveCLIUtils {
    
    public void writeToFile(final File file, final ArchiveDataVO archiveData) throws FileNotFoundException, IOException {
        FileOutputStream os = null;
        try {
            os = new FileOutputStream(file);
            os.write(archiveData.getArchivedBytes());
        } finally {
            if (os != null) {
                try {
                    os.close();
                } catch (IOException ignored) {} // NOPMD
            }
        }
    }
    
    public String getTypeName(final int type) {
        final String result;
        switch (type) {
            case ArchiveDataVO.TYPE_REQUEST:
                result = "request";
                break;
            case ArchiveDataVO.TYPE_RESPONSE:
                result = "response";
                break;
            default:
                result = "type" + type;
        }
        return result;
    }
}
