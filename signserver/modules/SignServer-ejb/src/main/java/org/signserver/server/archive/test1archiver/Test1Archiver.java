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
package org.signserver.server.archive.test1archiver;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Properties;
import org.apache.log4j.Logger;
import org.signserver.common.RequestContext;
import org.signserver.common.WorkerConfig;
import org.signserver.server.SignServerContext;
import org.signserver.server.archive.Archivable;
import org.signserver.server.archive.ArchiveException;
import org.signserver.server.archive.Archiver;
import org.signserver.server.archive.ArchiverInitException;

/**
 * Test Archiver used by the system tests to test the Archiver API. Not usable 
 * in production.
 * 
 * This Archiver just writes some information to a configured file unless the 
 * Archiver is disabled.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class Test1Archiver implements Archiver {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(Test1Archiver.class);
    
    public static final String PROCESSED = "PROCESSED";
    public static final String CLASSNAME = "CLASSNAME";
    public static final String INSTANCE = "INSTANCE";
    public static final String LISTINDEX = "LISTINDEX";
    public static final String WORKERID = "WORKERID";
    public static final String ENTITYMANAGER_AVAILABLE = "ENTITYMANAGER_AVAILABLE";
    
    private int listIndex;
    private File outFile;
    private boolean disabled;
    private boolean doFail;
    
    @Override
    public void init(int listIndex, WorkerConfig config, SignServerContext context) throws ArchiverInitException {
        this.listIndex = listIndex;
        String file = config.getProperty("ARCHIVER" + listIndex + ".FILE");
        if (file == null) {
            throw new ArchiverInitException(
                    "ARCHIVERx.FILE property configured");
        } else {
            outFile = new File(file);
            LOG.debug("Using outFile: " + outFile.getAbsolutePath());
        }
        disabled = Boolean.parseBoolean(config.getProperty("ARCHIVER" 
                + listIndex + ".ISDISABLED", "false"));
        doFail = Boolean.parseBoolean(config.getProperty("ARCHIVER" 
                + listIndex + ".DOFAIL", "false"));
    }

    @Override
    public boolean archive(Archivable archivable, RequestContext requestContext)
            throws ArchiveException {
        final boolean archived;
        if (doFail) {
            throw new ArchiveException("Simulating failure...");
        } else if (!disabled && Archivable.TYPE_RESPONSE.equals(archivable.getType())) {
            
            final Integer workerId = (Integer) requestContext.get(RequestContext.WORKER_ID);
            final Properties properties = new Properties();
            properties.setProperty(CLASSNAME, this.getClass().getName());
            properties.setProperty(INSTANCE, this.toString());
            properties.setProperty(LISTINDEX, String.valueOf(listIndex));
            properties.setProperty(PROCESSED, String.valueOf(true));
            properties.setProperty(WORKERID, String.valueOf(workerId));
            properties.setProperty(ENTITYMANAGER_AVAILABLE, String.valueOf(requestContext.getEntityManager() != null));
            OutputStream out = null;
            try {
                out = new FileOutputStream(outFile);
                properties.store(out, null);
            } catch (IOException ex) {
                throw new ArchiveException(ex);
            } finally {
                if (out != null) {
                    try {
                        out.close();
                    } catch (IOException ignored) {} // NOPMD
                }
            }
            
            archived = true;
        } else {
            archived = false;
        }
        return archived;
    }

}
