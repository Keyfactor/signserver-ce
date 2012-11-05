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
package org.signserver.server.archive.base64dbarchiver;

import java.security.cert.X509Certificate;
import java.util.Map;
import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Base64;
import org.signserver.common.ArchiveDataVO;
import org.signserver.common.RequestContext;
import org.signserver.common.WorkerConfig;
import org.signserver.common.util.XForwardedForUtils;
import org.signserver.server.SignServerContext;
import org.signserver.server.archive.Archivable;
import org.signserver.server.archive.ArchiveException;
import org.signserver.server.archive.Archiver;
import org.signserver.server.archive.ArchiverInitException;
import org.signserver.server.archive.olddbarchiver.ArchiveOfTypes;
import org.signserver.server.archive.olddbarchiver.entities.ArchiveDataService;
import org.signserver.server.log.IWorkerLogger;

/**
 * Archiver archiving to the database table ArchiveData with the archived bytes
 * in base64 encoding.
 * 
 * Currently only Archivable.TYPE_RESPONSE are supported.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class Base64DatabaseArchiver implements Archiver {
    
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(Base64DatabaseArchiver.class);
    
    private static final String PROPERTY_ARCHIVE_OF_TYPE = "ARCHIVE_OF_TYPE";
    private static final String PROPERTY_USE_FORWARDED_ADDRESS = "USE_FORWARDED_ADDRESS";
 
    private ArchiveDataService dataService;
    
    private ArchiveOfTypes archiveOfTypes;
    
    private boolean useXForwardedFor = false;

    @Override
    public void init(int listIndex, WorkerConfig config, SignServerContext context) throws ArchiverInitException {
        dataService = new ArchiveDataService(context.getEntityManager());
        
        // Configuration of what to archive
        final String propertyArchiveOfType = "ARCHIVER" + listIndex + "." + PROPERTY_ARCHIVE_OF_TYPE;
        try {
            archiveOfTypes = ArchiveOfTypes.valueOf(config.getProperty(propertyArchiveOfType, ArchiveOfTypes.RESPONSE.name()));
        } catch (IllegalArgumentException ex) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Illegal value for worker property " + propertyArchiveOfType + ": " + ex.getMessage());
            }
            throw new ArchiverInitException("Illegal value for worker property " + propertyArchiveOfType);
        }
        
        // configuration for using the X-FORWARDED-FOR header to determine source IP
        final String propertyXForwardedFor = "ARCHIVER" + listIndex + "." + PROPERTY_USE_FORWARDED_ADDRESS;
        useXForwardedFor = Boolean.valueOf(config.getProperty(propertyXForwardedFor));
    }

    @Override
    public boolean archive(Archivable archivable, RequestContext requestContext)
            throws ArchiveException {
        final boolean archived;
        
        // Get the type of this request
        int archiveType = -1;
        if (Archivable.TYPE_RESPONSE.equals(archivable.getType())) {
            archiveType = ArchiveDataVO.TYPE_RESPONSE;
        } else if (Archivable.TYPE_REQUEST.equals(archivable.getType())) {
            archiveType = ArchiveDataVO.TYPE_REQUEST;
        }
        
        // Only archive if the type of this request is the type configured for this Archiver
        if ((archiveOfTypes == ArchiveOfTypes.REQUEST && archiveType == ArchiveDataVO.TYPE_REQUEST)
                || (archiveOfTypes == ArchiveOfTypes.RESPONSE && archiveType == ArchiveDataVO.TYPE_RESPONSE)
                || (archiveOfTypes == ArchiveOfTypes.REQUEST_AND_RESPONSE && (archiveType == ArchiveDataVO.TYPE_RESPONSE || archiveType == ArchiveDataVO.TYPE_REQUEST))) {
            if (dataService == null) {
                throw new ArchiveException("Could not archive as archiver was not successfully initialized");
            }
            final Integer workerId = (Integer) requestContext.get(RequestContext.WORKER_ID);
            final X509Certificate certificate = (X509Certificate) requestContext.get(RequestContext.CLIENT_CERTIFICATE);
            String remoteIp = (String) requestContext.get(RequestContext.REMOTE_IP);

            final String uniqueId;
            
            if (useXForwardedFor) {
                final String forwardedIp = XForwardedForUtils.getXForwardedForIP(requestContext);
                
                if (forwardedIp != null) {
                    remoteIp = forwardedIp;
                }
            }
            
            uniqueId = dataService.create(archiveType,
                            workerId,
                            archivable.getArchiveId(),
                            certificate,
                            remoteIp,
                        new String(Base64.encode(archivable.getContentEncoded())));

            if (LOG.isDebugEnabled()) {
                LOG.debug("Archived with uniqueId: " + uniqueId);
            }
            Map<String, String> logMap = (Map<String, String>) requestContext.get(RequestContext.LOGMAP);
            String ids = logMap.get(IWorkerLogger.LOG_ARCHIVE_IDS);
            if (ids == null) {
                ids = uniqueId;
            } else {
                ids = ids + ", " + uniqueId;
            }
            logMap.put(IWorkerLogger.LOG_ARCHIVE_IDS, ids);
            
            archived = true;
        } else {
            archived = false;
        }
        return archived;
    }
}
