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
package org.signserver.server.archive.olddbarchiver;

import java.security.cert.X509Certificate;
import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Base64;
import org.signserver.common.ArchiveDataVO;
import org.signserver.common.RequestContext;
import org.signserver.common.WorkerConfig;
import org.signserver.server.SignServerContext;
import org.signserver.server.archive.Archivable;
import org.signserver.server.archive.ArchiveException;
import org.signserver.server.archive.Archiver;
import org.signserver.server.archive.ArchiverInitException;
import org.signserver.server.archive.olddbarchiver.entities.ArchiveDataService;

/**
 * Archiver only accepting responses and currently only supports Archivables of
 * class ArchiveDataArchivable. 
 * 
 *  Worker properties:
 *  ARCHIVERx.RESPONSEFORMAT - Format for storing the response in the database. 
 *  Can be "XML" for storage in an upgradeble XML encoded Base64PutHashMap (default) 
 *  or "BASE64" for only storing the request data bytes in base64 encoding.
 * 
 *  where x is the (zero-based) index in the ARCHIVERS property list.
 * 
 * Developers:
 * This class could be improved to support any Archivable if the
 * OldDatabaseArchiver should be able to be used with workers not returning
 * ArchiveData object any more.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class OldDatabaseArchiver implements Archiver {
    
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(OldDatabaseArchiver.class);
 
    public static final String RESPONSEFORMAT = "RESPONSEFORMAT";
    public static final String XML = "XML";
    public static final String BASE64 = "BASE64";

    private ArchiveDataService dataService;
    
    private boolean base64Encoding;

    @Override
    public void init(int listIndex, WorkerConfig config, SignServerContext context) throws ArchiverInitException {
        dataService = null;
        String responseFormatProperty = "ARCHIVER" + listIndex + "." + RESPONSEFORMAT;
        String responseFormat = config.getProperty(responseFormatProperty, XML);
        if (BASE64.equalsIgnoreCase(responseFormat)) {
            base64Encoding = true;
        } else if (XML.equalsIgnoreCase(responseFormat)) {
            base64Encoding = false;
        } else {
            throw new ArchiverInitException("Unknown value for property " + responseFormatProperty + ". Should be \"" + XML + "\" or \"" + BASE64 + "\"");
        }
        dataService = new ArchiveDataService(context.getEntityManager());
        if (LOG.isDebugEnabled()) {
            LOG.debug("Archiver" + listIndex + " will use base64 encoding: " + base64Encoding);
        }
    }

    @Override
    public boolean archive(Archivable archivable, RequestContext requestContext)
            throws ArchiveException {
        final boolean archived;
        if (Archivable.TYPE_RESPONSE.equals(archivable.getType())
                && archivable instanceof ArchiveDataArchivable) {
            if (dataService == null) {
                throw new ArchiveException("Could not archive as archiver was not successfully initialized");
            }
            final ArchiveDataArchivable ada = (ArchiveDataArchivable) archivable;
            final Integer workerId = (Integer) requestContext.get(RequestContext.WORKER_ID);
            final X509Certificate certificate = (X509Certificate) requestContext.get(RequestContext.CLIENT_CERTIFICATE);
            final String remoteIp = (String) requestContext.get(RequestContext.REMOTE_IP);

            final String uniqueId;
            if (base64Encoding) {
                uniqueId = dataService.create(ArchiveDataVO.TYPE_RESPONSE_BASE64ENCODED,
                             workerId,
                             ada.getArchiveId(),
                             certificate,
                             remoteIp,
                            new String(Base64.encode(ada.getContentEncoded())));
            } else {
                uniqueId = dataService.create(ArchiveDataVO.TYPE_RESPONSE_XMLENCODED,
                            workerId,
                            ada.getArchiveId(),
                            certificate,
                            remoteIp,
                             ada.getArchiveData());
            }
            // TODO: Log uniqueId
            archived = true;
        } else {
            archived = false;
        }
        return archived;
    }
}
