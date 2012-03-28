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
package org.signserver.server.archive.directdbarchiver;

import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.Date;
import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.sql.DataSource;
import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Base64;
import org.ejbca.util.CertTools;
import org.signserver.common.ArchiveDataVO;
import org.signserver.common.CompileTimeSettings;
import org.signserver.common.RequestContext;
import org.signserver.common.WorkerConfig;
import org.signserver.server.SignServerContext;
import org.signserver.server.archive.Archivable;
import org.signserver.server.archive.ArchiveException;
import org.signserver.server.archive.Archiver;
import org.signserver.server.archive.olddbarchiver.ArchiveDataArchivable;
import org.signserver.server.archive.olddbarchiver.OldDatabaseArchiver;

/**
 * Archiver archiving directly to the database using JDBC and a datasource 
 * name configured in the worker configuration.
 * 
 * Worker properties:
 * ARCHIVERx.ISDISABLED - TRUE if the archiver should not be used (Default FALSE)
 * ARCHIVERx.CONNECTIONNAME - The datasource JNDI name without the JNDI prefix
 * 
 * Originally contributed by Diego de Felice in the forum:
 * http://sourceforge.net/projects/signserver/forums/forum/668766/topic/4971929
 * 
 * Developers: 
 * This class could be improved to support any Archivable if the 
 * DirectDatabaseArchiver should be able to be used with workers not returning 
 * ArchiveData object any more.
 *
 * @author Diego de Felice
 * @version $Id$
 * @see OldDatabaseArchiver
 */
public class DirectDatabaseArchiver implements Archiver {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(DirectDatabaseArchiver.class);
    
    private boolean disabled;
    private DataSource datasource;

    @Override
    public void init(int listIndex, WorkerConfig config, SignServerContext context) {
        final String disabledProperty = "ARCHIVER" + listIndex + ".ISDISABLED";
        final String connectionNameProperty = "ARCHIVER" + listIndex + ".CONNECTIONNAME";
        datasource = null;
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("Configuring Direct Archiver " + listIndex);
        }
        
        disabled = Boolean.parseBoolean(config.getProperty(disabledProperty, "false"));
        if (LOG.isDebugEnabled()) {
            LOG.debug("Disabled: " + disabled);
        }
        
        String connectionName = config.getProperty(connectionNameProperty);
        if (connectionName == null) {
            LOG.error(connectionNameProperty + " property not configured");    
        } else {
            String dataSourceJNDI = CompileTimeSettings.getInstance().getProperty(CompileTimeSettings.DATASOURCE_JNDINAMEPREFIX) + connectionName;
            if (LOG.isDebugEnabled()) {
                LOG.debug("Using datasource JNDI name: " + dataSourceJNDI);
            }
            
            try {   
                if (!disabled) {
                    Context initialContext = new InitialContext();
                    if (initialContext == null) {
                        LOG.error("JNDI problem. Cannot get InitialContext.");
                    } else {
                        datasource = (DataSource) initialContext.lookup(dataSourceJNDI);
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("Configured Direct Archiver " + listIndex);
                        }
                    }
                }
            } catch (NamingException ex) {
                LOG.error("Error looking up datasource: " + dataSourceJNDI, ex);
            }
        }
    }

    @Override
    public boolean archive(Archivable archivable, RequestContext requestContext) throws ArchiveException {
        boolean archived = false;
        if (!disabled && Archivable.TYPE_RESPONSE.equals(archivable.getType()) && archivable instanceof ArchiveDataArchivable) {
            if (datasource == null) {
                throw new ArchiveException("Could not archive as archiver was not successfully initialized");
            }
            final ArchiveDataArchivable ada = (ArchiveDataArchivable) archivable;
            final Integer workerId = (Integer) requestContext.get(RequestContext.WORKER_ID);
            final X509Certificate certificate = (X509Certificate) requestContext.get(RequestContext.CLIENT_CERTIFICATE);
            final String remoteIp = (String) requestContext.get(RequestContext.REMOTE_IP);
            String uniqueId = ArchiveDataVO.TYPE_RESPONSE_BASE64ENCODED + ";" + workerId + ";" + ada.getArchiveId();
            if (LOG.isDebugEnabled()) {
                LOG.debug("Creating archive data, uniqueId=" + uniqueId);
            }
            PreparedStatement statement = null;
            Connection connection = null;
            try {
                if (datasource != null) {
                    connection = datasource.getConnection();
                } else {
                    throw new ArchiveException("Could not archive as connect to database could not be obtained");
                }
                String requestIssuerDn = null;
                String requestSn = null;
                if (certificate != null) {
                    requestIssuerDn = CertTools.getIssuerDN(certificate);
                    requestSn = certificate.getSerialNumber().toString(16);
                }
                String _queryString = "INSERT INTO ArchiveData( UNIQUEID, ARCHIVEDATA, ARCHIVEID, REQUESTCERTSERIALNUMBER, REQUESTIP, REQUESTISSUERDN, SIGNERID, TIME, TYPE ) VALUES( ?, ?, ?, ?, ?, ?, ?, ?, ? )";
                connection.setAutoCommit(false);
                statement = connection.prepareStatement(_queryString);
                statement.setString(1, uniqueId);
                statement.setString(2, new String(Base64.encode(ada.getContentEncoded())));
                statement.setString(3, ada.getArchiveId());
                statement.setString(4, requestSn);
                statement.setString(5, remoteIp);
                statement.setString(6, requestIssuerDn);
                statement.setInt(7, workerId);
                statement.setLong(8, new Date().getTime());
                statement.setInt(9, (int) ArchiveDataVO.TYPE_RESPONSE_BASE64ENCODED);
                int _nrows = statement.executeUpdate();
                connection.commit();
                if (_nrows == 0) {
                    throw new ArchiveException("Could not archive as no rows where inserted to database");
                }
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Archived data, uniqueId=" + uniqueId);
                }
                archived = true;
            } catch (SQLException ex) {
                throw new ArchiveException("Could not archive as a database access error occured", ex);
            } finally {
                try {
                    if (statement != null) {
                        statement.close();
                    }
                    if (connection != null) {
                        connection.setAutoCommit(true);
                        connection.close();
                    }
                } catch (Exception ex) {
                    LOG.info("Cannot finalize: " + ex);
                }
            }
        }
        return archived;
    }
}