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
package org.signserver.admin.common.auth;

import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Set;
import org.apache.log4j.Logger;
import org.signserver.ejb.interfaces.GlobalConfigurationSessionLocal;
import org.signserver.common.ClientEntry;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.SignServerUtil;
import org.signserver.server.log.AdminInfo;

/**
 * Helper methods for admin authorization.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class AdminAuthHelper {
 
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(AdminAuthHelper.class);

    private final GlobalConfigurationSessionLocal global;

    public AdminAuthHelper(GlobalConfigurationSessionLocal globalConfigurationSession) {
        this.global = globalConfigurationSession;
    }

    public AdminInfo requireAdminAuthorization(final X509Certificate cert, final String operation,
            final String... args) throws AdminNotAuthorizedException {
        LOG.debug(">requireAdminAuthorization");

        if (cert == null) {
            throw new AdminNotAuthorizedException(
                    "Administrator not authorized to resource. "
                    + "Client certificate authentication required.");
        } else {
           final boolean authorized = isAdminAuthorized(cert);

           log(cert, authorized, operation, args);

           if (!authorized) {
               throw new AdminNotAuthorizedException(
                       "Administrator not authorized to resource.");
           }
           
           return new AdminInfo(cert.getSubjectDN().getName(),
                   cert.getIssuerDN().getName(), cert.getSerialNumber());
        }
    }
    
    public AdminInfo requireAuditorAuthorization(final X509Certificate cert, final String operation,
            final String... args) throws AdminNotAuthorizedException {
        LOG.debug(">requireAuditorAuthorization");

        if (cert == null) {
            throw new AdminNotAuthorizedException(
                    "Auditor not authorized to resource. "
                    + "Client certificate authentication required.");
        } else {
           final boolean authorized = isAuditorAuthorized(cert);

           log(cert, authorized, operation, args);

           if (!authorized) {
               throw new AdminNotAuthorizedException(
                       "Auditor not authorized to resource.");
           }
           
           return new AdminInfo(cert.getSubjectDN().getName(),
                   cert.getIssuerDN().getName(), cert.getSerialNumber());
        }
    }
    
    public AdminInfo requireArchiveAuditorAuthorization(final X509Certificate cert, final String operation,
            final String... args) throws AdminNotAuthorizedException {
        LOG.debug(">requireArchiveAuditorAuthorization");

        if (cert == null) {
            throw new AdminNotAuthorizedException(
                    "Archive auditor not authorized to resource. "
                    + "Client certificate authentication required.");
        } else {
           final boolean authorized = isArchiveAuditorAuthorized(cert);

           log(cert, authorized, operation, args);

           if (!authorized) {
               throw new AdminNotAuthorizedException(
                       "Archive auditor not authorized to resource.");
           }
           
           return new AdminInfo(cert.getSubjectDN().getName(),
                   cert.getIssuerDN().getName(), cert.getSerialNumber());
        }
    }
    
    private void log(final X509Certificate certificate, 
            final boolean authorized, final String operation,
            final String... args) {
        final StringBuilder line = new StringBuilder()
                .append("ADMIN OPERATION")
                .append("; ")
                
                .append("subjectDN=")
                .append(SignServerUtil.getTokenizedSubjectDNFromCert(certificate))
                .append("; ")
                
                .append("serialNumber=")
                .append(certificate.getSerialNumber().toString(16))
                .append("; ")
                
                .append("issuerDN=")
                .append(SignServerUtil.getTokenizedIssuerDNFromCert(certificate))
                .append("; ")
                
                .append("authorized=")
                .append(authorized)
                .append("; ")
                
                .append("operation=")
                .append(operation)
                .append("; ")
                
                .append("arguments=");
        for (String arg : args) {
            line.append(arg.replace(";", "\\;").replace("=", "\\="));
            line.append(",");
        }
        line.append(";");
        LOG.info(line.toString());
    }

    public boolean isAdminAuthorized(final X509Certificate cert) { 
        final String allowAnyWSAdminProp = global.getGlobalConfiguration().getProperty(
                GlobalConfiguration.SCOPE_GLOBAL, "ALLOWANYWSADMIN");
        final boolean allowAnyWSAdmin = allowAnyWSAdminProp != null ?
                Boolean.parseBoolean(allowAnyWSAdminProp) : false;
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("allow any admin: " + allowAnyWSAdmin);
        }

        if (allowAnyWSAdmin) {
            return true;
        } else {
            return hasAuthorization(cert, getWSClients("WSADMINS"));
        }
    }
    
    public boolean isAuditorAuthorized(final X509Certificate cert) { 
        return hasAuthorization(cert, getWSClients("WSAUDITORS"));
    }
    
    public boolean isArchiveAuditorAuthorized(final X509Certificate cert) {
        return hasAuthorization(cert, getWSClients("WSARCHIVEAUDITORS"));
    }
    
    public boolean isPeerAuthorizedNoLogging(final X509Certificate cert, final String operation,
            final String... args) {
        LOG.debug(">isPeerAuthorizedNoLogging");
        return hasAuthorization(cert, getWSClients("WSPEERS"));
    }

    public boolean hasAuthorization(final X509Certificate cert,
            final Set<ClientEntry> authSet) {
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("Checking authorization for: SN: " +
                    cert.getSerialNumber().toString(16) +
                    " issuer: " + cert.getIssuerDN() + " agains admin set: " +
                    authSet);
        }

        return authSet.contains(new ClientEntry(cert.getSerialNumber(), SignServerUtil.getTokenizedIssuerDNFromCert(cert)));
    }

    public Set<ClientEntry> getWSClients(final String propertyName) {
        final String adminsProperty = global.getGlobalConfiguration().getProperty(
                GlobalConfiguration.SCOPE_GLOBAL, propertyName);
        
        if (adminsProperty == null) {
            LOG.warn(String.format("No %s global property set.", propertyName));
            return new HashSet<>();
        } else {
            return ClientEntry.clientEntriesFromProperty(adminsProperty);
        }
    }
    
    
    
}
