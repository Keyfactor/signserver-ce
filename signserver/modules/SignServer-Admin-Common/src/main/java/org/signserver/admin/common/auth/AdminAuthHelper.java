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
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.apache.log4j.Logger;
import org.signserver.common.CompileTimeSettings;
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

    public AdminInfo requireAdminAuthorization(final AdminPrincipal principal, final String operation,
                                              final String... args) throws AdminNotAuthorizedException {
        LOG.debug(">requireAdminAuthorization");

        if (principal == null) {
            throw new AdminNotAuthorizedException(
                    "Administrator not authorized to resource. "
                    + "Client certificate authentication required.");
        } else {
            final boolean authorized = principal.getRoles().contains("admin");

            log(principal, authorized, operation, args);

            if (!authorized) {
                throw new AdminNotAuthorizedException(
                        "Administrator not authorized to resource.");
            }

            return principal.getAdminInfo();
        }
    }

    public AdminInfo requireAuditorAuthorization(final AdminPrincipal principal, final String operation,
            final String... args) throws AdminNotAuthorizedException {
        LOG.debug(">requireAuditorAuthorization");

        if (principal == null) {
            throw new AdminNotAuthorizedException(
                    "Auditor not authorized to resource. "
                    + "Client certificate authentication required.");
        } else {
            final boolean authorized = principal.getRoles().contains("auditor");

            log(principal, authorized, operation, args);

            if (!authorized) {
                throw new AdminNotAuthorizedException(
                        "Auditor not authorized to resource.");
            }

            return principal.getAdminInfo();
        }
    }

    public AdminInfo requireArchiveAuditorAuthorization(final AdminPrincipal principal, final String operation,
                                                        final String... args) throws AdminNotAuthorizedException {
        LOG.debug(">requireArchiveAuditorAuthorization");

        if (principal == null) {
            throw new AdminNotAuthorizedException(
                    "Archive auditor not authorized to resource. "
                    + "Client certificate authentication required.");
        } else {
            final boolean authorized = principal.getRoles().contains("archive_auditor");

            log(principal, authorized, operation, args);

            if (!authorized) {
                throw new AdminNotAuthorizedException(
                        "Archive auditor not authorized to resource.");
            }

            return principal.getAdminInfo();
        }
    }

    private void log(final AdminPrincipal principal, final boolean authorized, final String operation, final String... args) throws AdminNotAuthorizedException {
        if (principal instanceof ClientCertAdminPrincipal clientCertAdminPrincipal) {
            log(clientCertAdminPrincipal.getClientCert(), authorized, operation, args);
        } else if (principal instanceof OidcAdminPrincipal oidcAdminPrincipal) {
            log(oidcAdminPrincipal, authorized, operation, args);
        } else {
            throw new AdminNotAuthorizedException("Unsupported principal: " + (principal == null ? null : principal.getClass().getName()));
        }
    }
private void log(final OidcAdminPrincipal user,
                     final boolean authorized, final String operation,
                     final String... args) {
        final StringBuilder line = new StringBuilder()
                .append("ADMIN OPERATION")
                .append("; ")

                .append("subject=")
                .append(user.getAdminInfo().getSubject())
                .append("; ")

                .append("serialNumber=")
                .append(user.getAdminInfo().getSerialNumber())
                .append("; ")

                .append("issuer=")
                .append(user.getAdminInfo().getIssuer())
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
        String allowAnyWSAdminProp = global.getGlobalConfiguration().getProperty(
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
                    " issuer: " + cert.getIssuerDN() + " against admin set: " +
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

    /**
     * List all roles the provided certificate matches.
     * @param cert to match against roles
     * @return list of roles
     */
    public List<String> getRoles(X509Certificate cert) {
        ArrayList<String> roles = new ArrayList<>(3);
        if (isAdminAuthorized(cert)) {
            roles.add("admin");
        }
        if (isAuditorAuthorized(cert)) {
            roles.add("auditor");
        }
        if (isArchiveAuditorAuthorized(cert)) {
            roles.add("archive_auditor");
        }
        return roles;
    }
}
