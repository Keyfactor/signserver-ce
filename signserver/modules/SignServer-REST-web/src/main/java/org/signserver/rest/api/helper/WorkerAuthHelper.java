package org.signserver.rest.api.helper;

import java.security.cert.X509Certificate;
import java.util.Set;
import org.signserver.admin.common.auth.AdminAuthHelper;
import org.signserver.common.ClientEntry;
import org.signserver.rest.api.exception.AdminNotAuthorizedException;
import org.signserver.server.log.AdminInfo;

/**
 * REST version of the AdminAuthHelper.
 *
 * Delegates all methods but uses the REST exception type in order to not change
 * the REST API.
 *
 * @author Hanna Hansson
 * @version $Id$
 */
public class WorkerAuthHelper {

    private final AdminAuthHelper delegate;

    public WorkerAuthHelper(AdminAuthHelper delegate) {
        this.delegate = delegate;
    }

    public AdminInfo requireAdminAuthorization(X509Certificate cert, String operation, String... args) throws AdminNotAuthorizedException {
        try {
            return delegate.requireAdminAuthorization(cert, operation, args);
        } catch (org.signserver.admin.common.auth.AdminNotAuthorizedException ex) {
            throw new AdminNotAuthorizedException(ex.getMessage(), ex);
        }
    }

    public AdminInfo requireAuditorAuthorization(X509Certificate cert, String operation, String... args) throws AdminNotAuthorizedException {
        try {
            return delegate.requireAuditorAuthorization(cert, operation, args);
        } catch (org.signserver.admin.common.auth.AdminNotAuthorizedException ex) {
            throw new AdminNotAuthorizedException(ex.getMessage(), ex);
        }
    }

    public AdminInfo requireArchiveAuditorAuthorization(X509Certificate cert, String operation, String... args) throws AdminNotAuthorizedException {
        try {
            return delegate.requireArchiveAuditorAuthorization(cert, operation, args);
        } catch (org.signserver.admin.common.auth.AdminNotAuthorizedException ex) {
            throw new AdminNotAuthorizedException(ex.getMessage(), ex);
        }
    }

    public boolean isAdminAuthorized(X509Certificate cert) {
        return delegate.isAdminAuthorized(cert);
    }

    public boolean isAuditorAuthorized(X509Certificate cert) {
        return delegate.isAuditorAuthorized(cert);
    }

    public boolean isArchiveAuditorAuthorized(X509Certificate cert) {
        return delegate.isArchiveAuditorAuthorized(cert);
    }

    public boolean hasAuthorization(X509Certificate cert, Set<ClientEntry> authSet) {
        return delegate.hasAuthorization(cert, authSet);
    }

    /*public Set<ClientEntry> getWSClients(String propertyName) {
        return delegate.getWSClients(propertyName);
    }*/
}
