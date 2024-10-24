package org.signserver.rest.api.helper;

import jakarta.servlet.http.HttpServletRequest;
import org.signserver.admin.common.auth.AdminAuthHelper;
import org.signserver.admin.common.auth.AdminNotAuthorizedException;
import org.signserver.common.ClientEntry;
import org.signserver.common.ForbiddenException;
import org.signserver.server.log.AdminInfo;

import java.security.cert.X509Certificate;
import java.util.Set;

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

    public AdminInfo restCallAuthorizer(HttpServletRequest httpServletRequest, String operation, String... args) throws AdminNotAuthorizedException, ForbiddenException {

        checkCustomHeader(httpServletRequest);

        try {
            return delegate.requireAdminAuthorization(getCertificate(httpServletRequest), operation, args);
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

    private void checkCustomHeader(HttpServletRequest httpServletRequest) throws ForbiddenException {
        if (httpServletRequest.getHeader("X-Keyfactor-Requested-With") == null) {
            //LOG.error("Missing required hedear X-Keyfactor-Requested-With");
            throw new ForbiddenException();
        }
    }

    private X509Certificate getCertificate(HttpServletRequest httpServletRequest) throws AdminNotAuthorizedException {
        final X509Certificate certificates = getClientCertificate(httpServletRequest);
        if (certificates == null) {
            throw new AdminNotAuthorizedException(
                    "Admin not authorized to resource. "
                            + "Client certificate authentication required.");
        }
        return certificates;
    }
    private X509Certificate getClientCertificate(HttpServletRequest httpServletRequest) {
        X509Certificate[] certificates = (X509Certificate[]) httpServletRequest.getAttribute("jakarta.servlet.request.X509Certificate");

        if (certificates != null) {
            return certificates[0];
        }
        return null;
    }
}
