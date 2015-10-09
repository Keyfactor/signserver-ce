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
package org.signserver.server;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import javax.servlet.http.HttpServletRequest;
import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Base64;
import org.signserver.common.RequestContext;

/**
 * Helper method for handling credentials from the web.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class CredentialUtils {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(CredentialUtils.class);
    
    /** HTTP request header for providing HTTP authentication data. */
    public static final String HTTP_AUTH_BASIC_AUTHORIZATION = "Authorization";
    
    /** HTTP response header for requesting HTTP authentication. */
    public static final String HTTP_AUTH_BASIC_WWW_AUTHENTICATE =
            "WWW-Authenticate";
    
    /**
     * Add all the found credentials to the request context.
     * Currently this includes username/password from HTTP Basic Auth as well
     * as the client certificate
     * @param context to put the credentials in
     * @param req the incoming Servlet request
     * @param clientCertificate to add (or null if none)
     */
    public static void addToRequestContext(RequestContext context, HttpServletRequest req, Certificate clientCertificate) {
        final CertificateClientCredential credentialCert;
        final UsernamePasswordClientCredential credentialPassword;

        if (clientCertificate instanceof X509Certificate) {
            final X509Certificate cert = (X509Certificate) clientCertificate;
            LOG.debug("Certificate-authentication: true");
            credentialCert = new CertificateClientCredential(
                    cert.getSerialNumber().toString(16),
                    cert.getIssuerDN().getName());
            context.put(RequestContext.CLIENT_CREDENTIAL_CERTIFICATE, credentialCert);
        } else {
            LOG.debug("Certificate-authentication: false");
            credentialCert = null;
        } 

        // Check is client supplied basic-credentials
        final String authorization =
                req.getHeader(HTTP_AUTH_BASIC_AUTHORIZATION);
        if (authorization != null) {
            LOG.debug("Password-authentication: true");

            final String decoded[] = new String(Base64.decode(
                    authorization.split("\\s")[1])).split(":", 2);

            credentialPassword = new UsernamePasswordClientCredential(
                    decoded[0], decoded[1]);
            context.put(RequestContext.CLIENT_CREDENTIAL_PASSWORD, credentialPassword);
        } else {
            LOG.debug("Password-authentication: false");
            credentialPassword = null;
        }
        
        // For backwards-compatibility also set CLIENT_CREDENTIAL with
        // cert if and otherwise if username/password is available
        if (credentialCert != null) {
            context.put(RequestContext.CLIENT_CREDENTIAL, credentialCert);
        } else if (credentialPassword != null) {
            context.put(RequestContext.CLIENT_CREDENTIAL, credentialPassword);
        }
    }
    
}
