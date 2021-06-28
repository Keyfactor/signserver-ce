/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.ejbca.peerconnector;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.concurrent.ConcurrentHashMap;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.util.Base64;

/**
 * Cache for reuse of client SSL AuthenticationToken lookup as long as the client certificate
 * stays the same.
 * 
 * This saves around 20-25ms of request time for each subsequent request on the authors workstation.
 * 
 * @version $Id$ 
 */
public enum AuthenticationSessionCache {
    INSTANCE;

    private final ConcurrentHashMap<String,SessionCacheEntry> cacheSslClientCert = new ConcurrentHashMap<String,SessionCacheEntry>();
    
    private class SessionCacheEntry {
        private AuthenticationToken authenticationToken;
        private long lastSeen;
    }
    
    public AuthenticationToken getAuthenticationTokenByFingerprint(final String certificateFingerprint, final long removeOlderThan) {
        if (certificateFingerprint!=null && removeOlderThan>0) {
            final long now = System.currentTimeMillis();
            if (certificateFingerprint!=null) {
                final SessionCacheEntry sessionCacheEntry = cacheSslClientCert.get(certificateFingerprint);
                if (sessionCacheEntry!=null && sessionCacheEntry.lastSeen>=now-removeOlderThan) {
                    sessionCacheEntry.lastSeen = now;
                    return sessionCacheEntry.authenticationToken;
                }
            }
        }
        return null;
    }

    public void updateAuthenticationTokenByFingerprint(final String certificateFingerprint, final AuthenticationToken authenticationToken, final long removeOlderThan) {
        if (certificateFingerprint!=null && removeOlderThan>0) {
            final long now = System.currentTimeMillis();
            if (certificateFingerprint!=null) {
                final SessionCacheEntry sessionCacheEntry = new SessionCacheEntry();
                sessionCacheEntry.authenticationToken = authenticationToken;
                sessionCacheEntry.lastSeen = now;
                cacheSslClientCert.put(certificateFingerprint, sessionCacheEntry);
            }
            for (final String currentKey : cacheSslClientCert.keySet()) {
                final SessionCacheEntry oldSessionCacheEntry = cacheSslClientCert.get(currentKey);
                if (oldSessionCacheEntry!=null && oldSessionCacheEntry.lastSeen<now-removeOlderThan) {
                    cacheSslClientCert.remove(currentKey);
                }
            }
        }
    }

    public void clear() {
        cacheSslClientCert.clear();
    }
    
    /** @return a base64 encoded SHA-256 fingerprint of the certificate */
    public static String generateKey(final X509Certificate x509Certificate) {
        if (x509Certificate==null) {
            return null;
        }
        try {
            // http://docs.oracle.com/javase/6/docs/technotes/guides/security/StandardNames.html#MessageDigest
            return new String(Base64.encode(MessageDigest.getInstance("SHA-256", BouncyCastleProvider.PROVIDER_NAME).digest(x509Certificate.getEncoded()), false));
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new IllegalStateException(e);
        } catch (CertificateEncodingException e) {
            return null;
        }
    }
}
