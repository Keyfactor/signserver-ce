/** ***********************************************************************
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
 ************************************************************************ */
package org.signserver.common;

import java.util.Collection;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import org.apache.log4j.Logger;

/**
 * Class representing admin or client authorization.
 *
 * @author Vinay Singh
 * @version $Id$
 *
 */
public class AuthorizedClientEntry {

    /**
     * Logger for this class.
     */
    private static Logger LOG = Logger.getLogger(AuthorizedClientEntry.class);
    
    private final MatchSubjectWithType matchSubjectWithType;
    private final MatchIssuerWithType matchIssuerWithType;
    private final String matchSubjectWithValue;
    private final String matchIssuerWithValue;

    /**
     * Construct a client entry given an instance of AuthorizedClient.
     *
     * @param client
     */
    public AuthorizedClientEntry(final CertificateMatchingRule client) {        
        this.matchSubjectWithValue = client.getMatchSubjectWithValue();
        this.matchIssuerWithValue = client.getMatchIssuerWithValue();
        this.matchSubjectWithType = client.getMatchSubjectWithType();
        this.matchIssuerWithType = client.getMatchIssuerWithType();
    }

    /**
     * Construct a client entry given certificate serial number and issuer.
     *
     * @param matchSubjectWithValue
     * @param matchIssuerWithValue
     * @param matchSubjectWithType
     * @param matchIssuerWithType
     */
    public AuthorizedClientEntry(final String matchSubjectWithValue, final String matchIssuerWithValue, final MatchSubjectWithType matchSubjectWithType, final MatchIssuerWithType matchIssuerWithType) {
        this.matchSubjectWithValue = matchSubjectWithValue;
        this.matchIssuerWithValue = matchIssuerWithValue;
        this.matchSubjectWithType = matchSubjectWithType;
        this.matchIssuerWithType = matchIssuerWithType;
    }

    /**
     * Given a collection of AuthorizedClient instances, produces a set of
     * ClientEntry instances.
     *
     * @param authClients Collection of authorized clients
     * @return Set of client entries
     */
    public static Set<AuthorizedClientEntry> clientEntriesFromAuthClients(
            final Collection<CertificateMatchingRule> authClients) {
        final Set<AuthorizedClientEntry> result = new HashSet<>();

        authClients.forEach((authClient) -> {
            result.add(new AuthorizedClientEntry(authClient));
        });

        return result;
    }

    public MatchSubjectWithType getMatchSubjectWithType() {
        return matchSubjectWithType;
    }

    public MatchIssuerWithType getMatchIssuerWithType() {
        return matchIssuerWithType;
    }

    public String getMatchSubjectWithValue() {
        return matchSubjectWithValue;
    }

    public String getMatchIssuerWithValue() {
        return matchIssuerWithValue;
    }

    @Override
    public int hashCode() {
        int hash = 5;
        hash = 53 * hash + Objects.hashCode(this.matchSubjectWithValue);
        hash = 53 * hash + Objects.hashCode(this.matchIssuerWithValue);
        hash = 53 * hash + Objects.hashCode(this.matchSubjectWithType);
        hash = 53 * hash + Objects.hashCode(this.matchIssuerWithType);
        return hash;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final AuthorizedClientEntry other = (AuthorizedClientEntry) obj;
        if (!Objects.equals(this.matchIssuerWithValue, other.matchIssuerWithValue)) {
            return false;
        }
        if (!Objects.equals(this.matchSubjectWithValue, other.matchSubjectWithValue)) {
            return false;
        }
        if (this.matchSubjectWithType != other.matchSubjectWithType) {
            return false;
        }
        if (this.matchIssuerWithType != other.matchIssuerWithType) {
            return false;
        }
        return true;
    }

}
