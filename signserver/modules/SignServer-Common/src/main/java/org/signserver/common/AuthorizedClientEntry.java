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

import java.math.BigInteger;
import java.util.Collection;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import org.apache.log4j.Logger;

/**
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

    private final BigInteger serialNumber;
    private final String issuerDN;
    private final MatchSubjectWithType matchSubjectWithType;
    private final MatchIssuerWithType matchIssuerWithType;

    /**
     * Construct a client entry given an instance of AuthorizedClient.
     *
     * @param client
     */
    public AuthorizedClientEntry(final CertificateMatchingRule client) {
        this.serialNumber = new BigInteger(client.getMatchSubjectWithValue(), 16);
        this.issuerDN = client.getMatchIssuerWithValue();
        this.matchSubjectWithType = client.getMatchSubjectWithType();
        this.matchIssuerWithType = client.getMatchIssuerWithType();
    }

    /**
     * Construct a client entry given certificate serial number and issuer.
     *
     * @param serialNumber Certificate serial number
     * @param issuerDN Issuer DN
     * @param matchSubjectWithType
     */
    public AuthorizedClientEntry(final BigInteger serialNumber, final String issuerDN, final MatchSubjectWithType matchSubjectWithType, final MatchIssuerWithType matchIssuerWithType) {
        this.serialNumber = serialNumber;
        this.issuerDN = issuerDN;
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

    @Override
    public int hashCode() {
        int hash = 5;
        hash = 53 * hash + Objects.hashCode(this.serialNumber);
        hash = 53 * hash + Objects.hashCode(this.issuerDN);
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
        if (!Objects.equals(this.issuerDN, other.issuerDN)) {
            return false;
        }
        if (!Objects.equals(this.serialNumber, other.serialNumber)) {
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
