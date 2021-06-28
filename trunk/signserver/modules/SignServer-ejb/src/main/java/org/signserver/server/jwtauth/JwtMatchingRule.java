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
package org.signserver.server.jwtauth;

import java.util.Objects;

/**
 * Represents a matching rule with a claim name/value pair from a given issuer
 * and optionally with a descriptive text.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class JwtMatchingRule {
    private final String claimName;
    private final String claimValue;
    private final String issuer;
    private final String description;

    public JwtMatchingRule(String claimName, String claimValue, String issuer, String description) {
        this.claimName = claimName;
        this.claimValue = claimValue;
        this.issuer = issuer;
        this.description = description;
    }

    public String getClaimName() {
        return claimName;
    }

    public String getClaimValue() {
        return claimValue;
    }

    public String getIssuer() {
        return issuer;
    }

    public String getDescription() {
        return description;
    }

    @Override
    public int hashCode() {
        int hash = 5;
        hash = 31 * hash + Objects.hashCode(this.claimName);
        hash = 31 * hash + Objects.hashCode(this.claimValue);
        hash = 31 * hash + Objects.hashCode(this.issuer);
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
        final JwtMatchingRule other = (JwtMatchingRule) obj;
        if (!Objects.equals(this.claimName, other.claimName)) {
            return false;
        }
        if (!Objects.equals(this.claimValue, other.claimValue)) {
            return false;
        }
        if (!Objects.equals(this.issuer, other.issuer)) {
            return false;
        }
        return true;
    }

    @Override
    public String toString() {
        return claimName + "=" + claimValue + "@" + issuer + "?description=" + description + '}';
    }
    
}
