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
package org.signserver.common;

import java.io.Serializable;
import java.util.Objects;

/**
 * Class representing an authorized client containing the Subject type, Subject
 * value, Issuer Type and Issue Value of trusted client certs.
 *
 * @author Vinay Singh
 * @version $Id$
 */
public class CertificateMatchingRule implements Comparable<Object>, Serializable {

    private MatchSubjectWithType matchSubjectWithType;
    private MatchIssuerWithType matchIssuerWithType;
    private String matchSubjectWithValue;
    private String matchIssuerWithValue;
    private String description;

    public CertificateMatchingRule(MatchSubjectWithType matchSubjectWithType, MatchIssuerWithType matchIssuerWithType, String matchSubjectWithValue, String matchIssuerWithValue, String description) {
        this.matchSubjectWithType = matchSubjectWithType;
        this.matchIssuerWithType = matchIssuerWithType;
        this.matchSubjectWithValue = matchSubjectWithValue;
        this.matchIssuerWithValue = matchIssuerWithValue;
        this.description = description;
    }

    public CertificateMatchingRule() {
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

    public String getDescription() {
        return description;
    }

    public void setMatchSubjectWithType(MatchSubjectWithType matchSubjectWithType) {
        this.matchSubjectWithType = matchSubjectWithType;
    }

    public void setMatchIssuerWithType(MatchIssuerWithType matchIssuerWithType) {
        this.matchIssuerWithType = matchIssuerWithType;
    }

    public void setMatchSubjectWithValue(String matchSubjectWithValue) {
        this.matchSubjectWithValue = matchSubjectWithValue;
    }

    public void setMatchIssuerWithValue(String matchIssuerWithValue) {
        this.matchIssuerWithValue = matchIssuerWithValue;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    @Override
    public int hashCode() {
        int hash = 3;
        hash = 29 * hash + Objects.hashCode(this.matchSubjectWithType);
        hash = 29 * hash + Objects.hashCode(this.matchIssuerWithType);
        hash = 29 * hash + Objects.hashCode(this.matchSubjectWithValue);
        hash = 29 * hash + Objects.hashCode(this.matchIssuerWithValue);
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
        final CertificateMatchingRule other = (CertificateMatchingRule) obj;
        if (!Objects.equals(this.matchSubjectWithValue, other.matchSubjectWithValue)) {
            return false;
        }
        if (!Objects.equals(this.matchIssuerWithValue, other.matchIssuerWithValue)) {
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

    

    @Override
    public String toString() {
        return "CertificateMatchingRule{" + "matchSubjectWithType=" + matchSubjectWithType + ", matchIssuerWithType=" + matchIssuerWithType + ", matchSubjectWithValue=" + matchSubjectWithValue + ", matchIssuerWithValue=" + matchIssuerWithValue + ", description=" + description + '}';
    }

    @Override
    public int compareTo(Object other) {
        if (other instanceof CertificateMatchingRule) {
            return matchSubjectWithValue.compareTo(((CertificateMatchingRule) other).matchSubjectWithValue);
        }
        return 0;
    }

}
