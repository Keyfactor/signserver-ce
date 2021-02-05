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

/**
 * Types for matching issuer DN with.
 *
 * @author Vinay Singh
 * @version $Id$
 */
public enum MatchIssuerWithType {

    /**
     * Issuer DN in the EJBCA BC DN style.
     *
     * Example for getting this format:
     * <pre>
     * CertTools.stringToBCDNString(cert.getIssuerX500Principal().getName())
     * </pre>
     */
    ISSUER_DN_BCSTYLE,

    // Future: Issuer DN as binary/DER encoded X500Name: ISSUER_DN_BINARY, ?
    // Future: ISSUER_DN_LDAPSTYLE ?

}
