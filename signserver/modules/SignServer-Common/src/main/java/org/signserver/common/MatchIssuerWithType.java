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
 *
 * @author Vinay Singh
 * @version $Id$
 */
public enum MatchIssuerWithType {
    ISSUER_DN_BINARY,
    ISSUER_DN_BCSTYLE,
    ISSUER_DN_LDAPSTYLE
}
