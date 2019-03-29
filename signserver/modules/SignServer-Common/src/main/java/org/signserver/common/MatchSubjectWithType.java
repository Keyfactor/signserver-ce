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
 * Class representing all allowed Subject types for trusted client certs.
 *
 * @author Vinay Singh
 * @version $Id$
 */
public enum MatchSubjectWithType {
    CERTIFICATE_SERIALNO,
    SUBJECT_RDN_CN,
    SUBJECT_RDN_SERIALNO;
}
