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

import java.math.BigInteger;

/**
 * Class representing all allowed Subject types for trusted client certs.
 *
 * @author Vinay Singh
 * @version $Id$
 */
public enum MatchSubjectWithType {

    /**
     * Serial number of the certificate.
     *
     * Encoding should be as output from BigInteger.toString(16).
     * @see BigInteger#toString(int)
     */
    CERTIFICATE_SERIALNO,

    /**
     * Common Name (CN) RDN in textual representation from Subject DN.
     */
    SUBJECT_RDN_CN,

    /**
     * Serial number (serialNumber/SN) RDN in textual representation from Subject DN.
     */
    SUBJECT_RDN_SERIALNO,

    /**
     * Country (C) RDN in textual representation from Subject DN.
     */
    SUBJECT_RDN_C,

    /**
     * Domain Component (DC) RDN in textual representation from Subject DN.
     */
    SUBJECT_RDN_DC,

    /**
     * State or Province (ST) RDN in textual representation from Subject DN.
     */
    SUBJECT_RDN_ST,

    /**
     * Locality (L) RDN in textual representation from Subject DN.
     */
    SUBJECT_RDN_L,

    /**
     * Organization (O) RDN in textual representation from Subject DN.
     */
    SUBJECT_RDN_O,

    /**
     * Organizational Unit (OU) RDN in textual representation from Subject DN.
     */
    SUBJECT_RDN_OU,

    /**
     * Title (title) RDN in textual representation from Subject DN.
     */
    SUBJECT_RDN_TITLE,

    /**
     * Unique ID (UID) RDN in textual representation from Subject DN.
     */
    SUBJECT_RDN_UID,

    /**
     * E-mail address in DN (E) RDN in textual representation from Subject DN.
     */
    SUBJECT_RDN_E,

    /**
     * RFC822Name Subject Alternative Name.
     */
    SUBJECT_ALTNAME_RFC822NAME,

    /**
     * MS UPN Subject Alternative Name.
     */
    SUBJECT_ALTNAME_MSUPN,
}
