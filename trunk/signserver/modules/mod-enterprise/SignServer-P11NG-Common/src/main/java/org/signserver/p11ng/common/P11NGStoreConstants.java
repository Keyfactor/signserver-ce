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
package org.signserver.p11ng.common;

/**
 * Class containing constants common for caching implementation of P11NG provider.
 * 
 * @author Vinay Singh
 * @version $Id$
 */
public class P11NGStoreConstants {

    public static final String CKA_LABEL = "LABEL";
    public static final String CKA_ID = "ID";
    public static final String CKA_SUBJECT = "SUBJECT";
    public static final String CKA_VALUE = "VALUE";

    public static final String CKO_PRIVATE_KEY = "PRIVATE_KEY";
    public static final String CKO_SECRET_KEY = "SECRET_KEY";
    public static final String CKO_CERTIFICATE = "CERTIFICATE";

}
