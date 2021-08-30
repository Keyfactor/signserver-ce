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
package org.signserver.module.tsa.conf;

import org.signserver.common.worker.WorkerConfigProperty;
import org.signserver.module.tsa.TimeStampSigner;

/**
 * Class containing the collection of configuration properties for a TSA worker.
 *
 * @author Andrey Sergeev
 * @version $Id$
 */
public class TSAWorkerConfigProperty extends WorkerConfigProperty {

    /**
     * Authentication type property.
     */
    public static final String AUTH_TYPE = "AUTHTYPE";
    /**
     * Default TSA policy OID.
     * @see TimeStampSigner#DEFAULTTSAPOLICYOID
     */
    public static final String DEFAULT_TSA_POLICY_OID = TimeStampSigner.DEFAULTTSAPOLICYOID;
    /**
     * Accepted extensions.
     * @see TimeStampSigner#ACCEPTEDEXTENSIONS
     */
    public static final String ACCEPTED_EXTENSIONS = TimeStampSigner.ACCEPTEDEXTENSIONS;
    /**
     * Default key for keystore.
     */
    public static final String DEFAULT_KEY = "DEFAULTKEY";
    /**
     * Keystore path.
     */
    public static final String KEYSTORE_PATH = "KEYSTOREPATH";
    /**
     * Keystore type.
     */
    public static final String KEYSTORE_TYPE = "KEYSTORETYPE";
    /**
     * Keystore password.
     */
    public static final String KEYSTORE_PASSWORD = "KEYSTOREPASSWORD";
    /**
     * Accept any policy flag.
     * @see TimeStampSigner#ACCEPTANYPOLICY
     */
    public static final String ACCEPT_ANY_POLICY = TimeStampSigner.ACCEPTANYPOLICY;
    /**
     * Accepted policies.
     * @see TimeStampSigner#ACCEPTEDPOLICIES
     */
    public static final String ACCEPTED_POLICIES = TimeStampSigner.ACCEPTEDPOLICIES;

}
