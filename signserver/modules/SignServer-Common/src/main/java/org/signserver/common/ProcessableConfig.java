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

import org.cesecore.util.CertTools;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.Serializable;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Base64;
import static org.signserver.common.util.PropertiesConstants.AUTHORIZED_CLIENTS;
import static org.signserver.common.util.PropertiesConstants.KEYSTORE_DATA;
import static org.signserver.common.util.PropertiesConstants.SIGNERCERT;
import static org.signserver.common.util.PropertiesConstants.SIGNERCERTCHAIN;

/**
 * 
 * Class used to store signer specific configuration.
 * 
 * @author Philip Vendil 2007 jan 23
 * @version $Id$
 */
public class ProcessableConfig {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(ProcessableConfig.class);
    
    
    private WorkerConfig workerConfig;

    public ProcessableConfig(WorkerConfig workerConfig) {
        this.workerConfig = workerConfig;
        if (get(AUTHORIZED_CLIENTS) == null) {
            put(AUTHORIZED_CLIENTS, new HashSet<AuthorizedClient>());
        }
        if (get(SIGNERCERT) == null) {
            put(SIGNERCERT, "");
        }
        if (get(SIGNERCERTCHAIN) == null) {
            put(SIGNERCERTCHAIN, "");
        }

        put(WorkerConfig.CLASS, this.getClass().getName());
    }

    private void put(String key, Serializable value) {
        if (value instanceof String) {
            workerConfig.setProperty(key, (String) value);
        } else {
            workerConfig.getData().put(key, value);
        }
    }

    private Serializable get(String key) {
        final String value = workerConfig.getProperty(key);
        if (value == null) {
            final Object o = workerConfig.getData().get(key);
            if (o instanceof Serializable) {
                return (Serializable) o;
            } else {
                return null;
            }
        }
        return value;
    }

    /**
     * Adds a Certificate SN to the collection of authorized clients	  
     * 
     * @param client the AuthorizedClient to add
     */
    @SuppressWarnings("unchecked")
    public void addAuthorizedClient(AuthorizedClient client) {
        ((HashSet<AuthorizedClient>) get(AUTHORIZED_CLIENTS)).add(client);
    }

    public WorkerConfig getWorkerConfig() {
        return workerConfig;
    }
}
