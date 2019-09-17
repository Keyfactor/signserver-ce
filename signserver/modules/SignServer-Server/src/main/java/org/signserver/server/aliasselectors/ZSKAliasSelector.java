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
package org.signserver.server.aliasselectors;

import java.util.Collections;
import java.util.List;
import javax.persistence.EntityManager;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.RequestContext;
import org.signserver.common.RequestMetadata;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.common.data.Request;
import org.signserver.server.IProcessable;
import org.signserver.server.WorkerContext;

/**
 * Alias selector implementation selecting a zone signing key alias based on
 * ZSK_KEY_ALIAS_PREFIX and ZSK_SEQUENCE_NUMBER.
 *
 * @author Vinay Singh
 * @version $Id$
 */
public class ZSKAliasSelector implements AliasSelector {

    public static String PROPERTY_ZSK_KEY_ALIAS_PREFIX = "ZSK_KEY_ALIAS_PREFIX";
    public static String ZSK_SEQUENCE_NUMBER = "ZSK_SEQUENCE_NUMBER";

    private String zskAliasprefix;

    @Override
    public void init(int workerId, WorkerConfig config, WorkerContext workerContext, EntityManager workerEM) {
        zskAliasprefix = config.getProperty(PROPERTY_ZSK_KEY_ALIAS_PREFIX);
    }

    @Override
    public String getAlias(int purpose, IProcessable processble, Request signRequest, RequestContext requestContext) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException {
        String alias = null;
        if (requestContext != null) {

            RequestMetadata requestMetadata = RequestMetadata.getInstance(requestContext);
            String seqNumberInString = requestMetadata.get(ZSK_SEQUENCE_NUMBER);
            // TODO: remove harcoded sequence number
            seqNumberInString = "";
            alias = zskAliasprefix + seqNumberInString;
        }
        return alias;
    }

    @Override
    public List<String> getFatalErrors() {
        return Collections.emptyList();
    }

}
