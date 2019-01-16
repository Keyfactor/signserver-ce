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
package org.signserver.ejb.interfaces;

import org.signserver.common.WorkerIdentifier;
import java.security.InvalidAlgorithmParameterException;
import java.util.List;
import java.util.Map;
import javax.ejb.Remote;
import org.cesecore.audit.AuditLogEntry;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.util.query.QueryCriteria;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.OperationUnsupportedException;
import org.signserver.common.QueryException;
import org.signserver.common.UnsupportedCryptoTokenParameter;
import org.signserver.server.cryptotokens.TokenSearchResults;

/**
 * Interface for the worker session bean.
 *
 * @version $Id$
 */
@Remote
public interface WorkerSessionRemote extends WorkerSession {

    List<? extends AuditLogEntry> selectAuditLogs(int startIndex, int max, QueryCriteria criteria, String logDeviceId) throws AuthorizationDeniedException;

    /**
     * Queries the specified worker's crypto token.
     *
     * @param workerId Id of worker to query
     * @param startIndex Start index of first result (0-based)
     * @param max Maximum number of results to return
     * @param qc Search criteria for matching results
     * @param includeData If 'false' only the alias and key type is included,
     * otherwise all information available is returned
     * @param params Additional crypto token parameters to pass to the token
     * @return the search result
     * @throws OperationUnsupportedException in case the search operation is not
     * supported by the worker
     * @throws CryptoTokenOfflineException in case the token is not in a
     * searchable state
     * @throws QueryException in case the query could not be understood or could
     * not be executed
     * @throws InvalidWorkerIdException in case the worker ID is not existing
     * @throws InvalidAlgorithmParameterException If the supplied crypto token
     * parameters was not valid
     * @throws UnsupportedCryptoTokenParameter In case the supplied crypto token
     * parameter was not known or supported by the token
     * @throws AuthorizationDeniedException in case the operation was not
     * allowed
     */
    TokenSearchResults searchTokenEntries(WorkerIdentifier workerId, final int startIndex, final int max, final QueryCriteria qc, final boolean includeData, final Map<String, Object> params) throws
            InvalidWorkerIdException,
            AuthorizationDeniedException,
            CryptoTokenOfflineException,
            QueryException,
            InvalidAlgorithmParameterException,
            UnsupportedCryptoTokenParameter,
            OperationUnsupportedException;
}
