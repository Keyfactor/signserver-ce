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
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Map;
import javax.ejb.Local;
import javax.ejb.Remote;
import org.cesecore.audit.AuditLogEntry;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.util.query.QueryCriteria;
import org.signserver.common.ArchiveDataVO;
import org.signserver.common.ArchiveMetadata;
import org.signserver.common.AuthorizedClient;
import org.signserver.common.CryptoTokenAuthenticationFailureException;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.ICertReqData;
import org.signserver.common.ISignerCertReqInfo;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.KeyTestResult;
import org.signserver.common.OperationUnsupportedException;
import org.signserver.common.ProcessRequest;
import org.signserver.common.ProcessResponse;
import org.signserver.common.QueryException;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.UnsupportedCryptoTokenParameter;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerStatus;
import org.signserver.server.cryptotokens.TokenSearchResults;
import org.signserver.server.log.AdminInfo;

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
     * @param includeData If 'false' only the alias and key type is included, otherwise all information available is returned
     * @return the search result
     * @throws OperationUnsupportedException in case the search operation is not supported by the worker
     * @throws CryptoTokenOfflineException in case the token is not in a searchable state
     * @throws QueryException in case the query could not be understood or could not be executed
     * @throws InvalidWorkerIdException in case the worker ID is not existing
     * @throws AuthorizationDeniedException in case the operation was not allowed
     * @throws SignServerException in case of any other problem
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
