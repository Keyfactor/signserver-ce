/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.module.apk.signer;

import java.util.LinkedList;
import java.util.List;
import javax.persistence.EntityManager;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.common.data.Request;
import org.signserver.server.IProcessable;
import org.signserver.server.IServices;
import org.signserver.server.WorkerContext;
import org.signserver.server.aliasselectors.AliasSelector;
import org.signserver.server.cryptotokens.ICryptoTokenV4;
import org.signserver.test.utils.mock.MockedCryptoToken;

/**
 * Mocked version of the ApkSigner using a MockedCryptoToken.
 *
 * @author Marcus Lundblad
 * @version $Id$
 */
public class MockedApkRotateSigner extends ApkRotateSigner {
    private final MockedCryptoToken mockedToken;
    private final String keyAlias;

    public MockedApkRotateSigner(final String keyAlias, final MockedCryptoToken mockedToken) {
        this.keyAlias = keyAlias;
        this.mockedToken = mockedToken;
    }

    @Override
    public ICryptoTokenV4 getCryptoToken(final IServices services) {
        return mockedToken;
    }

    @Override
    protected AliasSelector createAliasSelector(String aliasSelectorClassName) {
        return new AliasSelector() {
            @Override
            public void init(int workerId, WorkerConfig config, WorkerContext workerContext, EntityManager workerEM) {
            }

            @Override
            public String getAlias(int purpose, IProcessable processble, Request signRequest, RequestContext requestContext) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException {
                return keyAlias;
            }

            @Override
            public List<String> getFatalErrors() {
                return new LinkedList<>();
            }
        };
    }

}
