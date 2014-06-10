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
package org.signserver.module.xades.signer;

import java.io.IOException;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.Map;
import org.apache.xml.security.algorithms.MessageDigestAlgorithm;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampToken;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.SignServerException;
import org.signserver.ejb.interfaces.IInternalWorkerSession;
import org.signserver.server.tsa.InternalTimeStampTokenFetcher;
import xades4j.UnsupportedAlgorithmException;
import xades4j.providers.MessageDigestEngineProvider;
import xades4j.providers.TimeStampTokenGenerationException;
import xades4j.providers.TimeStampTokenProvider;

/**
 * Time-stamp token provider using the internal worker session.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class InternalTimeStampTokenProvider implements TimeStampTokenProvider {

    /** Mapping from digest URI (xml-sec) to OID. */
    private static final Map<String, ASN1ObjectIdentifier> digestUriToOidMap;
    static {
        digestUriToOidMap = new HashMap<String, ASN1ObjectIdentifier>(6);
        digestUriToOidMap.put(MessageDigestAlgorithm.ALGO_ID_DIGEST_NOT_RECOMMENDED_MD5, TSPAlgorithms.MD5);
        digestUriToOidMap.put(MessageDigestAlgorithm.ALGO_ID_DIGEST_RIPEMD160, TSPAlgorithms.RIPEMD160);
        digestUriToOidMap.put(MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA1, TSPAlgorithms.SHA1);
        digestUriToOidMap.put(MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA256, TSPAlgorithms.SHA256);
        digestUriToOidMap.put(MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA384, TSPAlgorithms.SHA384);
        digestUriToOidMap.put(MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA512, TSPAlgorithms.SHA512);
    }

    private final MessageDigestEngineProvider messageDigestProvider;

    private final InternalTimeStampTokenFetcher fetcher;

    public InternalTimeStampTokenProvider(final MessageDigestEngineProvider messageDigestProvider,
            final IInternalWorkerSession session, final String workerNameOrId, final String username, final String password) {
        this.messageDigestProvider = messageDigestProvider;
        this.fetcher = new InternalTimeStampTokenFetcher(session, workerNameOrId, username, password);
    }

    @Override
    public TimeStampTokenRes getTimeStampToken(final byte[] tsDigestInput, final String digestAlgUri) throws TimeStampTokenGenerationException {
        try {
            MessageDigest md = messageDigestProvider.getEngine(digestAlgUri);
            byte[] imprint = md.digest(tsDigestInput);
            TimeStampToken token = fetcher.fetchToken(imprint, digestUriToOidMap.get(digestAlgUri));
            return new TimeStampTokenRes(token.getEncoded(), token.getTimeStampInfo().getGenTime());
        } catch (UnsupportedAlgorithmException ex) {
            throw new TimeStampTokenGenerationException("Digest algorithm not supported", ex);
        } catch (IllegalRequestException ex) {
            throw new TimeStampTokenGenerationException("The time-stamp request failed", ex);
        } catch (CryptoTokenOfflineException ex) {
            throw new TimeStampTokenGenerationException("The time-stamp request could not be processed because of offline TSA", ex);
        } catch (SignServerException ex) {
            throw new TimeStampTokenGenerationException("The time-stamp request could not be processed because of internal error in the TSA", ex);
        } catch (TSPException ex) {
            throw new TimeStampTokenGenerationException("Invalid time stamp response", ex);
        } catch (IOException ex) {
            throw new TimeStampTokenGenerationException("Encoding error", ex);
        }
    }

}
