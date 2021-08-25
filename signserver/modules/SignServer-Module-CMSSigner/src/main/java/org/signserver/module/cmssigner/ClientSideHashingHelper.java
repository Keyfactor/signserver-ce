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
package org.signserver.module.cmssigner;

import java.util.HashSet;
import java.util.LinkedList;
import java.util.Set;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestAlgorithmIdentifierFinder;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.RequestContext;
import org.signserver.common.RequestMetadata;
import static org.signserver.common.SignServerConstants.DEFAULT_NULL;
import org.signserver.common.WorkerConfig;

/**
 * Helper class for handling the client-side hashing worker properties and its
 * logic.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class ClientSideHashingHelper {

    private static final Logger LOG = Logger.getLogger(ClientSideHashingHelper.class);

    public static final String CLIENTSIDEHASHING = "CLIENTSIDEHASHING";
    public static final String ALLOW_CLIENTSIDEHASHING_OVERRIDE = "ALLOW_CLIENTSIDEHASHING_OVERRIDE";
    public static final String ACCEPTED_HASHDIGEST_ALGORITHMS = "ACCEPTED_HASH_DIGEST_ALGORITHMS";

    public static final String CLIENTSIDE_HASHDIGESTALGORITHM_PROPERTY = "CLIENTSIDE_HASHDIGESTALGORITHM";
    public static final String USING_CLIENTSUPPLIED_HASH_PROPERTY = "USING_CLIENTSUPPLIED_HASH";

    private boolean clientSideHashing;
    private boolean allowClientSideHashingOverride;
    private Set<AlgorithmIdentifier> acceptedHashDigestAlgorithms;

    public void init(WorkerConfig config, LinkedList<String> configErrors) {


        final String clientSideHashingValue = config.getProperty(CLIENTSIDEHASHING, Boolean.FALSE.toString());
        if (Boolean.FALSE.toString().equalsIgnoreCase(clientSideHashingValue)) {
            clientSideHashing = false;
        } else if (Boolean.TRUE.toString().equalsIgnoreCase(clientSideHashingValue)) {
            clientSideHashing = true;
        } else {
            configErrors.add("Incorrect value for property " + CLIENTSIDEHASHING + ". Expecting TRUE or FALSE.");
        }

        final String allowClientSideHashingOverrideValue = config.getProperty(ALLOW_CLIENTSIDEHASHING_OVERRIDE, Boolean.FALSE.toString());
        if (Boolean.FALSE.toString().equalsIgnoreCase(allowClientSideHashingOverrideValue)) {
            allowClientSideHashingOverride = false;
        } else if (Boolean.TRUE.toString().equalsIgnoreCase(allowClientSideHashingOverrideValue)) {
            allowClientSideHashingOverride = true;
        } else {
            configErrors.add("Incorrect value for property " + ALLOW_CLIENTSIDEHASHING_OVERRIDE + ". Expecting TRUE or FALSE.");
        }

        final String acceptedHashDigestAlgorithmsValue
                = config.getProperty(ACCEPTED_HASHDIGEST_ALGORITHMS, DEFAULT_NULL);
        final DigestAlgorithmIdentifierFinder algFinder = new DefaultDigestAlgorithmIdentifierFinder();

        if (acceptedHashDigestAlgorithmsValue != null) {
            acceptedHashDigestAlgorithms = new HashSet<>();
            for (final String digestAlgorithmString
                    : acceptedHashDigestAlgorithmsValue.split(",")) {
                final String digestAlgorithmStringTrim = digestAlgorithmString.trim();
                final AlgorithmIdentifier alg = algFinder.find(digestAlgorithmStringTrim);

                if (alg == null || alg.getAlgorithm() == null) {
                    configErrors.add("Illegal algorithm specified for " + ACCEPTED_HASHDIGEST_ALGORITHMS + ": "
                            + digestAlgorithmStringTrim);
                } else {
                    acceptedHashDigestAlgorithms.add(alg);
                }
            }
        }


        /* require ACCEPTED_HASHDIGEST_ALGORITHMS to be set when either
         * CLIENTSIDEHASHING is set to true or ALLOW_CLIENTSIDEHASHING_OVERRIDE
         * is set to true
         */
        if (acceptedHashDigestAlgorithms == null &&
            (allowClientSideHashingOverride || clientSideHashing)) {
            configErrors.add("Must specify " + ACCEPTED_HASHDIGEST_ALGORITHMS +
                             " when " + CLIENTSIDEHASHING + " or " +
                             ALLOW_CLIENTSIDEHASHING_OVERRIDE + " is true");
        }

    }

    /**
     * Get the algorithm provided by the client in the request as OID if we
     * support the algorithm.
     *
     * @param requestContext of the request
     * @return the OID of the hash algorithm
     * @throws IllegalRequestException in case hash algorithm is not provided or unsupported
     */
    public final AlgorithmIdentifier getClientSideHashAlgorithm(final RequestContext requestContext)
            throws IllegalRequestException {
        AlgorithmIdentifier alg = null;
        final String value = RequestMetadata.getInstance(requestContext).get(CLIENTSIDE_HASHDIGESTALGORITHM_PROPERTY);
        if (value != null && !value.isEmpty()) {
            final DigestAlgorithmIdentifierFinder algFinder =
                    new DefaultDigestAlgorithmIdentifierFinder();
            alg = algFinder.find(value);
        }

        if (alg == null) {
            throw new IllegalRequestException("Client-side hashing request must specify hash algorithm used");
        }

        /* DefaultDigestAlgorithmIdentifierFinder returns an AlgorithmIdentifer
         * with a null algorithm for an unknown algorithm
         */
        if (alg.getAlgorithm() == null) {
            throw new IllegalRequestException("Client specified an unknown digest algorithm");
        }

        if (CollectionUtils.isNotEmpty(acceptedHashDigestAlgorithms) &&
            !acceptedHashDigestAlgorithms.contains(alg)) {
            throw new IllegalRequestException("Client specified a non-accepted digest hash algorithm");
        }

        // From BC 1.69 DefaultDigestAlgorithmIdentifierFinder does not use DERNull for all params but
        // we want (?) that as we had it before
        return new AlgorithmIdentifier(alg.getAlgorithm(), DERNull.INSTANCE);
    }

    /**
     * Get the algorithm name provided by the client in the request if we
     * support the algorithm.
     *
     * @param requestContext of the request
     * @return the name of the hash algorithm
     * @throws IllegalRequestException in case hash algorithm is not provided or unsupported
     */
    public final String getClientSideHashAlgorithmName(final RequestContext requestContext)
            throws IllegalRequestException {
        final String value = RequestMetadata.getInstance(requestContext).get(CLIENTSIDE_HASHDIGESTALGORITHM_PROPERTY);
        // Call getClientSideHashAlgorithm to validate request
        getClientSideHashAlgorithm(requestContext);
        return value;
    }

    public boolean isClientSideHashing() {
        return clientSideHashing;
    }

    public boolean isAllowClientSideHashingOverride() {
        return allowClientSideHashingOverride;
    }

    public Set<AlgorithmIdentifier> getAcceptedHashDigestAlgorithms() {
        return acceptedHashDigestAlgorithms;
    }

    /**
     * Checks if the request is for client-side hashing and it is configured
     * to be allowed etc.
     * @param requestContext of the request
     * @return true if client-side hashing should be used
     * @throws IllegalRequestException If Client-side/Server-side hashing requested but not allowed.
     */
    protected boolean shouldUseClientSideHashing(final RequestContext requestContext)
            throws IllegalRequestException {
        final boolean useClientSideHashing;
        final Boolean clientSideHashingRequested =
            getClientSuppliedHashRequest(requestContext);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Client-side hashing configured: " + clientSideHashing + "\n"
                    + "Client-side hashing requested: " + clientSideHashingRequested);
        }
        if (clientSideHashingRequested == null) {
            useClientSideHashing = clientSideHashing;
        } else {
            if (clientSideHashingRequested) {
                if (!clientSideHashing && !allowClientSideHashingOverride) {
                    throw new IllegalRequestException("Client-side hashing requested but not allowed");
                }
            } else {
                if (clientSideHashing && !allowClientSideHashingOverride) {
                    throw new IllegalRequestException("Server-side hashing requested but not allowed");
                }
            }

            useClientSideHashing = clientSideHashingRequested;
        }

        return useClientSideHashing;
    }

    /**
     * Read the request metadata property for USING_CLIENTSUPPLIED_HASH if any.
     * Note that empty String is treated as an unset property.
     * @param context to read from
     * @return null if no USING_CLIENTSUPPLIED_HASH request property specified otherwise
     * true or false.
     */
    private static Boolean getClientSuppliedHashRequest(final RequestContext context) {
        final String value = RequestMetadata.getInstance(context).get(USING_CLIENTSUPPLIED_HASH_PROPERTY);
        if (StringUtils.isNotBlank(value)) {
            return Boolean.parseBoolean(value);
        }
        return null;
    }
}
