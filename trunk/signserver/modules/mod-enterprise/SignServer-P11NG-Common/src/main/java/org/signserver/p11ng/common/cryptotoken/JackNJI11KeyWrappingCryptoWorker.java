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
package org.signserver.p11ng.common.cryptotoken;

import java.util.LinkedList;
import java.util.List;
import javax.persistence.EntityManager;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import static org.signserver.p11ng.common.cryptotoken.JackNJI11KeyWrappingCryptoToken.PROPERTY_WRAPPED_TESTKEY;
import org.signserver.server.IServices;
import org.signserver.server.WorkerContext;
import org.signserver.server.cryptotokens.CryptoTokenHelper;
import static org.signserver.server.cryptotokens.CryptoTokenHelper.CKM_PREFIX;
import static org.signserver.server.cryptotokens.CryptoTokenHelper.DEFAULT_WRAPPING_CIPHER_ALGORITHM;
import static org.signserver.server.cryptotokens.CryptoTokenHelper.PROPERTY_WRAPPING_CIPHER_ALGORITHM;
import org.signserver.server.cryptotokens.ICryptoTokenV4;
import org.signserver.server.signers.CryptoWorker;

/**
 * Unwrapping crypto worker referencing an other JackNJI11 crypto worker.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class JackNJI11KeyWrappingCryptoWorker extends CryptoWorker {
    
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(JackNJI11KeyWrappingCryptoWorker.class);

    // Worker properties

    // Log fields
    //...

    // Default values

    // Configuration errors
    private final LinkedList<String> configErrors = new LinkedList<>();

    // Configuration values  
    private String unwrapKeyAlias;
    private String wrappedTestKeyAlias;
    private String wrappingCipher;
    private long wrappingCipherValue;    
    
    @Override
    public void init(int workerId, WorkerConfig config, WorkerContext workerContext, EntityManager workerEM) {
        super.init(workerId, config, workerContext, workerEM);

        unwrapKeyAlias = config.getProperty(CryptoTokenHelper.PROPERTY_DEFAULTKEY);
        if (unwrapKeyAlias == null) {
            configErrors.add("Missing " + CryptoTokenHelper.PROPERTY_DEFAULTKEY + " property");
        }
        wrappedTestKeyAlias = config.getProperty(PROPERTY_WRAPPED_TESTKEY);

        wrappingCipher = config.getProperty(PROPERTY_WRAPPING_CIPHER_ALGORITHM);
        if (StringUtils.isBlank(wrappingCipher)) {
            wrappingCipher = DEFAULT_WRAPPING_CIPHER_ALGORITHM;
        }
        
        try {
            if (StringUtils.isNumeric(wrappingCipher)) {// long constant value is provided for cipher algorithm
                wrappingCipherValue = Long.parseLong(wrappingCipher);
            } else {
                if (wrappingCipher.startsWith("0x")) {// hexa decimial value is provided for cipher algorithm
                    wrappingCipherValue = Long.parseLong(wrappingCipher.substring("0x".length()), 16);
                } else if (wrappingCipher.startsWith(CKM_PREFIX)) {// CKM constant name is provided for key cipher algorithm
                    wrappingCipherValue = CryptoTokenHelper.getProviderCipherAlgoValue(wrappingCipher);
                } else {
                    configErrors.add("Provided cipher algorithm " + wrappingCipher + " is invalid");
                }
            }
        } catch (NumberFormatException ex) {
            configErrors.add("Cipher algorithm could not be parsed as number: " + ex.getMessage());
        } catch (IllegalArgumentException ex) {
            configErrors.add(ex.getMessage());
        }

    }

    @Override
    protected List<String> getFatalErrors(IServices services) {
        final LinkedList<String> errors = new LinkedList<>(super.getFatalErrors(services));
        errors.addAll(configErrors);
        return errors;
    }

    @Override
    public ICryptoTokenV4 getCryptoToken(IServices services) throws SignServerException {
        ICryptoTokenV4 superToken = super.getCryptoToken(services);
        if (superToken instanceof JackNJI11CryptoToken) {
            return new JackNJI11KeyWrappingCryptoToken(unwrapKeyAlias, wrappedTestKeyAlias, ((JackNJI11CryptoToken) superToken).getSlot(), wrappingCipherValue);
        } else {
            throw new SignServerException("Crypto token must be JackNJI11CryptoToken");
        }
    }
    
}
