/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.p11ng.common.cli;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Base64;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.p11ng.common.provider.CryptokiDevice;
import org.signserver.p11ng.common.provider.CryptokiManager;
import org.signserver.p11ng.common.provider.JackNJI11Provider;

/**
 * Testing signing thread implementation.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public class TestSignThread extends OperationsThread {
    /** Logger for this class */
    private static final Logger LOG = Logger.getLogger(TestSignThread.class);
    
    private final int id;
    private final FailureCallback failureCallback;
    private final String alias;
    private final String libName;
    private final String libDir;
    private final long slotId;
    private final String pin;
    private final int warmupTime;
    private final int timeLimit;
    private final boolean useCache;
    private final String signatureAlgorithm;

    public TestSignThread(final int id,
                          final FailureCallback failureCallback,
                          final String alias,
                          final String libName, final String libDir,
                          final long slotId, final String pin,
                          final int warmupTime, final int timeLimit, final boolean useCache, final String signatureAlgorithm) {
        super(failureCallback);
        this.id = id;
        this.failureCallback = failureCallback;
        this.alias = alias;
        this.libName = libName;
        this.libDir = libDir;
        this.slotId = slotId;
        this.pin = pin;
        this.warmupTime = warmupTime;
        this.timeLimit = timeLimit;
        this.useCache = useCache;
        this.signatureAlgorithm = signatureAlgorithm;
    }
    
    @Override
    public void run() {
        final CryptokiDevice device = CryptokiManager.getInstance().getDevice(libName, libDir);
        final CryptokiDevice.Slot slot = device.getSlot(slotId);
        slot.login(pin);
        final JackNJI11Provider provider = slot.getProvider();
        
        slot.setUseCache(useCache);

        LOG.info("Starting thread " + id);
        
        final long startTime = System.currentTimeMillis();
        final long stopTime =
                timeLimit > 0 ? startTime + timeLimit : Long.MAX_VALUE;
        final long startCountingTime = startTime + warmupTime;
        
        try {
            while (!isStop()) {
                PrivateKey privKey = null;
                try {
                    privKey = slot.aquirePrivateKey(alias);
                    slot.getCertificateChain(alias);
                    final Signature sign = Signature.getInstance(signatureAlgorithm, provider);
                
                    sign.initSign(privKey);
                    sign.update("Some data to be signed".getBytes("UTF-8"));
                    byte[] signature = sign.sign();

                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Signing in thread " + id);
                        LOG.debug("Signature: " + new String(Base64.encode(signature)));
                    }

                    final long currTime = System.currentTimeMillis();

                    if (currTime > stopTime) {
                        break;
                    }

                    if (currTime >= startCountingTime) {
                        registerOperation();
                    }
                } finally {
                    if (privKey != null) {
                        slot.releasePrivateKey(privKey);
                    }
                }      
            }
        } catch (NoSuchAlgorithmException | InvalidKeyException |
                 UnsupportedEncodingException | SignatureException |
                 CryptoTokenOfflineException | RuntimeException e) {
            LOG.error("Failing signing: " + e.getMessage());
            fireFailure(getName() + ": failed after " + getNumberOfOperations() + " signings: " + e.getMessage());
        }
    }
}
