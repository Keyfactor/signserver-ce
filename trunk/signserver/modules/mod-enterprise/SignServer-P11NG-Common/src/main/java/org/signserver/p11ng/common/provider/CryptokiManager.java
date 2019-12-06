/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.p11ng.common.provider;

import com.sun.jna.Native;
import com.sun.jna.NativeLibrary;
import java.security.Provider;
import java.security.Security;
import java.util.HashMap;
import org.apache.log4j.Logger;
import org.pkcs11.jacknji11.CEi;
import org.pkcs11.jacknji11.Ci;
import org.pkcs11.jacknji11.jna.JNAi;
import org.pkcs11.jacknji11.jna.JNAiNative;

/**
 * Singleton managing the various cryptoki devices available.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class CryptokiManager {

    private static final Logger LOG = Logger.getLogger(CryptokiManager.class);

    private static final CryptokiManager INSTANCE = new CryptokiManager();

    private final HashMap<String, CryptokiDevice> devices = new HashMap<>();

    public static CryptokiManager getInstance() {
        return INSTANCE;
    }

    private CryptokiManager() {}


    public synchronized CryptokiDevice getDevice(final String name, final String libDir) {
        LOG.debug(">getDevice(" + name + ", " + libDir + ")");
        CryptokiDevice result = devices.get(getId(name, libDir));
        if (result == null) {
            NativeLibrary.addSearchPath(name, libDir);
            JNAiNative jnaiNative = (JNAiNative) Native.loadLibrary(name, JNAiNative.class);
            CEi ce = new CEi(new Ci(new JNAi(jnaiNative)));
            result = new CryptokiDevice(ce, getInstallOrReInstallProvider());
            devices.put(getId(name, libDir), result);
        }
        return result;
    }

    private JackNJI11Provider getInstallOrReInstallProvider() {
        final JackNJI11Provider result;
        Provider p = Security.getProvider(JackNJI11Provider.NAME);
        if (p instanceof JackNJI11Provider) {
            result = (JackNJI11Provider) p;
            if (LOG.isDebugEnabled()) {
                LOG.debug("Using existing provider");
            }
        } else if (p != null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Found old provider. Re-installing.");
            }
            Security.removeProvider(JackNJI11Provider.NAME);
            result = new JackNJI11Provider();
            Security.addProvider(result);
        } else {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Did not found our provider: " + p);
            }
            result = new JackNJI11Provider();
            Security.addProvider(result);
        }
        return result;
    }

    private static String getId(final String name, final String libDir) {
        return name + "@" + libDir;
    }
}
