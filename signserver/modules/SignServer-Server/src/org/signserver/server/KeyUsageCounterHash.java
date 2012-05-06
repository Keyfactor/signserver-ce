/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.signserver.server;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Hex;

/**
 * Utility class for creating the hash used by the KeyUsageCounter.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class KeyUsageCounterHash {
    
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(KeyUsageCounterHash.class);
    
    public static String create(PublicKey key) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA256", "BC");
            final String res = new String(
                    Hex.encode(md.digest(key.getEncoded())));
            md.reset();
            return res;
        } catch (NoSuchProviderException ex) {
            final String message
                    = "Nu such provider trying to hash public key";
            LOG.error(message, ex);
            throw new RuntimeException(message, ex);
        } catch (NoSuchAlgorithmException ex) {
            final String message
                    = "Nu such algorithm trying to hash public key";
            LOG.error(message, ex);
            throw new RuntimeException(message, ex);
        }
    }   
}
