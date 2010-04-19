/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package org.signserver.server;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;
import net.sourceforge.scuba.util.Hex;
import org.apache.log4j.Logger;

/**
 *
 * @author markus
 */
@Entity
@Table(name = "KeyUsageCounter")
public class KeyUsageCounter {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(KeyUsageCounter.class);

    @Id
    private String keyHash;

    private long counter;

    public KeyUsageCounter() {
        counter = 0;
    }

    public KeyUsageCounter(String keyHash) {
        this();
        this.keyHash = keyHash;
    }

    public long getCounter() {
        return counter;
    }

    public String getKeyHash() {
        return keyHash;
    }

    @Override
    public String toString() {
        return "Counter(" + keyHash +", " + counter + ")";
    }

    public static String createKeyHash(PublicKey key) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA256", "BC");
            final String res = Hex.bytesToHexString(md.digest(key.getEncoded()));
            if (LOG.isDebugEnabled()) {
                LOG.debug("key hash: " + res);
            }
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
