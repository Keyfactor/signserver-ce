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
package org.signserver.server.cryptotokens;

import java.io.Serializable;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.log4j.Logger;
import org.ejbca.util.Base64;
import org.ejbca.util.keystore.KeyTools;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;

/**
 * Dummy implementation of an Extended Crypto Token used
 * for test and demonstration purposes.
 * 
 * @author Philip Vendil 21 nov 2007
 * @version $Id$
 */
public class ExtendedHardCodedCryptoToken extends HardCodedCryptoToken
        implements IExtendedCryptoToken {

    private static final Logger log = Logger.getLogger(ExtendedHardCodedCryptoToken.class);
    public static final String KEYREF_AES256KEY = "AES256KEY";
    public static final String KEYREF_RSA1024KEY = "RSA1024KEY";
    private static final byte[] AES256KEY = Base64.decode("DlGEu3/pY6DB2MnkrC/UbDzXzMZVeCg9z1+U+AS6tBE=".getBytes());
    private static final byte[] RSA1024PRIVKEY = Base64.decode(("MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAKIpzGrxOqOjquzj"
            + "ueBQIATX8cyU8Q7eCfkHI7heahyAf8B6du88DpbHl33UOD+1HEL78McOfqmzL/C5"
            + "2uszth/upCnFXruEudzBAjk7fZkul0Qf88qXeMBk1hC0jA3uLdZlwc3OnvJ+HG6s"
            + "s1vJG2njGPKtbjmXd8D6FRE+RafvAgMBAAECgYB5x2n75axjt0VlIJ82FPX2rTSo"
            + "rjFZOOXEXdg1XLHTNay6nz0x66gJE1pw5C5ZqWjP5OOsmPYF+srFvMzqVKsvlhwb"
            + "uZnKbyWvCeyMpSr4Ob+A+SvPKDK3IjL2wms3Csq9CWdqtFwGBcETTfGqjL/0PB2b"
            + "zsrNQ2Gi4tmaBwM6AQJBAP6rzYqoVemHpBtq493TfxMkttWg6q0AeTZJmvxlkcUE"
            + "CnKNk35ZWU+FoXsuV44n1w3Pu6Ri2iepyRHwLZIIdfMCQQCjAmvDQYcuwODYttdw"
            + "BH9zYEUW0v9v8/QuVGcggRFaFx0So8+kIKz68+IWh2LINns3u0ZzXx4dVZes5/wj"
            + "Q9kVAkEAzMmicwmCbFPipxmBOvPDj8VKMOdBTvS+g+UUeDnEykTBkfQ+0q9Onh+7"
            + "Bq7xQSLQUA7nuPy0qIhjY8VbH78l+QJAapzXvEGsV3DA3hxftRzL+rrZFP91H1SP"
            + "vIlpVYH0xlZdpmZLFM5mNE+z7AYqHkY7uoyanDR2rrrfU6/6YVorrQJAEI83lpYz"
            + "o4ywGKR1RpQ9EDctxRmV573kf80/QlYKuk/pchbRpPCIFXzlXuSLDYBS7jsc2mkW"
            + "J8+7q6Sl9X/rlA==").getBytes());
    private static final byte[] RSA1024PUBKEY = Base64.decode(("MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCiKcxq8Tqjo6rs47ngUCAE1/HM"
            + "lPEO3gn5ByO4XmocgH/AenbvPA6Wx5d91Dg/tRxC+/DHDn6psy/wudrrM7Yf7qQp"
            + "xV67hLncwQI5O32ZLpdEH/PKl3jAZNYQtIwN7i3WZcHNzp7yfhxurLNbyRtp4xjy"
            + "rW45l3fA+hURPkWn7wIDAQAB").getBytes());

    /**
     * @see org.signserver.server.cryptotokens.IExtendedCryptoToken#decryptData(java.lang.String, byte[])
     */
    @Override
    public byte[] decryptData(String keyRef, byte[] data)
            throws CryptoTokenOfflineException {
        byte[] retval = null;
        if (keyRef.startsWith(KEYREF_AES256KEY)) {
            try {
                SecretKey key = new SecretKeySpec(AES256KEY, "AES");
                Cipher c = Cipher.getInstance("AES");
                c.init(Cipher.DECRYPT_MODE, key);
                retval = c.doFinal(data);
            } catch (Exception e) {
                log.error("Error encrypting data, " + e.getClass().getName() + " :" + e.getMessage(), e);
            }
        } else if (keyRef.startsWith(KEYREF_RSA1024KEY)) {
            try {
                PKCS8EncodedKeySpec pkKeySpec = new PKCS8EncodedKeySpec(RSA1024PRIVKEY);
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                Key key = keyFactory.generatePrivate(pkKeySpec);
                Cipher c = Cipher.getInstance("RSA");
                c.init(Cipher.DECRYPT_MODE, key);
                retval = c.doFinal(data);
            } catch (Exception e) {
                log.error("Error encrypting data, " + e.getClass().getName() + " :" + e.getMessage(), e);
            }
        } else {
            log.error("Error key reference couldn't be found");
        }
        return retval;
    }

    /**
     * @see org.signserver.server.cryptotokens.IExtendedCryptoToken#encryptData(java.lang.String, byte[])
     */
    @Override
    public byte[] encryptData(String keyRef, byte[] data)
            throws CryptoTokenOfflineException {
        byte[] retval = null;
        if (keyRef.startsWith(KEYREF_AES256KEY)) {
            try {
                SecretKey key = new SecretKeySpec(AES256KEY, "AES");
                Cipher c = Cipher.getInstance("AES");
                c.init(Cipher.ENCRYPT_MODE, key);
                retval = c.doFinal(data);
            } catch (Exception e) {
                log.error("Error encrypting data, " + e.getClass().getName() + " :" + e.getMessage(), e);
            }
        } else if (keyRef.startsWith(KEYREF_RSA1024KEY)) {
            try {
                X509EncodedKeySpec pkKeySpec = new X509EncodedKeySpec(RSA1024PUBKEY);
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                Key key = keyFactory.generatePublic(pkKeySpec);
                Cipher c = Cipher.getInstance("RSA");
                c.init(Cipher.ENCRYPT_MODE, key);
                retval = c.doFinal(data);
            } catch (Exception e) {
                log.error("Error encrypting data, " + e.getClass().getName() + " :" + e.getMessage(), e);
            }
        } else {
            log.error("Error key reference couldn't be found");
        }
        return retval;
    }

    /**
     * @see org.signserver.server.cryptotokens.IExtendedCryptoToken#genExportableKey(java.lang.String, java.lang.String)
     */
    @Override
    public Serializable genExportableKey(String keyAlg, String keySpec)
            throws IllegalRequestException, CryptoTokenOfflineException {
        Serializable retval = null;
        if (CryptoTokenUtils.isKeyAlgAssymmetric(keyAlg)) {
            try {
                retval = KeyTools.genKeys(keySpec, keyAlg);
            } catch (Exception e) {
                throw new IllegalRequestException(e.getClass().getName() + " : " + e.getMessage());
            }
        } else {
            try {
                KeyGenerator keyGen = KeyGenerator.getInstance(keyAlg);
                if (keySpec != null) {
                    keyGen.init(Integer.parseInt(keySpec));
                }
                retval = keyGen.generateKey();
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalRequestException("NoSuchAlgorithmException :" + e.getMessage());
            }
        }
        return retval;
    }

    /**
     * 
     * @param keyAlg The only supported parameters are RSA and AES returning a 1024 RSA or a 256 bit AES
     * @param keySpec not used.
     * @see org.signserver.server.cryptotokens.IExtendedCryptoToken#genNonExportableKey(java.lang.String, java.lang.String)
     */
    @Override
    public String genNonExportableKey(String keyAlg, String keySpec)
            throws IllegalRequestException, CryptoTokenOfflineException {

        Random rand = new Random();
        String randString = Integer.toHexString(rand.nextInt());

        if (keyAlg.equalsIgnoreCase("AES")) {
            return KEYREF_AES256KEY + randString;
        }

        if (keyAlg.equalsIgnoreCase("RSA")) {
            return KEYREF_RSA1024KEY + randString;
        }
        throw new IllegalRequestException("Not supported Key Algorithm given.");
    }
}
