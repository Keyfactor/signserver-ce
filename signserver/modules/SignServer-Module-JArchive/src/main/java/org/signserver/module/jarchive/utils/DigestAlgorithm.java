/**
 * Copyright 2014 Florent Daigniere
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// This is copied from JSign to avoid having a dependency for just this enum

package org.signserver.module.jarchive.utils;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.tsp.TSPAlgorithms;

/**
 * Digest algorithm.
 * 
* @author Florent Daigniere
* @since 1.3
*/
public enum DigestAlgorithm {
    MD5("MD5", TSPAlgorithms.MD5),
    SHA1("SHA-1", TSPAlgorithms.SHA1),
    SHA256("SHA-256", TSPAlgorithms.SHA256),
    SHA384("SHA-384", TSPAlgorithms.SHA384),
    SHA512("SHA-512", TSPAlgorithms.SHA512);

    /** The JCE name of the algorithm */
    public final String id;

    /** The object identifier of the algorithm */
    public final ASN1ObjectIdentifier oid;

    DigestAlgorithm(String id, ASN1ObjectIdentifier oid) {
        this.id = id;
        this.oid = oid;
    }

    /**
     * Parse the specified value and returns the corresponding digest algorithm.
     * This method is more permissive than {@link #valueOf(String)}, it's case
     * insensitive and ignores hyphens.
     * 
     * @param name the name of the digest algorithm
     * @return the digest algorithm, or <code>null</code> if the name specified doesn't match any supported algorithm
     */
    public static DigestAlgorithm of(String name) {
        if (name == null) {
            return null;
        }
        
        name = name.toUpperCase().replaceAll("-", "");
        for (DigestAlgorithm algorithm : values()) {
            if (algorithm.name().equals(name)) {
                return algorithm;
            }
        }
        
        if ("SHA2".equals(name)) {
            return SHA256;
        }
        
        return null;
    }

    /**
     * Return the algorithm matching the specified object identifier.
     * 
     * @param oid the ASN.1 object identifier of the algorithm
     * @return the digest algorithm, or <code>null</code> if none matches the specified oid
     */
    public static DigestAlgorithm of(ASN1ObjectIdentifier oid) {
        for (DigestAlgorithm algorithm : values()) {
            if (algorithm.oid.equals(oid)) {
                return algorithm;
            }
        }
        
        return null;
    }

    /**
     * Return a MessageDigest for this algorithm.
     * 
     * @return a MessageDigest for this algorithm
     */
    public MessageDigest getMessageDigest() {
        try {
            return MessageDigest.getInstance(id);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Return the default algorithm (currently SHA-256, SHA-1 has been deprecated since January 1st 2016).
     * 
     * @return the default algorithm ({@link #SHA256})
     * @see <a href="http://social.technet.microsoft.com/wiki/contents/articles/1760.windows-root-certificate-program-technical-requirements-version-2-0.aspx">Windows Root Certificate Program - Technical Requirements version 2.0</a>
     * @see <a href="http://blogs.technet.com/b/pki/archive/2011/02/08/common-questions-about-sha2-and-windows.aspx">Common Questions about SHA2 and Windows</a>
     */
    public static DigestAlgorithm getDefault() {
        return SHA256;
    }
}
