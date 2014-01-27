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

import java.util.Properties;

/**
 * Helper methods used by the CryptoTokens.
 *
 * @version $Id$
 */
public class CryptoTokenHelper {
   
    public static final String PROPERTY_NEXTCERTSIGNKEY = "NEXTCERTSIGNKEY";
    public static final String PROPERTY_ATTRIBUTESFILE = "ATTRIBUTESFILE";
    public static final String PROPERTY_SLOTLISTINDEX = "SLOTLISTINDEX";
    public static final String PROPERTY_SLOT = "SLOT";
    public static final String PROPERTY_SHAREDLIBRARY = "SHAREDLIBRARY";
    public static final String PROPERTY_PIN = "PIN";
    public static final String PROPERTY_DEFAULTKEY = "DEFAULTKEY";
    public static final String PROPERTY_AUTHCODE = "AUTHCODE";
    
    /** A workaround for the feature in SignServer 2.0 that property keys are 
     * always converted to upper case. The EJBCA CA Tokens usually use mixed case properties
     */
    public static Properties fixP11Properties(final Properties props) {
        String prop = props.getProperty(PROPERTY_AUTHCODE);
        if (prop != null) {
            props.setProperty("authCode", prop);
        }
        prop = props.getProperty(PROPERTY_DEFAULTKEY);
        if (prop != null) {
            props.setProperty("defaultKey", prop);
        }
        prop = props.getProperty(PROPERTY_PIN);
        if (prop != null) {
            props.setProperty("pin", prop);
        }
        prop = props.getProperty(PROPERTY_SHAREDLIBRARY);
        if (prop != null) {
            props.setProperty("sharedLibrary", prop);
        }
        prop = props.getProperty(PROPERTY_SLOT);
        if (prop != null) {
            props.setProperty("slot", prop);
        }
        prop = props.getProperty(PROPERTY_SLOTLISTINDEX);
        if (prop != null) {
            props.setProperty("slotListIndex", prop);
        }
        prop = props.getProperty(PROPERTY_ATTRIBUTESFILE);
        if (prop != null) {
            props.setProperty("attributesFile", prop);
        }
        prop = props.getProperty(PROPERTY_NEXTCERTSIGNKEY);
        if (prop != null) {
            props.setProperty("nextCertSignKey", prop);
        }
        return props;
    }
}
