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
package org.signserver.validationservice.server.validcache;

import java.security.cert.Certificate;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.ejbca.util.CertTools;

import org.signserver.validationservice.common.Validation;

/**
 * Validation Cache remembering a certificate validation for a 
 * configured amount of time. It only caches certificate
 * of a given issuers.
 *
 * @author Philip Vendil 26 nov 2007
 * @version $Id$
 */
public class ValidationCache {

    private Set<String> cachedIssuersDNSet = new HashSet<String>();
    private ValidationMap validationMap = new ValidationMap();
    private TimeQueue timeQueue;

    /**
     * Constructor creating a ValidationCache
     * 
     * @param cachedIssuersDN a list of issuer DNs that should be cached.
     * @param cacheTimeMS time in milliseconds of how long it should be cached.
     */
    public ValidationCache(List<String> cachedIssuersDN, long cacheTimeMS) {
        cachedIssuersDNSet.addAll(cachedIssuersDN);
        timeQueue = new TimeQueue(validationMap, cacheTimeMS);
    }

    /**
     * Adds a validation to the cache if the issuer of the certificate
     * is one of the cachedIssuerDNs
     * 
     * @param cert certificate used as key in the cache.
     * @param validation the validation to add.
     */
    public void put(Certificate cert, Validation validation) {
        if (cachedIssuersDNSet.contains(CertTools.getIssuerDN(cert))) {
            timeQueue.pushNew(cert);
            validationMap.put(cert, validation);
        }
    }

    /**
     * Returns a Validation from the cache if it exists.
     * @param cert the certificate to look up a validation for
     * @return the validation if it exists otherwise null.
     */
    public Validation get(Certificate cert) {
        timeQueue.popOld();
        return validationMap.get(cert);
    }
}
