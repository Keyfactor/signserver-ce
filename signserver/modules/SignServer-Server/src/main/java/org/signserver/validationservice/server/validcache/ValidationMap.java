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
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.signserver.validationservice.common.Validation;

/**
 * 
 * Validation Map containing the Certificate -> validation mappings.
 *
 * @author Philip Vendil 26 nov 2007
 * @version $Id$
 */
class ValidationMap {

    Map<Certificate, Validation> validationMap = Collections.synchronizedMap(new HashMap<Certificate, Validation>());

    /**
     * Adds a entry to the map.
     * @param cert key 
     * @param validation validation
     */
    void put(Certificate cert, Validation validation) {
        validationMap.put(cert, validation);
    }

    /**
     * Returning the validation from the map if it still exists there.
     * @param cert the certificate to search a validation for
     * @return the validation of null if it doesn't exists in map.
     */
    Validation get(Certificate cert) {
        return validationMap.get(cert);
    }

    /**
     * Removing and entry from the cache.
     * 
     * @param cert key that should be removed from the cache.
     */
    void remove(Certificate cert) {
        validationMap.remove(cert);
    }
}
