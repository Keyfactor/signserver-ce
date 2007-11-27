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

import java.security.Provider;
import java.security.Security;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import org.signserver.common.IllegalRequestException;

/**
 * Class containing help methods that could be used when implementing
 * a cryptotoken
 * 
 * 
 * @author Philip Vendil 21 nov 2007
 *
 * @version $Id: CryptoTokenUtils.java,v 1.1 2007-11-27 06:05:08 herrvendil Exp $
 */

public class CryptoTokenUtils {

	/**
	 * Checks all installed key generator algorithms if the given one exists
	 * and if it is a symmetric key or asymmetric.
	 * @param keyAlg the key algorithm to check
	 * @return true if the algorithm is asymmetric
	 * @throws IllegalRequestException if the given algorithm cannot be found as 
	 * either symmetric or asymmetric
	 */
	public static boolean isKeyAlgAssymmetric(String keyAlg) throws IllegalRequestException{
		   String[] names = getCryptoImpls("KeyPairGenerator");	
			for (int i = 0; i < names.length; i++) {
				if(names[i].equalsIgnoreCase(keyAlg)){
					return true;
				}
			}
			names = getCryptoImpls("KeyGenerator");	
			for (int i = 0; i < names.length; i++) {
				if(names[i].equalsIgnoreCase(keyAlg)){
					return false;
				}
			}
			
			throw new IllegalRequestException("Error given key algorithm " + keyAlg + " isn't supported by the system. " +
					"Are you sure the providers are installed correctly.");
	}
	
	
	/**
	 * Method for listening different crypto implementations supported
	 * by the different installed providers.
	 */
    public static String[] getCryptoImpls(String serviceType) {
        Set<String> result = new HashSet<String>();
    
        // All all providers
        Provider[] providers = Security.getProviders();
        for (int i=0; i<providers.length; i++) {
            // Get services provided by each provider
            Set<?> keys = providers[i].keySet();
            for (Iterator<?> it=keys.iterator(); it.hasNext(); ) {
                String key = (String)it.next();
                key = key.split(" ")[0];
    
                if (key.startsWith(serviceType+".")) {
                    result.add(key.substring(serviceType.length()+1));
                } else if (key.startsWith("Alg.Alias."+serviceType+".")) {
                    // This is an alias
                    result.add(key.substring(serviceType.length()+11));
                }
            }
        }
        return (String[])result.toArray(new String[result.size()]);
    }
	
}
