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

import java.util.Comparator;

/**
 * Class responsible for sorting the token entries in ascending order of key
 * alias.
 *
 * @author Vinay Singh
 * @version $Id$
 */
public class TokenEntryKeyAliasOrderByASC implements Comparator<TokenEntry> {

    @Override
    public int compare(TokenEntry o1, TokenEntry o2) {
        return o1.getAlias().compareTo(o2.getAlias());
    }

}
