/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package org.signserver.server;

import org.signserver.common.SignServerException;
import org.signserver.server.cryptotokens.ICryptoToken;

/**
 *
 * @author markus
 */
public interface CryptoTokenSupplier {
    ICryptoToken getCurrentCryptoToken() throws SignServerException;
}
