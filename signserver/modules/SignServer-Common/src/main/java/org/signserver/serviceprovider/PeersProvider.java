/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.signserver.serviceprovider;

import java.util.List;
import org.cesecore.authentication.tokens.AuthenticationToken;

/**
 *
 * @author Marcus Lundblad
 * @version $Id$
 */
public interface PeersProvider {
    List<PeersInInfo> createPeersIncoming();
    void remove(Integer id, AuthenticationToken authenticationToken);
}
