/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.ejbca.peerconnector;

import javax.ejb.Remote;

/**
 * SSB for performing long running background tasks under JEE5.
 * 
 * @version $Id$
 */
@Remote
public interface BackgroundTaskSessionRemote extends BackgroundTaskSession {

}
