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
package org.signserver.server.aliasselectors;

import junit.framework.TestCase;
import org.signserver.common.RequestContext;
import org.signserver.common.WorkerConfig;
import org.signserver.server.UsernamePasswordClientCredential;
import org.signserver.server.cryptotokens.ICryptoToken;

/**
 * Unit tests for the username alias selector.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public class AuthorizedUsernameAliasSelectorUnitTest extends TestCase {
    
    /**
     * Test that getting alias with an authorized username in the request
     * works as expected using a default (not set) prefix.
     * 
     * @throws Exception 
     */
    public void testGetAliasWithUsername() throws Exception {
       final AliasSelector selector = new AuthorizedUsernameAliasSelector();
       final RequestContext context = new RequestContext();
       
       context.put(RequestContext.CLIENT_CREDENTIAL,
               new UsernamePasswordClientCredential("user4711", "secret"));
       selector.init(4711, new WorkerConfig(), null, null);
       
       assertEquals("Alias", "user4711",
               selector.getAlias(ICryptoToken.PURPOSE_SIGN, null, null, context));
    }
    
    /**
     * Test getting alias with a alias prefix set.
     * 
     * @throws Exception 
     */
    public void testGetAliasWithUsernameAndPrefix() throws Exception {
       final WorkerConfig config = new WorkerConfig();
       final AliasSelector selector = new AuthorizedUsernameAliasSelector();
       final RequestContext context = new RequestContext();
       
       config.setProperty(AuthorizedUsernameAliasSelector.PROPERTY_ALIAS_PREFIX,
                          "key_");
       context.put(RequestContext.CLIENT_CREDENTIAL,
               new UsernamePasswordClientCredential("user4711", "secret"));
       selector.init(4711, config, null, null);
       
       assertEquals("Alias", "key_user4711",
               selector.getAlias(ICryptoToken.PURPOSE_SIGN, null, null, context));
    }
    
    /**
     * Test that when no username is set in the request, null is returned.
     * 
     * @throws Exception 
     */
    public void testGetAliasWithNoUsername() throws Exception {
       final AliasSelector selector = new AuthorizedUsernameAliasSelector();
       final RequestContext context = new RequestContext();

       selector.init(4711, new WorkerConfig(), null, null);
       
       assertNull("Alias", selector.getAlias(ICryptoToken.PURPOSE_SIGN,
                                             null, null, context));
    }
    
    /**
     * Test setting an unknown object as CLIENT_CREDENTIAL in the request.
     * getAlias() should return null in this case.
     * 
     * @throws Exception 
     */
    public void testGetAliasWithStrangeRequest() throws Exception {
        final WorkerConfig config = new WorkerConfig();
        final AliasSelector selector = new AuthorizedUsernameAliasSelector();
        final RequestContext context = new RequestContext();

        config.setProperty(AuthorizedUsernameAliasSelector.PROPERTY_ALIAS_PREFIX,
                           "key_");
        context.put(RequestContext.CLIENT_CREDENTIAL, "strange value");
        selector.init(4711, config, null, null);

        assertNull("Alias should be null",
                selector.getAlias(ICryptoToken.PURPOSE_SIGN, null, null, context));
    }
    
    /**
     * Test that when no key prefix has been set, the alias returned equals
     * the user name in the request.
     * 
     * @throws Exception 
     */
    public void testGetAliasNoPrefix() throws Exception {
        final WorkerConfig config = new WorkerConfig();
        final AliasSelector selector = new AuthorizedUsernameAliasSelector();
        final RequestContext context = new RequestContext();
       
        context.put(RequestContext.CLIENT_CREDENTIAL,
            new UsernamePasswordClientCredential("user4711", "secret"));
        selector.init(4711, config, null, null);
       
        assertEquals("Alias", "user4711",
               selector.getAlias(ICryptoToken.PURPOSE_SIGN, null, null, context));
    }
}
