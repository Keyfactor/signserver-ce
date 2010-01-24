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
package org.signserver.server;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import javax.naming.Context;
import javax.naming.InitialContext;
import org.apache.log4j.Logger;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.ProcessRequest;
import org.signserver.common.ProcessResponse;
import org.signserver.common.RequestContext;
import org.signserver.ejb.interfaces.IGlobalConfigurationSession;

/**
 * Sample accounter for demonstration purpuses only which holds accounts in
 * the global configuration.
 *
 * Two properties are used in the global configuration:
 *
 * GLOBALCONFIGSAMPLEACCOUNTER_USERS = Mapping from credential to accountno
 * Ex: user1,password:account1; user2,password2:account2
 *
 * GLOBALCONFIGSAMPLEACCOUNTER_ACCOUNTS = Map from accountno to saldo
 * Ex: account1:14375; account2:12
 *
 *
 * @author markus
 */
public class GlobalConfigSampleAccounter implements IAccounter {

    private static final Logger LOG =
            Logger.getLogger(GlobalConfigSampleAccounter.class);

    public static final String GLOBALCONFIGSAMPLEACCOUNTER_ACCOUNTS =
            "GLOBALCONFIGSAMPLEACCOUNTER_ACCOUNTS";
    public static final String GLOBALCONFIGSAMPLEACCOUNTER_USERS =
            "GLOBALCONFIGSAMPLEACCOUNTER_USERS";
    

    private IGlobalConfigurationSession.ILocal gCSession;

    public void init(final Properties props) {
        LOG.debug("init");
    }

    public boolean purchase(final IClientCredential credential,
            final ProcessRequest request, final ProcessResponse response,
            final RequestContext context) throws AccounterException {

        if (LOG.isDebugEnabled()) {
            LOG.debug("purchase called for "
                + (String) context.get(RequestContext.TRANSACTION_ID));
        }

        try {
            final GlobalConfiguration config =
                    getGlobalConfigurationSession().getGlobalConfiguration();
            final String usersMapping =
                    config.getProperty(GlobalConfiguration.SCOPE_GLOBAL,
                    GLOBALCONFIGSAMPLEACCOUNTER_USERS);
            final String accountsMapping =
                    config.getProperty(GlobalConfiguration.SCOPE_GLOBAL,
                    GLOBALCONFIGSAMPLEACCOUNTER_ACCOUNTS);

            final Map<String, String> usersTable =
                    parseCredentialMapping(usersMapping);

            final Map<String, Integer> accountsTable =
                    parseAccountMapping(accountsMapping);

            String key;
            if (credential instanceof CertificateClientCredential) {
                final CertificateClientCredential certCred =
                        (CertificateClientCredential) credential;

                key = certCred.getSerialNumber() + "," + certCred.getIssuerDN();
            } else if (credential instanceof UsernamePasswordClientCredential) {
                final UsernamePasswordClientCredential passCred =
                        (UsernamePasswordClientCredential) credential;

                key = passCred.getUsername() + ","
                        + passCred.getPassword();
            } else if (credential == null) {
                LOG.debug("Null credential");
                key = null;

            } else {
                LOG.debug("Unknown credential type: "
                        + credential.getClass().getName());
                key = null;
            }

            String accountNo = usersTable.get(key);

            // No account for user given the credential supplied
            if (accountNo == null) {
                return false;
            }

            Integer saldo = accountsTable.get(accountNo);

            // No account
            if (saldo == null) {
                return false;
            }

            // Purchase
            saldo -= 1;
            accountsTable.put(accountNo, saldo);

            // No funds
            if (saldo  < 0) {
                return false;
            }

            getGlobalConfigurationSession().setProperty(
                    GlobalConfiguration.SCOPE_GLOBAL,
                    GLOBALCONFIGSAMPLEACCOUNTER_ACCOUNTS,
                    storeAccountMapping(accountsTable));

            return true;

        } catch (Exception ex) {
            throw new AccounterException("Accounting error", ex);
        }
    }

     private IGlobalConfigurationSession.ILocal getGlobalConfigurationSession() throws Exception {
        if (gCSession == null) {
            final Context context = new InitialContext();
            gCSession = (IGlobalConfigurationSession.ILocal)
                    context.lookup(IGlobalConfigurationSession.ILocal.JNDI_NAME);
        }
        return gCSession;
    }

    private Map<String, String> parseCredentialMapping(String mapping) {
        if (mapping == null) {
            return Collections.emptyMap();
        }
        final String[] entries = mapping.split(";");
        final Map<String, String> result = new HashMap<String, String>();
        for (String entry : entries) {
            final String[] keyvalue = entry.trim().split(":");
            if (keyvalue.length == 2) {
                result.put(keyvalue[0].trim(), keyvalue[1].trim());
            }
        }
        return result;
    }

    private Map<String, Integer> parseAccountMapping(String mapping) {
        if (mapping == null) {
            return Collections.emptyMap();
        }
        final String[] entries = mapping.split(";");
        final Map<String, Integer> result = new HashMap<String, Integer>();
        for (String entry : entries) {
            final String[] keyvalue = entry.trim().split(":");
            if (keyvalue.length == 2) {
                result.put(keyvalue[0].trim(), Integer.parseInt(keyvalue[1].trim()));
            }
        }
        return result;
    }

    private String storeAccountMapping(Map<String, Integer> mapping) {
        if (mapping == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, Integer> entry : mapping.entrySet()) {
            sb.append(entry.getKey());
            sb.append(":");
            sb.append(entry.getValue());
            sb.append(";");
        }
        return sb.toString();
    }
    
}
