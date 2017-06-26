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
import org.apache.log4j.Logger;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.RequestContext;
import org.signserver.common.data.Request;
import org.signserver.common.data.Response;
import org.signserver.ejb.interfaces.GlobalConfigurationSessionLocal;

/**
 * Sample accounter for demonstration purposes only which holds accounts in
 * the global configuration.
 * <p>
 *    The accounter has two global configuration properties:
 * </p>
 * <ul>
 *    <li>
 *        <b>GLOBALCONFIGSAMPLEACCOUNTER_USERS</b> = Mapping from credential to
 *           account number (Required).<br/>
 *           Ex: user1,password:account1; user2,password2:account2
 *    </li>
 *    <li><b>GLOBALCONFIGSAMPLEACCOUNTER_ACCOUNTS</b> = Map from account
 *           number to balance (Required)<br/>
 *          Ex: account1:14375; account2:12         
 *    </li>
 * </ul>
 * <p>
 *    Note: This accounter is not safe for use in production as concurrent
 *    requests can overwrite the balance. Instead an accounter using a real
 *    database should be used.
 * </p>
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class GlobalConfigSampleAccounter implements IAccounter {

    /** Logger for this class. */
    private static final Logger LOG
            = Logger.getLogger(GlobalConfigSampleAccounter.class);

    // Global configuration properties
    public static final String GLOBALCONFIGSAMPLEACCOUNTER_ACCOUNTS
            = "GLOBALCONFIGSAMPLEACCOUNTER_ACCOUNTS";
    public static final String GLOBALCONFIGSAMPLEACCOUNTER_USERS
            = "GLOBALCONFIGSAMPLEACCOUNTER_USERS";

    private GlobalConfigurationSessionLocal gCSession;

    @Override
    public void init(final Properties props) {
        // This accounter does not use any worker properties
    }

    @Override
    public boolean purchase(final IClientCredential credential,
            final Request request, final Response response,
            final RequestContext context) throws AccounterException {

        if (LOG.isDebugEnabled()) {
            LOG.debug("purchase called for "
                + (String) context.get(RequestContext.TRANSACTION_ID));
        }

        // Read global configuration values
        final GlobalConfiguration config =
                getGlobalConfigurationSession(context).getGlobalConfiguration();
        final String usersMapping =
                config.getProperty(GlobalConfiguration.SCOPE_GLOBAL,
                GLOBALCONFIGSAMPLEACCOUNTER_USERS);
        final String accountsMapping =
                config.getProperty(GlobalConfiguration.SCOPE_GLOBAL,
                GLOBALCONFIGSAMPLEACCOUNTER_ACCOUNTS);

        // Parse users "table"
        final Map<String, String> usersTable =
                parseCredentialMapping(usersMapping);

        // Parse accounts "table"
        final Map<String, Integer> accountsTable =
                parseAccountMapping(accountsMapping);

        // Get username (or certificate serial number) from request
        final String key;
        if (credential instanceof CertificateClientCredential) {
            final CertificateClientCredential certCred =
                    (CertificateClientCredential) credential;

            key = certCred.getSerialNumber() + "," + certCred.getIssuerDN();
        } else if (credential instanceof UsernamePasswordClientCredential) {
            final UsernamePasswordClientCredential passCred =
                    (UsernamePasswordClientCredential) credential;

            key = passCred.getUsername() + "," + passCred.getPassword();
        } else if (credential == null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("No credential");
            }
            key = null;

        } else {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Unknown credential type: "
                    + credential.getClass().getName());
            }
            key = null;
        }

        // Get account
        final String accountNo = usersTable.get(key);

        // No account for user given the credential supplied
        if (accountNo == null) {
            return false;
        }

        // Get current balance
        Integer balance = accountsTable.get(accountNo);

        // No account
        if (balance == null) {
            return false;
        }

        // Purchase
        balance -= 1;
        accountsTable.put(accountNo, balance);

        // No funds
        if (balance  < 0) {
            // Purchase not granted
            return false;
        }

        // Store the new balance
        getGlobalConfigurationSession(context).setProperty(
                GlobalConfiguration.SCOPE_GLOBAL,
                GLOBALCONFIGSAMPLEACCOUNTER_ACCOUNTS,
                storeAccountMapping(accountsTable));

        // Purchase granted
        return true;
    }

    private GlobalConfigurationSessionLocal getGlobalConfigurationSession(RequestContext context) {
        return context.getServices().get(GlobalConfigurationSessionLocal.class);
    }

    private Map<String, String> parseCredentialMapping(String mapping) {
        if (mapping == null) {
            return Collections.emptyMap();
        }
        final String[] entries = mapping.split(";");
        final Map<String, String> result = new HashMap<>();
        for (String entry : entries) {
            final String[] keyvalue = entry.trim().split(":");
            if (keyvalue.length == 2) {
                result.put(keyvalue[0].trim(), keyvalue[1].trim());
            }
        }
        if (LOG.isDebugEnabled()) {
            final StringBuilder str = new StringBuilder();
            str.append("Credential mapping: ");
            str.append("\n");
            for (Map.Entry<String, String> entry : result.entrySet()) {
                str.append("\"");
                str.append(entry.getKey());
                str.append("\"");
                str.append(" --> ");
                str.append("\"");
                str.append(entry.getValue());
                str.append("\"");
                str.append("\n");
            }
            LOG.debug(str.toString());
        }
        return result;
    }

    private Map<String, Integer> parseAccountMapping(String mapping) {
        if (mapping == null) {
            return Collections.emptyMap();
        }
        final String[] entries = mapping.split(";");
        final Map<String, Integer> result = new HashMap<>();
        for (String entry : entries) {
            final String[] keyvalue = entry.trim().split(":");
            if (keyvalue.length == 2) {
                result.put(keyvalue[0].trim(),
                        Integer.parseInt(keyvalue[1].trim()));
            }
        }
        if (LOG.isDebugEnabled()) {
            final StringBuilder str = new StringBuilder();
            str.append("Accounts: ");
            str.append("\n");
            for (Map.Entry<String, Integer> entry : result.entrySet()) {
                str.append("\"");
                str.append(entry.getKey());
                str.append("\"");
                str.append(" --> ");
                str.append(entry.getValue());
                str.append("\n");
            }
            LOG.debug(str.toString());
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
