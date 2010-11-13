package org.signserver.server;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import javax.ejb.EJBException;
import org.apache.log4j.Logger;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.RequestContext;
import org.signserver.common.ServiceLocator;
import org.signserver.ejb.interfaces.IGlobalConfigurationSession;

/**
 * Sample TimeStampSignerLookup'er reading the lookup-table from the global-
 * configuration store.
 *
 * This is only working for a limited number of users and is only here as an
 * example. A real implementation should use some kind of database.
 *
 * The global property TIMESTAMPSIGNERMAPPING is of the form:
 * UNIQUE_USER_KEY1:WORKERNAMEORID1; UNIQUE_USER_KEY1:WORKERNAMEORID1;
 * and so on.
 * UNIQUE_USER_KEY1 for a cert authorized client is SERIALNUMBER,ISSUERDN
 * UNIQUE_USER_KEY1 for a passowrd authorized client is USERNAME,PASSWORD
 *
 * user1,password:TimeStampSigner_policy1; certserialno,issuerdn:TimeStampSigner_policy1;
 *
 * for an entry that should map from a particular oid add the oid after the user:
 * user1,password,1.2.1:TimeStampSigner_policy1;
 *
 * @author markus
 * @version $Id$
 */
public class GlobalConfigMappedTimeStampSignerLookup implements ITimeStampSignerLookup {

    private static final Logger LOG = 
            Logger.getLogger(GlobalConfigMappedTimeStampSignerLookup.class);

    private IGlobalConfigurationSession.ILocal gCSession;

    public String lookupClientAuthorizedWorker(IClientCredential credential, RequestContext context) {
        if (LOG.isDebugEnabled()) {
            LOG.debug(">lockupClientAuthorizedWorker");
        }
        try {
            final GlobalConfiguration config = getGlobalConfigurationSession().getGlobalConfiguration();
            final String mapping =
                    config.getProperty(GlobalConfiguration.SCOPE_GLOBAL,
                    "TIMESTAMPSIGNERMAPPING");

            final Map<String, String> lookupTable = parseMapping(mapping);
            
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

            if (key != null && context.get(
                    ITimeStampSignerLookup.TSA_REQUESTEDPOLICYOID) != null) {
                key += "," + context.get(ITimeStampSignerLookup.TSA_REQUESTEDPOLICYOID);
            }

            final String worker = lookupTable.get(key);

            if (LOG.isDebugEnabled()) {
                LOG.debug("Request key: " + key + ", Will return worker: " + worker);
            }

            return worker;
        } catch (Exception ex) {
            throw new EJBException("Looking up worker failed", ex);
        }
    }

    private IGlobalConfigurationSession.ILocal getGlobalConfigurationSession() throws Exception {
        if (gCSession == null) {
            gCSession = ServiceLocator.getInstance().lookupRemote(
                        IGlobalConfigurationSession.ILocal.class);
        }
        return gCSession;
    }

    private Map<String, String> parseMapping(String mapping) {
        
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
        if (LOG.isDebugEnabled()) {
            final StringBuilder str = new StringBuilder();
            str.append("Authorization mapping: ");
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
}
