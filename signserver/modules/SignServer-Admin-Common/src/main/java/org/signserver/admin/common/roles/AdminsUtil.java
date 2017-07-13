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
package org.signserver.admin.common.roles;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.LinkedHashMap;
import java.util.Map;
import org.apache.log4j.Logger;
import org.signserver.common.ClientEntry;
import org.signserver.common.SignServerUtil;

/**
 * Utility methods for handling administrator rules and roles.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class AdminsUtil {
    
    /**
     * Logger for this class.
     */
    private static final Logger LOG = Logger.getLogger(AdminsUtil.class);

    public static LinkedHashMap<ClientEntry, AdminEntry> parseAdmins(String admins, String auditors, String archiveAuditors, String peerSystems) {
        final LinkedHashMap<ClientEntry, AdminEntry> entryMap
                = new LinkedHashMap<>();

        // Admins
        if (admins != null && admins.contains(";")) {
            for (String entryString : admins.split(";")) {
                final String[] parts = entryString.split(",", 2);
                try {
                    final ClientEntry client
                            = new ClientEntry(new BigInteger(parts[0], 16), parts[1]);
                    AdminEntry entry = entryMap.get(client);
                    if (entry == null) {
                        entry = new AdminEntry(client);
                        entryMap.put(client, entry);
                    }
                    entry.setAdmin(true);
                } catch (NumberFormatException e) {
                    LOG.error("Invalid serialnumber for administrator: "
                            + parts[0]);
                } catch (ArrayIndexOutOfBoundsException e) {
                    LOG.error("Invalid administrator definition: " + entryString);
                }
            }
        }

        // Auditors
        if (auditors != null && auditors.contains(";")) {
            for (String entryString : auditors.split(";")) {
                final String[] parts = entryString.split(",", 2);

                try {
                    final ClientEntry client
                            = new ClientEntry(new BigInteger(parts[0], 16), parts[1]);
                    AdminEntry entry = entryMap.get(client);
                    if (entry == null) {
                        entry = new AdminEntry(client);
                        entryMap.put(client, entry);
                    }
                    entry.setAuditor(true);
                } catch (NumberFormatException e) {
                    LOG.error("Invalid serialnumber for administrator: "
                            + parts[0]);
                } catch (ArrayIndexOutOfBoundsException e) {
                    LOG.error("Invalid administrator definition: " + entryString);
                }
            }
        }

        // Archive auditors
        if (archiveAuditors != null && archiveAuditors.contains(";")) {
            for (final String entryString : archiveAuditors.split(";")) {
                final String[] parts = entryString.split(",", 2);

                try {
                    final ClientEntry client
                            = new ClientEntry(new BigInteger(parts[0], 16), parts[1]);
                    AdminEntry entry = entryMap.get(client);
                    if (entry == null) {
                        entry = new AdminEntry(client);
                        entryMap.put(client, entry);
                    }
                    entry.setArchiveAuditor(true);
                } catch (NumberFormatException e) {
                    LOG.error("Invalid serialnumber for administrator: "
                            + parts[0]);
                } catch (ArrayIndexOutOfBoundsException e) {
                    LOG.error("Invalid administrator definition: " + entryString);
                }
            }
        }
        
        // Peer systems
        if (peerSystems != null && peerSystems.contains(";")) {
            for (final String entryString : peerSystems.split(";")) {
                final String[] parts = entryString.split(",", 2);

                try {
                    final ClientEntry client
                            = new ClientEntry(new BigInteger(parts[0], 16), parts[1]);
                    AdminEntry entry = entryMap.get(client);
                    if (entry == null) {
                        entry = new AdminEntry(client);
                        entryMap.put(client, entry);
                    }
                    entry.setPeerSystem(true);
                } catch (NumberFormatException e) {
                    LOG.error("Invalid serialnumber for administrator: "
                            + parts[0]);
                } catch (ArrayIndexOutOfBoundsException e) {
                    LOG.error("Invalid administrator definition: " + entryString);
                }
            }
        }

        return entryMap;
    }

    public static String serializeAdmins(final Map<ClientEntry, AdminEntry> entries) {
        final StringBuilder buff = new StringBuilder();
        for (AdminEntry entry : entries.values()) {
            if (entry.isAdmin()) {
                buff.append(entry.getClient().getSerialNumber().toString(16));
                buff.append(",");
                buff.append(entry.getClient().getIssuerDN());
                buff.append(";");
            }
        }
        return buff.toString();
    }

    public static String serializeAuditors(final Map<ClientEntry, AdminEntry> entries) {
        final StringBuilder buff = new StringBuilder();
        for (AdminEntry entry : entries.values()) {
            if (entry.isAuditor()) {
                buff.append(entry.getClient().getSerialNumber().toString(16));
                buff.append(",");
                buff.append(entry.getClient().getIssuerDN());
                buff.append(";");
            }
        }
        return buff.toString();
    }

    public static String serializeArchiveAuditors(final Map<ClientEntry, AdminEntry> entries) {
        final StringBuilder buff = new StringBuilder();
        for (AdminEntry entry : entries.values()) {
            if (entry.isArchiveAuditor()) {
                buff.append(entry.getClient().getSerialNumber().toString(16));
                buff.append(",");
                buff.append(entry.getClient().getIssuerDN());
                buff.append(";");
            }
        }
        return buff.toString();
    }

    public static String serializePeerSystems(final Map<ClientEntry, AdminEntry> entries) {
        final StringBuilder buff = new StringBuilder();
        for (AdminEntry entry : entries.values()) {
            if (entry.isPeerSystem()) {
                buff.append(entry.getClient().getSerialNumber().toString(16));
                buff.append(",");
                buff.append(entry.getClient().getIssuerDN());
                buff.append(";");
            }
        }
        return buff.toString();
    }

    /**
     * @return The issuer DN formatted as expected by the AdminWS
     */
    public static String getIssuerDN(X509Certificate certificate) {
        String dn = certificate.getIssuerX500Principal().getName();
        SignServerUtil.BasicX509NameTokenizer tok
                = new SignServerUtil.BasicX509NameTokenizer(dn);
        StringBuilder buf = new StringBuilder();
        while (tok.hasMoreTokens()) {
            final String token = tok.nextToken();
            buf.append(token);
            if (tok.hasMoreTokens()) {
                buf.append(", ");
            }
        }
        return buf.toString();
    }

}
