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
package org.signserver.cli;

import java.util.LinkedList;
import java.util.List;
import javax.ejb.EJBException;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.ParseException;
import org.apache.commons.cli.GnuParser;
import org.apache.commons.cli.Options;
import org.signserver.common.GlobalConfiguration;

/**
 * Command for managing the list of authorized WS admins.
 *
 * @version $Id$
 */
public class WSAdminsCommand extends BaseCommand {

    public static final String ADD = "add";
    public static final String REMOVE = "remove";
    public static final String LIST = "list";
    public static final String CERTSERIALNO = "certserialno";
    public static final String ISSUERDN = "issuerdn";
    
    /** The command line options. */
    private static final Options OPTIONS;
    
    private static final String USAGE =
            "Usage: signserver wsadmins -add -certserialno <certificate serial number> -issuerdn <issuer DN>\n"
            + "Usage: signserver wsadmins -remove -certserialno <certificate serial number> -issuerdn <issuer DN>\n"
            + "Usage: signserver wsadmins -list\n"
            + "Example 1: signserver wsadmins -add -certserialno 0123ABCDEF -issuerdn \"CN=Neo Morpheus, C=SE\"\n"
            + "Example 2: signserver wsadmins -remove -certserialno 0123ABCDEF -issuerdn \"CN=Neo Morpheus, C=SE\"\n"
            + "Example 3: signserver wsadmins -list";

    static {
        OPTIONS = new Options();
        OPTIONS.addOption(ADD, false, "Add a new WS admin");
        OPTIONS.addOption(REMOVE, false, "Remove a WS admin");
        OPTIONS.addOption(LIST, false, "List all WS admins");

        OPTIONS.addOption(CERTSERIALNO, true,
                "Subject certificate serial number");
        OPTIONS.addOption(ISSUERDN, true,
                "Issuer distinguished name");
    }
    
    private String operation;
    private String certSerialNo;
    private String issuerDN;

    /**
     * Creates a new instance of GenerateKeyCommand.
     * @param args command line arguments
     */
    public WSAdminsCommand(String[] args) {
        super(args);
        try {
            // Parse the command line
            parseCommandLine(new GnuParser().parse(OPTIONS, args));
        } catch (ParseException ex) {
            throw new IllegalArgumentException(ex.getLocalizedMessage(), ex);
        }
        validateOptions();
    }

    /**
     * Reads all the options from the command line.
     *
     * @param line The command line to read from
     */
    private void parseCommandLine(final CommandLine line) {
        certSerialNo = line.getOptionValue(CERTSERIALNO, null);
        issuerDN = line.getOptionValue(ISSUERDN, null);
        if (line.hasOption(ADD)) {
            operation = ADD;
        } else if (line.hasOption(REMOVE)) {
            operation = REMOVE;
        } else if (line.hasOption(LIST)) {
            operation = LIST;
        }
    }

    /**
     * Checks that all mandatory options are given.
     */
    private void validateOptions() {
        if (operation == null) {
            System.err.println("Missing operation: -add, -remove or -list");
            System.err.println(USAGE);
            System.exit(1);
        } else if (!operation.equals(LIST)) {
            if (certSerialNo == null) {
                System.err.println("Missing option: -certserialno");
                System.err.println(USAGE);
                System.exit(1);
            } else if (issuerDN == null) {
                System.err.println("Missing option: -issuerdn");
                System.err.println(USAGE);
                System.exit(1);
            }
        }
    }

    /**
     * Runs the command
     *
     * @param hostname
     * @throws IllegalAdminCommandException Error in command args
     * @throws ErrorAdminCommandException Error running command
     */
    public void execute(String hostname) throws IllegalAdminCommandException,
            ErrorAdminCommandException {

        try {
            final String admins = getCommonAdminInterface(hostname).getGlobalConfiguration().getProperty(
                    GlobalConfiguration.SCOPE_GLOBAL, "WSADMINS");
            final List<Entry> entries = parseAdmins(admins);

            if (LIST.equals(operation)) {
                final StringBuilder buff = new StringBuilder();
                buff.append("Authorized administrators:");
                buff.append("\n");
                for (Entry entry : entries) {
                    buff.append(String.format("%-20s %s",
                            entry.getCertSerialNo(), entry.getIssuerDN()));
                    buff.append("\n");
                }
                System.out.println(buff.toString());
            } else if (ADD.equals(operation)) {
                final String newAdmins =
                        admins + ";" + certSerialNo + "," + issuerDN;

                entries.add(new Entry(certSerialNo, issuerDN));
                getCommonAdminInterface(hostname).setGlobalProperty(
                        GlobalConfiguration.SCOPE_GLOBAL, "WSADMINS",
                        serializeAdmins(entries));
                System.out.println("Administrator added");
            } else if (REMOVE.equals(operation)) {
                if (entries.remove(new Entry(certSerialNo, issuerDN))) {
                    getCommonAdminInterface(hostname).setGlobalProperty(
                            GlobalConfiguration.SCOPE_GLOBAL, "WSADMINS",
                            serializeAdmins(entries));
                    System.out.println("Administrator removed");
                } else {
                    System.err.println("No such administrator");
                }
            }
        } catch (IllegalAdminCommandException e) {
            throw e;
        } catch (EJBException eJBException) {
            if (eJBException.getCausedByException() instanceof IllegalArgumentException) {
                System.err.println(eJBException.getMessage());
            } else {
                throw new ErrorAdminCommandException(eJBException);
            }
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }

    private static List<Entry> parseAdmins(final String admins) {
        final List<Entry> entries = new LinkedList<Entry>();
        if (admins != null && admins.contains(";")) {
            for (String entry : admins.split(";")) {
                final String[] parts = entry.split(",", 2);
                entries.add(new Entry(parts[0], parts[1]));
            }
        }
        return entries;
    }

    private static String serializeAdmins(final List<Entry> entries) {
        final StringBuilder buff = new StringBuilder();
        for (Entry entry : entries) {
            buff.append(entry.getCertSerialNo());
            buff.append(",");
            buff.append(entry.getIssuerDN());
            buff.append(";");
        }
        return buff.toString();
    }

    public int getCommandType() {
        return TYPE_EXECUTEONALLNODES;
    }

    private static class Entry {

        private String certSerialNo;
        private String issuerDN;

        public Entry(String certSerialNo, String issuerDN) {
            this.certSerialNo = certSerialNo;
            this.issuerDN = issuerDN;
        }

        public String getCertSerialNo() {
            return certSerialNo;
        }

        public String getIssuerDN() {
            return issuerDN;
        }

        @Override
        public boolean equals(Object obj) {
            if (obj == null) {
                return false;
            }
            if (getClass() != obj.getClass()) {
                return false;
            }
            final Entry other = (Entry) obj;
            if ((this.certSerialNo == null) ? (other.certSerialNo != null) : !this.certSerialNo.equals(other.certSerialNo)) {
                return false;
            }
            if ((this.issuerDN == null) ? (other.issuerDN != null) : !this.issuerDN.equals(other.issuerDN)) {
                return false;
            }
            return true;
        }

        @Override
        public int hashCode() {
            int hash = 7;
            hash = 89 * hash + (this.certSerialNo != null ? this.certSerialNo.hashCode() : 0);
            hash = 89 * hash + (this.issuerDN != null ? this.issuerDN.hashCode() : 0);
            return hash;
        }
    }
}
