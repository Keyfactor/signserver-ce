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
package org.signserver.admin.cli.defaultimpl;

import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;
import javax.ejb.EJBException;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.GnuParser;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.signserver.cli.spi.CommandFailureException;
import org.signserver.cli.spi.IllegalCommandArgumentsException;
import org.signserver.cli.spi.UnexpectedCommandFailureException;
import org.signserver.common.GlobalConfiguration;

/**
 * Command for managing the list of authorized WS admins.
 *
 * @version $Id$
 */
public class WSAdminsCommand extends AbstractAdminCommand {

    public static final String ADD = "add";
    public static final String REMOVE = "remove";
    public static final String LIST = "list";
    public static final String CERTSERIALNO = "certserialno";
    public static final String ISSUERDN = "issuerdn";
    public static final String CERT = "cert";
    
    /** The command line options. */
    private static final Options OPTIONS;
    
    private static final String USAGE =
            "Usage: signserver wsadmins -add -certserialno <certificate serial number> -issuerdn <issuer DN>\n"
    		+ "Usage: signserver wsadmins -add -cert <PEM or DER file>\n"
            + "Usage: signserver wsadmins -remove -certserialno <certificate serial number> -issuerdn <issuer DN>\n"
            + "Usage: signserver wsadmins -list\n"
            + "Example 1: signserver wsadmins -add -certserialno 0123ABCDEF -issuerdn \"CN=Neo Morpheus, C=SE\"\n"
            + "Example 2: signserver wsadmins -add -cert wsadmin.pem\n"
            + "Example 3: signserver wsadmins -remove -certserialno 0123ABCDEF -issuerdn \"CN=Neo Morpheus, C=SE\"\n"
            + "Example 4: signserver wsadmins -list";

    static {
        OPTIONS = new Options();
        OPTIONS.addOption(ADD, false, "Add a new WS admin");
        OPTIONS.addOption(REMOVE, false, "Remove a WS admin");
        OPTIONS.addOption(LIST, false, "List all WS admins");

        OPTIONS.addOption(CERTSERIALNO, true,
                "Subject certificate serial number");
        OPTIONS.addOption(ISSUERDN, true,
                "Issuer distinguished name");
        OPTIONS.addOption(CERT, true, "Certificate file");
    }
    
    private String operation;
    private String certSerialNo;
    private String issuerDN;
    private String cert;

    @Override
    public String getDescription() {
        return "Manages authorizations for WS administrators";
    }

    @Override
    public String getUsages() {
        return USAGE;
    }

    /**
     * Reads all the options from the command line.
     *
     * @param line The command line to read from
     */
    private void parseCommandLine(final CommandLine line) {
        certSerialNo = line.getOptionValue(CERTSERIALNO, null);
        issuerDN = line.getOptionValue(ISSUERDN, null);
        cert = line.getOptionValue(CERT, null);
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
    private void validateOptions() throws IllegalCommandArgumentsException {
        if (operation == null) {
            throw new IllegalCommandArgumentsException("Missing operation: -add, -remove or -list");
        } else if (!operation.equals(LIST)) {
        	if (cert != null) {
        		// don't allow -cert option in combination with -certserialno and -issuerdn
        		if (certSerialNo != null || issuerDN != null) {
                            throw new IllegalCommandArgumentsException("Can't use the option -cert at the same time as -certserialno and -issuerdn");
        		}
        	} else {
        		if (certSerialNo == null) {
        			throw new IllegalCommandArgumentsException("Missing option: -certserialno");
        		} else if (issuerDN == null) {
        			throw new IllegalCommandArgumentsException("Missing option: -issuerdn");
        		}
        	}
        }
    }

    @Override
    public int execute(String... args) throws IllegalCommandArgumentsException, CommandFailureException, UnexpectedCommandFailureException {
        try {
            // Parse the command line
            parseCommandLine(new GnuParser().parse(OPTIONS, args));
        } catch (ParseException ex) {
            throw new IllegalCommandArgumentsException(ex.getMessage());
        }
        validateOptions();
        
        try {
            final String admins = getGlobalConfigurationSession().getGlobalConfiguration().getProperty(
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
                getOutputStream().println(buff.toString());
            } else if (ADD.equals(operation)) {
            	if (cert == null) {
            		// serial number and issuer DN was entered manually
            		entries.add(new Entry(certSerialNo, issuerDN));
            	} else {
            		// read serial number and issuer DN from cert file
            		X509Certificate certificate = getCertFromFile(cert);
            		String sn = certificate.getSerialNumber().toString(16);
            		String dn = certificate.getIssuerDN().getName();
            		entries.add(new Entry(sn, dn));
            	}
                getGlobalConfigurationSession().setProperty(
                        GlobalConfiguration.SCOPE_GLOBAL, "WSADMINS",
                        serializeAdmins(entries));
                getOutputStream().println("Administrator added");
            } else if (REMOVE.equals(operation)) {
                if (entries.remove(new Entry(certSerialNo, issuerDN))) {
                    getGlobalConfigurationSession().setProperty(
                            GlobalConfiguration.SCOPE_GLOBAL, "WSADMINS",
                            serializeAdmins(entries));
                    getOutputStream().println("Administrator removed");
                } else {
                    getErrorStream().println("No such administrator");
                }
            }
            return 0;
        } catch (EJBException eJBException) {
            if (eJBException.getCausedByException() instanceof IllegalArgumentException) {
                getErrorStream().println(eJBException.getMessage());
                return -2;
            } else {
                throw new UnexpectedCommandFailureException(eJBException);
            }
        } catch (Exception e) {
            throw new UnexpectedCommandFailureException(e);
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
