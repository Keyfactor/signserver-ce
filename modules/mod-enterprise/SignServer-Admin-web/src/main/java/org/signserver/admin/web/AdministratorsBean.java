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
package org.signserver.admin.web;

import org.signserver.admin.web.ejb.NotLoggedInException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import javax.ejb.EJB;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ManagedProperty;
import javax.faces.bean.ViewScoped;
import org.apache.log4j.Logger;
import org.cesecore.util.CertTools;
import org.signserver.common.ClientEntry;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.SignServerUtil;
import org.signserver.admin.web.ejb.AdminNotAuthorizedException;
import org.signserver.admin.web.ejb.AdminWebSessionBean;

/**
 *
 * @author Markus Kilås
 * @version $Id$
 */
@ManagedBean
@ViewScoped
public class AdministratorsBean {

    /**
     * Logger for this class.
     */
    private static final Logger LOG = Logger.getLogger(AdministratorsBean.class);

    private static final String ALLOWANYWSADMIN = "ALLOWANYWSADMIN";

    @EJB
    private AdminWebSessionBean workerSessionBean;

    @ManagedProperty(value = "#{authenticationBean}")
    private AuthenticationBean authBean;

    private LinkedHashMap<ClientEntry, Entry> admins;
    private List<Entry> config;
    private GlobalConfiguration globalConfig;

    private Boolean allowAny;

    private String certSN;
    private String issuerDN;
    private String oldCertSN;
    private String oldIssuerDN;
    private boolean fromCertificate;

    private boolean roleAdmin = true;
    private boolean roleAuditor;
    private boolean roleArchiveAuditor;

    private boolean edit;
    private String cert;
    private boolean remove;
    
    private String loadErrorMessage;

    /**
     * Creates a new instance of GlobalConfigurationBean.
     */
    public AdministratorsBean() {
    }

    public AuthenticationBean getAuthBean() {
        return authBean;
    }

    public void setAuthBean(AuthenticationBean authBean) {
        this.authBean = authBean;
    }

    private GlobalConfiguration getGlobalConfig() throws AdminNotAuthorizedException {
        if (globalConfig == null) {
            globalConfig = workerSessionBean.getGlobalConfiguration(authBean.getAdminCertificate());
        }
        return globalConfig;
    }

    public List<Entry> getConfig() throws AdminNotAuthorizedException {
        if (config == null) {
            config = new ArrayList<>(getAdmins().values());
        }
        return config;
    }

    private LinkedHashMap<ClientEntry, Entry> getAdmins() throws AdminNotAuthorizedException {
        if (admins == null) {
            admins = parseAdmins();
        }
        return admins;
    }

    public boolean isAllowAny() throws AdminNotAuthorizedException {
        if (allowAny == null) {
            // set initial state for the allow all checkbox
            final String property = getGlobalConfig().getProperty(GlobalConfiguration.SCOPE_GLOBAL, ALLOWANYWSADMIN);
            allowAny = property != null && Boolean.TRUE.toString().equalsIgnoreCase(property);
        }
        return allowAny;
    }

    public String getCertSN() {
        return certSN;
    }

    public void setCertSN(String certSN) {
        this.certSN = certSN;
    }

    public String getIssuerDN() {
        return issuerDN;
    }

    public void setIssuerDN(String issuerDN) {
        this.issuerDN = issuerDN;
    }

    public String getOldCertSN() {
        if (oldCertSN == null) {
            oldCertSN = certSN;
        }
        return oldCertSN;
    }

    public void setOldCertSN(String oldCertSN) {
        this.oldCertSN = oldCertSN;
    }

    public String getOldIssuerDN() {
        if (oldIssuerDN == null) {
            oldIssuerDN = issuerDN;
        }
        return oldIssuerDN;
    }

    public String getLoadErrorMessage() {
        return loadErrorMessage;
    }

    public void setOldIssuerDN(String oldIssuerDN) {
        this.oldIssuerDN = oldIssuerDN;
    }

    public boolean isFromCertificate() {
        return fromCertificate;
    }

    public boolean isRoleAdmin() {
        return roleAdmin;
    }

    public void setRoleAdmin(boolean roleAdmin) {
        this.roleAdmin = roleAdmin;
    }

    public boolean isRoleAuditor() {
        return roleAuditor;
    }

    public void setRoleAuditor(boolean roleAuditor) {
        this.roleAuditor = roleAuditor;
    }

    public boolean isRoleArchiveAuditor() {
        return roleArchiveAuditor;
    }

    public void setRoleArchiveAuditor(boolean roleArchiveAuditor) {
        this.roleArchiveAuditor = roleArchiveAuditor;
    }

    public boolean isEdit() {
        return edit;
    }

    public boolean isRemove() {
        return remove;
    }

    public String getCert() {
        return cert;
    }

    public void setCert(String cert) {
        this.cert = cert;
    }

    public String allowAnyAction(boolean allowAny) throws AdminNotAuthorizedException {
        workerSessionBean.setGlobalProperty(authBean.getAdminCertificate(), GlobalConfiguration.SCOPE_GLOBAL, ALLOWANYWSADMIN, String.valueOf(allowAny));
        this.allowAny = null;
        return "administrators?faces-redirect=true";
    }

    public void editAction(Entry entry) throws AdminNotAuthorizedException {
        this.edit = true;
        this.certSN = entry.getHexSerialNumber();
        this.issuerDN = entry.getClient().getIssuerDN();
        this.roleAdmin = entry.isAdmin();
        this.roleAuditor = entry.isAuditor();
        this.roleArchiveAuditor = entry.isArchiveAuditor();
    }

    public void removeAction(Entry entry) {
        this.remove = true;
        this.certSN = entry.getHexSerialNumber();
        this.issuerDN = entry.getClient().getIssuerDN();
        this.roleAdmin = entry.isAdmin();
        this.roleAuditor = entry.isAuditor();
        this.roleArchiveAuditor = entry.isArchiveAuditor();
    }

    public String removeSubmitAction() throws AdminNotAuthorizedException {
        final ClientEntry oldEntry = new ClientEntry(new BigInteger(certSN, 16), issuerDN);

        getAdmins().remove(oldEntry);

        workerSessionBean.setGlobalProperty(authBean.getAdminCertificate(),
                GlobalConfiguration.SCOPE_GLOBAL,
                "WSADMINS",
                serializeAdmins(admins));
        workerSessionBean.setGlobalProperty(authBean.getAdminCertificate(),
                GlobalConfiguration.SCOPE_GLOBAL,
                "WSAUDITORS",
                serializeAuditors(admins));
        workerSessionBean.setGlobalProperty(authBean.getAdminCertificate(),
                GlobalConfiguration.SCOPE_GLOBAL,
                "WSARCHIVEAUDITORS",
                serializeArchiveAuditors(admins));
        return "administrators?faces-redirect=true";
    }

    public String editSubmitAction() throws AdminNotAuthorizedException {

        final ClientEntry newCred = new ClientEntry(new BigInteger(certSN, 16), issuerDN);
        final ClientEntry oldEntry = new ClientEntry(new BigInteger(oldCertSN, 16), oldIssuerDN);

        getAdmins().remove(oldEntry);

        final Entry newEntry
                = new Entry(newCred,
                        roleAdmin,
                        roleAuditor,
                        roleArchiveAuditor);

        getAdmins().put(newCred, newEntry);

        workerSessionBean.setGlobalProperty(authBean.getAdminCertificate(),
                GlobalConfiguration.SCOPE_GLOBAL,
                "WSADMINS",
                serializeAdmins(admins));
        workerSessionBean.setGlobalProperty(authBean.getAdminCertificate(),
                GlobalConfiguration.SCOPE_GLOBAL,
                "WSAUDITORS",
                serializeAuditors(admins));
        workerSessionBean.setGlobalProperty(authBean.getAdminCertificate(),
                GlobalConfiguration.SCOPE_GLOBAL,
                "WSARCHIVEAUDITORS",
                serializeArchiveAuditors(admins));
        return "administrators?faces-redirect=true";
    }

    public String addSubmitAction() throws AdminNotAuthorizedException {

        final ClientEntry newCred = new ClientEntry(new BigInteger(certSN, 16), issuerDN);

        final Entry newEntry
                = new Entry(newCred,
                        roleAdmin,
                        roleAuditor,
                        roleArchiveAuditor);

        getAdmins().put(newCred, newEntry);

        if (roleAdmin) {
            workerSessionBean.setGlobalProperty(authBean.getAdminCertificate(),
                    GlobalConfiguration.SCOPE_GLOBAL,
                    "WSADMINS",
                    serializeAdmins(admins));
        }
        if (roleAuditor) {
            workerSessionBean.setGlobalProperty(authBean.getAdminCertificate(),
                    GlobalConfiguration.SCOPE_GLOBAL,
                    "WSAUDITORS",
                    serializeAuditors(admins));
        }
        if (roleArchiveAuditor) {
            workerSessionBean.setGlobalProperty(authBean.getAdminCertificate(),
                    GlobalConfiguration.SCOPE_GLOBAL,
                    "WSARCHIVEAUDITORS",
                    serializeArchiveAuditors(admins));
        }
        return "administrators?faces-redirect=true";
    }

    public void browseAction() {
        fromCertificate = true;
    }

    public void loadCurrentAction() throws NotLoggedInException {
        X509Certificate current = getAuthBean().getAdminCertificate();
        certSN = current.getSerialNumber().toString(16);
        issuerDN = getIssuerDN(current);
    }

    public void cancelBrowseAction() {
        fromCertificate = false;
    }

    public void loadAction() {
        try {
            final X509Certificate certificate = (X509Certificate) CertTools.getCertfromByteArray(cert.getBytes(StandardCharsets.UTF_8));
            certSN = certificate.getSerialNumber().toString(16);
            issuerDN = CertTools.stringToBCDNString(certificate.getIssuerX500Principal().getName());
            fromCertificate = false;
            loadErrorMessage = null;
        } catch (CertificateParsingException ex) {
            loadErrorMessage = "Unable to load certificate: " + ex.getLocalizedMessage();
        }

    }

    /////////////////////////////////////////////////////
    // TODO: Duplicated from AdminGUI AdministratorsFrame.java this MUST be refactored!
    // some adaptions done here
    private LinkedHashMap<ClientEntry, Entry> parseAdmins()
            throws AdminNotAuthorizedException {
        GlobalConfiguration globalConfig1 = getGlobalConfig();
        String admins = globalConfig1.getProperty(GlobalConfiguration.SCOPE_GLOBAL, "WSADMINS");
        String auditors = globalConfig1.getProperty(GlobalConfiguration.SCOPE_GLOBAL, "WSAUDITORS");
        String archiveAuditors = globalConfig1.getProperty(GlobalConfiguration.SCOPE_GLOBAL, "WSARCHIVEAUDITORS");

        final LinkedHashMap<ClientEntry, Entry> entryMap
                = new LinkedHashMap<>();

        // Admins
        if (admins != null && admins.contains(";")) {
            for (String entryString : admins.split(";")) {
                final String[] parts = entryString.split(",", 2);
                try {
                    final ClientEntry client
                            = new ClientEntry(new BigInteger(parts[0], 16), parts[1]);
                    Entry entry = entryMap.get(client);
                    if (entry == null) {
                        entry = new Entry(client);
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
                    Entry entry = entryMap.get(client);
                    if (entry == null) {
                        entry = new Entry(client);
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
                    Entry entry = entryMap.get(client);
                    if (entry == null) {
                        entry = new Entry(client);
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

        return entryMap;
    }

    private static String serializeAdmins(final Map<ClientEntry, Entry> entries) {
        final StringBuilder buff = new StringBuilder();
        for (Entry entry : entries.values()) {
            if (entry.isAdmin()) {
                buff.append(entry.getClient().getSerialNumber().toString(16));
                buff.append(",");
                buff.append(entry.getClient().getIssuerDN());
                buff.append(";");
            }
        }
        return buff.toString();
    }

    private static String serializeAuditors(final Map<ClientEntry, Entry> entries) {
        final StringBuilder buff = new StringBuilder();
        for (Entry entry : entries.values()) {
            if (entry.isAuditor()) {
                buff.append(entry.getClient().getSerialNumber().toString(16));
                buff.append(",");
                buff.append(entry.getClient().getIssuerDN());
                buff.append(";");
            }
        }
        return buff.toString();
    }

    private static String serializeArchiveAuditors(final Map<ClientEntry, Entry> entries) {
        final StringBuilder buff = new StringBuilder();
        for (Entry entry : entries.values()) {
            if (entry.isArchiveAuditor()) {
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
    private String getIssuerDN(X509Certificate certificate) {
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

    public static class Entry {

        private final ClientEntry client;
        private boolean admin;
        private boolean auditor;
        private boolean archiveAuditor;
        private final String hexSerialNumber;

        public Entry(final ClientEntry client, final boolean admin,
                final boolean auditor, final boolean archiveAuditor) {
            this.client = client;
            this.admin = admin;
            this.auditor = auditor;
            this.archiveAuditor = archiveAuditor;
            this.hexSerialNumber = client.getSerialNumber().toString(16);
        }

        private Entry(final ClientEntry client) {
            this.client = client;
            this.hexSerialNumber = client.getSerialNumber().toString(16);
        }

        public ClientEntry getClient() {
            return client;
        }

        public boolean isAdmin() {
            return admin;
        }

        public boolean isAuditor() {
            return auditor;
        }

        public boolean isArchiveAuditor() {
            return archiveAuditor;
        }

        public void setAdmin(boolean admin) {
            this.admin = admin;
        }

        public void setAuditor(boolean auditor) {
            this.auditor = auditor;
        }

        public void setArchiveAuditor(boolean archiveAuditor) {
            this.archiveAuditor = archiveAuditor;
        }

        public String getHexSerialNumber() {
            return hexSerialNumber;
        }

        @Override
        public int hashCode() {
            int hash = 5;
            hash = 29 * hash + Objects.hashCode(this.client);
            hash = 29 * hash + (this.admin ? 1 : 0);
            hash = 29 * hash + (this.auditor ? 1 : 0);
            hash = 29 * hash + (this.archiveAuditor ? 1 : 0);
            hash = 29 * hash + Objects.hashCode(this.hexSerialNumber);
            return hash;
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (obj == null) {
                return false;
            }
            if (getClass() != obj.getClass()) {
                return false;
            }
            final Entry other = (Entry) obj;
            if (this.admin != other.admin) {
                return false;
            }
            if (this.auditor != other.auditor) {
                return false;
            }
            if (this.archiveAuditor != other.archiveAuditor) {
                return false;
            }
            if (!Objects.equals(this.hexSerialNumber, other.hexSerialNumber)) {
                return false;
            }
            return Objects.equals(this.client, other.client);
        }

        public String getRoles() {
            final StringBuilder sb = new StringBuilder();
            if (admin) {
                sb.append("Admin");
            }
            if (auditor) {
                if (sb.length() != 0) {
                    sb.append(", ");
                }
                sb.append("Auditor");
            }
            if (archiveAuditor) {
                if (sb.length() != 0) {
                    sb.append(", ");
                }
                sb.append("Archive Auditor");
            }
            return sb.toString();
        }

    }

    ////////////////////////////////////////////////////
}
