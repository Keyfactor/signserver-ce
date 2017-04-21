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
import javax.ejb.EJB;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ManagedProperty;
import javax.faces.bean.ViewScoped;
import org.apache.log4j.Logger;
import org.cesecore.util.CertTools;
import org.signserver.admin.common.roles.AdminEntry;
import org.signserver.admin.common.roles.AdminsUtil;
import org.signserver.common.ClientEntry;
import org.signserver.common.GlobalConfiguration;
import org.signserver.admin.common.auth.AdminNotAuthorizedException;
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

    private LinkedHashMap<ClientEntry, AdminEntry> admins;
    private List<AdminEntry> config;
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

    public List<AdminEntry> getConfig() throws AdminNotAuthorizedException {
        if (config == null) {
            config = new ArrayList<>(getAdmins().values());
        }
        return config;
    }

    private LinkedHashMap<ClientEntry, AdminEntry> getAdmins() throws AdminNotAuthorizedException {
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

    public void editAction(AdminEntry entry) throws AdminNotAuthorizedException {
        this.edit = true;
        this.certSN = entry.getHexSerialNumber();
        this.issuerDN = entry.getClient().getIssuerDN();
        this.roleAdmin = entry.isAdmin();
        this.roleAuditor = entry.isAuditor();
        this.roleArchiveAuditor = entry.isArchiveAuditor();
    }

    public void removeAction(AdminEntry entry) {
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
                "WSAUDITORS",
                AdminsUtil.serializeAuditors(admins));
        workerSessionBean.setGlobalProperty(authBean.getAdminCertificate(),
                GlobalConfiguration.SCOPE_GLOBAL,
                "WSARCHIVEAUDITORS",
                AdminsUtil.serializeArchiveAuditors(admins));
        workerSessionBean.setGlobalProperty(authBean.getAdminCertificate(),
                GlobalConfiguration.SCOPE_GLOBAL,
                "WSADMINS",
                AdminsUtil.serializeAdmins(admins));
        return "administrators?faces-redirect=true";
    }

    public String editSubmitAction() throws AdminNotAuthorizedException {

        final ClientEntry newCred = new ClientEntry(new BigInteger(certSN, 16), issuerDN);
        final ClientEntry oldEntry = new ClientEntry(new BigInteger(oldCertSN, 16), oldIssuerDN);

        getAdmins().remove(oldEntry);

        final AdminEntry newEntry
                = new AdminEntry(newCred,
                        roleAdmin,
                        roleAuditor,
                        roleArchiveAuditor);

        getAdmins().put(newCred, newEntry);

        workerSessionBean.setGlobalProperty(authBean.getAdminCertificate(),
                GlobalConfiguration.SCOPE_GLOBAL,
                "WSAUDITORS",
                AdminsUtil.serializeAuditors(admins));
        workerSessionBean.setGlobalProperty(authBean.getAdminCertificate(),
                GlobalConfiguration.SCOPE_GLOBAL,
                "WSARCHIVEAUDITORS",
                AdminsUtil.serializeArchiveAuditors(admins));
        workerSessionBean.setGlobalProperty(authBean.getAdminCertificate(),
                GlobalConfiguration.SCOPE_GLOBAL,
                "WSADMINS",
                AdminsUtil.serializeAdmins(admins));
        return "administrators?faces-redirect=true";
    }

    public String addSubmitAction() throws AdminNotAuthorizedException {

        final ClientEntry newCred = new ClientEntry(new BigInteger(certSN, 16), issuerDN);

        final AdminEntry newEntry
                = new AdminEntry(newCred,
                        roleAdmin,
                        roleAuditor,
                        roleArchiveAuditor);

        getAdmins().put(newCred, newEntry);

        if (roleAuditor) {
            workerSessionBean.setGlobalProperty(authBean.getAdminCertificate(),
                    GlobalConfiguration.SCOPE_GLOBAL,
                    "WSAUDITORS",
                    AdminsUtil.serializeAuditors(admins));
        }
        if (roleArchiveAuditor) {
            workerSessionBean.setGlobalProperty(authBean.getAdminCertificate(),
                    GlobalConfiguration.SCOPE_GLOBAL,
                    "WSARCHIVEAUDITORS",
                    AdminsUtil.serializeArchiveAuditors(admins));
        }
        if (roleAdmin) {
            workerSessionBean.setGlobalProperty(authBean.getAdminCertificate(),
                    GlobalConfiguration.SCOPE_GLOBAL,
                    "WSADMINS",
                    AdminsUtil.serializeAdmins(admins));
        }
        return "administrators?faces-redirect=true";
    }

    public void browseAction() {
        fromCertificate = true;
    }

    public void loadCurrentAction() throws NotLoggedInException {
        X509Certificate current = getAuthBean().getAdminCertificate();
        certSN = current.getSerialNumber().toString(16);
        issuerDN = AdminsUtil.getIssuerDN(current);
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

    private LinkedHashMap<ClientEntry, AdminEntry> parseAdmins()
            throws AdminNotAuthorizedException {
        GlobalConfiguration globalConfig1 = getGlobalConfig();
        String admins = globalConfig1.getProperty(GlobalConfiguration.SCOPE_GLOBAL, "WSADMINS");
        String auditors = globalConfig1.getProperty(GlobalConfiguration.SCOPE_GLOBAL, "WSAUDITORS");
        String archiveAuditors = globalConfig1.getProperty(GlobalConfiguration.SCOPE_GLOBAL, "WSARCHIVEAUDITORS");
        return AdminsUtil.parseAdmins(admins, auditors, archiveAuditors);
    }
}
