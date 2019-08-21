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
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.ServiceLoader;
import javax.ejb.EJB;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ManagedProperty;
import javax.faces.bean.ViewScoped;
import javax.faces.model.ListDataModel;
import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationToken;
import org.cesecore.util.CertTools;
import org.signserver.admin.common.roles.AdminEntry;
import org.signserver.admin.common.roles.AdminsUtil;
import org.signserver.common.ClientEntry;
import org.signserver.common.GlobalConfiguration;
import org.signserver.admin.common.auth.AdminNotAuthorizedException;
import org.signserver.admin.web.ejb.AdminWebSessionBean;
import org.signserver.common.SignServerUtil;
import org.signserver.serviceprovider.PeersInInfo;
import org.signserver.serviceprovider.PeersProvider;

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

    // copied from PeersGlobalConstants to avoid depending on that package
    private static final String PEERS_INCOMING_ENABLED = "PEERS_INCOMING_ENABLED";

    @EJB
    private AdminWebSessionBean workerSessionBean;

    @ManagedProperty(value = "#{authenticationBean}")
    private AuthenticationBean authBean;

    private LinkedHashMap<ClientEntry, AdminEntry> admins;
    private List<AdminEntry> config;
    private GlobalConfiguration globalConfig;

    private Boolean allowAny;
    private Boolean allowIncomingPeerSystems;

    private String certSN;
    private String issuerDN;
    private String oldCertSN;
    private String oldIssuerDN;
    private boolean fromCertificate;

    private boolean roleAdmin = true;
    private boolean roleAuditor;
    private boolean roleArchiveAuditor;
    private boolean rolePeerSystem;

    private boolean edit;
    private String cert;
    private boolean remove;
    
    private String loadErrorMessage;
    private ListDataModel<PeersInInfo> peerConnectorsInModel;

    private boolean hasCachedPeersProvider = false;
    private PeersProvider cachedPeersProvider;

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

    public Boolean getAllowIncomingPeerSystems() throws AdminNotAuthorizedException {
        if (allowIncomingPeerSystems == null) {
            // set initial state for the allow all checkbox
            final String property = getGlobalConfig().getProperty(GlobalConfiguration.SCOPE_GLOBAL, PEERS_INCOMING_ENABLED);
            allowIncomingPeerSystems = property != null && Boolean.TRUE.toString().equalsIgnoreCase(property);
        }
        return allowIncomingPeerSystems;
    }

    public void setAllowIncomingPeerSystems(Boolean allowIncomingPeerSystems) {
        this.allowIncomingPeerSystems = allowIncomingPeerSystems;
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

    public boolean isRolePeerSystem() {
        return rolePeerSystem;
    }

    public void setRolePeerSystem(boolean rolePeerSystem) {
        this.rolePeerSystem = rolePeerSystem;
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
    
    public String saveAllowIncomingAction() throws AdminNotAuthorizedException {
        workerSessionBean.setGlobalProperty(authBean.getAdminCertificate(), GlobalConfiguration.SCOPE_GLOBAL, PEERS_INCOMING_ENABLED, String.valueOf(allowIncomingPeerSystems));
        this.allowIncomingPeerSystems = null;
        return "administrators?faces-redirect=true";
    }

    public String allowIncomingAction(boolean allowIncoming) throws AdminNotAuthorizedException {
        workerSessionBean.setGlobalProperty(authBean.getAdminCertificate(), GlobalConfiguration.SCOPE_GLOBAL, PEERS_INCOMING_ENABLED, String.valueOf(allowIncoming));
        this.allowIncomingPeerSystems = null;
        return "administrators?faces-redirect=true";
    }

    public void editAction(AdminEntry entry) throws AdminNotAuthorizedException {
        this.edit = true;
        this.certSN = entry.getHexSerialNumber();
        this.issuerDN = entry.getClient().getIssuerDN();
        this.roleAdmin = entry.isAdmin();
        this.roleAuditor = entry.isAuditor();
        this.roleArchiveAuditor = entry.isArchiveAuditor();
        this.rolePeerSystem = entry.isPeerSystem();
    }

    public void removeAction(AdminEntry entry) {
        this.remove = true;
        this.certSN = entry.getHexSerialNumber();
        this.issuerDN = entry.getClient().getIssuerDN();
        this.roleAdmin = entry.isAdmin();
        this.roleAuditor = entry.isAuditor();
        this.roleArchiveAuditor = entry.isArchiveAuditor();
        this.rolePeerSystem = entry.isPeerSystem();
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
                "WSPEERS",
                AdminsUtil.serializePeerSystems(admins));
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
                        roleArchiveAuditor,
                        rolePeerSystem);

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
                "WSPEERS",
                AdminsUtil.serializePeerSystems(admins));
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
                        roleArchiveAuditor,
                        rolePeerSystem);

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
        if (rolePeerSystem) {
            workerSessionBean.setGlobalProperty(authBean.getAdminCertificate(),
                    GlobalConfiguration.SCOPE_GLOBAL,
                    "WSPEERS",
                    AdminsUtil.serializePeerSystems(admins));
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
            issuerDN = AdminsUtil.getIssuerDN(certificate);
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
        String peerSystems = globalConfig1.getProperty(GlobalConfiguration.SCOPE_GLOBAL, "WSPEERS");
        return AdminsUtil.parseAdmins(admins, auditors, archiveAuditors, peerSystems);
    }
    
    public ListDataModel<PeersInInfo> getPeerConnectorsIn() {
        if (peerConnectorsInModel == null) {
            final PeersProvider pp = getPeersProvider();
            
            if (pp != null) {
                final List<PeersInInfo> incoming = pp.createPeersIncoming();

                // Sort by credential, remote address and last seen
                Collections.sort(incoming, new Comparator<PeersInInfo>() {
                    @Override
                    public int compare(final PeersInInfo first,
                                       final PeersInInfo second) {
                        final int authCompare =
                                first.getAuthenticationToken().toString().
                                compareTo(second.getAuthenticationToken().toString());
                        if (authCompare != 0) {
                            return authCompare;
                        }
                        final int addressCompare = first.getRemoteAddress().compareTo(second.getRemoteAddress());
                        if (addressCompare != 0) {
                            return addressCompare;
                        }
                        return Long.valueOf(second.getLastUpdate() - first.getLastUpdate()).intValue();
                    }
                });
                peerConnectorsInModel = new ListDataModel<>(incoming);
            } else {
                peerConnectorsInModel = new ListDataModel<>();
            }
        }
        return peerConnectorsInModel;
    }

    public boolean isRolePresent() throws AdminNotAuthorizedException {
        final X509Certificate certificate = ((X509CertificateAuthenticationToken) getCurrentPeerConnectorIn().getAuthenticationToken()).getCertificate();
        final AdminEntry entry = getAdmins().get(new ClientEntry(certificate.getSerialNumber(), SignServerUtil.getTokenizedIssuerDNFromCert(certificate)));
        return entry != null;
    }
    
    public boolean isRoleForPeerPresent() throws AdminNotAuthorizedException {
        final X509Certificate certificate = ((X509CertificateAuthenticationToken) getCurrentPeerConnectorIn().getAuthenticationToken()).getCertificate();
        final AdminEntry entry = getAdmins().get(new ClientEntry(certificate.getSerialNumber(), SignServerUtil.getTokenizedIssuerDNFromCert(certificate)));
        return entry != null && entry.isPeerSystem();
    }
    
    public void extendRoleAndRulesAction() throws AdminNotAuthorizedException {
        final X509Certificate certificate = ((X509CertificateAuthenticationToken) getCurrentPeerConnectorIn().getAuthenticationToken()).getCertificate();
        final AdminEntry entry = getAdmins().get(new ClientEntry(certificate.getSerialNumber(), SignServerUtil.getTokenizedIssuerDNFromCert(certificate)));
        editAction(entry);
    }
    
    public String createRoleAndRulesAction() throws AdminNotAuthorizedException {
        final X509Certificate certificate = ((X509CertificateAuthenticationToken) getCurrentPeerConnectorIn().getAuthenticationToken()).getCertificate();
        final ClientEntry clientEntry = new ClientEntry(certificate.getSerialNumber(), SignServerUtil.getTokenizedIssuerDNFromCert(certificate));
        final AdminEntry entry = getAdmins().get(clientEntry);
        if (entry == null) {
            final AdminEntry entry2 = new AdminEntry(clientEntry);
            this.edit = false;
            this.certSN = entry2.getHexSerialNumber();
            this.issuerDN = entry2.getClient().getIssuerDN();
            this.roleAdmin = false;
            this.roleAuditor = false;
            this.roleArchiveAuditor = false;
            this.rolePeerSystem = true;
            return "administrators-add";
        } else {
            editAction(entry);
            return null;
        }
    }
    
    private PeersInInfo getCurrentPeerConnectorIn() {
        return getPeerConnectorsIn().getRowData();
    }

    public void clearIncomingAction() {
        final PeersInInfo pii = getCurrentPeerConnectorIn();
        if (pii == null) {
            LOG.info("Unable to clear nonexisting info.");
        } else {
            final PeersProvider pp = getPeersProvider();

            if (pp != null) {
                pp.removeIncomingPeer(pii.getId(), pii.getAuthenticationToken());
            }
            peerConnectorsInModel = null;
        }
    }
    
    private ClientEntry newEntry;
    private ClientEntry getNewEntry() throws AdminNotAuthorizedException {
        if (newEntry == null) {
            final X509Certificate certificate = ((X509CertificateAuthenticationToken) getCurrentPeerConnectorIn().getAuthenticationToken()).getCertificate();
            newEntry = new ClientEntry(certificate.getSerialNumber(), SignServerUtil.getTokenizedIssuerDNFromCert(certificate));
        }
        return newEntry;
    }
    
    public String getCurrentCertSN() throws AdminNotAuthorizedException {
        return new AdminEntry(getNewEntry()).getHexSerialNumber();
    }
    
    public String getCurrentIssuerDN() throws AdminNotAuthorizedException {
        return getNewEntry().getIssuerDN();
    }

    public boolean isPeersAvailable() {
        return getPeersProvider() != null;
    }

    /**
     * Return the first found peers provider interface implementation.
     * Note: past Java 8 this could use the new Optional-using methods from
     * ServiceLoader to avoid ugly != null checks when used.
     * 
     * @return The first found PeersProvider implementation
     */
    private PeersProvider getPeersProvider() {
        if (!hasCachedPeersProvider) {
            final ServiceLoader sl = ServiceLoader.load(PeersProvider.class);

            // lazily just return the first found implementation for now
            if (sl.iterator().hasNext()) {
                cachedPeersProvider = (PeersProvider) sl.iterator().next();
            } else {
                cachedPeersProvider = null;
            }
            hasCachedPeersProvider = true;
        }

        return cachedPeersProvider;
    }
}
