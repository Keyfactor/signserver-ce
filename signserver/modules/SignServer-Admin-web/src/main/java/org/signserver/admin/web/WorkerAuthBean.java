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

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyStoreException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.ResourceBundle;
import java.util.regex.Pattern;
import javax.ejb.EJB;
import javax.ejb.EJBException;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ManagedProperty;
import javax.faces.bean.ViewScoped;
import javax.faces.context.FacesContext;
import javax.xml.ws.soap.SOAPFaultException;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.certificates.util.DNFieldExtractor;
import org.cesecore.util.CertTools;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerIdentifier;
import org.signserver.admin.common.auth.AdminNotAuthorizedException;
import org.signserver.admin.web.ejb.AdminWebSessionBean;
import org.signserver.admin.web.ejb.NotLoggedInException;
import org.signserver.common.CertificateMatchingRule;
import org.signserver.common.MatchIssuerWithType;
import org.signserver.common.MatchSubjectWithType;

/**
 *
 * @author Markus Kilås
 * @version $Id$
 */
@ManagedBean
@ViewScoped
public class WorkerAuthBean {
    
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(WorkerAuthBean.class);

    //@ManagedProperty(value = "#{param.id}")
    private Integer id;

    private String property;
    private String propertyValue;

    @EJB
    private AdminWebSessionBean workerSessionBean;

    @ManagedProperty(value = "#{authenticationBean}")
    private AuthenticationBean authBean;

    private Worker worker;
    private String status;
    private List<KeyValue> config;
    private WorkerConfig workerConfig;

    private String destroyKeyAlias;
    private Integer destroyKeyStep = 0;
    private boolean destroyKeySuccess;
    private String destroyKeyError;    
    
    private String oldMatchSubjectWithType;
    private String oldMatchIssuerWithType;
    private String oldMatchSubjectWithValue;
    private String oldMatchIssuerWithValue;
    private String oldDescription;

    private String cert;
    private X509Certificate certificate;
    private boolean fromCertificate;
    private boolean importState;

    private String loadErrorMessage;
    private String errorMessage;
    
    private String matchSubjectWithType;
    private String matchIssuerWithType;
    private String matchSubjectWithValue;
    private String matchIssuerWithValue;
    private String description;

    private static final Pattern SERIAL_PATTERN = Pattern.compile("\\bSERIALNUMBER=", Pattern.CASE_INSENSITIVE);
    private MatchSubjectWithType selectedSubjectMatchType = MatchSubjectWithType.CERTIFICATE_SERIALNO;
    
    /**
     * Creates a new instance of WorkerBean
     */
    public WorkerAuthBean() {
    }

    public Worker getWorker() throws AdminNotAuthorizedException {
        if (worker == null) {
            Properties conf = getWorkerConfig().getProperties();
            boolean existing;
            String name = conf.getProperty("NAME");
            if (name == null) {
                name = "Unknown ID " + getId();
                existing = false;
            } else {
                existing = true;
            }

            worker = new Worker(getId(), existing, name, conf);
        }
        return worker;
    }

    public AuthenticationBean getAuthBean() {
        return authBean;
    }

    public void setAuthBean(AuthenticationBean authBean) {
        this.authBean = authBean;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public Integer getId() {
        if (id == null) {
            id = 0;
        }
        return id;
    }

    public String getStatus() throws AdminNotAuthorizedException {
        if (status == null) {
            ByteArrayOutputStream bout = new ByteArrayOutputStream();
            try {
                workerSessionBean.getStatus(authBean.getAdminCertificate(), new WorkerIdentifier(getId())).displayStatus(new PrintStream(bout, false, StandardCharsets.UTF_8.toString()), true);
                status = bout.toString(StandardCharsets.UTF_8.toString());
            } catch (UnsupportedEncodingException | InvalidWorkerIdException ex) {
                throw new IllegalStateException(ex);
            }
        }
        return status;
    }

    public List<KeyValue> getConfig() throws AdminNotAuthorizedException {
        if (config == null) {
            Properties properties = getWorkerConfig().getProperties();
            config = new ArrayList<>(properties.size());
            for (Map.Entry<Object, Object> entry : properties.entrySet()) {
                String value = (String) entry.getValue();
                if (value.length() > 50) {
                    value = value.substring(0, 50) + "...";
                }
                config.add(new KeyValue((String) entry.getKey(), value));
            }
        }
        return config;
    }

    private WorkerConfig getWorkerConfig() throws AdminNotAuthorizedException {
        if (workerConfig == null) {
            workerConfig = workerSessionBean.getCurrentWorkerConfig(authBean.getAdminCertificate(), getId());
        }
        return workerConfig;
    }

    public String workerAction(String page) {
        StringBuilder sb = new StringBuilder();
        sb.append(StringUtils.trim(page));
        sb.append("?faces-redirect=true&amp;includeViewParams=true");
        return sb.toString();
    }

    public String bulkAction(String page) {
        StringBuilder sb = new StringBuilder();
        sb.append(StringUtils.trim(page));
        sb.append("?faces-redirect=true&amp;id=").append(getId()); // TODO: +Going back page / viewing navigation path
        return sb.toString();
    }

    public String getDestroyKeyAlias() {
        return destroyKeyAlias;
    }

    public void setDestroyKeyAlias(String destroyKeyAlias) {
        this.destroyKeyAlias = StringUtils.trim(destroyKeyAlias);
    }

    public void destroyKeyStep1Action() {
        destroyKeyStep = 1;
    }

    public void destroyKeyCancelAction() {
        destroyKeyStep = 0;
    }

    public void destroyKeyStep2Action() {
        destroyKeyStep = 2;
        destroyKeySuccess = false;
        try {
            destroyKeySuccess = workerSessionBean.removeKey(authBean.getAdminCertificate(), id, destroyKeyAlias);
            destroyKeyError = null;
        } catch (AdminNotAuthorizedException ex) {
            destroyKeyError = "Authorization denied:\n" + ex.getLocalizedMessage();
        } catch (CryptoTokenOfflineException ex) {
            destroyKeyError = "Unable to remove key because token was not active:\n" + ex.getLocalizedMessage();
        } catch (InvalidWorkerIdException | KeyStoreException | SignServerException | SOAPFaultException | EJBException ex) {
            destroyKeyError = "Unable to remove key:\n" + ex.getLocalizedMessage();
        }
    }

    public Integer getDestroyKeyStep() {
        return destroyKeyStep;
    }

    public void setDestroyKeyStep(Integer destroyKeyStep) {
        this.destroyKeyStep = destroyKeyStep;
    }

    public boolean isDestroyKeySuccess() {
        return destroyKeySuccess;
    }

    public String getDestroyKeyError() {
        return destroyKeyError;
    }

    public String getProperty() {
        return property;
    }

    public void setProperty(String property) {
        this.property = StringUtils.trim(property);
    }

    public String getPropertyValue() throws AdminNotAuthorizedException {
        if (propertyValue == null && property != null) {
            propertyValue = getWorkerConfig().getProperty(property);
        }
        return propertyValue;
    }

    public void setPropertyValue(String propertyValue) {
        this.propertyValue = StringUtils.trim(propertyValue);
    }

    public String getLoadErrorMessage() {
        return loadErrorMessage;
    }

    public String getErrorMessage() {
        return errorMessage;
    }

    public void setErrorMessage(String errorMessage) {
        this.errorMessage = errorMessage;
    }
    
    public String editAction() throws AdminNotAuthorizedException {

        final CertificateMatchingRule oldAuthorizedClient = new CertificateMatchingRule();
        oldAuthorizedClient.setMatchIssuerWithValue(oldMatchIssuerWithValue);
        oldAuthorizedClient.setMatchSubjectWithValue(oldMatchSubjectWithValue);
        oldAuthorizedClient.setDescription(oldDescription);
        oldAuthorizedClient.setMatchSubjectWithType(MatchSubjectWithType.valueOf(oldMatchSubjectWithType));
        oldAuthorizedClient.setMatchIssuerWithType(MatchIssuerWithType.valueOf(oldMatchIssuerWithType));

        String matchSubjectwithValueToBeUsed;
        if (MatchSubjectWithType.valueOf(matchSubjectWithType) == MatchSubjectWithType.CERTIFICATE_SERIALNO) {

            try {
                final BigInteger sn = new BigInteger(matchSubjectWithValue, 16);
                matchSubjectwithValueToBeUsed = sn.toString(16);
            } catch (NumberFormatException ex) {
                errorMessage = "Invalid subject value: " + matchSubjectWithValue;
                LOG.error(errorMessage, ex);
                return null;
            }

        } else {
            matchSubjectwithValueToBeUsed = matchSubjectWithValue;
        }

        final CertificateMatchingRule client = new CertificateMatchingRule();

        try {
            client.setMatchIssuerWithValue(CertTools.stringToBCDNString(matchIssuerWithValue));
        } catch (IllegalArgumentException | StringIndexOutOfBoundsException ex) {
            errorMessage = "Invalid issuer value: " + matchIssuerWithValue;
            LOG.error(errorMessage, ex);
            return null;
        }

        client.setMatchSubjectWithValue(matchSubjectwithValueToBeUsed);
        client.setDescription(description);
        client.setMatchSubjectWithType(MatchSubjectWithType.valueOf(matchSubjectWithType));
        client.setMatchIssuerWithType(MatchIssuerWithType.valueOf(matchIssuerWithType));

        boolean removed = workerSessionBean.removeAuthorizedClientGen2(authBean.getAdminCertificate(), worker.getId(), oldAuthorizedClient);
        if (removed) {
            workerSessionBean.addAuthorizedClientGen2(authBean.getAdminCertificate(), worker.getId(), client);
            workerSessionBean.reloadConfiguration(authBean.getAdminCertificate(), worker.getId());
        }

        return "worker-authorization?faces-redirect=true&amp;includeViewParams=true&amp;id=" + id;
    }

    public String addAction() throws AdminNotAuthorizedException {
        String matchSubjectwithValueToBeUsed;

        if (MatchSubjectWithType.valueOf(matchSubjectWithType) == MatchSubjectWithType.CERTIFICATE_SERIALNO) {

            try {
                final BigInteger sn = new BigInteger(matchSubjectWithValue, 16);
                matchSubjectwithValueToBeUsed = sn.toString(16);
            } catch (NumberFormatException ex) {
                errorMessage = "Invalid subject value: " + matchSubjectWithValue;
                LOG.error(errorMessage, ex);
                return null;
            }

        } else {
            matchSubjectwithValueToBeUsed = matchSubjectWithValue;
        }

        CertificateMatchingRule certMatchingRule = new CertificateMatchingRule();

        try {
            certMatchingRule.setMatchIssuerWithValue(CertTools.stringToBCDNString(matchIssuerWithValue));
        } catch (IllegalArgumentException | StringIndexOutOfBoundsException ex) {
            errorMessage = "Invalid issuer value: " + matchIssuerWithValue;
            LOG.error(errorMessage, ex);
            return null;
        }

        certMatchingRule.setMatchSubjectWithValue(matchSubjectwithValueToBeUsed);
        certMatchingRule.setDescription(description);
        certMatchingRule.setMatchSubjectWithType(MatchSubjectWithType.valueOf(matchSubjectWithType));
        certMatchingRule.setMatchIssuerWithType(MatchIssuerWithType.valueOf(matchIssuerWithType));

        workerSessionBean.addAuthorizedClientGen2(authBean.getAdminCertificate(), worker.getId(), certMatchingRule);
        workerSessionBean.reloadConfiguration(authBean.getAdminCertificate(), worker.getId());
        return "worker-authorization?faces-redirect=true&amp;includeViewParams=true&amp;id=" + id;
    }



    public void browseAction() {
        fromCertificate = true;
    }
    
    public void importAction() {
        importState = true;
    }
    
    public void loadCurrentAction() throws NotLoggedInException {
        cert = null;
        certificate = getAuthBean().getAdminCertificate();
        importState = true;
        fromCertificate = false;
    }

    public void cancelBrowseAction() {
        fromCertificate = false;
        importState = false;
        cert = null;
        certificate = null;
        loadErrorMessage = "";
    }

    public void loadCertAction() {
        loadErrorMessage = "";
        try {
            certificate = CertTools.getCertfromByteArray(cert.getBytes(), X509Certificate.class);
            fromCertificate = false;
            importState = true;
        }  catch (CertificateParsingException ex) {
            loadErrorMessage = "Unable to load certificate: " + ex.getLocalizedMessage();
        }
    }
    
    public void selectSubjectMatchType(final MatchSubjectWithType matchType) {
        selectedSubjectMatchType = matchType;
    }

    public MatchSubjectWithType getSelectedSubjectMatchType() {
        return selectedSubjectMatchType;
    }

    private String getMatchSubjectValueFromCert(final X509Certificate cert) {
        final MatchSubjectWithType type = selectedSubjectMatchType != null ?
                                          selectedSubjectMatchType :
                                          MatchSubjectWithType.SUBJECT_RDN_CN;
        String certstring = CertTools.getSubjectDN(cert);
        final String altNameString = CertTools.getSubjectAlternativeName(cert);
        certstring = SERIAL_PATTERN.matcher(certstring).replaceAll("SN=");
        final DNFieldExtractor dnExtractor = new DNFieldExtractor(certstring, DNFieldExtractor.TYPE_SUBJECTDN);
        final DNFieldExtractor anExtractor = new DNFieldExtractor(altNameString, DNFieldExtractor.TYPE_SUBJECTALTNAME);
        int parameter = DNFieldExtractor.CN;
        DNFieldExtractor usedExtractor = dnExtractor;
        final String subjectValue;
        if (type == MatchSubjectWithType.CERTIFICATE_SERIALNO) {
            subjectValue = cert.getSerialNumber().toString(16);
        } else {
            switch (type) {
                case SUBJECT_RDN_CN:
                parameter = DNFieldExtractor.CN;
                break;
                case SUBJECT_RDN_SERIALNO:
                    parameter = DNFieldExtractor.SN;
                    break;
                case SUBJECT_RDN_DC:
                    parameter = DNFieldExtractor.DC;
                    break;
                case SUBJECT_RDN_ST:
                    parameter = DNFieldExtractor.ST;
                    break;
                case SUBJECT_RDN_L:
                    parameter = DNFieldExtractor.L;
                    break;
                case SUBJECT_RDN_O:
                    parameter = DNFieldExtractor.O;
                    break;
                case SUBJECT_RDN_OU:
                    parameter = DNFieldExtractor.OU;
                    break;
                case SUBJECT_RDN_TITLE:
                    parameter = DNFieldExtractor.T;
                    break;
                case SUBJECT_RDN_UID:
                    parameter = DNFieldExtractor.UID;
                    break;
                case SUBJECT_RDN_E:
                    parameter = DNFieldExtractor.E;
                    break;
                case SUBJECT_RDN_C:
                    parameter = DNFieldExtractor.C;
                    break;
                case SUBJECT_ALTNAME_RFC822NAME:
                    parameter = DNFieldExtractor.RFC822NAME;
                    usedExtractor = anExtractor;
                    break;
                case SUBJECT_ALTNAME_MSUPN:
                    parameter = DNFieldExtractor.UPN;
                    usedExtractor = anExtractor;
                    break;
                default: // It should not happen though
                    throw new AssertionError(type.name());
            }

            final int size = usedExtractor.getNumberOfFields(parameter);

            if (size == 0) {
                subjectValue = null;
            } else {
                /* always select the first subject value, even in the case
                 * when there are multiple values, as that's the one that is
                 * shown as selectable.
                 */
                subjectValue = usedExtractor.getField(parameter, 0);
            }
        }
        
        return subjectValue;
    }
    
    public void loadFieldAction() {
        matchSubjectWithValue = getMatchSubjectValueFromCert(certificate);
        matchIssuerWithValue = CertTools.stringToBCDNString(certificate.getIssuerX500Principal().getName());
        matchSubjectWithType = selectedSubjectMatchType.name();
        matchIssuerWithType = MatchIssuerWithType.ISSUER_DN_BCSTYLE.toString();
        fromCertificate = false;
        loadErrorMessage = null;
        importState = false;
        cert = null;
        certificate = null;
    }

    public String addPropertyAction() throws AdminNotAuthorizedException {
        //workerSessionBean.setWorkerProperty(getAuthBean().getAdminCertificate(), id, property, propertyValue);
        return "worker-authorization?faces-redirect=true&amp;includeViewParams=true&amp;id=" + id;
    }

    public String removePropertyAction() throws AdminNotAuthorizedException {
        CertificateMatchingRule certMatchingRule = new CertificateMatchingRule();
        certMatchingRule.setMatchIssuerWithValue(matchIssuerWithValue);
        certMatchingRule.setMatchSubjectWithValue(matchSubjectWithValue);
        certMatchingRule.setDescription(description);
        certMatchingRule.setMatchSubjectWithType(MatchSubjectWithType.valueOf(matchSubjectWithType));
        certMatchingRule.setMatchIssuerWithType(MatchIssuerWithType.valueOf(matchIssuerWithType));
        workerSessionBean.removeAuthorizedClientGen2(getAuthBean().getAdminCertificate(), id, certMatchingRule);
        workerSessionBean.reloadConfiguration(authBean.getAdminCertificate(), worker.getId());
        return "worker-authorization?faces-redirect=true&amp;includeViewParams=true&amp;id=" + id;
    }
    
    public Collection<CertificateMatchingRule> getAuthorizedClientsGen2() throws AdminNotAuthorizedException {
        return workerSessionBean.getAuthorizedClientsGen2(authBean.getAdminCertificate(), id);
    }

    public Collection<AuthField> getSubjectFieldsFromCert() throws CertificateParsingException {
        final Collection<AuthField> fields = new LinkedList<>();
        
        if (certificate == null) {
            return fields;
        }
        
        String certstring = CertTools.getSubjectDN(certificate);
        certstring = SERIAL_PATTERN.matcher(certstring).replaceAll("SN=");
        final String altNameString = CertTools.getSubjectAlternativeName(certificate);
        final DNFieldExtractor dnExtractor = new DNFieldExtractor(certstring, DNFieldExtractor.TYPE_SUBJECTDN);
        final DNFieldExtractor anExtractor = new DNFieldExtractor(altNameString, DNFieldExtractor.TYPE_SUBJECTALTNAME);
        int parameter = DNFieldExtractor.CN;
        DNFieldExtractor usedExtractor = dnExtractor;
        final FacesContext context = FacesContext.getCurrentInstance();
        final ResourceBundle bundle = context.getApplication().getResourceBundle(context, "text");
        
        for (final MatchSubjectWithType type : MatchSubjectWithType.values()) {
            final String label = bundle.getString(type.name());

            if (type == MatchSubjectWithType.CERTIFICATE_SERIALNO) {
                final String subjectValue =
                        certificate.getSerialNumber().toString(16);
                fields.add(new AuthField(true, type, label, subjectValue));
            } else {
                switch (type) {
                    case SUBJECT_RDN_CN:
                    parameter = DNFieldExtractor.CN;
                    break;
                case SUBJECT_RDN_SERIALNO:
                    parameter = DNFieldExtractor.SN;
                    break;
                case SUBJECT_RDN_DC:
                    parameter = DNFieldExtractor.DC;
                    break;
                case SUBJECT_RDN_ST:
                    parameter = DNFieldExtractor.ST;
                    break;
                case SUBJECT_RDN_L:
                    parameter = DNFieldExtractor.L;
                    break;
                case SUBJECT_RDN_O:
                    parameter = DNFieldExtractor.O;
                    break;
                case SUBJECT_RDN_OU:
                    parameter = DNFieldExtractor.OU;
                    break;
                case SUBJECT_RDN_TITLE:
                    parameter = DNFieldExtractor.T;
                    break;
                case SUBJECT_RDN_UID:
                    parameter = DNFieldExtractor.UID;
                    break;
                case SUBJECT_RDN_E:
                    parameter = DNFieldExtractor.E;
                    break;
                case SUBJECT_RDN_C:
                    parameter = DNFieldExtractor.C;
                    break;
                case SUBJECT_ALTNAME_RFC822NAME:
                    parameter = DNFieldExtractor.RFC822NAME;
                    usedExtractor = anExtractor;
                    break;
                case SUBJECT_ALTNAME_MSUPN:
                    parameter = DNFieldExtractor.UPN;
                    usedExtractor = anExtractor;
                    break;
                default: // It should not happen though
                    throw new AssertionError(type.name());
                }

                final int size = usedExtractor.getNumberOfFields(parameter);
                
                
                if (size == 0) {
                    fields.add(new AuthField(false, type, label, null));
                } else {
                    for (int i = 0; i < size; i++) {
                        final String subjectValue = usedExtractor.getField(parameter, i);
                        fields.add(new AuthField(i == 0, type, label, subjectValue));
                    }
                }
            }
        }
        
        return fields;
    }

    public String getCert() {
        return cert;
    }

    public void setCert(String cert) {
        this.cert = StringUtils.trim(cert);
    }

    public boolean isFromCertificate() {
        return fromCertificate;
    }

    public boolean isImportState() {
        return importState;
    }

    public List<SelectItem> getMatchWithSubjectTypes() {
        List<SelectItem> result = new ArrayList<>();
        FacesContext context = FacesContext.getCurrentInstance();
        ResourceBundle bundle = context.getApplication().getResourceBundle(context, "text");
        
        for (MatchSubjectWithType type : MatchSubjectWithType.values()) {
            result.add(new SelectItem(bundle.getString(type.name()), type.name()));
        }

        return result;
    }
    
    public List<SelectItem> getMatchWithIssuerTypes() {
        List<SelectItem> result = new ArrayList<>();
        FacesContext context = FacesContext.getCurrentInstance();
        ResourceBundle bundle = context.getApplication().getResourceBundle(context, "text");

        for (MatchIssuerWithType type : MatchIssuerWithType.values()) {
            result.add(new SelectItem(bundle.getString(type.name()), type.name()));
        }

        return result;
    }

    public String getMatchSubjectWithType() {
        return matchSubjectWithType;
    }

    public void setMatchSubjectWithType(String matchSubjectWithType) {
        this.matchSubjectWithType = StringUtils.trim(matchSubjectWithType);
    }

    public String getMatchIssuerWithType() {
        return matchIssuerWithType;
    }

    public void setMatchIssuerWithType(String matchIssuerWithType) {
        this.matchIssuerWithType = StringUtils.trim(matchIssuerWithType);
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = StringUtils.trim(description);
    }    

    public String getMatchSubjectWithValue() {
        return matchSubjectWithValue;
    }

    public void setMatchSubjectWithValue(String matchSubjectWithValue) {
        this.matchSubjectWithValue = matchSubjectWithValue;
    }

    public String getMatchIssuerWithValue() {
        return matchIssuerWithValue;
    }

    public void setMatchIssuerWithValue(String matchIssuerWithValue) {
        this.matchIssuerWithValue = matchIssuerWithValue;
    }

    public String getOldMatchSubjectWithType() {
        if (oldMatchSubjectWithType == null) {
            oldMatchSubjectWithType = matchSubjectWithType;
        }
        return oldMatchSubjectWithType;
    }

    public void setOldMatchSubjectWithType(String oldMatchSubjectWithType) {
        this.oldMatchSubjectWithType = StringUtils.trim(oldMatchSubjectWithType);
    }

    public String getOldMatchIssuerWithType() {
        if (oldMatchIssuerWithType == null) {
            oldMatchIssuerWithType = matchIssuerWithType;
        }
        return oldMatchIssuerWithType;
    }

    public void setOldMatchIssuerWithType(String oldMatchIssuerWithType) {
        this.oldMatchIssuerWithType = StringUtils.trim(oldMatchIssuerWithType);
    }

    public String getOldMatchSubjectWithValue() {
        if (oldMatchSubjectWithValue == null) {
            oldMatchSubjectWithValue = matchSubjectWithValue;
        }
        return oldMatchSubjectWithValue;
    }

    public void setOldMatchSubjectWithValue(String oldMatchSubjectWithValue) {
        this.oldMatchSubjectWithValue = StringUtils.trim(oldMatchSubjectWithValue);
    }

    public String getOldMatchIssuerWithValue() {
        if (oldMatchIssuerWithValue == null) {
            oldMatchIssuerWithValue = matchIssuerWithValue;
        }
        return oldMatchIssuerWithValue;
    }

    public void setOldMatchIssuerWithValue(String oldMatchIssuerWithValue) {
        this.oldMatchIssuerWithValue = StringUtils.trim(oldMatchIssuerWithValue);
    }

    public String getOldDescription() {
        if (oldDescription == null) {
            oldDescription = description;
        }
        return oldDescription;
    }

    public void setOldDescription(String oldDescription) {
        this.oldDescription = StringUtils.trim(oldDescription);
    }
    
    /**
     * Checks that the provided old rule actually exists.
     * @return true if it exists
     * @throws AdminNotAuthorizedException 
     */
    public boolean isExistingRule() throws AdminNotAuthorizedException {
        CertificateMatchingRule certMatchingRule = new CertificateMatchingRule();
        certMatchingRule.setMatchIssuerWithValue(getOldMatchIssuerWithValue());
        certMatchingRule.setMatchSubjectWithValue(getOldMatchSubjectWithValue());
        certMatchingRule.setDescription(getOldDescription());
        certMatchingRule.setMatchSubjectWithType(MatchSubjectWithType.valueOf(getOldMatchSubjectWithType()));
        certMatchingRule.setMatchIssuerWithType(MatchIssuerWithType.valueOf(getOldMatchIssuerWithType()));
        return getAuthorizedClientsGen2().contains(certMatchingRule);
    }

    /**
     * Reload authorizations from database. 
     */
    public String reloadFromDatabase() throws AdminNotAuthorizedException {
        // invalidate old cached config
        config = null;

        config = getConfig();
        
        return "worker-authorization?faces-redirect=true&amp;includeViewParams=true&amp;id=" + getId();
    }

    /**
     * Bean representing a subject field from a loaded certificate.
     */
    public static class AuthField {
        private boolean selectable;
        private MatchSubjectWithType subjectMatchType;
        private String subjectMatchLabel;
        private String subjectMatchValue;
        
        /**
         * Create a new instance of the bean.
         *
         * @param selectable True if the field should be possible to select in the UI
         * @param subjectMatchType The subject type
         * @param subjectMatchLabel The label to show for the type in the UI
         * @param subjectMatchValue The value for the subject (or null if not available from the certificate)
         */
        public AuthField(final boolean selectable,
                         final MatchSubjectWithType subjectMatchType,
                         final String subjectMatchLabel,
                         final String subjectMatchValue) {
            this.selectable = selectable;
            this.subjectMatchType = subjectMatchType;
            this.subjectMatchLabel = subjectMatchLabel;
            this.subjectMatchValue = subjectMatchValue;
        }

        public boolean getSelectable() {
            return selectable;
        }
        
        public MatchSubjectWithType getSubjectMatchType() {
            return subjectMatchType;
        }

        public String getSubjectMatchLabel() {
            return subjectMatchLabel;
        }

        public String getSubjectMatchValue() {
            return subjectMatchValue;
        }
        
        public void setSelectable(final boolean selectable) {
            this.selectable = selectable;
        }

        public void setSubjectMatchType(final MatchSubjectWithType subjectMatchType) {
            this.subjectMatchType = subjectMatchType;
        }

        public void setSubjectMatchLabel(final String subjectMatchLabel) {
            this.subjectMatchLabel = subjectMatchLabel;
        }

        public void setSubjectMatchValue(final String subjectMatchValue) {
            this.subjectMatchValue = subjectMatchValue;
        }
    }
}
