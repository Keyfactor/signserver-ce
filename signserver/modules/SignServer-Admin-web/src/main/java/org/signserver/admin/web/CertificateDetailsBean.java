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
import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Properties;
import javax.ejb.EJB;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ManagedProperty;
import javax.faces.bean.ViewScoped;
import javax.faces.context.ExternalContext;
import javax.faces.context.FacesContext;
import javax.faces.event.AjaxBehaviorEvent;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.WordUtils;
import org.apache.commons.lang.time.FastDateFormat;
import org.apache.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaMiscPEMGenerator;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.pem.PemWriter;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.util.query.elems.RelationalOperator;
import org.signserver.admin.common.query.QueryCondition;
import org.signserver.admin.common.query.QueryOrdering;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.NoSuchWorkerException;
import org.signserver.common.OperationUnsupportedException;
import org.signserver.common.QueryException;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.server.cryptotokens.CryptoTokenHelper;
import org.signserver.server.cryptotokens.TokenEntry;
import org.signserver.server.cryptotokens.TokenSearchResults;
import org.signserver.admin.common.auth.AdminNotAuthorizedException;
import org.signserver.admin.web.ejb.AdminWebSessionBean;

/**
 *
 * @author Markus Kilås
 * @version $Id$
 */
@ManagedBean
@ViewScoped
public class CertificateDetailsBean {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(CertificateDetailsBean.class);

    private static final FastDateFormat FDF = FastDateFormat.getInstance("yyyy-MM-dd HH:mm:ss zz");

    private static final String CONTENT_TYPE = "application/pkix-cert";
    private static final String FILE_SUFFIX = ".pem";
    
    public static final String PANE_GENERAL = "general";
    public static final String PANE_DETAILS = "details";

    //@ManagedProperty(value = "#{param.id}")
    private Integer id;

    @EJB
    private AdminWebSessionBean workerSessionBean;

    @ManagedProperty(value = "#{authenticationBean}")
    private AuthenticationBean authBean;

    private Worker worker;
    private WorkerConfig workerConfig;

    private boolean withChain;
    private String keyInToken;

    private boolean generalPanel = true;
    private GeneralCertificate general;
    private X509Certificate certificate;
    private List<Certificate> certificateChain;

    private DetailedCertificate detailed;
    private List<DetailedCertificate> detailedList;
    private String detailedListSelection;

    /**
     * Creates a new instance of WorkerBean
     */
    public CertificateDetailsBean() {
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

    public boolean isGeneralPanel() {
        return generalPanel;
    }

    private WorkerConfig getWorkerConfig() throws AdminNotAuthorizedException {
        if (workerConfig == null) {
            workerConfig = workerSessionBean.getCurrentWorkerConfig(authBean.getAdminCertificate(), getId());
        }
        return workerConfig;
    }

    public String workerAction(String page) {
        StringBuilder sb = new StringBuilder();
        sb.append(page);
        sb.append("?faces-redirect=true&amp;includeViewParams=true");
        return sb.toString();
    }

    public String bulkAction(String page) {
        StringBuilder sb = new StringBuilder();
        sb.append(page);
        sb.append("?faces-redirect=true&amp;workers=").append(getId()); // TODO: +Going back page / viewing navigation path
        return sb.toString();
    }

    public boolean isWithChain() {
        return withChain;
    }

    public void setWithChain(boolean withChain) {
        this.withChain = withChain;
    }

    public boolean isForKeyInToken() {
        return keyInToken != null && !keyInToken.isEmpty();
    }

    public String getPane() {
        return generalPanel ? PANE_GENERAL : PANE_DETAILS;
    }

    public void setPane(String pane) {
        generalPanel = !pane.equals(PANE_DETAILS);
    }

    public String getPANE_GENERAL() {
        return PANE_GENERAL;
    }

    public String getPANE_DETAILS() {
        return PANE_DETAILS;
    }

    public void detailsPanelAction() {
        generalPanel = false;
    }

    public void generalPanelAction() {
        generalPanel = true;
    }

    public GeneralCertificate getGeneral() throws AdminNotAuthorizedException {
        if (general == null) {
            general = new GeneralCertificate();
            try {
                if (certificate == null) {
                    if (keyInToken != null && !keyInToken.isEmpty()) {
                        try {
                            TokenSearchResults search = workerSessionBean.queryTokenEntries(authBean.getAdminCertificate(), getId(), 0, 1, Arrays.asList(new QueryCondition(CryptoTokenHelper.TokenEntryFields.keyAlias.name(), RelationalOperator.EQ, keyInToken)), Collections.<QueryOrdering>emptyList(), true);
                            if (search.getEntries().isEmpty()) {
                                LOG.error("No result");
                            } else {
                                TokenEntry entry = search.getEntries().get(0);
                                certificateChain = Arrays.asList(entry.getParsedChain());
                                if (!certificateChain.isEmpty()) {
                                    certificate = (X509Certificate) certificateChain.iterator().next();
                                }
                            }
                        } catch (OperationUnsupportedException | CryptoTokenOfflineException | QueryException | InvalidWorkerIdException | AuthorizationDeniedException | SignServerException | CertificateException ex) {
                            LOG.error(ex);
                        }
                    } else if (withChain) {
                        certificateChain = workerSessionBean.getSignerCertificateChain(authBean.getAdminCertificate(), getId());
                        if (certificateChain != null) {
                            certificate = (X509Certificate) certificateChain.iterator().next();
                        }
                    } else {
                        certificate = (X509Certificate) workerSessionBean.getSignerCertificate(authBean.getAdminCertificate(), getId());
                        certificateChain = Arrays.asList((Certificate) certificate);
                    }
                }

                if (certificate != null) {
                    general.setExists(true);

                    final List<String> usages = general.getUsages();
                    final boolean[] keyUsages = certificate.getKeyUsage();
                    if (keyUsages != null) {
                        // digitalSignature        (0),
                        if (keyUsages[0]) {
                            usages.add("digitalSignature");
                        }
                        // nonRepudiation          (1),
                        if (keyUsages[1]) {
                            usages.add("nonRepudiation");
                        }
                        // keyEncipherment         (2),
                        if (keyUsages[2]) {
                            usages.add("keyEncipherment");
                        }
                        // dataEncipherment        (3),
                        if (keyUsages[3]) {
                            usages.add("dataEncipherment");
                        }
                        // keyAgreement            (4),
                        if (keyUsages[4]) {
                            usages.add("keyAgreement");
                        }
                        // keyCertSign             (5),
                        if (keyUsages[5]) {
                            usages.add("keyCertSign");
                        }
                        // cRLSign                 (6),
                        if (keyUsages[6]) {
                            usages.add("cRLSign");
                        }
                        // encipherOnly            (7),
                        if (keyUsages[7]) {
                            usages.add("encipherOnly");
                        }
                        // decipherOnly
                        if (keyUsages[8]) {
                            usages.add("decipherOnly");
                        }
                    }

                    general.setIssuer(certificate.getIssuerDN().getName());
                    general.setSerialNumber(certificate.getSerialNumber().toString(16));
                    general.setSubject(certificate.getSubjectDN().getName());

                    general.setNotBefore(FDF.format(certificate.getNotBefore()));
                    general.setNotAfter(FDF.format(certificate.getNotAfter()));

                    byte[] certBytes = certificate.getEncoded();
                    for (String algorithm : new String[]{"SHA1", "SHA-256"}) {
                        try {
                            general.getFingerprints().add(new KeyValue<>(algorithm, Hex.toHexString(MessageDigest.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME).digest(certBytes))));
                        } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
                            LOG.error("Algorithm not supported: " + ex.getLocalizedMessage());
                        }
                    }
                }
            } catch (CertificateEncodingException ex) {
                LOG.error(ex.getLocalizedMessage(), ex);
            } catch (CryptoTokenOfflineException ignored) {
            } // NOPMD

        }
        return general;
    }

    public DetailedCertificate getDetailed() {
        if (detailed == null) {
            detailed = getDetailedList().get(0);
        }
        return detailed;
    }

    public List<DetailedCertificate> getDetailedList() {
        if (detailedList == null) {
            detailedList = new ArrayList<>(certificateChain.size());
            int count = 0;
            for (Certificate cert : certificateChain) {
                if (cert instanceof X509Certificate) {
                    X509Certificate xCert = (X509Certificate) cert;
                    DetailedCertificate dc = new DetailedCertificate(cert);

                    dc.setVersion(String.valueOf(xCert.getVersion()));
                    dc.setSerialNumber(xCert.getSerialNumber().toString(16));
                    dc.setIssuer(xCert.getIssuerDN().getName());
                    dc.setNotBefore(FDF.format(xCert.getNotBefore()));
                    dc.setNotAfter(FDF.format(xCert.getNotAfter()));
                    dc.setSubject(xCert.getSubjectDN().getName());

                    dc.setKeyAlgorithm(xCert.getPublicKey().getAlgorithm());
                    dc.setPublicKey(WordUtils.wrap(Hex.toHexString(xCert.getPublicKey().getEncoded()), 100, "\n", true));

                    if (xCert.getCriticalExtensionOIDs() != null) {
                        for (String extensionOid : xCert.getCriticalExtensionOIDs()) {
                            // TODO: Parse extension names and values
                            dc.getCriticalExtensions().add(new KeyValue<>(extensionOid, "<Not supported yet>"));
                        }
                    }

                    if (xCert.getNonCriticalExtensionOIDs() != null) {
                        for (String extensionOid : xCert.getNonCriticalExtensionOIDs()) {
                            // TODO: Parse extension names and values
                            dc.getCriticalExtensions().add(new KeyValue<>(extensionOid, "<Not supported yet>"));
                        }
                    }

                    dc.setSignatureAlgorithm(xCert.getSigAlgName());
                    dc.setSignatureValue(WordUtils.wrap(Hex.toHexString(xCert.getSignature()), 100, "\n", true));

                    try {
                        byte[] certBytes = xCert.getEncoded();
                        for (String algorithm : new String[]{"SHA1", "SHA-256"}) {
                            try {
                                dc.getFingerprints().add(new KeyValue<>(algorithm, Hex.toHexString(MessageDigest.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME).digest(certBytes))));
                            } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
                                LOG.error("Algorithm not supported: " + ex.getLocalizedMessage());
                            }
                        }
                    } catch (CertificateEncodingException ex) {
                        LOG.error("Unable to encode certificate: " + ex.getLocalizedMessage(), ex);
                    }

                    final StringBuilder name = new StringBuilder();
                    name.append(++count).append(": ");
                    if (dc.getSubject() != null) {
                        name.append(dc.getSubject());
                    } else {
                        name.append(dc.getSerialNumber());
                    }
                    dc.setFriendlyName(name.toString());

                    detailedList.add(dc);
                }
            }
        }
        return detailedList;
    }

    public String getDetailedListSelection() {
        if (detailedListSelection == null) {
            detailedListSelection = getDetailed().getFriendlyName();
        }
        return detailedListSelection;
    }

    public void setDetailedListSelection(String detailedListSelection) {
        this.detailedListSelection = detailedListSelection;
    }

    public void viewSelectedAction(AjaxBehaviorEvent event) {
        getDetailedListSelection();
        for (DetailedCertificate dc : getDetailedList()) {
            if (dc.getFriendlyName().equals(detailedListSelection)) {
                detailed = dc;
                break;
            }
        }
    }

    public void exportSelectedAction(boolean includeChain)
            throws IOException, AdminNotAuthorizedException, NoSuchWorkerException {
        List<Certificate> certs = new ArrayList<>();
        if (includeChain) {
            for (DetailedCertificate dc : getDetailedList()) {
                certs.add(dc.getCertificate());
            }
        } else {
            getDetailed();
            certs.add(detailed.getCertificate());
        }

        // Create PEM file
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        try (PemWriter writer = new PemWriter(new OutputStreamWriter(bout, StandardCharsets.US_ASCII))) {
            for (Certificate cert : certs) {
                writer.writeObject(new JcaMiscPEMGenerator(cert));
            }
        }

        // Send HTTP response
        final FacesContext context = FacesContext.getCurrentInstance();
        final ExternalContext externalContext = context.getExternalContext();
        final byte[] body = bout.toByteArray();

        externalContext.responseReset();
        externalContext.setResponseContentType(CONTENT_TYPE);
        externalContext.setResponseContentLength(body.length);
        externalContext.setResponseHeader("Content-Disposition", "attachment; filename=\"" + getWorker().getName() + "-"
                + (StringUtils.isNotEmpty(keyInToken) ? keyInToken + "-" : "")
                + "certificate-" + (certs.size() > 1 ? "chain" : detailed.getSerialNumber()) + FILE_SUFFIX);

        try (OutputStream out = externalContext.getResponseOutputStream()) {
            out.write(body);
        }

        context.responseComplete();
    }

    public String getKeyInToken() {
        return keyInToken;
    }

    public void setKeyInToken(String keyInToken) {
        this.keyInToken = keyInToken;
    }

    public boolean isCertificateAvailable() throws AdminNotAuthorizedException {
        return getGeneral().isExists();
    }

    public static final class GeneralCertificate {

        private final List<String> usages = new ArrayList<>(5);
        private String subject;
        private String serialNumber;
        private String issuer;
        private String notBefore;
        private String notAfter;
        private final List<KeyValue<String, String>> fingerprints = new ArrayList<>(5);
        private boolean exists;

        public List<String> getUsages() {
            return usages;
        }

        public String getSubject() {
            return subject;
        }

        public void setSubject(String subject) {
            this.subject = subject;
        }

        public String getSerialNumber() {
            return serialNumber;
        }

        public void setSerialNumber(String serialNumber) {
            this.serialNumber = serialNumber;
        }

        public String getIssuer() {
            return issuer;
        }

        public void setIssuer(String issuer) {
            this.issuer = issuer;
        }

        public String getNotBefore() {
            return notBefore;
        }

        public void setNotBefore(String notBefore) {
            this.notBefore = notBefore;
        }

        public String getNotAfter() {
            return notAfter;
        }

        public void setNotAfter(String notAfter) {
            this.notAfter = notAfter;
        }

        public List<KeyValue<String, String>> getFingerprints() {
            return fingerprints;
        }

        public boolean isExists() {
            return exists;
        }

        public void setExists(boolean exists) {
            this.exists = exists;
        }

    }

    public static class DetailedCertificate {

        private final Certificate certificate;
        private String friendlyName;
        private String version;
        private String serialNumber;
        private String issuer;
        private String notBefore;
        private String notAfter;
        private String subject;
        private String keyAlgorithm;
        private String publicKey;
        private final List<KeyValue<String, String>> criticalExtensions = new ArrayList<>();
        private final List<KeyValue<String, String>> nonCriticalExtensions = new ArrayList<>();
        private String signatureAlgorithm;
        private String signatureValue;
        private final List<KeyValue<String, String>> fingerprints = new ArrayList<>(5);

        public DetailedCertificate(Certificate certificate) {
            this.certificate = certificate;
        }

        public Certificate getCertificate() {
            return certificate;
        }

        public String getFriendlyName() {
            return friendlyName;
        }

        public void setFriendlyName(String friendlyName) {
            this.friendlyName = friendlyName;
        }

        public String getVersion() {
            return version;
        }

        public void setVersion(String version) {
            this.version = version;
        }

        public String getSerialNumber() {
            return serialNumber;
        }

        public void setSerialNumber(String serialNumber) {
            this.serialNumber = serialNumber;
        }

        public String getIssuer() {
            return issuer;
        }

        public void setIssuer(String issuer) {
            this.issuer = issuer;
        }

        public String getNotBefore() {
            return notBefore;
        }

        public void setNotBefore(String notBefore) {
            this.notBefore = notBefore;
        }

        public String getNotAfter() {
            return notAfter;
        }

        public void setNotAfter(String notAfter) {
            this.notAfter = notAfter;
        }

        public String getSubject() {
            return subject;
        }

        public void setSubject(String subject) {
            this.subject = subject;
        }

        public String getKeyAlgorithm() {
            return keyAlgorithm;
        }

        public void setKeyAlgorithm(String keyAlgorithm) {
            this.keyAlgorithm = keyAlgorithm;
        }

        public String getPublicKey() {
            return publicKey;
        }

        public void setPublicKey(String publicKey) {
            this.publicKey = publicKey;
        }

        public String getSignatureAlgorithm() {
            return signatureAlgorithm;
        }

        public void setSignatureAlgorithm(String signatureAlgorithm) {
            this.signatureAlgorithm = signatureAlgorithm;
        }

        public String getSignatureValue() {
            return signatureValue;
        }

        public void setSignatureValue(String signatureValue) {
            this.signatureValue = signatureValue;
        }

        public List<KeyValue<String, String>> getCriticalExtensions() {
            return criticalExtensions;
        }

        public List<KeyValue<String, String>> getNonCriticalExtensions() {
            return nonCriticalExtensions;
        }

        public List<KeyValue<String, String>> getFingerprints() {
            return fingerprints;
        }

    }
}
