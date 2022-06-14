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

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Optional;
import java.util.Properties;
import java.util.concurrent.ThreadLocalRandom;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ViewScoped;
import javax.faces.context.ExternalContext;
import javax.faces.context.FacesContext;
import org.apache.commons.lang.StringUtils;
import org.signserver.server.cesecore.certificates.util.AlgorithmConstants;
import org.signserver.server.cesecore.certificates.util.AlgorithmTools;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.GenericSignResponse;
import org.signserver.common.PKCS10CertReqInfo;
import org.signserver.common.ProcessResponse;
import org.signserver.common.RequestAndResponseManager;
import org.signserver.common.WorkerConfig;
import org.signserver.admin.common.auth.AdminNotAuthorizedException;
import org.signserver.common.AbstractCertReqData;

/**
 *
 * @author Markus Kilås
 * @version $Id$
 */
@ManagedBean
@ViewScoped
public class CSRBulkBean extends BulkBean {

    private static final String FORMAT_STANDARD = "standard";

    private static final String FORMAT_SIGNED = "signed";
    private static final String CONTENT_TYPE_SIGNED = "application/pkcs7-signature";
    private static final String FILESUFFIX_SIGNED = ".p7s";

    private List<CSRWorker> myWorkers;
    private String format;
    private String requestSigner;

    private List<String> keysList;
    private String keys;

    /**
     * Creates a new instance of CSRBulkBean.
     */
    public CSRBulkBean() {

    }

    private void initSigning() throws AdminNotAuthorizedException {
        // Find and select first matching REQUESTSIGNER
        for (CSRWorker w : getCSRWorkers()) {
            final String signer = (String) w.getConfig()
                    .get("REQUESTSIGNER");
            if (signer != null && getAvailableWorkersMenu().stream().anyMatch(a -> a.getItemValue().equalsIgnoreCase(signer))) {
                requestSigner = signer;
                break;
            }
        }

        format = requestSigner == null ? FORMAT_STANDARD : FORMAT_SIGNED;
    }

    public List<CSRWorker> getCSRWorkers() throws AdminNotAuthorizedException {
        if (myWorkers == null) {
            myWorkers = new ArrayList<>();
            int index = 0;
            Iterator<String> ks = getKeysList().iterator();
            for (int id : getWorkerIdsList()) {
                WorkerConfig config = getWorkerSessionBean().getCurrentWorkerConfig(getAuthBean().getAdminCertificate(), id);
                String name = config.getProperty("NAME");
                boolean exists = true;
                if (name == null) {
                    name = "Not Found";
                    exists = false;
                }

                String alias = ks.hasNext() ? ks.next() : null;
                final boolean fixedAlias;

                if (alias == null || alias.isEmpty()) {
                    alias = config.getProperty("NEXTCERTSIGNKEY");
                    if (alias == null) {
                        alias = config.getProperty("DEFAULTKEY");
                    }
                    fixedAlias = false;
                } else {
                    fixedAlias = true;
                }

                String signatureAlgorithm = config.getProperty("SIGNATUREALGORITHM", "");
                String requestDN = config.getProperty("REQUESTDN", "");

                myWorkers.add(new CSRWorker(id, exists, name, config.getProperties(), alias, signatureAlgorithm, requestDN, index++, fixedAlias));

                // Select checkbox
                getSelectedIds().put(id, exists);
            }
        }
        return myWorkers;
    }

    public String getKeys() {
        return keys;
    }

    public void setKeys(String keys) {
        this.keys = StringUtils.trim(keys);
    }

    public List<String> getKeysList() {
        if (keysList == null) {
            keysList = new ArrayList<>();
            if (keys != null) {
                String[] split = keys.split(",");
                keysList = Arrays.asList(split);
            }
        }
        return keysList;
    }

    public List<CSRWorker> getSelectedTestKeyWorkers() throws AdminNotAuthorizedException {
        final ArrayList<CSRWorker> results = new ArrayList<>(getSelectedIds().size());
        for (CSRWorker worker : getCSRWorkers()) {
            if (Boolean.TRUE.equals(getSelectedIds().get(worker.getId()))) {
                results.add(worker);
            }
        }
        return results;
    }

    public String getFORMAT_STANDARD() {
        return FORMAT_STANDARD;
    }

    public String getFORMAT_SIGNED() {
        return FORMAT_SIGNED;
    }

    public String getFormat() throws AdminNotAuthorizedException {
        if (format == null) {
            initSigning();
        }
        return format;
    }

    public void setFormat(String format) {
        this.format = format;
    }

    public String getRequestSigner() throws AdminNotAuthorizedException {
        if (requestSigner == null) {
            initSigning();
        }
        return requestSigner;
    }

    public void setRequestSigner(String requestSigner) {
        this.requestSigner = requestSigner;
    }

    @SuppressWarnings("UseSpecificCatch") // We really want to catch all sorts of exceptions
    public void generateAction() throws AdminNotAuthorizedException {
        //FacesMessage errorMessage = new FacesMessage("Test error");
        //errorMessage.setSeverity(FacesMessage.SEVERITY_ERROR);
        //FacesContext.getCurrentInstance().addMessage(null, errorMessage);

        for (CSRWorker worker : getSelectedTestKeyWorkers()) {

            try {
                final boolean explicitEccParameters
                        = Boolean.parseBoolean(worker.getConfig().getProperty(WorkerConfig.PROPERTY_EXPLICITECC, "false"));
                final PKCS10CertReqInfo certReqInfo
                        = new PKCS10CertReqInfo();
                certReqInfo.setSignatureAlgorithm(worker.signatureAlgorithm);
                certReqInfo.setSubjectDN(worker.dn);
                certReqInfo.setAttributes(null);

                final AbstractCertReqData reqData = getWorkerSessionBean()
                        .getPKCS10CertificateRequestForAlias(getAuthBean().getAdminCertificate(), worker.getId(),
                                certReqInfo, explicitEccParameters, worker.getAlias());

                if (reqData == null) {
                    worker.setError("Unable to generate certificate request");
                } else {
                    byte[] fileContent;
                    if (FORMAT_STANDARD.equals(format)) {
                        fileContent = reqData.toArmoredForm().getBytes(StandardCharsets.UTF_8);
                        worker.setContentType(reqData.getContentType());
                        worker.setFileSuffix(reqData.getFileSuffix());
                    } else {
                        GenericSignRequest req = new GenericSignRequest(ThreadLocalRandom.current().nextInt(), reqData.toArmoredForm().getBytes(StandardCharsets.UTF_8));

                        final Collection<byte[]> results
                                = getWorkerSessionBean().process(getAuthBean().getAdminCertificate(),
                                        String.valueOf(requestSigner),
                                        Collections.singletonList(RequestAndResponseManager.serializeProcessRequest(req)));
                        ProcessResponse response = RequestAndResponseManager.parseProcessResponse(results.iterator().next());
                        fileContent = ((GenericSignResponse) response).getProcessedData();
                        worker.setContentType(CONTENT_TYPE_SIGNED);
                        worker.setFileSuffix(FILESUFFIX_SIGNED);
                    }
                    worker.setPemFile(fileContent);
                    worker.setSuccess(null);
                    worker.setError(null);

                    getSelectedIds().remove(worker.getId());
                }
            } catch (Exception ex) {
                worker.setSuccess(null);
                worker.setError("Failed: " + ex.getMessage());
            }
        }

        /*if (getSelectedIds().isEmpty()) {
            return "workers";
        } else*/ {
            //return "";
        }
    }

    public void downloadAction(CSRWorker worker) throws IOException {
        final FacesContext context = FacesContext.getCurrentInstance();
        final ExternalContext externalContext = context.getExternalContext();
        final byte[] body = worker.getPemFile();

        externalContext.responseReset();
        externalContext.setResponseContentType(worker.getContentType());
        externalContext.setResponseContentLength(body.length);
        externalContext.setResponseHeader("Content-Disposition", "attachment; filename=\"" + worker.getName() + "-" + worker.getAlias() + worker.fileSuffix);

        try (OutputStream out = externalContext.getResponseOutputStream()) {
            out.write(body);
        }

        context.responseComplete();
    }

    public static class CSRWorker extends Worker {

        private String alias;
        private String signatureAlgorithm;
        private String dn;
        private byte[] pemFile;
        private final int rowIndex;
        private boolean showOther;
        private List<SelectItem> aliasMenuValues;
        private String contentType;
        private String fileSuffix;
        private final boolean fixedAlias;
        private boolean selectSignatureAlgorithmFromList = true;
        private List<SelectItem> signatureAlgorithmMenuValues;

        public CSRWorker(int id, boolean exists, String name, Properties config, String alias, String signatureAlgorithm, String dn, int rowIndex, boolean fixedAlias) {
            super(id, exists, name, config);
            this.alias = alias;
            this.signatureAlgorithm =
                    getNormalizedSignatureAlgorithm(signatureAlgorithm);
            this.dn = dn;
            this.rowIndex = rowIndex;
            if (alias == null) {
                showOther = true;
            }
            if (StringUtils.isBlank(signatureAlgorithm)) {
                this.signatureAlgorithm = AlgorithmConstants.SIGALG_SHA256_WITH_RSA;
            }
            this.fixedAlias = fixedAlias;
        }

        public String getAlias() {
            return alias;
        }

        public void setAlias(String alias) {
            this.alias = alias;
        }

        public String getSignatureAlgorithm() {
            return signatureAlgorithm;
        }

        public void setSignatureAlgorithm(String signatureAlgorithm) {
            this.signatureAlgorithm =
                    getNormalizedSignatureAlgorithm(signatureAlgorithm);
        }

        /**
         * Returns a signature algorithm normalized according to the 
         * representations in CESeCore, if matching one of these, otherwise
         * returns the passed in value.
         * 
         * @param sigAlg algorithm name to match
         * @return matched algorithm name, or the passed in value if not matched
         */
        private String getNormalizedSignatureAlgorithm(final String sigAlg) {
            final String trimmedSigAlg = StringUtils.trim(sigAlg);
            List<SelectItem> knownAlgs = getSignatureAlgorithmMenuValues();
            String result = sigAlg;
            Optional<SelectItem> first = knownAlgs.stream().filter(alg -> alg.getItemValue().equalsIgnoreCase(trimmedSigAlg)).findFirst();
            if (first.isPresent()) {
                result = first.get().getItemValue();
            }
            return result;
        }

        public String getDn() {
            return dn;
        }

        public void setDn(String dn) {
            this.dn = dn;
        }

        public byte[] getPemFile() {
            return pemFile;
        }

        public void setPemFile(byte[] pemFile) {
            this.pemFile = pemFile;
        }

        public boolean isShowOther() {
            return showOther;
        }

        public void setShowOther(boolean showOther) {
            this.showOther = showOther || alias == null || alias.isEmpty();
            aliasMenuValues = null;
        }

//        public UploadedFile getUploadedFile() {
//            return uploadedFile;
//        }
//
//        public void setUploadedFile(UploadedFile uploadedFile) {
//            this.uploadedFile = uploadedFile;
//        }
        public int getRowIndex() {
            return rowIndex;
        }

        public boolean isFixedAlias() {
            return fixedAlias;
        }

        public boolean isSelectSignatureAlgorithmFromList() {
            return selectSignatureAlgorithmFromList;
        }

        public void setSelectSignatureAlgorithmFromList(final boolean selectSignatureAlgorithmFromList) {
            this.selectSignatureAlgorithmFromList = selectSignatureAlgorithmFromList;
        }

        public List<SelectItem> getSignatureAlgorithmMenuValues() {
            if (signatureAlgorithmMenuValues == null) {
                signatureAlgorithmMenuValues = new ArrayList<>();
                AlgorithmTools.SIG_ALGS_RSA.forEach((alg) -> {
                    signatureAlgorithmMenuValues.add(new SelectItem(alg, alg));
                });
                AlgorithmTools.SIG_ALGS_DSA.forEach((alg) -> {
                    signatureAlgorithmMenuValues.add(new SelectItem(alg, alg));
                });
                AlgorithmTools.SIG_ALGS_ECDSA.forEach((alg) -> {
                    signatureAlgorithmMenuValues.add(new SelectItem(alg, alg));
                });
                AlgorithmTools.SIG_ALG_EDDSA.forEach((alg) -> {
                  signatureAlgorithmMenuValues.add(new SelectItem(alg, alg));
                });
                AlgorithmTools.SIG_ALGS_ECGOST3410.forEach((alg) -> {
                    signatureAlgorithmMenuValues.add(new SelectItem(alg, alg));
                });
                AlgorithmTools.SIG_ALGS_DSTU4145.forEach((alg) -> {
                    signatureAlgorithmMenuValues.add(new SelectItem(alg, alg));
                });
            }
            return signatureAlgorithmMenuValues;
        }

        public List<SelectItem> getAliasMenuValues() {
            if (aliasMenuValues == null) {
                aliasMenuValues = new ArrayList<>();
                Properties config = getConfig();
                String defaultKey = config.getProperty("DEFAULTKEY");
                if (defaultKey != null) {
                    aliasMenuValues.add(new SelectItem("Default key (" + defaultKey + ")", defaultKey));
                }
                String nextKey = config.getProperty("NEXTCERTSIGNKEY");
                if (nextKey != null) {
                    aliasMenuValues.add(new SelectItem("Next key (" + nextKey + ")", nextKey));
                }
                if (alias != null && !alias.equals(defaultKey) && !alias.equals(nextKey)) {
                    aliasMenuValues.add(new SelectItem("Other key (" + alias + ")", alias));
                }
            }
            return aliasMenuValues;
        }

        public String getAliasMenuValuesFirst() {
            return aliasMenuValues.iterator().next().getItemValue();
        }

        public String getContentType() {
            return contentType;
        }

        public void setContentType(String contentType) {
            this.contentType = contentType;
        }

        public String getFileSuffix() {
            return fileSuffix;
        }

        public void setFileSuffix(String fileSuffix) {
            this.fileSuffix = fileSuffix;
        }

    }
}
