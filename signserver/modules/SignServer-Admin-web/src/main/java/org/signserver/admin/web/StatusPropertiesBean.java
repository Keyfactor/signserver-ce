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

import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Properties;
import java.util.ResourceBundle;
import javax.ejb.EJB;
import javax.ejb.EJBException;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ManagedProperty;
import javax.faces.bean.ViewScoped;
import org.apache.commons.lang.time.FastDateFormat;
import org.apache.log4j.Logger;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.NoSuchWorkerException;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerIdentifier;
import org.signserver.common.WorkerStatus;
import org.signserver.admin.common.auth.AdminNotAuthorizedException;
import org.signserver.admin.web.ejb.AdminWebSessionBean;
import static org.signserver.common.SignServerConstants.DISABLED;

/**
 *
 * @author Markus Kilås
 * @version $Id$
 */
@ManagedBean
@ViewScoped
public class StatusPropertiesBean {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(StatusPropertiesBean.class);

    private static final FastDateFormat FDF = FastDateFormat.getInstance("yyyy-MM-dd HH:mm:ss zz");
    private static final String CERTIFICATE_CHAIN = "Certificate_Chain_COLON";
    private static final String SIGNER_CERTIFICATE = "Signer_Certificate_COLON";

    //@ManagedProperty(value = "#{param.id}")
    private Integer id;

    @EJB
    private AdminWebSessionBean workerSessionBean;

    @ManagedProperty(value = "#{authenticationBean}")
    private AuthenticationBean authBean;
    
    @ManagedProperty("#{text}")
    private ResourceBundle text;

    private Worker worker;
    private List<StatusProperty> statuses;
    private WorkerConfig workerConfig;

    /**
     * Creates a new instance of WorkerBean
     */
    public StatusPropertiesBean() {
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

    @SuppressWarnings("UseSpecificCatch") // We really want to catch all sorts of exceptions
    public List<StatusProperty> getStatuses() throws AdminNotAuthorizedException, NoSuchWorkerException {
        if (statuses == null) {

            statuses = new ArrayList<>(7);

            String tokenStatus;
            try {
                tokenStatus = workerSessionBean.isTokenActive(getAuthBean().getAdminCertificate(), new WorkerIdentifier(getId())) ?
                              text.getString("ACTIVE") : text.getString("OFFLINE");
            } catch (InvalidWorkerIdException ex) {
                tokenStatus = text.getString("Unknown");
            } catch (Exception ex) {
                tokenStatus = text.getString("Unknown");
                LOG.error("Error getting status for worker " + getId(), ex);
            }

            String workerStatus;
            try {
                boolean workerSetAsDisabled = workerConfig.getProperty(DISABLED, "FALSE").equalsIgnoreCase("TRUE");
                if (workerSetAsDisabled) {
                    workerStatus = text.getString("DISABLED");
                } else {
                    final WorkerStatus status = workerSessionBean.getStatus(getAuthBean().getAdminCertificate(), new WorkerIdentifier(getId()));
                    workerStatus = status.getFatalErrors().isEmpty()
                            ? text.getString("ACTIVE") : text.getString("OFFLINE");
                }
            } catch (InvalidWorkerIdException ex) {
                workerStatus = text.getString("Unknown");
            } catch (Exception ex) {
                workerStatus = text.getString("Unknown");
                LOG.error("Error getting status for worker " + getId(), ex);
            }

            statuses.add(new StatusProperty(text.getString("ID"), getId(), false, null));
            statuses.add(new StatusProperty(text.getString("Name"), getWorker().getName(), false, null));
            statuses.add(new StatusProperty(text.getString("Worker_Status"), workerStatus, false, null));
            statuses.add(new StatusProperty(text.getString("Token_Status"), tokenStatus, false, null));

            try {
                Collection<? extends Certificate> certificateChain;
                Date notBefore = workerSessionBean.getSigningValidityNotBefore(authBean.getAdminCertificate(), (int) getId());
                Date notAfter = workerSessionBean.getSigningValidityNotAfter(authBean.getAdminCertificate(), (int) getId());
                Certificate certificate = workerSessionBean.getSignerCertificate(authBean.getAdminCertificate(), (int) getId());
                try {
                    certificateChain = workerSessionBean.getSignerCertificateChain(authBean.getAdminCertificate(), getId());
                } catch (EJBException ex) {
                    // Handle problem caused by bug in server
                    LOG.error("Error getting signer certificate chain", ex);
                    certificateChain = Collections.emptyList();
                }
                statuses.add(new StatusProperty(text.getString("Validity_Not_Before"),
                                                notBefore, false, null));
                statuses.add(new StatusProperty(text.getString("Validity_Not_After"),
                                                notAfter, false, null));
                statuses.add(new StatusProperty(text.getString(SIGNER_CERTIFICATE),
                                                certificate, certificate != null,
                                                "certificate-details?worker=" + getId()));
                statuses.add(new StatusProperty(text.getString(CERTIFICATE_CHAIN),
                                                certificateChain,
                                                certificate != null && !certificateChain.isEmpty(),
                                                "certificate-details?worker=" + getId() + "&amp;chain=true"));
            } catch (CryptoTokenOfflineException ex) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("offline: " + getId());
                }
            } catch (RuntimeException ex) {
                LOG.warn("Methods not supported by server", ex);
            }

        }
        return statuses;
    }

    private WorkerConfig getWorkerConfig() throws AdminNotAuthorizedException {
        if (workerConfig == null) {
            workerConfig = workerSessionBean.getCurrentWorkerConfig(authBean.getAdminCertificate(), getId());
        }
        return workerConfig;
    }

    public void setText(ResourceBundle text) {
        this.text = text;
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

    public static class StatusProperty {

        private final String key;
        private final Object value;
        private final boolean hasDetails;
        private final String description;
        private final String detailsOutcome;

        public StatusProperty(String key, Object value, boolean hasDetails, String detailsOutcome) {
            this.key = key;
            this.value = value;
            this.hasDetails = hasDetails;
            this.description = parse(value);
            this.detailsOutcome = detailsOutcome;
        }

        public String getKey() {
            return key;
        }

        public Object getValue() {
            return value;
        }

        public boolean isHasDetails() {
            return hasDetails;
        }

        public String getDescription() {
            return description;
        }

        public String getDetailsOutcome() {
            return detailsOutcome;
        }

        private String parse(Object value) {
            String result;
            if (value instanceof Date) {
                result = FDF.format((Date) value);
            } else if (value != null) {
                result = value.toString();
            } else {
                result = "";
            }

            if (result.length() > 50) {
                result = result.substring(0, 50) + "...";
            }

            return result;
        }

        @Override
        public String toString() {
            return description;
        }
    }

}
