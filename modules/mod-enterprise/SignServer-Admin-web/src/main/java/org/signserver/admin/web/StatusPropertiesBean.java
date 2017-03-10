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
    private static final String CERTIFICATE_CHAIN = "Certificate chain:";
    private static final String SIGNER_CERTIFICATE = "Signer certificate:";

    //@ManagedProperty(value = "#{param.id}")
    private Integer id;

    @EJB
    private AdminWebSessionBean workerSessionBean;

    @ManagedProperty(value = "#{authenticationBean}")
    private AuthenticationBean authBean;

    private Worker worker;
    private List<StatusProperty> statuses;
    private WorkerConfig workerConfig;

    /**
     * Creates a new instance of WorkerBean
     */
    public StatusPropertiesBean() {
    }

    public Worker getWorker() throws AdminNotAuthorizedException, NoSuchWorkerException {
        if (worker == null) {
            Properties conf = getWorkerConfig().getProperties();
            final String name = conf.getProperty("NAME");
            if (name == null) {
                throw new NoSuchWorkerException(String.valueOf(id));
            }
            worker = new Worker(id, true, name, conf);
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
        return id;
    }

    @SuppressWarnings("UseSpecificCatch") // We really want to catch all sorts of exceptions
    public List<StatusProperty> getStatuses() throws AdminNotAuthorizedException, NoSuchWorkerException {
        if (statuses == null) {

            statuses = new ArrayList<>(7);

            String tokenStatus;
            try {
                final WorkerStatus status = workerSessionBean.getStatus(getAuthBean().getAdminCertificate(), new WorkerIdentifier(id));
                tokenStatus = status.getFatalErrors().isEmpty() ? "ACTIVE" : "OFFLINE";
            } catch (InvalidWorkerIdException ex) {
                tokenStatus = "Unknown";
            } catch (Exception ex) {
                tokenStatus = "Unknown";
                LOG.error("Error getting status for worker " + id, ex);
            }

            statuses.add(new StatusProperty("ID", id, false));
            statuses.add(new StatusProperty("Name", getWorker().getName(), false));
            statuses.add(new StatusProperty("Token status", tokenStatus, false));

            try {
                Collection<? extends Certificate> certificateChain;
                Date notBefore = workerSessionBean.getSigningValidityNotBefore(authBean.getAdminCertificate(), (int) id);
                Date notAfter = workerSessionBean.getSigningValidityNotAfter(authBean.getAdminCertificate(), (int) id);
                Certificate certificate = workerSessionBean.getSignerCertificate(authBean.getAdminCertificate(), (int) id);
                try {
                    certificateChain = workerSessionBean.getSignerCertificateChain(authBean.getAdminCertificate(), id);
                } catch (EJBException ex) {
                    // Handle problem caused by bug in server
                    LOG.error("Error getting signer certificate chain", ex);
                    certificateChain = Collections.emptyList();
                }
                statuses.add(new StatusProperty("Validity not before:", notBefore, false));
                statuses.add(new StatusProperty("Validity not after:", notAfter, false));
                statuses.add(new StatusProperty(SIGNER_CERTIFICATE, certificate, certificate != null));
                statuses.add(new StatusProperty(CERTIFICATE_CHAIN, certificateChain, certificate != null && !certificateChain.isEmpty()));
            } catch (CryptoTokenOfflineException ex) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("offline: " + id);
                }
            } catch (RuntimeException ex) {
                LOG.warn("Methods not supported by server", ex);
            }

        }
        return statuses;
    }

    private WorkerConfig getWorkerConfig() throws AdminNotAuthorizedException {
        if (workerConfig == null) {
            workerConfig = workerSessionBean.getCurrentWorkerConfig(authBean.getAdminCertificate(), id);
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
        sb.append("?faces-redirect=true&amp;workers=").append(id); // TODO: +Going back page / viewing navigation path
        return sb.toString();
    }

    public String detailsAction(StatusProperty property) {
        final String outcome;
        if (property.getKey() == null) {
            outcome = null;
        } else switch (property.getKey()) {
            case SIGNER_CERTIFICATE:
                outcome = "certificate-details?faces-redirect=true&amp;worker=" + id;
                break;
            case CERTIFICATE_CHAIN:
                outcome = "certificate-details?faces-redirect=true&amp;worker=" + id + "&amp;chain=true";
                break;
            default:
                outcome = null;
                break;
        }
        return outcome;
    }

    public static class StatusProperty {

        private final String key;
        private final Object value;
        private final boolean hasDetails;
        private final String description;

        public StatusProperty(String key, Object value, boolean hasDetails) {
            this.key = key;
            this.value = value;
            this.hasDetails = hasDetails;
            this.description = parse(value);
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
