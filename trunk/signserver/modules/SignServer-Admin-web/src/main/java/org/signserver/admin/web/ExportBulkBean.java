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
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateEncodingException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Properties;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ViewScoped;
import javax.faces.context.ExternalContext;
import javax.faces.context.FacesContext;
import org.apache.log4j.Logger;
import org.signserver.common.util.PropertiesDumper;
import org.signserver.admin.common.auth.AdminNotAuthorizedException;
import org.signserver.common.CertificateMatchingRule;

/**
 *
 * @author Markus Kilås
 * @version $Id$
 */
@ManagedBean
@ViewScoped
public class ExportBulkBean extends BulkBean {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(ExportBulkBean.class);

    private static final String EXPORT_ALL_WORKERS = "all";
    private static final String EXPORT_NO_WORKERS = "no";
    private static final String EXPORT_SELECTED_WORKERS = "selected";

    private static final String FILE_SUFFIX = ".properties";

    private String reloadTarget;
    private Boolean exportNonWorkerGlobalConfig = false;

    private List<MyWorker> myWorkers;
    private Properties outProperties;
    private String error;
    private String success;
    private boolean generated;

    /**
     * Creates a new instance of WorkersManagedBean
     */
    public ExportBulkBean() {

    }

    public List<MyWorker> getMyWorkers() throws AdminNotAuthorizedException {
        if (myWorkers == null) {
            myWorkers = new ArrayList<>();
            for (int id : getWorkerIdsList()) {
                Properties config = getWorkerSessionBean().getProperties(getAuthBean().getAdminCertificate(), id);
                String name = config.getProperty("NAME");
                boolean exists = true;
                if (name == null) {
                    name = "Not Found";
                    exists = false;
                }

                Collection<CertificateMatchingRule> authorizedClients = getWorkerSessionBean().getAuthorizedClientsGen2(getAuthBean().getAdminCertificate(), id);

                MyWorker worker = new MyWorker(id, exists, name, config, authorizedClients);
                myWorkers.add(worker);

                // Select checkbox
                getSelectedIds().put(id, exists);
            }
        }
        return myWorkers;
    }

    public List<MyWorker> getMySelectedWorkers() throws AdminNotAuthorizedException {
        final ArrayList<MyWorker> results = new ArrayList<>(getSelectedIds().size());
        for (MyWorker worker : getMyWorkers()) {
            if (Boolean.TRUE.equals(getSelectedIds().get(worker.getId()))) {
                results.add(worker);
            }
        }
        return results;
    }

    public boolean isGenerated() {
        return generated;
    }

    public String generateAction() {
        generated = false;
        try {
            Properties globalConfig = getWorkerSessionBean().getGlobalConfiguration(getAuthBean().getAdminCertificate()).getConfig();
            outProperties = new Properties();

            if (exportNonWorkerGlobalConfig) {
                PropertiesDumper.dumpNonWorkerSpecificGlobalConfiguration(globalConfig, outProperties);
            }

            final List<MyWorker> workers;
            if (reloadTarget == null) {
                workers = Collections.emptyList();
            } else switch (reloadTarget) {
                case EXPORT_ALL_WORKERS:
                    workers = getAllWorkers();
                    break;
                case EXPORT_SELECTED_WORKERS:
                    workers = getMySelectedWorkers();
                    break;
                default:
                    workers = Collections.emptyList();
                    break;
            }

            for (MyWorker worker : workers) {
                PropertiesDumper.dumpWorkerPropertiesGen2(worker.getId(), globalConfig, worker.getConfig(), worker.getAuthorizedClientsGen2(), outProperties);
            }

            if (!outProperties.isEmpty()) {
                error = null;
                success = "Configuration exported successfully";
                generated = true;
            } else {
                error = "Nothing selected";
                success = null;
            }
        } catch (AdminNotAuthorizedException e) {
            error = "Authorization denied:\n" + e.getLocalizedMessage();
            success = null;
        } catch (CertificateEncodingException e) {
            error = "Failed to encode certificate:\n" + e.getLocalizedMessage();
            success = null;
        }
        return "";
    }

    public String downloadAction() {
        if (generated) {
            final FacesContext context = FacesContext.getCurrentInstance();
            final ExternalContext externalContext = context.getExternalContext();
            try (OutputStream out = externalContext.getResponseOutputStream()) {
                ByteArrayOutputStream bout = new ByteArrayOutputStream();
                outProperties.store(bout, null);
                String properties = bout.toString(StandardCharsets.ISO_8859_1.name());
                final byte[] body = properties.getBytes(StandardCharsets.ISO_8859_1);

                externalContext.responseReset();
                externalContext.setResponseContentType("text/plain");
                externalContext.setResponseContentLength(body.length);
                externalContext.setResponseHeader("Content-Disposition",
                        "attachment; filename=\"dump-" + System.currentTimeMillis() + FILE_SUFFIX + "\"");

                out.write(body);
                context.responseComplete();
            } catch (FileNotFoundException e) {
                error = "The selected file could not be written:\n" + e.getLocalizedMessage();
                success = null;
            } catch (IOException e) {
                error = "Failed to write the properties to file:\n" + e.getLocalizedMessage();
                success = null;
            }
        }
        return "";
    }

    private List<MyWorker> getAllWorkers() throws AdminNotAuthorizedException {
        List<MyWorker> results = new ArrayList<>();
        for (int id : getWorkerSessionBean().getAllWorkers(getAuthBean().getAdminCertificate())) {
            Properties config = getWorkerSessionBean().getCurrentWorkerConfig(getAuthBean().getAdminCertificate(), id).getProperties();
            final String name = config.getProperty("NAME", String.valueOf(id));
            Collection<CertificateMatchingRule> authorizedClients = getWorkerSessionBean().getAuthorizedClientsGen2(getAuthBean().getAdminCertificate(), id);
            results.add(new MyWorker(id, name != null, name, config, authorizedClients));
        }
        return results;
    }

    public String getEXPORT_ALL_WORKERS() {
        return EXPORT_ALL_WORKERS;
    }

    public String getEXPORT_NO_WORKERS() {
        return EXPORT_NO_WORKERS;
    }

    public String getEXPORT_SELECTED_WORKERS() {
        return EXPORT_SELECTED_WORKERS;
    }

    public String getReloadTarget() throws AdminNotAuthorizedException {
        if (reloadTarget == null) {
            reloadTarget = getMyWorkers().isEmpty() ? EXPORT_ALL_WORKERS : EXPORT_SELECTED_WORKERS;
        }
        return reloadTarget;
    }

    public void setReloadTarget(String reloadTarget) {
        this.reloadTarget = reloadTarget;
    }

    public Boolean getExportNonWorkerGlobalConfig() {
        return exportNonWorkerGlobalConfig;
    }

    public void setExportNonWorkerGlobalConfig(Boolean exportNonWorkerGlobalConfig) {
        this.exportNonWorkerGlobalConfig = exportNonWorkerGlobalConfig;
    }

    public String getError() {
        return error;
    }

    public String getSuccess() {
        return success;
    }

    public static class MyWorker extends Worker {

        private final Collection<CertificateMatchingRule> authorizedClients;

        public MyWorker(int id, boolean exists, String name, Properties config, Collection<CertificateMatchingRule> authorizedClients) {
            super(id, exists, name, config);
            this.authorizedClients = authorizedClients;
        }

        public Collection<CertificateMatchingRule> getAuthorizedClientsGen2() {
            return authorizedClients;
        }

    }
}
