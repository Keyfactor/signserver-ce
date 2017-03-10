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
import org.signserver.common.AuthorizedClient;
import org.signserver.common.WorkerConfig;
import org.signserver.common.util.PropertiesDumper;
import org.signserver.admin.common.auth.AdminNotAuthorizedException;

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
    private Boolean exportNonWorkerGlobalConfig = true;

    private List<MyWorker> myWorkers;
    private String result;
    private String error;

    /**
     * Creates a new instance of WorkersManagedBean
     */
    public ExportBulkBean() {

    }

    public List<MyWorker> getMyWorkers() throws AdminNotAuthorizedException {
        if (myWorkers == null) {
            myWorkers = new ArrayList<>();
            for (int id : getWorkerIdsList()) {
                WorkerConfig config = getWorkerSessionBean().getCurrentWorkerConfig(getAuthBean().getAdminCertificate(), id);
                String name = config.getProperty("NAME");
                boolean exists = true;
                if (name == null) {
                    name = "Not Found";
                    exists = false;
                }

                Collection<AuthorizedClient> authorizedClients = getWorkerSessionBean().getAuthorizedClients(getAuthBean().getAdminCertificate(), id);

                MyWorker worker = new MyWorker(id, exists, name, config.getProperties(), authorizedClients);
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

    public String exportAction() throws AdminNotAuthorizedException {
        //FacesMessage errorMessage = new FacesMessage("Test error");
        //errorMessage.setSeverity(FacesMessage.SEVERITY_ERROR);
        //FacesContext.getCurrentInstance().addMessage(null, errorMessage);

        try {
            Properties globalConfig = getWorkerSessionBean().getGlobalConfiguration(getAuthBean().getAdminCertificate()).getConfig();
            Properties outProperties = new Properties();

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
                PropertiesDumper.dumpWorkerProperties(worker.getId(), globalConfig, worker.getConfig(), worker.getAuthorizedClients(), outProperties);
            }

            // Write the properties
            ByteArrayOutputStream bout = new ByteArrayOutputStream();
            outProperties.store(bout, null);

            result = bout.toString(StandardCharsets.ISO_8859_1.name());
            error = null;

            sendForDownload(result, "dump-" + System.currentTimeMillis());

        } catch (AdminNotAuthorizedException ex) {
            error = "Authorization denied:\n" + ex.getLocalizedMessage();
        } catch (CertificateEncodingException ex) {
            error = "Failed to encode certificate:\n" + ex.getLocalizedMessage();
        } catch (FileNotFoundException ex) {
            error = "The selected file could not be written:\n" + ex.getLocalizedMessage();
        } catch (IOException ex) {
            error = "Failed to write the properties to file:\n" + ex.getLocalizedMessage();
        }
        return "";
    }

    private void sendForDownload(String properties, String fileTitle) throws IOException {
        final FacesContext context = FacesContext.getCurrentInstance();
        final ExternalContext externalContext = context.getExternalContext();
        final byte[] body = properties.getBytes(StandardCharsets.ISO_8859_1);

        externalContext.responseReset();
        externalContext.setResponseContentType("text/plain");
        externalContext.setResponseContentLength(body.length);
        externalContext.setResponseHeader("Content-Disposition", "attachment; filename=\"" + fileTitle + FILE_SUFFIX);

        try (OutputStream out = externalContext.getResponseOutputStream()) {
            out.write(body);
        }

        context.responseComplete();
    }

    private List<MyWorker> getAllWorkers() throws AdminNotAuthorizedException {
        List<MyWorker> results = new ArrayList<>();
        for (int id : getWorkerSessionBean().getAllWorkers(getAuthBean().getAdminCertificate())) {
            Properties config = getWorkerSessionBean().getCurrentWorkerConfig(getAuthBean().getAdminCertificate(), id).getProperties();
            final String name = config.getProperty("NAME", String.valueOf(id));
            Collection<AuthorizedClient> authorizedClients = getWorkerSessionBean().getAuthorizedClients(getAuthBean().getAdminCertificate(), id);
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

    public String getResult() {
        return result;
    }

    public void setResult(String result) {
        this.result = result;
    }

    public String getError() {
        return error;
    }

    public void setError(String error) {
        this.error = error;
    }

    public static class MyWorker extends Worker {

        private final Collection<AuthorizedClient> authorizedClients;

        public MyWorker(int id, boolean exists, String name, Properties config, Collection<AuthorizedClient> authorizedClients) {
            super(id, exists, name, config);
            this.authorizedClients = authorizedClients;
        }

        public Collection<AuthorizedClient> getAuthorizedClients() {
            return authorizedClients;
        }

    }
}
