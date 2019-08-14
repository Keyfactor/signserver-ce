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
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import javax.ejb.EJB;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ManagedProperty;
import javax.faces.bean.ViewScoped;
import javax.faces.context.ExternalContext;
import javax.faces.context.FacesContext;
import org.apache.log4j.Logger;
import org.signserver.common.ArchiveMetadata;
import org.signserver.common.SignServerException;
import org.signserver.admin.common.auth.AdminNotAuthorizedException;
import org.signserver.admin.web.ejb.AdminWebSessionBean;

/**
 *
 * @author Markus Kilås
 * @version $Id$
 */
@ManagedBean
@ViewScoped
public class ArchiveDownloadBean {

    /**
     * Logger for this class.
     */
    private static final Logger LOG = Logger.getLogger(ArchiveDownloadBean.class);

    @EJB
    private AdminWebSessionBean workerSessionBean;

    @ManagedProperty(value = "#{authenticationBean}")
    private AuthenticationBean authBean;

    private String uniqueId;
    private String uniqueIds;
    private String errorMessage;

    /**
     * Creates a new instance of ArchiveDownloadBean.
     */
    public ArchiveDownloadBean() {
    }

    public AuthenticationBean getAuthBean() {
        return authBean;
    }

    public void setAuthBean(AuthenticationBean authBean) {
        this.authBean = authBean;
    }

    public String getUniqueId() {
        return uniqueId;
    }

    public void setUniqueId(String uniqueId) {
        this.uniqueId = uniqueId;
    }

    public String getUniqueIds() {
        return uniqueIds;
    }

    public void setUniqueIds(String uniqueIds) {
        this.uniqueIds = uniqueIds;
    }

    public String getErrorMessage() {
        return errorMessage;
    }

    public void init() throws AdminNotAuthorizedException, IOException { // preRenderView in archive-download.xhtml

        try {
            // Multiple entries ZIP:ed or one uncompressed?
            if (uniqueIds != null && !uniqueIds.trim().isEmpty()) {
                List<String> ids = new ArrayList<>();
                for (String id : uniqueIds.split(",")) {
                    id = id.trim();
                    if (!id.isEmpty()) {
                        ids.add(id);
                    }
                }

                List<ArchiveMetadata> results = workerSessionBean.queryArchiveWithIds(authBean.getAdminCertificate(), ids, true);

                if (results == null || results.isEmpty()) {
                    errorMessage = "No such archive entries";
                } else {
                    final FacesContext context = FacesContext.getCurrentInstance();
                    final ExternalContext externalContext = context.getExternalContext();

                    externalContext.responseReset();

                    // No content-length as we will be streaming
                    externalContext.setResponseContentType("application/zip");
                    externalContext.setResponseHeader("Content-Disposition", "attachment; filename=\"archives.zip");

                    try (ZipOutputStream out = new ZipOutputStream(externalContext.getResponseOutputStream())) {
                        for (ArchiveMetadata data : results) {
                            ZipEntry entry = new ZipEntry(ArchiveMetadata.suggestedFilename(data.getArchiveId(), data.getType()));
                            out.putNextEntry(entry);
                            out.write(data.getArchiveData());
                            out.closeEntry();
                        }
                    }

                    context.responseComplete();
                }

            } else {

                List<ArchiveMetadata> results = workerSessionBean.queryArchiveWithIds(authBean.getAdminCertificate(), Collections.singletonList(uniqueId), true);

                if (results == null || results.isEmpty()) {
                    errorMessage = "No such archive entry";
                } else {
                    final FacesContext context = FacesContext.getCurrentInstance();
                    final ExternalContext externalContext = context.getExternalContext();
                    final byte[] body = results.get(0).getArchiveData();

                    externalContext.responseReset();
                    externalContext.setResponseContentType("application/octet-stream");
                    externalContext.setResponseContentLength(body.length);
                    externalContext.setResponseHeader("Content-Disposition", "attachment; filename=\"" + ArchiveMetadata.suggestedFilename(results.get(0).getArchiveId(), results.get(0).getType()));

                    try (OutputStream out = externalContext.getResponseOutputStream()) {
                        out.write(body);
                    }

                    context.responseComplete();
                }
            }
        } catch (SignServerException ex) {
            errorMessage = ex.getMessage();
            LOG.error("Reload failed within the selected interval: " + ex.getMessage(), ex);
        }
    }

}
