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
import java.io.ByteArrayInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.TreeMap;
import javax.ejb.EJB;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ManagedProperty;
import javax.faces.bean.ViewScoped;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.signserver.common.WorkerConfig;
import org.signserver.common.util.PropertiesApplier;
import org.signserver.common.util.PropertiesConstants;
import org.signserver.common.util.PropertiesParser;
import org.signserver.admin.common.auth.AdminNotAuthorizedException;
import org.signserver.admin.web.ejb.AdminWebSessionBean;

/**
 *
 * @author Markus Kilås
 * @version $Id$
 */
@ManagedBean
@ViewScoped
public class AddWorkerBean {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(AddWorkerBean.class);

    @EJB
    private AdminWebSessionBean workerSessionBean;

    @ManagedProperty(value = "#{authenticationBean}")
    private AuthenticationBean authBean;

    private String workerId = "GENID1";
    private String name;
    private String implementationClass;
    private String cryptoTokenImplementationClass;
    private String type = "PROCESSABLE";

    private final TreeMap<String, String> config = new TreeMap<>();

    private boolean propertyEditing;
    private boolean propertyAdding;
    private String propertyName;
    private String propertyValue;
    private String propertyOld;

    private String configuration;
    private String errorMessage;
    
    private Map<String, String> templates;
    private String selectedTemplate;
    private Method method;
    private Step step = Step.STEP0;

    /**
     * Creates a new instance of WorkerBean
     */
    public AddWorkerBean() {
    }

    public AuthenticationBean getAuthBean() {
        return authBean;
    }

    public void setAuthBean(AuthenticationBean authBean) {
        this.authBean = authBean;
    }

    public String getWorkerId() {
        return workerId;
    }

    public void setWorkerId(String workerId) {
        this.workerId = workerId;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getImplementationClass() {
        return implementationClass;
    }

    public void setImplementationClass(String implementationClass) {
        this.implementationClass = implementationClass;
    }

    public String getCryptoTokenImplementationClass() {
        return cryptoTokenImplementationClass;
    }

    public void setCryptoTokenImplementationClass(String cryptoTokenImplementationClass) {
        this.cryptoTokenImplementationClass = cryptoTokenImplementationClass;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public Map.Entry[] getConfig() {
        return config.entrySet().toArray(new Map.Entry[0]);
    }

    public boolean isPropertyEditing() {
        return propertyEditing;
    }

    public void setPropertyEditing(boolean propertyEditing) {
        this.propertyEditing = propertyEditing;
    }

    public boolean isPropertyAdding() {
        return propertyAdding;
    }

    public void setPropertyAdding(boolean propertyAdding) {
        this.propertyAdding = propertyAdding;
    }

    public void fromTemplateAction() {
        method = Method.TEMPLATE;
        step = Step.STEP1;
        resetAction();
    }
    
    public void fromFileAction() {
        method = Method.FILE;
        step = Step.STEP2;
        resetAction();
    }

    public void fromPropertiesAction() {
        method = Method.FORM;
        step = Step.STEP1;
        resetAction();
    }

    public void addPropertyAction() {
        this.config.put(propertyName, propertyValue);
        propertyAdding = false;
    }

    public void editPropertyAction() {
        if (!propertyOld.equals(propertyName)) {
            this.config.remove(propertyOld);
        }
        this.config.put(propertyName, propertyValue);
        propertyEditing = false;
    }

    public String getPropertyName() {
        return propertyName;
    }

    public void setPropertyName(String propertyName) {
        this.propertyName = propertyName;
    }

    public String getPropertyValue() {
        return propertyValue;
    }

    public void setPropertyValue(String propertyValue) {
        this.propertyValue = propertyValue;
    }

    public void startEditPropertyAction(String property) {
        this.propertyOld = property;
        this.propertyName = property;
        this.propertyValue = config.get(property);
        this.propertyEditing = true;
        this.propertyAdding = false;
    }

    public void startAddPropertyAction() {
        this.propertyOld = null;
        this.propertyName = null;
        this.propertyValue = null;
        this.propertyEditing = false;
        this.propertyAdding = true;
    }

    public void removePropertyAction(String property) {
        this.config.remove(property);
    }

    public void cancelPropertyAction() {
        propertyOld = null;
        propertyName = null;
        propertyValue = null;
        propertyAdding = false;
        propertyEditing = false;
    }

    public void nextAction() {
        step = Step.STEP2;
        resetAction();
    }

    public String getConfiguration() {
        return configuration;
    }

    public void setConfiguration(String configuration) {
        this.configuration = configuration;
    }

    public String getErrorMessage() {
        return errorMessage;
    }

    public void resetAction() {
        if (step == Step.STEP2) {
            switch (method) {
                case FORM:
                    configuration = generateProperties();
                    break;
                case TEMPLATE:
                    configuration = templates.get(selectedTemplate);
                    break;
                case FILE:
                    configuration = "";
                    break;
            }
        }
    }

    public void backAction() {
        if (step == Step.STEP2) {
            if (method == Method.FILE) {
                step = Step.STEP0;
            } else {
                step = Step.STEP1;
            }
        } else {
            step = Step.STEP0;
        }

        this.errorMessage = null;
    }

    public void backToFirstAction() {
        step = Step.STEP0;
    }

    public String applyAction() throws NotLoggedInException {
        List<Integer> modifiedWorkers = null;
        final Properties props = new Properties();
        try {
            props.load(new ByteArrayInputStream(configuration.getBytes(StandardCharsets.ISO_8859_1)));

            if (props.isEmpty()) {
                errorMessage = "No properties loaded";
            } else {
                final PropertiesParser parser = new PropertiesParser();

                parser.process(props);

                if (parser.hasErrors()) {
                    final List<String> errors = parser.getErrors();

                    // show the first error message from the parser, to avoid overflowing
                    // TODO: maybe add a "more errors..." view later...
                    errorMessage = "Error parsing properties: " + errors.get(0);
                } else {
                    final PropertiesApplier applier = new AdminWebPropertiesApplier(workerSessionBean, authBean.getAdminCertificate());

                    applier.apply(parser);

                    if (applier.hasError()) {
                        errorMessage = "Error applying properties: " + applier.getError();
                    } else {
                        modifiedWorkers = applier.getWorkerIds();

                        try {
                            for (final int id : modifiedWorkers) {
                                workerSessionBean.reloadConfiguration(authBean.getAdminCertificate(), id);
                            }
                            errorMessage = null;
                        } catch (AdminNotAuthorizedException e) {
                            errorMessage = "Error reloading workers: " + e.getMessage();
                        }
                    }
                }
            }
        } catch (IOException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Error loading properties", e);
            }
            errorMessage = "Error loading properties: " + e.getMessage();
        }

        if (errorMessage == null) {
            if (modifiedWorkers != null) {
                // TODO: Future: String successMessage = "Added/modified workers with the following IDs:" + StringUtils.join(modifiedWorkers.toArray(), ", ");
                return "workers?faces-redirect=true&amp;selected=" + StringUtils.join(modifiedWorkers.toArray(), ",");
            } else {
                return "workers?faces-redirect=true";
            }
        } else {
            return null;
        }
    }

    private String generateProperties() {
        // TODO: merge in previous content from the text editor in the case
        // when the user goes back and changes some values in the form and then
        // back to the editor

        final Properties properties = new Properties();

        final String workerPrefix
                = PropertiesConstants.WORKER_PREFIX + workerId;

        // insert IMPLEMENTATION_CLASS property
        properties.setProperty(workerPrefix + "." + PropertiesConstants.IMPLEMENTATION_CLASS, implementationClass);

        if (cryptoTokenImplementationClass != null && !cryptoTokenImplementationClass.isEmpty()) {
            // insert CRYPTOTOKEN_IMPLEMENTATION_CLASS property
            properties.setProperty(workerPrefix + "."
                    + PropertiesConstants.CRYPTOTOKEN_IMPLEMENTATION_CLASS,
                    cryptoTokenImplementationClass);
        }

        // insert NAME worker property   
        properties.setProperty(workerPrefix + "." + PropertiesConstants.NAME, name);

        properties.setProperty(workerPrefix + "." + WorkerConfig.TYPE, type);

        // generate additional properties
        for (Map.Entry<String, String> entry : config.entrySet()) {
            properties.setProperty(workerPrefix + "." + entry.getKey(), entry.getValue());
        }

        final StringWriter writer = new StringWriter();

        try {
            properties.store(writer, null);
        } catch (IOException e) {
            // ignore
        }

        return writer.toString();
    }

    public Map<String, String> getTemplates() {
        if (templates == null) {
            templates = new TreeMap<>();

            try (InputStream metaIn = getClass().getResourceAsStream("/sampleconfigs.properties")) {
                if (metaIn == null) {
                    throw new FileNotFoundException("Unable to find /sampleconfigs.properties");
                }
                Properties metaFile = new Properties();
                metaFile.load(metaIn);
                
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Loaded /sampleconfigs.properties");
                }

                for (String file : metaFile.getProperty("sampleconfigs.files", "").split(";")) {
                    try (InputStream fileIn = getClass().getResourceAsStream("/sampleconfigs/" + file)) {
                        templates.put(file, IOUtils.toString(fileIn, StandardCharsets.ISO_8859_1.name()));
                    }
                }
                
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Loaded " + templates.size() + " sample configs");
                }
                
            } catch (IOException ex) {
                LOG.error("Failed to load sample config templates: " + ex.getMessage());
            }
        }
        return templates;
    }
    
    public List<String> getTemplateNames() {
        return new ArrayList<>(getTemplates().keySet());
    }

    public boolean isMethodTemplate() {
        return method == Method.TEMPLATE;
    }
    
    public boolean isMethodFile() {
        return method == Method.FILE;
    }
    
    public boolean isMethodForm() {
        return method == Method.FORM;
    }
    
    public boolean isStep0() {
        return step == Step.STEP0;
    }
    
    public boolean isStep1() {
        return step == Step.STEP1;
    }
    
    public boolean isStep2() {
        return step == Step.STEP2;
    }

    public String getSelectedTemplate() {
        return selectedTemplate;
    }

    public void setSelectedTemplate(String selectedTemplate) {
        this.selectedTemplate = selectedTemplate;
    }

    private static enum Method {
        TEMPLATE,
        FILE,
        FORM
    }
    
    private static enum Step {
        STEP0,
        STEP1,
        STEP2
    }
}
