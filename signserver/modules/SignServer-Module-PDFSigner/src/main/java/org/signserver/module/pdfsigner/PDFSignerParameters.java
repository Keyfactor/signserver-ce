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
package org.signserver.module.pdfsigner;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;

import org.apache.log4j.Logger;
import org.signserver.common.WorkerConfig;

import com.lowagie.text.BadElementException;
import com.lowagie.text.Image;
import com.lowagie.text.pdf.PdfSignatureAppearance;
import java.io.ByteArrayInputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.DecoderException;
import org.cesecore.util.CertTools;
import org.signserver.common.IllegalRequestException;
import static org.signserver.common.SignServerConstants.DEFAULT_NULL;
import org.signserver.common.SignServerException;

/**
 * Class that holds configuration values passed to pdfsigner.
 *
 * @author rayback_2
 * @version $Id$
 */
public class PDFSignerParameters {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(PDFSignerParameters.class);
    
    private final int workerId;
    private final WorkerConfig config;
    
    // private member declarations holding configuration property values
    private String reason = PDFSigner.REASONDEFAULT;
    private String location = PDFSigner.LOCATIONDEFAULT;

    private boolean add_visible_signature = PDFSigner.ADD_VISIBLE_SIGNATURE_DEFAULT;
    private String visible_sig_page = PDFSigner.VISIBLE_SIGNATURE_PAGE_DEFAULT;
    private String visible_sig_rectangle = PDFSigner.VISIBLE_SIGNATURE_RECTANGLE_DEFAULT;
    private int visible_sig_rectangle_llx;
    private int visible_sig_rectangle_lly;
    private int visible_sig_rectangle_urx;
    private int visible_sig_rectangle_ury;
    private String visible_sig_name;

    private String visible_sig_custom_image_base64;
    private String visible_sig_custom_image_path;
    private boolean visible_sig_custom_image_scale_to_rectangle = PDFSigner.VISIBLE_SIGNATURE_CUSTOM_IMAGE_SCALE_TO_RECTANGLE_DEFAULT;

    private int certification_level = PDFSigner.CERTIFICATION_LEVEL_DEFAULT;

    private String tsa_url;
    private String tsa_username;
    private String tsa_password;

    private boolean embed_crl = PDFSigner.EMBED_CRL_DEFAULT;
    private boolean embed_ocsp_response = PDFSigner.EMBED_OCSP_RESPONSE_DEFAULT;
    
    /** Used to mitigate a collision signature vulnerability described in http://pdfsig-collision.florz.de/ */
    private boolean refuseDoubleIndirectObjects;
    
    /** Permissions to not allow in a document. */
    private final Set<String> rejectPermissions = new HashSet<>();
    /** Permissions to set. **/
    private Permissions setPermissions;
    /** Permissions to remove. **/
    private Set<String> removePermissions;
    /** Password to set as owner password. */
    private String setOwnerPassword;
    
    // helper variables
    private boolean useCustomImage;
    private boolean useTimestamp;
    private boolean useTimestampAuthorization;
    private Image custom_image;

    private String tsa_worker;
    
    private String alias;
    private List<Certificate> signerCertChain;

    private String digestAlgorithm;
    
    private final List<String> configErrors;

    private final Set<String> allowPropertyOverride;

    public PDFSignerParameters(int workerId, WorkerConfig config, final List<String> configErrors, Map<String, String> requestMetadata, final Set<String> allowPropertyOverride) throws IllegalRequestException, SignServerException {
        this.workerId = workerId;
        this.config = config;
        this.configErrors = configErrors;
        this.allowPropertyOverride = allowPropertyOverride;
        extractAndProcessConfigurationProperties(requestMetadata);
    }

    private void extractAndProcessConfigurationProperties(Map<String, String> requestMetadata) throws IllegalRequestException, SignServerException {
        // requestMetadata could be missing if using ClientWS
        if (requestMetadata == null) {
            requestMetadata = new HashMap<>();
        }
        
        // The reason shown in the PDF signature
        reason = config.getProperty(PDFSigner.REASON, PDFSigner.REASONDEFAULT);
        String strMetadataValue = requestMetadata.get(PDFSigner.REASON);
        if (strMetadataValue != null && !strMetadataValue.isEmpty()) {
            if (isOverrideAllowed(PDFSigner.REASON)) {
                reason = strMetadataValue;
            } else {
                throw new IllegalRequestException("Overriding " + PDFSigner.REASON + " not permitted");
            }
        }
        LOG.debug("Using reason: " + reason);

        // The location shown in the PDF signature
        location = config.getProperty(PDFSigner.LOCATION, PDFSigner.LOCATIONDEFAULT);
        strMetadataValue = requestMetadata.get(PDFSigner.LOCATION);
        if (strMetadataValue != null && !strMetadataValue.isEmpty()) {
            if (isOverrideAllowed(PDFSigner.LOCATION)) {
                location = strMetadataValue;
            } else {
                throw new IllegalRequestException("Overriding " + PDFSigner.LOCATION + " not permitted");
            }
        }
        LOG.debug("Using location: " + location);

        // are we adding visible or invisible signature
        // note : ParseBoolean returns false for everything but "True"
        add_visible_signature = Boolean.parseBoolean(config.getProperty(PDFSigner.ADD_VISIBLE_SIGNATURE, Boolean.toString(PDFSigner.ADD_VISIBLE_SIGNATURE_DEFAULT)).trim());
        strMetadataValue = requestMetadata.get(PDFSigner.ADD_VISIBLE_SIGNATURE);
        if (strMetadataValue != null && !strMetadataValue.isEmpty()) {
            if (isOverrideAllowed(PDFSigner.ADD_VISIBLE_SIGNATURE)) {
                add_visible_signature = Boolean.parseBoolean(strMetadataValue);
            } else {
                throw new IllegalRequestException("Overriding " + PDFSigner.ADD_VISIBLE_SIGNATURE + " not permitted");
            }
        }
        LOG.debug("Using visible signature: " + add_visible_signature);

        // timestamp url
        if (config.getProperty(PDFSigner.TSA_URL, DEFAULT_NULL) != null) {
            tsa_url = config.getProperty(PDFSigner.TSA_URL, DEFAULT_NULL);
            LOG.debug("Using tsa url : " + tsa_url);
        } else if (config.getProperty(PDFSigner.TSA_WORKER, DEFAULT_NULL) != null) {
            tsa_worker = config.getProperty(PDFSigner.TSA_WORKER, DEFAULT_NULL);
        }
        
        // Unless USE_TIMESTAMP=false or no TSA_URL or TSA_WORKER is configured then use timestamp
        String useTimeStampWorkerProperty = config.getProperty(PDFSigner.USE_TIMESTAMP);
        if (useTimeStampWorkerProperty == null || useTimeStampWorkerProperty.equalsIgnoreCase(Boolean.TRUE.toString())) {
            useTimestamp = tsa_url != null || tsa_worker != null;
        }

        if (useTimestamp
                && config.getProperty(PDFSigner.TSA_USERNAME, DEFAULT_NULL) != null
                && config.getPropertyThatCouldBeEmpty(PDFSigner.TSA_PASSWORD) != null) { // Password Might be empty string so no default
            tsa_username = config.getProperty(
                    PDFSigner.TSA_USERNAME, DEFAULT_NULL);
            tsa_password = config.getPropertyThatCouldBeEmpty(
                    PDFSigner.TSA_PASSWORD);
            useTimestampAuthorization = true;
        }
        
        // Override use_timestamp
        strMetadataValue = requestMetadata.get(PDFSigner.USE_TIMESTAMP);
        if (strMetadataValue != null && !strMetadataValue.isEmpty()) {
            if (isOverrideAllowed(PDFSigner.USE_TIMESTAMP)) {
                useTimestamp = Boolean.parseBoolean(strMetadataValue) && (tsa_url != null || tsa_worker != null);
            } else {
                throw new IllegalRequestException("Overriding " + PDFSigner.USE_TIMESTAMP + " not permitted");
            }
                
            LOG.debug("Using timestamp : " + useTimestamp);
        }

        // should we embed crl inside the cms package
        embed_crl = Boolean.parseBoolean(config.getProperty(PDFSigner.EMBED_CRL, Boolean.toString(PDFSigner.EMBED_CRL_DEFAULT)).trim());
        strMetadataValue = requestMetadata.get(PDFSigner.EMBED_CRL);
        if (strMetadataValue != null && !strMetadataValue.isEmpty()) {
            if (isOverrideAllowed(PDFSigner.EMBED_CRL)) {
                embed_crl = Boolean.parseBoolean(strMetadataValue);
            } else {
                throw new IllegalRequestException("Overriding " + PDFSigner.EMBED_CRL + " not permitted");
            }
        }
        LOG.debug("Using embed crl inside cms package : " + isEmbed_crl());

        // should we embed ocsp response inside the cms package
        embed_ocsp_response = Boolean.parseBoolean(config.getProperty(PDFSigner.EMBED_OCSP_RESPONSE, Boolean.toString(PDFSigner.EMBED_OCSP_RESPONSE_DEFAULT)).trim());
        strMetadataValue = requestMetadata.get(PDFSigner.EMBED_OCSP_RESPONSE);
        if (strMetadataValue != null && !strMetadataValue.isEmpty()) {
            if (isOverrideAllowed(PDFSigner.EMBED_OCSP_RESPONSE)) {
                embed_ocsp_response = Boolean.parseBoolean(strMetadataValue);
            } else {
                throw new IllegalRequestException("Overriding " + PDFSigner.EMBED_OCSP_RESPONSE + " not permitted");
            }
        }
        LOG.debug("Using embed ocsp inside cms package : "
                + isEmbed_ocsp_response());

        // should we refuse PDF documents that contains multiple
        // indirect objects with the same name
        refuseDoubleIndirectObjects = Boolean.parseBoolean(config.getProperty(
                PDFSigner.REFUSE_DOUBLE_INDIRECT_OBJECTS, Boolean.FALSE.toString()));
        
        // Reject permissions
        String rejectPermissionsValue = config.getPropertyThatCouldBeEmpty(PDFSigner.REJECT_PERMISSIONS);
        if (rejectPermissionsValue != null) {
            String[] array = rejectPermissionsValue.split(",");
            rejectPermissions.addAll(Arrays.asList(array));
        }
        strMetadataValue = requestMetadata.get(PDFSigner.REJECT_PERMISSIONS);
        if (strMetadataValue != null && !strMetadataValue.isEmpty()) {
            if (isOverrideAllowed(PDFSigner.REJECT_PERMISSIONS)) {
                String[] array = strMetadataValue.split(",");
                rejectPermissions.addAll(Arrays.asList(array));
            } else {
                throw new IllegalRequestException("Overriding " + PDFSigner.REJECT_PERMISSIONS + " not permitted");
            }
        }

        // Set permissions
        String setPermissionsValue = config.getPropertyThatCouldBeEmpty(PDFSigner.SET_PERMISSIONS);
        if (setPermissionsValue != null) {
            String[] array = setPermissionsValue.split(",");
            try {
                setPermissions = Permissions.fromSet(Arrays.asList(array), true);
            } catch (UnknownPermissionException ex) {
                configErrors.add("Signer " + workerId + " misconfigured: " + ex.getMessage());
            }
        }
        strMetadataValue = requestMetadata.get(PDFSigner.SET_PERMISSIONS);
        if (strMetadataValue != null && !strMetadataValue.isEmpty()) {
            if (isOverrideAllowed(PDFSigner.SET_PERMISSIONS)) {
                String[] array = strMetadataValue.split(",");
                try {
                    setPermissions = Permissions.fromSet(Arrays.asList(array), true);
                } catch (UnknownPermissionException ex) {
                    throw new SignServerException("Signer " + workerId + " missconfigured: " + ex.getMessage());
                }
            } else {
                throw new IllegalRequestException("Overriding " + PDFSigner.SET_PERMISSIONS + " not permitted");
            }
        }

        // Remove permissions
        String removePermissionsValue = config.getPropertyThatCouldBeEmpty(PDFSigner.REMOVE_PERMISSIONS);
        if (removePermissionsValue != null) {
            String[] array = removePermissionsValue.split(",");
            removePermissions = new HashSet<>();
            removePermissions.addAll(Arrays.asList(array));
        }
        strMetadataValue = requestMetadata.get(PDFSigner.REMOVE_PERMISSIONS);
        if (strMetadataValue != null && !strMetadataValue.isEmpty()) {
            if (isOverrideAllowed(PDFSigner.REMOVE_PERMISSIONS)) {
                String[] array = strMetadataValue.split(",");
                removePermissions = new HashSet<>();
                removePermissions.addAll(Arrays.asList(array));
            } else {
                throw new IllegalRequestException("Overriding " + PDFSigner.REMOVE_PERMISSIONS + " not permitted");
            }
        }
        // Set ownerpassword
        setOwnerPassword = config.getPropertyThatCouldBeEmpty(PDFSigner.SET_OWNERPASSWORD);
        strMetadataValue = requestMetadata.get(PDFSigner.SET_OWNERPASSWORD);
        if (strMetadataValue != null && !strMetadataValue.isEmpty()) {
            if (isOverrideAllowed(PDFSigner.SET_OWNERPASSWORD)) {
                setOwnerPassword = strMetadataValue;
            } else {
                throw new IllegalRequestException("Overriding " + PDFSigner.SET_OWNERPASSWORD + " not permitted");
            }
        }
        
        // if signature is choosen to be visible proceed with setting visibility
        // properties
        if (add_visible_signature) {
            // page to draw visible signature at            
            visible_sig_page = config.getProperty(PDFSigner.VISIBLE_SIGNATURE_PAGE, PDFSigner.VISIBLE_SIGNATURE_PAGE_DEFAULT);
            strMetadataValue = requestMetadata.get(PDFSigner.VISIBLE_SIGNATURE_PAGE);
            if (strMetadataValue != null && !strMetadataValue.isEmpty()) {
                if (isOverrideAllowed(PDFSigner.VISIBLE_SIGNATURE_PAGE)) {
                    visible_sig_page = strMetadataValue;
                } else {
                throw new IllegalRequestException("Overriding " + PDFSigner.VISIBLE_SIGNATURE_PAGE + " not permitted");
            }
            }

            LOG.debug("Using visible signature page: " + visible_sig_page);

            // The location of the visible signature rectangle(llx, lly, urx,
            // ury)
            // llx = lower left x coordinate, lly = lower left y coordinate, urx
            // = upper right x coordinate, ury = upper right y coordinate
            visible_sig_rectangle = config.getProperty(PDFSigner.VISIBLE_SIGNATURE_RECTANGLE, PDFSigner.VISIBLE_SIGNATURE_RECTANGLE_DEFAULT);
            strMetadataValue = requestMetadata.get(PDFSigner.VISIBLE_SIGNATURE_RECTANGLE);
            if (strMetadataValue != null && !strMetadataValue.isEmpty()) {
                if (isOverrideAllowed(PDFSigner.VISIBLE_SIGNATURE_RECTANGLE)) {
                    visible_sig_rectangle = strMetadataValue;
                } else {
                    throw new IllegalRequestException("Overriding " + PDFSigner.VISIBLE_SIGNATURE_RECTANGLE + " not permitted");
                }
            }
            LOG.debug("Using rectangle: " + visible_sig_rectangle);

            String[] rect = visible_sig_rectangle.split(",");

            if (rect.length < 4) {
                configErrors.add("RECTANGLE property must contain 4 comma separated values with no spaces.");
            } else { // Only read values when all 4 are provided otherwise ArrayIndexOutOfBoundException will be thrown
                try {
                    visible_sig_rectangle_llx = Integer.valueOf(rect[0]);
                    visible_sig_rectangle_lly = Integer.valueOf(rect[1]);
                    visible_sig_rectangle_urx = Integer.valueOf(rect[2]);
                    visible_sig_rectangle_ury = Integer.valueOf(rect[3]);
                } catch (NumberFormatException ex) {
                    configErrors.add("Invalid RECTANGLE property specified: " + visible_sig_rectangle);
                    LOG.error("Invalid RECTANGLE property specified", ex);
                }
            }
            
            strMetadataValue = requestMetadata.get(PDFSigner.VISIBLE_SIGNATURE_NAME);
            if (strMetadataValue != null && !strMetadataValue.isEmpty()) {
                if (isOverrideAllowed(PDFSigner.VISIBLE_SIGNATURE_NAME)) {
                    visible_sig_name = strMetadataValue;
                    LOG.debug("Using visible signature name: " + visible_sig_name);
                } else {
                    throw new IllegalRequestException("Overriding " + PDFSigner.VISIBLE_SIGNATURE_NAME + " not permitted");
                }
            }

            // custom image to use with signature
            // base64 encoded byte[]
            visible_sig_custom_image_base64 = config.getProperty(
                    PDFSigner.VISIBLE_SIGNATURE_CUSTOM_IMAGE_BASE64, DEFAULT_NULL);
            LOG.debug("base64 encoded custom image is set");
            strMetadataValue = requestMetadata.get(PDFSigner.VISIBLE_SIGNATURE_CUSTOM_IMAGE_BASE64);
            if (strMetadataValue != null && !strMetadataValue.isEmpty()) {
                if (isOverrideAllowed(PDFSigner.VISIBLE_SIGNATURE_CUSTOM_IMAGE_BASE64)) {
                    visible_sig_custom_image_base64 = strMetadataValue;
                    LOG.debug("base64 encoded custom image is set with request metadata");
                } else {
                    throw new IllegalRequestException("Overriding " + PDFSigner.VISIBLE_SIGNATURE_CUSTOM_IMAGE_BASE64 + " not permitted");
                }
            }
            
            // custom image path. Do not set if base64 encoded image is
            // specified
            if (visible_sig_custom_image_base64 == null) {
                visible_sig_custom_image_path = config.getProperty(
                        PDFSigner.VISIBLE_SIGNATURE_CUSTOM_IMAGE_PATH, DEFAULT_NULL);
                LOG.debug("using custom image path : "
                        + visible_sig_custom_image_path);
            }
            
            boolean use_image_from_base64_string = visible_sig_custom_image_base64 != null;                    
            boolean use_image_from_path = visible_sig_custom_image_path != null;
                  
            useCustomImage = use_image_from_base64_string
                    || use_image_from_path;

            // custom image resizing (if we are using custom image)
            if (useCustomImage) {

                // retrieve custom image
                byte[] imageByteArray = null;
                if (use_image_from_base64_string) {
                    try {
                        imageByteArray = Base64.decode(visible_sig_custom_image_base64.getBytes());
                    } catch (DecoderException ex) {
                        configErrors.add("Error reading custom image base 64 encoded data: " + ex.getMessage());
                        LOG.error("Error reading custom image base 64 encoded data", ex);
                    }
                } else {
                    try {
                        imageByteArray = readFile(visible_sig_custom_image_path);
                    } catch (IOException ex) {
                        configErrors.add("Error reading custom image data from path specified: " + ex.getMessage());
                        LOG.error("Error reading custom image data from path specified", ex);
                    }
                }

                if (imageByteArray != null) {
                    try {
                        custom_image = Image.getInstance(imageByteArray);

                        // If image instance is valid, continue with remaining stuff otherwise catch error
                        visible_sig_custom_image_scale_to_rectangle = Boolean.parseBoolean(config.getProperty(PDFSigner.VISIBLE_SIGNATURE_CUSTOM_IMAGE_SCALE_TO_RECTANGLE, Boolean.toString(PDFSigner.VISIBLE_SIGNATURE_CUSTOM_IMAGE_SCALE_TO_RECTANGLE_DEFAULT)).trim());
                        if (Boolean.toString(visible_sig_custom_image_scale_to_rectangle) != null) {
                            LOG.debug("resize custom image to rectangle : "
                                    + visible_sig_custom_image_scale_to_rectangle);
                        }
                        
                        strMetadataValue = requestMetadata.get(PDFSigner.VISIBLE_SIGNATURE_CUSTOM_IMAGE_SCALE_TO_RECTANGLE);
                        if (strMetadataValue != null && !strMetadataValue.isEmpty()) {
                            if (isOverrideAllowed(PDFSigner.VISIBLE_SIGNATURE_CUSTOM_IMAGE_SCALE_TO_RECTANGLE)) {
                                visible_sig_custom_image_scale_to_rectangle = Boolean.parseBoolean(strMetadataValue);
                                LOG.debug("resize custom image to rectangle : "
                                        + visible_sig_custom_image_scale_to_rectangle);
                            } else {
                                throw new IllegalRequestException("Overriding " + PDFSigner.VISIBLE_SIGNATURE_CUSTOM_IMAGE_SCALE_TO_RECTANGLE + " not permitted");
                            }
                        }

                        // if we are using custom image and the
                        // VISIBLE_SIGNATURE_CUSTOM_IMAGE_SCALE_TO_RECTANGLE is set to
                        // true resize image to fit to rectangle specified
                        // If set to false calculate urx and ury coordinates from image
                        if (visible_sig_custom_image_scale_to_rectangle) {
                            resizeImageToFitToRectangle();
                        } else {
                            calculateUpperRightRectangleCoordinatesFromImage();
                        }
                    } catch (BadElementException | IOException ex) {
                        configErrors.add("Problem constructing image from custom image data: " + ex.getMessage());
                        LOG.error("Problem constructing image from custom image data", ex);
                    }
                }
                
            }
        }

        // Certification level
        String level = config.getProperty(PDFSigner.CERTIFICATION_LEVEL, "NOT_CERTIFIED");
        strMetadataValue = requestMetadata.get(PDFSigner.CERTIFICATION_LEVEL);
        if (strMetadataValue != null && !strMetadataValue.isEmpty()) {
            if (isOverrideAllowed(PDFSigner.CERTIFICATION_LEVEL)) {
                level = strMetadataValue;
            } else {
                throw new IllegalRequestException("Overriding " + PDFSigner.CERTIFICATION_LEVEL + " not permitted");
            }
        }
        if (level.equalsIgnoreCase("NO_CHANGES_ALLOWED")) {
            certification_level
                    = PdfSignatureAppearance.CERTIFIED_NO_CHANGES_ALLOWED;
        } else if (level.equalsIgnoreCase("FORM_FILLING_AND_ANNOTATIONS")) {
            certification_level
                    = PdfSignatureAppearance.CERTIFIED_FORM_FILLING_AND_ANNOTATIONS;
        } else if (level.equalsIgnoreCase("FORM_FILLING")) {
            certification_level
                    = PdfSignatureAppearance.CERTIFIED_FORM_FILLING;
        } else if (level.equalsIgnoreCase("NOT_CERTIFIED")) {
            certification_level = PdfSignatureAppearance.NOT_CERTIFIED;
        } else {
            configErrors.add("Unknown value for CERTIFICATION_LEVEL");
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("using certification level: " + certification_level);
        }
        
        // Specific parameters

        strMetadataValue = requestMetadata.get(PDFSigner.SIGNERCERTCHAIN);
        if (strMetadataValue != null && !strMetadataValue.isEmpty()) {
            if (isOverrideAllowed(PDFSigner.SIGNERCERTCHAIN)) {
                List<Certificate> result = null;
                try {
                    result = CertTools.getCertsFromPEM(new ByteArrayInputStream(strMetadataValue.getBytes()), Certificate.class);
                } catch (CertificateException e) {
                    LOG.error(e);
                    configErrors.add("Unable to read certificates from SIGNERCERTCHAIN: " + e.getMessage());
                }
                setSignerCertChain(result);
            } else {
                throw new IllegalRequestException("Overriding " + PDFSigner.SIGNERCERTCHAIN + " not permitted");
            }
        }
        LOG.debug("Using signer cert chain: " + getSignerCertChain());

        strMetadataValue = requestMetadata.get(PDFSigner.DIGESTALGORITHM);
        if (strMetadataValue != null && !strMetadataValue.isEmpty()) {
            if (isOverrideAllowed(PDFSigner.DIGESTALGORITHM)) {
                digestAlgorithm = strMetadataValue;
            } else {
                throw new IllegalRequestException("Overriding " + PDFSigner.DIGESTALGORITHM + " not permitted");
            }    
        }
        LOG.debug("Using digestAlgorithm: " + digestAlgorithm);
    }

    /**
     * Read byte[] data from file.
     *
     * @param pFilePath
     * @return content of file
     * @throws IOException
     */
    public byte[] readFile(String pFilePath) throws IOException {
        FileInputStream fis = null;
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        try {
            fis = new FileInputStream(pFilePath);
            byte[] buff = new byte[1024];
            int count;
            while ((count = fis.read(buff, 0, buff.length)) > 0) {
                bout.write(buff, 0, count);
            }
        } finally {
            if (fis != null) {
                fis.close();
            }
        }

        return bout.toByteArray();
    }

    /**
     * resize image to fit to a specified rectangle
     */
    private void resizeImageToFitToRectangle() {
        float newWidth = visible_sig_rectangle_urx - visible_sig_rectangle_llx;
        float newHeight = visible_sig_rectangle_ury - visible_sig_rectangle_lly;
        custom_image.scaleToFit(newWidth, newHeight);
    }

    /**
     * set upper right coordinates of the rectangle from given image
     */
    private void calculateUpperRightRectangleCoordinatesFromImage() {
        visible_sig_rectangle_urx = (int) (visible_sig_rectangle_llx + custom_image.getWidth());
        visible_sig_rectangle_ury = (int) (visible_sig_rectangle_lly + custom_image.getHeight());
    }
    
    private boolean isOverrideAllowed(String property) {
        return allowPropertyOverride.contains(property);
    }

    public String getReason() {
        return reason;
    }

    public String getLocation() {
        return location;
    }

    public boolean isAdd_visible_signature() {
        return add_visible_signature;
    }

    public String getVisible_sig_page() {
        return visible_sig_page;
    }

    public String getVisible_sig_rectangle() {
        return visible_sig_rectangle;
    }

    public int getVisible_sig_rectangle_llx() {
        return visible_sig_rectangle_llx;
    }

    public int getVisible_sig_rectangle_lly() {
        return visible_sig_rectangle_lly;
    }

    public int getVisible_sig_rectangle_urx() {
        return visible_sig_rectangle_urx;
    }

    public int getVisible_sig_rectangle_ury() {
        return visible_sig_rectangle_ury;
    }
    
    public String getVisible_sig_name() {
        return visible_sig_name;
    }

    public String getVisible_sig_custom_image_base64() {
        return visible_sig_custom_image_base64;
    }

    public String getVisible_sig_custom_image_path() {
        return visible_sig_custom_image_path;
    }

    public boolean isVisible_sig_custom_image_scale_to_rectangle() {
        return visible_sig_custom_image_scale_to_rectangle;
    }

    public String getTsa_url() {
        return tsa_url;
    }
    
    public String getTsa_worker() {
        return tsa_worker;
    }

    public String getTsa_username() {
        return tsa_username;
    }

    public String getTsa_password() {
        return tsa_password;
    }

    public boolean isUse_custom_image() {
        return useCustomImage;
    }

    public boolean isUseTimestamp() {
        return useTimestamp;
    }

    public boolean isUseTimestampAuthorization() {
        return useTimestampAuthorization;
    }

    public Image getCustom_image() {
        return custom_image;
    }

    public boolean isEmbed_crl() {
        return embed_crl;
    }

    public boolean isEmbed_ocsp_response() {
        return embed_ocsp_response;
    }

    /**
     * @return if we should refuse PDF documents that contains multiple
     * indirect objects with the same name
     */
    public boolean isRefuseDoubleIndirectObjects() {
        return refuseDoubleIndirectObjects;
    }

    public int getCertification_level() {
        return certification_level;
    }

    /**
     * @return Set with permissions to reject.
     */
    public Set<String> getRejectPermissions() {
        return rejectPermissions;
    }

    /**
     * @return Permissions to remove or null.
     */
    public Set<String> getRemovePermissions() {
        return removePermissions;
    }

    /**
     * @return The permissions to use or null.
     */
    public Permissions getSetPermissions() {
        return setPermissions;
    }

    /**
     * @return The owner password to set or null.
     */
    public String getSetOwnerPassword() {
        return setOwnerPassword;
    }

    /**
     * @return the signerCertChain
     */
    public List<Certificate> getSignerCertChain() {
        return signerCertChain;
    }

    /**
     * @param signerCertChain the signerCertChain to set
     */
    public void setSignerCertChain(List<Certificate> signerCertChain) {
        this.signerCertChain = signerCertChain;
    }

    /**
     * @return String
     */
    public String getDigestAlgorithm() {
        return digestAlgorithm;
    }

    /**
     * @param digestAlgorithm
     */
    public void setDigestAlgorithm(String digestAlgorithm) {
        this.digestAlgorithm = digestAlgorithm;
    }

}
