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
import java.net.MalformedURLException;

import org.apache.log4j.Logger;
import org.ejbca.util.Base64;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;

import com.lowagie.text.BadElementException;
import com.lowagie.text.Image;
import com.lowagie.text.pdf.PdfSignatureAppearance;

/**
 * Class that holds configuration values passed to pdfsigner.
 *
 * @author rayback_2
 * @version $Id$
 */
public class PDFSignerParameters {

	public transient Logger log = Logger.getLogger(this.getClass());

	private WorkerConfig config;

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

	private String visible_sig_custom_image_base64;
	private String visible_sig_custom_image_path;
	private boolean visible_sig_custom_image_scale_to_rectangle = PDFSigner.VISIBLE_SIGNATURE_CUSTOM_IMAGE_SCALE_TO_RECTANGLE_DEFAULT;

        private int certification_level = PDFSigner.CERTIFICATION_LEVEL_DEFAULT;

	private String tsa_url;
	private String tsa_username;
	private String tsa_password;

	private boolean embed_crl = PDFSigner.EMBED_CRL_DEFAULT;
	private boolean embed_ocsp_response = PDFSigner.EMBED_OCSP_RESPONSE_DEFAULT;

        private boolean refuseDoubleIndirectObjects;

	// helper variables
	private boolean use_custom_image = false;
	private boolean use_timestamp = false;
	private boolean use_timestamp_authorization = false;
	private Image custom_image = null;

	public PDFSignerParameters(WorkerConfig pConfig)
			throws IllegalRequestException, SignServerException {
		config = pConfig;
		extractAndProcessConfigurationProperties();
	}

	private void extractAndProcessConfigurationProperties()
			throws IllegalRequestException, SignServerException {

		// The reason shown in the PDF signature
		if (config.getProperties().getProperty(PDFSigner.REASON) != null) {
			reason = config.getProperties().getProperty(PDFSigner.REASON);
		}
		log.debug("Using reason: " + reason);

		// The location shown in the PDF signature
		if (config.getProperties().getProperty(PDFSigner.LOCATION) != null) {
			location = config.getProperties().getProperty(PDFSigner.LOCATION);
		}
		log.debug("Using location: " + location);

		// are we adding visible or invisible signature
		// note : ParseBoolean returns false for everything but "True"
		if (config.getProperties().getProperty(PDFSigner.ADD_VISIBLE_SIGNATURE) != null) {
			add_visible_signature = Boolean.parseBoolean(config.getProperties()
					.getProperty(PDFSigner.ADD_VISIBLE_SIGNATURE).trim());
		}
		log.debug("Using visible signature: " + add_visible_signature);

		// timestamp url
		if (config.getProperties().getProperty(PDFSigner.TSA_URL) != null) {
			tsa_url = config.getProperties().getProperty(PDFSigner.TSA_URL);
			use_timestamp = true;
			log.debug("Using tsa url : " + tsa_url);
		}

		if (use_timestamp
				&& config.getProperties().getProperty(PDFSigner.TSA_USERNAME) != null
				&& config.getProperties().getProperty(PDFSigner.TSA_PASSWORD) != null) {
			tsa_username = config.getProperties().getProperty(
					PDFSigner.TSA_USERNAME);
			tsa_password = config.getProperties().getProperty(
					PDFSigner.TSA_PASSWORD);
			use_timestamp_authorization = true;
		}

		// should we embed crl inside the cms package
		if (config.getProperties().getProperty(PDFSigner.EMBED_CRL) != null) {
			embed_crl = Boolean.parseBoolean(config.getProperties()
					.getProperty(PDFSigner.EMBED_CRL).trim());
		}
		log.debug("Using embed crl inside cms package : " + isEmbed_crl());

		// should we embed ocsp response inside the cms package
		if (config.getProperties().getProperty(PDFSigner.EMBED_OCSP_RESPONSE) != null) {
			embed_ocsp_response = Boolean.parseBoolean(config.getProperties()
					.getProperty(PDFSigner.EMBED_OCSP_RESPONSE).trim());
		}
		log.debug("Using embed ocsp inside cms package : "
				+ isEmbed_ocsp_response());

                // should we refuse PDF documents that contains multiple
                // indirect objects with the same name
                if (config.getProperties().getProperty(
                        PDFSigner.REFUSE_DOUBLE_INDIRECT_OBJECTS) != null) {
                    refuseDoubleIndirectObjects = Boolean.parseBoolean(config
                            .getProperties().getProperty(
                                PDFSigner.REFUSE_DOUBLE_INDIRECT_OBJECTS));
                }

		// if signature is chosen to be visible proceed with setting visibility
		// properties
		if (add_visible_signature) {
			// page to draw visible signature at
			if (config.getProperties().getProperty(
					PDFSigner.VISIBLE_SIGNATURE_PAGE) != null) {
				visible_sig_page = config.getProperties().getProperty(
						PDFSigner.VISIBLE_SIGNATURE_PAGE);
			}

			log.debug("Using visible signature page: " + visible_sig_page);

			// The location of the visible signature rectangle(llx, lly, urx,
			// ury)
			// llx = lower left x coordinate, lly = lower left y coordinate, urx
			// = upper right x coordinate, ury = upper right y coordinate
			if (config.getProperties().getProperty(
					PDFSigner.VISIBLE_SIGNATURE_RECTANGLE) != null) {
				visible_sig_rectangle = config.getProperties().getProperty(
						PDFSigner.VISIBLE_SIGNATURE_RECTANGLE);
			}
			log.debug("Using rectangle: " + visible_sig_rectangle);

			String[] rect = visible_sig_rectangle.split(",");
			if (rect.length < 4) {
				throw new IllegalRequestException(
						"RECTANGLE property must contain 4 comma separated values with no spaces.");
			}
			visible_sig_rectangle_llx = Integer.valueOf(rect[0]);
			visible_sig_rectangle_lly = Integer.valueOf(rect[1]);
			visible_sig_rectangle_urx = Integer.valueOf(rect[2]);
			visible_sig_rectangle_ury = Integer.valueOf(rect[3]);

			// custom image to use with signature
			// base64 encoded byte[]
			if (config.getProperties().getProperty(
					PDFSigner.VISIBLE_SIGNATURE_CUSTOM_IMAGE_BASE64) != null) {
				visible_sig_custom_image_base64 = config
						.getProperties()
						.getProperty(
								PDFSigner.VISIBLE_SIGNATURE_CUSTOM_IMAGE_BASE64);
				log.debug("base64 encoded custom image is set");
			}

			// custom image path. Do not set if base64 encoded image is
			// specified
			if (visible_sig_custom_image_base64 == null
					|| visible_sig_custom_image_base64.isEmpty()) {
				if (config.getProperties().getProperty(
						PDFSigner.VISIBLE_SIGNATURE_CUSTOM_IMAGE_PATH) != null) {
					visible_sig_custom_image_path = config
							.getProperties()
							.getProperty(
									PDFSigner.VISIBLE_SIGNATURE_CUSTOM_IMAGE_PATH);
					log.debug("using custom image path : "
							+ visible_sig_custom_image_path);
				}
			}

			boolean use_image_from_base64_string = visible_sig_custom_image_base64 != null
					&& !visible_sig_custom_image_base64.isEmpty();
			boolean use_image_from_path = visible_sig_custom_image_path != null
					&& !visible_sig_custom_image_path.isEmpty();

			use_custom_image = use_image_from_base64_string
					|| use_image_from_path;

			// custom image resizing (if we are using custom image)
			if (use_custom_image) {

				// retrieve custom image
				byte[] imageByteArray;
				if (use_image_from_base64_string) {
					imageByteArray = Base64
							.decode(visible_sig_custom_image_base64.getBytes());
				} else {
					try {
						imageByteArray = readFile(visible_sig_custom_image_path);
					} catch (IOException e) {
						throw new SignServerException(
								"Error reading custom image data from path specified",
								e);
					}
				}

				try {
					custom_image = Image.getInstance(imageByteArray);
				} catch (BadElementException e) {
					throw new SignServerException(
							"Problem constructing image from custom image data",
							e);
				} catch (MalformedURLException e) {
					throw new SignServerException(
							"Problem constructing image from custom image data",
							e);
				} catch (IOException e) {
					throw new SignServerException(
							"Problem constructing image from custom image data",
							e);
				}

				if (config
						.getProperties()
						.getProperty(
								PDFSigner.VISIBLE_SIGNATURE_CUSTOM_IMAGE_SCALE_TO_RECTANGLE) != null) {
					visible_sig_custom_image_scale_to_rectangle = Boolean
							.parseBoolean(config
									.getProperties()
									.getProperty(
											PDFSigner.VISIBLE_SIGNATURE_CUSTOM_IMAGE_SCALE_TO_RECTANGLE)
									.trim());
					log.debug("resize custom image to rectangle : "
							+ visible_sig_custom_image_scale_to_rectangle);
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
			}
		}

                // Certification level
                final String level = config.getProperty(PDFSigner.CERTIFICATION_LEVEL);
                if (level != null) {
                    if (level.equalsIgnoreCase("NO_CHANGES_ALLOWED")) {
                        certification_level =
                                PdfSignatureAppearance.CERTIFIED_NO_CHANGES_ALLOWED;
                    } else if (level.equalsIgnoreCase("FORM_FILLING_AND_ANNOTATIONS")) {
                        certification_level =
                                PdfSignatureAppearance.CERTIFIED_FORM_FILLING_AND_ANNOTATIONS;
                    } else if (level.equalsIgnoreCase("FORM_FILLING")) {
                        certification_level =
                                PdfSignatureAppearance.CERTIFIED_FORM_FILLING;
                    } else if (level.equalsIgnoreCase("NOT_CERTIFIED")) {
                        certification_level = PdfSignatureAppearance.NOT_CERTIFIED;
                    } else {
                        throw new SignServerException(
                                "Unknown value for CERTIFICATION_LEVEL");
                    }
                }
                if (log.isDebugEnabled()) {
                    log.debug("using certification level: " + certification_level);
                }
	}

	/**
	 * Read byte[] data from file.
	 *
	 * @param pFilePath
	 * @return content of file
	 * @throws IOException
	 */
	public byte[] readFile(String pFilePath) throws IOException {
		FileInputStream fis = new FileInputStream(pFilePath);
		ByteArrayOutputStream bout = new ByteArrayOutputStream();
		try {

			byte[] buff = new byte[1024];
			int count = 0;
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
		visible_sig_rectangle_urx = (int) (visible_sig_rectangle_llx + custom_image
				.getWidth());
		visible_sig_rectangle_ury = (int) (visible_sig_rectangle_lly + custom_image
				.getHeight());
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

	public String getTsa_username() {
		return tsa_username;
	}

	public String getTsa_password() {
		return tsa_password;
	}

	public boolean isUse_custom_image() {
		return use_custom_image;
	}

	public boolean isUse_timestamp() {
		return use_timestamp;
	}

	public boolean isUse_timestamp_authorization() {
		return use_timestamp_authorization;
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
}
