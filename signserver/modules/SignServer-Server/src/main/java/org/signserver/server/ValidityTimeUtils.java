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
package org.signserver.server;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.Calendar;
import java.util.Date;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.PrivateKeyUsagePeriod;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.SignServerConstants;
import org.signserver.common.WorkerConfig;

/**
 * Utility methods for checking the validity time of signer certificates.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class ValidityTimeUtils {
    
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(ValidityTimeUtils.class);
    
    /**
     * OID for the PrivateKeyUsagePeriod extension.
     * Specified here as different versions of BouncyCastle (i.e. 1.45 vs 1.46) 
     * uses different types for it breaking runtime compatibility.
     */
    private static final DERObjectIdentifier PRIVATE_KEY_USAGE_PERIOD = new DERObjectIdentifier("2.5.29.16");
  
    /**
     * Get the signing validity for the given worker, either notAfter(true) or 
     * notBefore(false).
     * @param notAfter True if the notAfter time should be returned
     * @param workerId Id of worker
     * @param awc Worker configuration
     * @param cert The signer certificate
     * @return The validity date
     * @throws CryptoTokenOfflineException if the signing validity could not be obtained
     */
    public static Date getSigningValidity(final boolean notAfter, final int workerId,
            final WorkerConfig awc, final X509Certificate cert)
            throws CryptoTokenOfflineException {
        Date certDate = null;
        Date privatekeyDate = null;
        Date minreimainingDate = null;

        boolean checkcertvalidity = awc.getProperties().getProperty(
                SignServerConstants.CHECKCERTVALIDITY, "TRUE").equalsIgnoreCase(
                "TRUE");
        boolean checkprivatekeyvalidity = awc.getProperties().getProperty(
                SignServerConstants.CHECKCERTPRIVATEKEYVALIDITY, "TRUE").
                equalsIgnoreCase("TRUE");
        int minremainingcertvalidity = Integer.valueOf(awc.getProperties().
                getProperty(SignServerConstants.MINREMAININGCERTVALIDITY, "0"));
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("checkcertvalidity: " + checkcertvalidity);
            LOG.debug("checkprivatekeyvalidity: " + checkprivatekeyvalidity);
            LOG.debug("minremainingcertvalidity: " + minremainingcertvalidity);
        }

        // Certificate validity period. Cert must not be expired.
        if (checkcertvalidity) {
            certDate = notAfter ? cert.getNotAfter() : cert.getNotBefore();
        }

        // Private key usage period. Private key must not be expired
        if (checkprivatekeyvalidity) {
            // Check privateKeyUsagePeriod of it exists
            try {
                final PrivateKeyUsagePeriod p = getPrivateKeyUsagePeriod(cert);
                if (p != null) {
                    privatekeyDate = notAfter ? p.getNotAfter().getDate()
                            : p.getNotBefore().getDate();
                }
            } catch (IOException e) {
                LOG.error(e);
                CryptoTokenOfflineException newe =
                        new CryptoTokenOfflineException(
                        "Error Signer " + workerId
                        + " have a problem with PrivateKeyUsagePeriod, check server LOG.");
                newe.initCause(e);
                throw newe;
            } catch (ParseException e) {
                LOG.error(e);
                CryptoTokenOfflineException newe =
                        new CryptoTokenOfflineException(
                        "Error Signer " + workerId
                        + " have a problem with PrivateKeyUsagePeriod, check server LOG.");
                newe.initCause(e);
                throw newe;
            }
        }

        // Check remaining validity of certificate. Must not be too short.
        if (notAfter && minremainingcertvalidity > 0) {
            final Date certNotAfter = cert.getNotAfter();
            final Calendar cal = Calendar.getInstance();
            cal.setTime(certNotAfter);
            cal.add(Calendar.DAY_OF_MONTH, -minremainingcertvalidity);
            minreimainingDate = cal.getTime();
        }

        Date res = certDate;
        res = max(notAfter, res, privatekeyDate);
        res = max(notAfter, res, minreimainingDate);
        
        if (LOG.isDebugEnabled()) {
            LOG.debug((notAfter ? "min(" : "max(") + certDate + ", "
                    + privatekeyDate + ", " + minreimainingDate + ") = "
                    + res);
        }
        return res;
    }
    
    private static PrivateKeyUsagePeriod getPrivateKeyUsagePeriod(
            final X509Certificate cert) throws IOException {
        PrivateKeyUsagePeriod res = null;
        final byte[] extvalue = cert.getExtensionValue(PRIVATE_KEY_USAGE_PERIOD.getId());
        
        if ((extvalue != null) && (extvalue.length > 0)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug(
                    "Found a PrivateKeyUsagePeriod in the signer certificate.");
            }
            final DEROctetString oct = (DEROctetString) (new ASN1InputStream(
                    new ByteArrayInputStream(extvalue)).readObject());

            res = PrivateKeyUsagePeriod.
                    getInstance((ASN1Sequence) new ASN1InputStream(
                    new ByteArrayInputStream(oct.getOctets())).
                    readObject());
        }
        return res;
    }
    
    
    /**
     * @param inv If the max function should be inverrted (min).
     * @param date1 Operand 1
     * @param date2 Operand 2
     * @return The last of the two dates unless inv is true in which case it
     * returns the first of the two.
     */
    private static Date max(final boolean inv, final Date date1,
            final Date date2) {
        if (date1 == null) {
            return date2;
        } else if (date2 == null) {
            return date1;
        }
        return inv && date1.before(date2) ? date1 : date2;
    }

    /**
     * Checks that the current time is withing the signers "signing validity".
     * @param workerId Id of worker
     * @param awc Worker configuration
     * @param cert Signer certificate
     * @throws CryptoTokenOfflineException with an error message if the signer 
     * was not within the validity time or there was an error obtaining the time
     */
    public static void checkSignerValidity(final int workerId, final WorkerConfig awc, final X509Certificate cert) throws CryptoTokenOfflineException {
        // Check certificate, privatekey and minremaining validities
        final Date notBefore =
                ValidityTimeUtils.getSigningValidity(false, workerId, awc, cert);
        final Date notAfter =
                ValidityTimeUtils.getSigningValidity(true, workerId, awc, cert);
        if (LOG.isDebugEnabled()) {
            LOG.debug("The signer validity is from '"
                    + notBefore + "' until '" + notAfter + "'");
        }

        // Compare with current date
        final Date now = new Date();
        if (notBefore != null && now.before(notBefore)) {
            final String msg = "Error Signer " + workerId
                    + " is not valid until " + notBefore;
            if (LOG.isDebugEnabled()) {
                LOG.debug(msg);
            }
            throw new CryptoTokenOfflineException(msg);
        }
        if (notAfter != null && now.after(notAfter)) {
            String msg = "Error Signer " + workerId
                    + " expired at " + notAfter;
            if (LOG.isDebugEnabled()) {
                LOG.debug(msg);
            }
            throw new CryptoTokenOfflineException(msg);
        }
    }
}
