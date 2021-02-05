/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.ejbca.peerconnector;

import java.util.List;

import javax.ejb.Local;

import org.cesecore.certificates.certificate.Base64CertData;
import org.cesecore.certificates.certificate.CertificateData;

/**
 * Local interface for PeerPublisherSession.
 * 
 * NOTE: This class is Enterprise only. Any moves of this class have to be mirrored in the permission file of the SVN repository.
 * 
 * @version $Id$
 */
@Local
public interface PeerPublisherSessionLocal extends PeerPublisherSession {

    /** @return the CertificateData entity by its primary key or null if it wasn't found. */
    CertificateData rawGetCertificateData(String fingerprint);

    /** @return the Base64CertData entity by its primary key or null if it wasn't found. */
    Base64CertData rawGetBase64CertData(String fingerprint);

    /** @return a row count optionally limited by revocation status and issuer OR certificate profile id. */
    int getRowEstimate(List<String> issuerDns, List<Integer> certificateProfileIds, boolean onlyRevoked);

    /** @return a list of primary keys and the updateTime column that indicates when the row was last updated starting from the provided lastFingerprint. */
    List<FingerprintAndTime> getFingerprintAndTimes(List<String> issuerDns, List<Integer> certificateProfileIds, boolean onlyRevoked, String lastFingerprint, int maxResults);

    /** @return a list of missing or out-dated rows for each of the provided fingerprints. */
    List<FingerprintAndHint> getMissingRows(List<FingerprintAndTime> existingRowsAtRemoteNode);
}
