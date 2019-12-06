/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.ejbca.peerconnector.keybind;

/**
 * Information about an InternalKeyBinding.
 * 
 * @version $Id$
 */
public class InternalKeyBindingStatusReport {
    private final String type;
    private final int id;
    private final String name;
    private final String status;
    private final String certificateFingerprint;
    private final int cryptoTokenId;
    private final String cryptoTokenName;
    private final boolean cryptoTokenActive;
    private final String currentKeyPairAlias;
    private final String currentKeyPairAlgorithm;
    private final String currentKeyPairSpecs;
    private final String currentKeyPairSubjectKeyId;
    
    public InternalKeyBindingStatusReport(final String type, final int id, final String name, final String status, final String certificateFingerprint,
            final int cryptoTokenId, final String cryptoTokenName, final boolean cryptoTokenActive, final String currentKeyPairAlias,
            final String currentKeyPairAlgorithm, final String currentKeyPairSpecs, final String currentKeyPairSubjectKeyId) {
        this.type = type;
        this.id = id;
        this.name = name;
        this.status = status;
        this.certificateFingerprint = certificateFingerprint;
        this.cryptoTokenId = cryptoTokenId;
        this.cryptoTokenName = cryptoTokenName;
        this.cryptoTokenActive = cryptoTokenActive;
        this.currentKeyPairAlias = currentKeyPairAlias;
        this.currentKeyPairAlgorithm = currentKeyPairAlgorithm;
        this.currentKeyPairSpecs = currentKeyPairSpecs;
        this.currentKeyPairSubjectKeyId = currentKeyPairSubjectKeyId;
    }

    public String getType() { return type; }
    public int getId() { return id; }
    public String getName() { return name; }
    public String getStatus() { return status; }
    public String getCertificateFingerprint() { return certificateFingerprint; }
    public int getCryptoTokenId() { return cryptoTokenId; }
    public String getCryptoTokenName() { return cryptoTokenName; }
    public boolean isCryptoTokenActive() { return cryptoTokenActive; }
    public String getCurrentKeyPairAlias() { return currentKeyPairAlias; }
    public String getCurrentKeyPairAlgorithm() { return currentKeyPairAlgorithm; }
    public String getCurrentKeyPairSpecs() { return currentKeyPairSpecs; }
    public String getCurrentKeyPairSubjectKeyId() { return currentKeyPairSubjectKeyId; }
}
