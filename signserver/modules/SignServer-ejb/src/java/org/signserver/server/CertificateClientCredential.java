package org.signserver.server;

public class CertificateClientCredential implements IClientCredential {

    private String serialNumber;
    private String issuerDN;

    public CertificateClientCredential(String serialNumber, String issuerDN) {
        this.serialNumber = serialNumber;
        this.issuerDN = issuerDN;
    }

    public String getIssuerDN() {
        return issuerDN;
    }

    public String getSerialNumber() {
        return serialNumber;
    }
}
