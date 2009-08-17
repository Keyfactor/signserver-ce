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

package org.signserver.module.xmlvalidator;

/**
 * Test data for TestXMLValidator.
 * 
 * @author Markus Kilås
 * $version $Id$
 */
class XMLValidatorTestData {

	/**
	   * SerialNumber: 9072735712286141837
	     IssuerDN: CN=AdminTrunk2CA1,O=EJBCA Trunk3,C=SE
	   Start Date: Mon May 18 16:46:59 CEST 2009
	   Final Date: Wed May 18 16:46:59 CEST 2011
	    SubjectDN: CN=xmlsigner2,O=SignServer Test,C=SE
	   */
	static final String CERT_XMLSIGNER = 
		"MIIDejCCAmKgAwIBAgIIfejVD5fQ7Y0wDQYJKoZIhvcNAQEFBQAwPTEXMBUGA1UEAwwOQWRtaW5U"
		+"cnVuazJDQTExFTATBgNVBAoMDEVKQkNBIFRydW5rMzELMAkGA1UEBhMCU0UwHhcNMDkwNTE4MTQ0"
		+"NjU5WhcNMTEwNTE4MTQ0NjU5WjA8MRMwEQYDVQQDDAp4bWxzaWduZXIyMRgwFgYDVQQKDA9TaWdu"
		+"U2VydmVyIFRlc3QxCzAJBgNVBAYTAlNFMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA"
		+"242WCkRvThZJR9YWr1R7Hpkjxzrvnzc5TeytbAmcA6ZMZYoroXEXQv2wW2yYoJl6UcSJCg7Z4Vr/"
		+"Xdn5O7Nd/YXkAbjP1OflYFI/yE90uAAfz6eKtgfiu7xEmGRogQjBA7xsEWrmyB1GUJCovEXYupss"
		+"jMKcnNQKO+FCKY7imTb0EWoc82f1Z1y7LG7PdpZqRZkCaEeVBrdJoBYLTVAJq89p/stsqiL8rdaE"
		+"1Eq9DkY2JqjPcK+9dCJ+tVUbd0MReFC/NYkDBepCYWqs3AXSYmI7nb6pkfvxRitQ5mcecZg8Jcq/"
		+"Gq0ZQ8mFJgnSVa3+vxMNa/E3EV4V3n1Ng1kk/QIDAQABo38wfTAdBgNVHQ4EFgQUkts3bypVw2DK"
		+"XyVgEqiMN6ULPBwwDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBRQyb5w7zsEEfalmYd7zvUzxENQ"
		+"ZDAOBgNVHQ8BAf8EBAMCBeAwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMEMA0GCSqGSIb3"
		+"DQEBBQUAA4IBAQCc8LCp/lBBVeiuKDhwTqEnyKH8GQmDq1dRfuxAeUXfCVfzhnPTPTvpa3qDnNeE"
		+"F9ftmaUK/c2ieSEeHHsIoNzZrFtQ1v2kDP6uRq1P5GVnSs/4UPazZDZDwDWIq8XNDeVpW4Ua0pqJ"
		+"GmOdUSQPJUZvAJRlLkZ/9R/kygbG3n5GSVecDk1tNlOqGHLuclNSkLZwyIleJkysf9YQOKESoRSM"
		+"X8NdNtXWjosoLA0NaNhQocuxThgLnI4k2T85wVfd69SqqbeakssW7ARIE9F1PIZa7LDQAVic7XIE"
		+"fiKVZ4CQ01/QX+xn0pEhDjIHqfld5ghxDRJWxR9C2B4O2YDnfEOG";
	  
	/**
	   * SerialNumber: 8811693520800705369
	         IssuerDN: CN=AdminTrunk2CA1,O=EJBCA Trunk3,C=SE
	       Start Date: Mon May 11 09:57:53 CEST 2009
	       Final Date: Thu May 09 09:57:53 CEST 2019
	        SubjectDN: CN=AdminTrunk2CA1,O=EJBCA Trunk3,C=SE
	   */
	static final String CERT_ISSUER = 
	  	"MIIDXzCCAkegAwIBAgIIeklskiDv61kwDQYJKoZIhvcNAQEFBQAwPTEXMBUGA1UEAwwOQWRtaW5U"
		+"cnVuazJDQTExFTATBgNVBAoMDEVKQkNBIFRydW5rMzELMAkGA1UEBhMCU0UwHhcNMDkwNTExMDc1"
		+"NzUzWhcNMTkwNTA5MDc1NzUzWjA9MRcwFQYDVQQDDA5BZG1pblRydW5rMkNBMTEVMBMGA1UECgwM"
		+"RUpCQ0EgVHJ1bmszMQswCQYDVQQGEwJTRTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB"
		+"AKRvUvHK2CuLmntie0DRvc9OSHyRe4UbPfwKsRq3QqH+rn5gsYIFlsRVYstY16qh0tFnsQiFRld4"
		+"V6TqZn/2xKmDnF7mpfEiM2nfczNi3yabdmqm64692hglRly9jqbOveHenRk8F5Wj7Db5stN5V3O3"
		+"RfIl+cIUWrQAq2WJkYJXp2RN+sK9Sz7RwD0YMru9SobtarttF4JuFJrPLkf/Ds8AMMtlxkEnDIHl"
		+"BAhFQtOURmoEOKzieMeW/7jZSLYIy9sZTQoZjs0Ks+YlZvHY39YWUisc88Saa9hhThjIHhhU/e8S"
		+"Tk6xReyMTYJwMAB9WpvCPWoLQtAbhF2SD/Y3Rt8CAwEAAaNjMGEwHQYDVR0OBBYEFFDJvnDvOwQR"
		+"9qWZh3vO9TPEQ1BkMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAUUMm+cO87BBH2pZmHe871"
		+"M8RDUGQwDgYDVR0PAQH/BAQDAgGGMA0GCSqGSIb3DQEBBQUAA4IBAQAFsegj+buOHqFkt2vkC3Gq"
		+"b2JAeDfDScwI5zH336lFCSLsyEYGBaFS3xd+WnvTIaacGQplN1iG5ATGsKzNtwrOfzaDRkDIictw"
		+"OJBG5S4kZU0mF5dGpE9/VAp6DNiqMxnXRL8Yh2+EMMuVOSEKp0MogQprEIxIsQj5FhbBASldpQgO"
		+"140lqoeXrmm/nMMf/EM5Tqf2BiX/CgTwqiuY7Lf3Ov7QfepLI1AWgFabHkysU2YTvjDupNi5/+gB"
		+"5jIA5vhavMpylDbucUdM9vAetXmqe1P3sOKipGKHvkWFNJNyOmDjN9wnr+i9PFxU0IehSRdim60x"
		+"Cw3AxYWCo94Dz/6F";
	  
	static final String CERT_OTHER =
		 "MIIDTjCCAjagAwIBAgIIH51RSUxYOpYwDQYJKoZIhvcNAQEFBQAwPTEXMBUGA1UEAwwOQWRtaW5U"
		+"cnVuazJDQTExFTATBgNVBAoMDEVKQkNBIFRydW5rMjELMAkGA1UEBhMCU0UwHhcNMDkwNTA2MTEx"
		+"ODMxWhcNMTEwNTA2MTExODMxWjAQMQ4wDAYDVQQDDAV1c2VyMTCCASIwDQYJKoZIhvcNAQEBBQAD"
		+"ggEPADCCAQoCggEBAM1Qs6eVhfLKpK21Iog18Ulx/x5uQVCwGdo2lfRFGwT93sAtUvHujrPppxyQ"
		+"pKc7//3NrKJ27N8KcuLr2qmtjA14rIzVzfehSyr8GusNmRa9UKN7QjRDbkb3TED9ib2TbKzz9EQW"
		+"tuQrYC5vpcEug1QjJ/sd/LWV7gqMlR+M1p1abRywrpBlsZrryMwnkCE3COneGKRmMUF9LGOYzehW"
		+"x7NbpfGQuY+E7677bys9yTb6y+gDWBEPxfnhysRYGI/Ze0Wa04g/ICwi/nUd5LHV1NW9ibwvsCSV"
		+"V5iMtaGYjh6jR0uuk3evDJNI0loLBpEsMBleBC9XWFU+sfwjDnWXBEsCAwEAAaN/MH0wHQYDVR0O"
		+"BBYEFLkQvTnoDO9LQN4tA7pOB8AFsLyiMAwGA1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAUMAjPtLnd"
		+"SML5y9FmcUXD8C4Xtx8wDgYDVR0PAQH/BAQDAgXgMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEF"
		+"BQcDBDANBgkqhkiG9w0BAQUFAAOCAQEAKOa3XCgjWHD9rwv+dZrLtrQDtLSoj8DFgLghQ5alhPs2"
		+"/6v/DpjQUFLUmNqg9CwUy/UZwz09zJm4SDfnvbH3JjaCwNgp4VvG1TRK4D3wgaBaVZHrXONAyBDB"
		+"3XtSOoJuvR4pW1URG5kvL0wqB825dWsVzomUwhOPM1lMPgINWJwRun89bV9wAVcRNEdKM2d4Gb8A"
		+"Otn8gzx/E/MSaPzexW66Dd9dEHTJIjUpVdHd5Mp4BL/BdNYT2GtU+R1clObcDXUGFjMI9HaT2ARg"
		+"pN5nwZxfMj6Zz+9Y9fAZdWzjUa4rBwbNzZlvZ/uXQaIb4U0DPmSJZC0YwXmUqU5u7W7Zow==";
	
	static final String SIGNATURE_BY_XMLSIGNER2 = 
		 "1oJFP0W8m5k0OJe6A9skm9GPXoRhpGx+Tz5XJxuEW8paNQjKNZ0/UPi1Tyv01e+kve/legte8uQW"
		+"+X4m2oQOnt+s8qTHu9FgfJieLgjXT9nT9ruv96TwsFF6zsQF7TodYo1Ru3H/OJlu/tKPTnGDzE9H"
		+"arILFJNyTPFBA7Ulzxj8KRBHPkzIzzxD0AaodBWDut7nMGqlu1NC1afcT1eNNxfDB02wIvy4E6VI"
		+"/HfLN3uhTtOq50iPKT9x5M1znIIpnVlJlsTSmnGC7rMUaWDtpttF+LHBWQOnAFhSGS22mHQpbXXc"
		+"ZoDA2iab5GkpvzzNIpjuUszZ8Ea968kK59IxQA==";
	
	static final String SIGNATURE_BY_OTHER =
		"vNPmEQ9ckorNrQ793HZsVP8/NB07S2pNZkJ7JvfALNBkyDCntC+7UsiXWPRM1YMz3dnDF9WkjWHF"
		+"549XnjiwT7k0cBnKH0563rB0KWSjgAN7dT27g/+dKbvz7B6Q+v1uQDodahBW8Cpm6JuLwO0hZpHF"
		+"subk1bfz/iCUsJEuzGq++OyTGQJiVyJ7D/+fxRefVdORAcGRXBmvRUh3/pKGnv36BzYOR3z4lDLE"
		+"obSmC8X62cTYA+uCW3UJAhuxGEmXdYzrNTA0RH5ybC8kSkPmMvbxeA45hiyT6k8BiEhVAumncRkd"
		+"lWowqRrdOL0XaGczUUsp+BN6xsIqzfk3RCVtSQ==";
	
	/**
	 * Ok sig, ok cert
	 */
	static final String TESTXML1 = 
		"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
		+"<root><my-tag>My Data</my-tag><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">"
		+"    <SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments\"/><SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/><Reference URI=\"\"><Transforms><Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><DigestValue>uCUwcTJFETdIT9uYQPkG9GaXg+Y=</DigestValue></Reference></SignedInfo>"
		+"    <SignatureValue>"+SIGNATURE_BY_XMLSIGNER2+"</SignatureValue>"
		+"    <KeyInfo>"
		+"        <X509Data>"
		+"            <X509Certificate>"+CERT_XMLSIGNER+"</X509Certificate>"
		+"        <X509Certificate>"+CERT_ISSUER+"</X509Certificate>"
		+"        </X509Data>"
		+"    </KeyInfo>"
		+"</Signature ></root>";
	
	/**
	 * Ok sig, untrusted issuer
	 */
	static final String TESTXML2 =
		"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
		+"<root-tag>"
		+"    <tag2>Hello</tag2>"
		+"<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments\"/><SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/><Reference URI=\"\"><Transforms><Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><DigestValue>zMaM/bDls8EAts/a0NHQSHFoMqQ=</DigestValue></Reference></SignedInfo><SignatureValue>"
		+SIGNATURE_BY_OTHER+"</SignatureValue><KeyInfo><X509Data><X509Certificate>"+CERT_OTHER+"</X509Certificate></X509Data></KeyInfo></Signature></root-tag>";
	
	/**
	 * Ok sig, wrong certificate
	 */
	static final String TESTXML3 = 
		"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
		+"<root><my-tag>My Data</my-tag><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">"
		+"    <SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments\"/><SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/><Reference URI=\"\"><Transforms><Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><DigestValue>uCUwcTJFETdIT9uYQPkG9GaXg+Y=</DigestValue></Reference></SignedInfo>"
		+"    <SignatureValue>"+SIGNATURE_BY_XMLSIGNER2+"</SignatureValue>"
		+"    <KeyInfo>"
		+"        <X509Data>"
		+"        <X509Certificate>"+CERT_ISSUER+"</X509Certificate>"
		+"        </X509Data>"
		+"    </KeyInfo>"
		+"</Signature ></root>";
	
	/**
	 * Ok sig, no certificate
	 */
	static final String TESTXML33 = 
		"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
		+"<root><my-tag>My Data</my-tag><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">"
		+"    <SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments\"/><SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/><Reference URI=\"\"><Transforms><Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><DigestValue>uCUwcTJFETdIT9uYQPkG9GaXg+Y=</DigestValue></Reference></SignedInfo>"
		+"    <SignatureValue>"+SIGNATURE_BY_XMLSIGNER2+"</SignatureValue>"
		+"    <KeyInfo>"
		+"        <X509Data>"
		+"        </X509Data>"
		+"    </KeyInfo>"
		+"</Signature ></root>";
	
	/**
	 * Ok sig, missing cert 2
	 */
	private static final String TESTXML4 = 
		"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
		+"<root><my-tag>My Data</my-tag><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">"
		+"    <SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments\"/><SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/><Reference URI=\"\"><Transforms><Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><DigestValue>uCUwcTJFETdIT9uYQPkG9GaXg+Y=</DigestValue></Reference></SignedInfo>"
		+"    <SignatureValue>"+SIGNATURE_BY_XMLSIGNER2+"</SignatureValue>"
		+"    <KeyInfo>"
		+"        <X509Data>"
		+"            <X509Certificate>"+CERT_XMLSIGNER+"</X509Certificate>"
		+"        </X509Data>"
		+"    </KeyInfo>"
		+"</Signature ></root>";
	
	/**
	 * OK signature, first ca cert then signer cert
	 */
	static final String TESTXML5 = 
		"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
		+"<root><my-tag>My Data</my-tag><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">"
		+"    <SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments\"/><SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/><Reference URI=\"\"><Transforms><Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><DigestValue>uCUwcTJFETdIT9uYQPkG9GaXg+Y=</DigestValue></Reference></SignedInfo>"
		+"    <SignatureValue>"+SIGNATURE_BY_XMLSIGNER2+"</SignatureValue>"
		+"    <KeyInfo>"
		+"        <X509Data>"
		+"        <X509Certificate>"+CERT_ISSUER+"</X509Certificate>"
		+"            <X509Certificate>"+CERT_XMLSIGNER+"</X509Certificate>"
		+"        </X509Data>"
		+"    </KeyInfo>"
		+"</Signature ></root>";
	
}
