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
package org.signserver.test.utils;

/**
 * Hard-coded test certificates used by some tests.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public interface TestCerts {
    /**
     * subject=/CN=New Signer 1C/C=SE
     * issuer=/CN=DSS Root CA 10/OU=Testing/O=SignServer/C=SE
     * 
     * Validity
     *       Not Before: Jan  1 09:00:00 2025 GMT
     *       Not After : Dec 31 08:59:59 2029 GMT
     *
     * X509v3 Private Key Usage Period: 
     *       Not Before: Jan  2 09:01:00 2026 GMT, Not After: Jan  3 09:02:00 2028 GMT
     */
    static final String SIGNER1C_CERT =       
            "-----BEGIN CERTIFICATE-----\n" +
            "MIIEjzCCAnegAwIBAgIUByEwcZkjsNXhJmuniSCRDAvXkTIwDQYJKoZIhvcNAQEL\n" +
            "BQAwTTEXMBUGA1UEAwwORFNTIFJvb3QgQ0EgMTAxEDAOBgNVBAsMB1Rlc3Rpbmcx\n" +
            "EzARBgNVBAoMClNpZ25TZXJ2ZXIxCzAJBgNVBAYTAlNFMB4XDTI1MDEwMTA5MDAw\n" +
            "MFoXDTI5MTIzMTA4NTk1OVowJTEWMBQGA1UEAwwNTmV3IFNpZ25lciAxQzELMAkG\n" +
            "A1UEBhMCU0UwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCY3hdnwXn/\n" +
            "QKmF46dlI5L8Kz8iL7qXkmz8JcoRPNrQfIubQLog3OlXFh/2TYPIexsgHEJDr8i6\n" +
            "9pDav9PLfWMNRiyhEi69BnR55Ct2LKjdZrKmYWTBdw1tlltyG9HCbXASNZzMWvbi\n" +
            "MqzGi+sdBkpHBcEVC3BYGzfQcVp4MT71l6H8JZlibqhj/XYskYf6j2uAU5WpPVhV\n" +
            "eh2TMBzI9qutV4JW8wGDxB7xUwe3BCcC7ZvX87zt4TgmStUrH5r3tFKpRRuAT4N9\n" +
            "xtncnDqssWYLNlrsFJjIs9Nh/TdS7lFte/iB+4L1R5dvDIw5tZ5MSKQCGCNPGdB3\n" +
            "2ytKxVE9OUmhAgMBAAGjgY4wgYswDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBQg\n" +
            "eiHe6K27Aqj7cVikCWK52FgFojAdBgNVHQ4EFgQU5EtIIUhhkS+OG9r7LK+EXQxk\n" +
            "0xEwKwYDVR0QBCQwIoAPMjAyNjAxMDIwOTAxMDBagQ8yMDI4MDEwMzA5MDIwMFow\n" +
            "DgYDVR0PAQH/BAQDAgeAMA0GCSqGSIb3DQEBCwUAA4ICAQAC88XocSNZ3mk4lBpz\n" +
            "wuS9ed4x/Xa84Tltx2NimoJmCzR+clDZZ+Jndkzj9Hss7D8tqOR+BvMiB3FAyFk3\n" +
            "YbaDkrFaVUFBIpaJjvs2N1O9G6sQ/lBJGnkZiZ86JMhQuWGZHJ/GoGVzMVXuZkwg\n" +
            "sDHOhm4ooisO7iuk5w7gV6WA2YCjBKfoH8XgjqRLN8AjmXTPpmQtHxx+pVKvFR62\n" +
            "MDphkFOGs3EgxZosgFQzrICqfRiYjGCPToNYuJ+khKHN9IXuOT003bcQeoowbvfW\n" +
            "Vnu8w+Dv3kW4wjNXC45FRKpB9bHgokoJMgoL+dVVWxmBVDqpEmfVYEs+/C359mYm\n" +
            "USU0u3cAvPg3sbh3rGeMDFgNWlvUkIaZFm8ffOc6UUxWYJFWYgegr5EHdXT/OnC4\n" +
            "AOtZKGWp5Dqkas4bs71FsQlc9+R1Z9iiZ+yl2Zu5O+KP1NT//PJfUNld0s/mkgui\n" +
            "yt5MRSyhpd8p92FZF6X7AxNa/whXE5EjFMt4CAZZuXyADzzkzp6NwSPyxM2t7lh8\n" +
            "GO/vjvJaHKvG/HyfQhGAFojCLlEcbC9xz69O0VK44U+NWBy7ILSq+x1bwUv3+BlX\n" +
            "aHPcts7ZPJJVx9uXGnr71qvdl5bwbk+E2h47pO0EOQqtLGe6U4vvh0uhgnbb4+mF\n" +
            "FcdFIIQdZ5AaRZ7QhdwOZIcR0w==\n" +
            "-----END CERTIFICATE-----";
    
    /**
     * subject=/CN=New Signer 1D/C=SE
     * issuer=/CN=DSS Root CA 10/OU=Testing/O=SignServer/C=SE
     * Validity
     *       Not Before: Jan  1 09:00:00 2015 GMT
     *       Not After : Dec 31 08:59:59 2019 GMT
     * X509v3 Private Key Usage Period: 
     *       Not Before: Dec 29 09:00:00 2024 GMT, Not After: Dec 28 09:00:00 2029 GMT
     */
    static final String SIGNER1D_CERT =
            "-----BEGIN CERTIFICATE-----\n" +
            "MIIEjzCCAnegAwIBAgIUDTDz9hN1OM2cQlZsST9W65By8yUwDQYJKoZIhvcNAQEL\n" +
            "BQAwTTEXMBUGA1UEAwwORFNTIFJvb3QgQ0EgMTAxEDAOBgNVBAsMB1Rlc3Rpbmcx\n" +
            "EzARBgNVBAoMClNpZ25TZXJ2ZXIxCzAJBgNVBAYTAlNFMB4XDTE1MDEwMTA5MDAw\n" +
            "MFoXDTE5MTIzMTA4NTk1OVowJTEWMBQGA1UEAwwNTmV3IFNpZ25lciAxRDELMAkG\n" +
            "A1UEBhMCU0UwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDGuhc1Yrfo\n" +
            "G7TimL3p4nCkXmHLZ9mWxI7yVCUoBaJIXZrUO4VgvjZ2luXWvHA7mMGfoD3LygRo\n" +
            "OnVLTA49bA1TIWI7w6yh9/953pueqpSQ6iMHTSBH8fevs3H5AlGou4hKo0HvSOax\n" +
            "AiqkNW3NOqCqnKqDSYwOSzkoSWPWdClI5PtM9/6LoDQVNj+85735Wa3BGrTuy6Ha\n" +
            "K0+YjmS+NqGDVktCztHlcJHhx+ifgDUqda+DHhRE1wA+rlLyJzFSvT04pjc+1YNP\n" +
            "CDxmmi+1EAGA5UPMATPypEfK++UrFe1zdx08SZH5uVyYCDBGVN4iXENo7W1DxpYV\n" +
            "kPrjWr2RKmrjAgMBAAGjgY4wgYswDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBQg\n" +
            "eiHe6K27Aqj7cVikCWK52FgFojAdBgNVHQ4EFgQUV8zzghrKI/oP9In3A+0G9sy7\n" +
            "X6cwKwYDVR0QBCQwIoAPMjAyNDEyMjkwOTAwMDBagQ8yMDI5MTIyODA5MDAwMFow\n" +
            "DgYDVR0PAQH/BAQDAgeAMA0GCSqGSIb3DQEBCwUAA4ICAQBZGhymOKbkXPr4GweZ\n" +
            "DLviLzADppw8rt7JtKSRrj5LyyZKrl3Qm19iMYMmD7PVf9M8UGI3AI6X/APeUJ7w\n" +
            "vWOsX8PxmVzPWpNh/xUYGM85oVZ6k5bTjAqydEnJKJiXp/YrBAKyyEbrgjQffckR\n" +
            "rgg9kqYKOZXHYA9BAI9ReImZQktS/62RmYjjsHI0FM/0IrYUo1etHXVBPKSlVKDq\n" +
            "nzjrdp0+YxMqk6t08E1z0lUQr1WyJKkO8HldMhI21AjoVqTOEYPaQmYh8joQxNEF\n" +
            "mHot6YOkvIcfmYkj7bScpeUY8p219JVXfORlxngkpaHiwD5MXPuk9aXYTotfUsWE\n" +
            "cRRf+o4lNKzmnBuhGXMnWPUHdHDe96ocVWUlSn+olx/NKbt6B9F5PAlzss1/As7O\n" +
            "RMfwOx27vJzZF0G517fXOhb35H2Oe1ysHqgIAHDlhn4zvLjnnfFNMpQMRY7RpIe4\n" +
            "I3dc91L/dTbN9eMrF77C/8mE/lVXAADM5gLqD4VP8hbsvli/SgyR8AYFQbblN25u\n" +
            "k4zIQMUn0eu+t0DW0svwxRJ8yjszh77hMZMVcL8kd5lC6HpPaIUoHoSG8MnnYLkA\n" +
            "v/pLQ58auRWz8jwEq2lOrMrEi0eT01/PiKYszkprnvfsOuyejJVKbOF4755+CpI5\n" +
            "LosUKmJIbZV6u7/IRzYp0dmD4g==\n" +
            "-----END CERTIFICATE-----";
    
    /**
    subject=/CN=Signer 4/OU=Testing/O=SignServer/C=SE
    issuer=/CN=DSS Root CA 10/OU=Testing/O=SignServer/C=SE
    valid until=27/05/2021 09:51:45 GMT
    */
    static String CERT1 =
              "MIIElTCCAn2gAwIBAgIITz1ZKtegWpgwDQYJKoZIhvcNAQELBQAwTTEXMBUGA1UE"
            + "AwwORFNTIFJvb3QgQ0EgMTAxEDAOBgNVBAsMB1Rlc3RpbmcxEzARBgNVBAoMClNp"
            + "Z25TZXJ2ZXIxCzAJBgNVBAYTAlNFMB4XDTExMDUyNzA5NTE0NVoXDTIxMDUyNzA5"
            + "NTE0NVowRzERMA8GA1UEAwwIU2lnbmVyIDQxEDAOBgNVBAsMB1Rlc3RpbmcxEzAR"
            + "BgNVBAoMClNpZ25TZXJ2ZXIxCzAJBgNVBAYTAlNFMIIBIjANBgkqhkiG9w0BAQEF"
            + "AAOCAQ8AMIIBCgKCAQEAnCGlYABPTW3Jx607cdkHPDJEGXpKCXkI29zj8BxCIvC3"
            + "3kyGZB6M7EICU+7vt200u1TmSjx2auTfZI6sA2cDsESlMhKJ+8nj2uj1f5g9MYRb"
            + "+IIq1IIhDArWwICswnZkWL/5Ncggg2bNcidCblDy5SUQ+xMeXtJQWCU8Zn3a+ySZ"
            + "Z1ZiYZ10gUu5JValsuOb8YpcT/pqBPF0cgEy6mIe3ANolzxLKNUBYAsQzQnCvgx+"
            + "GqgbzYHo8fkppSGUFVYdFI0MC9CBT72eOxxQoguICWXus8BdIwebZDGQdluKvTNs"
            + "ig4hM39G6WvPqoEi9I86VhY9mSyY+WOeU5Y3ZsC8CQIDAQABo38wfTAdBgNVHQ4E"
            + "FgQUGqddBv2s8iEa5B98MVTbQ2HiFkAwDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAW"
            + "gBQgeiHe6K27Aqj7cVikCWK52FgFojAOBgNVHQ8BAf8EBAMCBeAwHQYDVR0lBBYw"
            + "FAYIKwYBBQUHAwIGCCsGAQUFBwMEMA0GCSqGSIb3DQEBCwUAA4ICAQB8HpFOfiTb"
            + "ylu06tg0yqvix93zZrJWSKT5PjwpqAU+btQ4fFy4GUBG6VuuVr27+FaFND3oaIQW"
            + "BXdQ1+6ea3Nu9WCnKkLLjg7OjBNWw1LCrHXiAHdIYM3mqayPcf7ezbr6AMnmwDs6"
            + "/8YAXjyRLmhGb23M8db+3pgTf0Co/CoeQWVa1eJObH7aO4/Koeg4twwbKG0MjwEY"
            + "ZPi0ZWB93w/llEHbvMNI9dsQWSqIU7W56KRFN66WdqFhjdVPyg86NudH+9jmp4x1"
            + "Ac9GKGNOYYfDnQCdsrJwZMvcI7bZykbd77ZC3zBzuaISAeRJq3rjHygSeKPHCYDW"
            + "zAVEP9yaO0fL7HMZ2uqHxokvuOo5SxgVfvLr+kT4ioQHz+r9ehkCf0dbydm7EqyJ"
            + "Y7YSFUDEqk57dnZDxy7ZgUA/TZf3I3rPjSopDxqiqJbm9L0GPW3zk0pAZx7dgLcq"
            + "2I8fv+DBEKqJ47/H2V5aopxsRhiKC5u8nEEbAMbBYgjGQT/5K4mBt0gUJFNek7vS"
            + "a50VH05u8P6yo/3ppDxGCXE2d2JfWlEIx7DRWWij2PuOgDGkvVt2soxtp8Lx+kS6"
            + "K+G+tA5BGZMyEPdqAakyup7udi4LoB0wfJ58Jr5QNHCx4icUWvCBUM5CTcH4O/pQ"
            + "oj/7HSYZlqigM72nR8f/gv1TwLVKz+ygzg==";
}
