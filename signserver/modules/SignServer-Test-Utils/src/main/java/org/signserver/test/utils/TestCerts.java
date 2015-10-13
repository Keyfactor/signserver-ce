/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.signserver.test.utils;

import org.bouncycastle.util.encoders.Base64;

/**
 *
 * @author Marcus Lundblad
 * @version $Id$
 */
public interface TestCerts {
    static final String SIGNER1C_CERT = 
            "-----BEGIN CERTIFICATE-----\n" +
            "MIIDBzCCAe+gAwIBAgIBATANBgkqhkiG9w0BAQUFADAeMRwwGgYDVQQDExNUZXN0\n" +
            "IFYzIENlcnRpZmljYXRlMB4XDTI1MDEwMTA5MDAwMFoXDTMwMDEwMTA5MDAwMFow\n" +
            "HjEcMBoGA1UEAxMTVGVzdCBWMyBDZXJ0aWZpY2F0ZTCCASIwDQYJKoZIhvcNAQEB\n" +
            "BQADggEPADCCAQoCggEBALGmSmtv9FtplILfe8kOjmEBdqo96WVMp6oy8bHMC59e\n" +
            "aE9Wu03kquoI2JMTwNcgapWKMYambzxr4rCVzBcc3kHpLaefnpq/5kFi9d8U6tgv\n" +
            "3T8Q8ZH1kMx/CH/fYQol0nMEqgl+S557zjNdBuSD36m45cN/UmI4K8Ie3S7a1xRx\n" +
            "2TuQZsxBxZUAU4SYgbC0DzwPXWB+EWJcGWXiqqZzKRNAnawNShkdEfVrCleg/Vff\n" +
            "T/iYOxMu3W/LQEpe69g/HmFYwYAATl7zm4jnVAhEZbEj8J4GhHW0gEo1qrf6CugO\n" +
            "a8/dEtGOSLLm9eilJIxydSiiTu9v9MAzs1LY3Ryt2wUCAwEAAaNQME4wHQYDVR0O\n" +
            "BBYEFDZcLOA/gL2djDmuITgKN+4JaT8IMC0GA1UdEAQmMCSgEBgOMjAxNTAxMDEx\n" +
            "MDAwMDChEBgOMjAyMDAxMDExMDAwMDAwDQYJKoZIhvcNAQEFBQADggEBAAGBmxuH\n" +
            "Z7VDnJacGonJOJxk5dDTA50c7Y8ggJZ3bpRW9afKTiAryq49ozm5sOv+XzWPf8FK\n" +
            "mbKhmknm3z8cfPL1LjA6c8dA0yvIpeT4IUYPqfWLHVpWTnbfnXQY97qKluRJF0sQ\n" +
            "AVNzxTE+ZDHBPFKzl/t8Zo9C7/ffNwxCVl0x5Ss8ie7q0y7PIm6yqnShPofvEnBE\n" +
            "F+dD33k8WXID2D/OLWQolrM6dnIGA9c1cFQ9v8kUXfX02fW4KGB09DAthgLv84zz\n" +
            "UoTzGmMnqBlb99BYjoDViVq4yWcxczJcjjIuj4hSNlH0Q/uWhqpmw4dqnlbH3fGO\n" +
            "ZvlQhYEZsj0eJMc=\n" +
            "-----END CERTIFICATE-----";
    
    static final String SIGNER1D_CERT =
            "-----BEGIN CERTIFICATE-----\n" +
            "MIIDBzCCAe+gAwIBAgIBATANBgkqhkiG9w0BAQUFADAeMRwwGgYDVQQDExNUZXN0\n" +
            "IFYzIENlcnRpZmljYXRlMB4XDTE1MDEwMTA5MDAwMFoXDTIwMDEwMTA5MDAwMFow\n" +
            "HjEcMBoGA1UEAxMTVGVzdCBWMyBDZXJ0aWZpY2F0ZTCCASIwDQYJKoZIhvcNAQEB\n" +
            "BQADggEPADCCAQoCggEBAJq2VhSoCMsOCI4YyGAOWHJk+8GNkz9/xsqDd4+YCkXl\n" +
            "pgBZvUrmCEhxd8IMS6LEvlAtv/TEGyh1FlL5ncUBFjPIbSvS7zM8f1gm06iNSdC9\n" +
            "dVwTHhu+L+mvajuFWlUr/agPaCM9rvUcUE5bceRioM0ORway1uyGGg5agecLbEKE\n" +
            "KB7mmmK4sJgwk6Ol/AbRk2bw2ep6XeZusEdplySTM3PFpbS97wRzJLQuo0pg9fZ3\n" +
            "yTvxlgRFbOJ7uGVY1H1ac2RcgvC3E+oSxg5Hk/xFn7R1iGMukn2exPVp0lPOz+QH\n" +
            "kgl+PefojU1MRTV4Nqf4jDp7zawhZz5yUvme3ZGg6tsCAwEAAaNQME4wHQYDVR0O\n" +
            "BBYEFCGmTJsyJQ/esdU6lsZXShnqS0LtMC0GA1UdEAQmMCSgEBgOMjAyNTAxMDEx\n" +
            "MDAwMDChEBgOMjAzMDAxMDExMDAwMDAwDQYJKoZIhvcNAQEFBQADggEBAB61vYmr\n" +
            "5fEuoN78Yiu3qZhOrJzA6I4D4F6NEX3vQOTfzjcdVLVRUhOmFHi33UfPcugWU1Nt\n" +
            "GLxa0nIdT+Pnc7AnoblBeNWNdYiM93DLHuQTwYyQVcQMlltHs2LhGesQ+LLijcTE\n" +
            "Cm+t1/HTuhQcENbS3IUyvp1borH+txTh+YBWKVmrvis+2SlLZSF8MppNO4NysaEa\n" +
            "ehTHOn0XLy9LSXHypmTqR/Jx5kfG12OcAx58baIMPbTbGxqR1tNceKb7+Sjy+urI\n" +
            "sX/0d4c1L1hohgpeJ2nbSeZ3SbSx/eNqhglBls/PSdEFqTpbAK7d+LfqkjDbKWbB\n" +
            "iVFbkjAvj/aacdk=\n" +
            "-----END CERTIFICATE-----";
    
    static byte[] certbytes1 = Base64.decode((
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
            + "oj/7HSYZlqigM72nR8f/gv1TwLVKz+ygzg==").getBytes());
}
