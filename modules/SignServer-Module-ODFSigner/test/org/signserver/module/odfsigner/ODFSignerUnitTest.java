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
package org.signserver.module.odfsigner;

import java.security.KeyPair;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.Arrays;
import static junit.framework.TestCase.assertNotNull;
import org.apache.log4j.Logger;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import static org.junit.Assert.*;
import org.junit.BeforeClass;
import org.junit.Test;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.GenericSignResponse;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.test.utils.builders.CertBuilder;
import org.signserver.test.utils.builders.CryptoUtils;
import org.signserver.test.utils.mock.MockedCryptoToken;
import org.xml.sax.SAXParseException;

/**
 * Unit tests for the ODFSigner class.
 *
 * System tests (and other tests) are available in the Test-System project.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class ODFSignerUnitTest {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(ODFSignerUnitTest.class);

    private static MockedCryptoToken tokenRSA;

    /**
     * predefined odt file in base64 format.
     */
    private static final String TEST_ODF_DOC =
        "UEsDBBQAAAgAAGBoekVexjIMJwAAACcAAAAIAAAAbWltZXR5cGVhcHBsaWNhdGlvbi92bmQub2Fz\n" +
        "aXMub3BlbmRvY3VtZW50LnRleHRQSwMEFAAACAAAYGh6RcYHdKvDBAAAwwQAABgAAABUaHVtYm5h\n" +
        "aWxzL3RodW1ibmFpbC5wbmeJUE5HDQoaCgAAAA1JSERSAAAAtQAAAQAIAgAAAHpBoIwAAASKSURB\n" +
        "VHic7dvLa1xVAMDheVYbbanVtopY8QUiKgqCLtyI4AMX7sSFW1f+jYIIokVRF258bGrRVFuxmtY0\n" +
        "tZnxTpKqIP4gotjC94Uk91zmQsL5MeecQGbL5XIEf2P2f/8AXNf0QdEHRR8UfVD0QdEHRR8UfVD0\n" +
        "QdEHRR8UfVD0QdEHZX99LJfL8Xg8fF0sFsNwMpnsDofrvfvL5XQyWd0Zxn/38M5o9/Kvr+K6sr8+\n" +
        "dqdz+JxMp6vpXS63F4vxeDJ87IyWQy9DOquLyXixHK1aGK9ev1PMaLRYDcarB8RxY/gn7x+/bl76\n" +
        "5NOPt0Y3P/XkEwcPHhjeNba3t2fT2ZXNjTPrPz74wL3Dnd2Wfg9gvGO3ku3F9mg0lcgNYd/7j2FS\n" +
        "52u3Xt66cGZjsnzv7fULm/fceey7ja1XX3zu/Xff+fTzs08/8/jGhZ9OnDh+8fLWlcub58/9MJ/P\n" +
        "D8zn0/l0WHouXbp47ufN1157/fBNyrgB7Ht9Gd4rxtPpobVD4x/Of3n23Ozg2kefnDl+/2MXfzx7\n" +
        "+pv1XzbOn/n69EenTr3x5lvff/XBZ198u3brkZPH7/jw3bdPPPzIyWO3r69/P8Q0lPIf/T78u/a/\n" +
        "vkxWU3vfQ4/e89BsPh4tJ6NhMRnWl0O33/HSy69sT2bDQvPSCy9e2tw6+fzLTz61sXbLLcMDzz3/\n" +
        "7FDVgdls68qVq1evThe/jkbz/+Y34t/0T/anQyVHjh67dmwZ7e4ihuHxu+7euVi98vDh1a70yG1H\n" +
        "R3uHmb1zy6E/bTtsPq5/+91/XJvt4ZCyN/7TzeUf/ywxnF12vi1G144vfzy/w/n2hrDfPvYmdFhl\n" +
        "/jqx+51scVz//P2Uog+KPij6oOiDog+KPij6oOiDog+KPij6oOiDog+KPij6oOiDog+KPij6oOiD\n" +
        "og+KPij6oOiDog+KPij6oOiDog+KPij6oOiDog+KPij6oOiDog+KPij6oOiDog+KPij6oOiDog+K\n" +
        "Pij6oOiDog+KPij6oOiDog+KPij6oOiDog+KPij6oOiDog+KPij6oOiDog+KPij6oOiDog+KPij6\n" +
        "oOiDog+KPij6oOiDog+KPij6oOiDog+KPij6oOiDog+KPij6oOiDog+KPij6oOiDog+KPij6oOiD\n" +
        "og+KPij6oOiDog+KPij6oOiDog+KPij6oOiDog+KPij6oOiDog+KPij6oOiDog+KPij6oOiDog+K\n" +
        "Pij6oOiDog+KPij6oOiDog+KPij6oOiDog+KPij6oOiDog+KPij6oOiDog+KPij6oOiDog+KPij6\n" +
        "oOiDog+KPij6oOiDog+KPij6oOiDog+KPij6oOiDog+KPij6oOiDog+KPij6oOiDog+KPij6oOiD\n" +
        "og+KPij6oOiDog+KPij6oOiDog+KPij6oOiDog+KPij6oOiDog+KPij6oOiDog+KPij6oOiDog+K\n" +
        "Pij6oOiDog+KPij6oOiDog+KPij6oOiDog+KPij6oOiDog+KPij6oOiDog+KPij6oOiDog+KPij6\n" +
        "oOiDog+KPij6oOiDog+KPii/AeVrBs9xBI2ZAAAAAElFTkSuQmCCUEsDBBQACAgIAGBoekUAAAAA\n" +
        "AAAAAAAAAAALAAAAY29udGVudC54bWylV8Fu2zgQvfcrBBXYm0Ir3m0TNXYvRYAFEqBoUmCvNEXZ\n" +
        "RClSS1KW/fc7JC2acixHW1+cmPPe8HFmOEM/fN3VPNlSpZkUizS/maUJFUSWTKwX6c/Xx+wu/br8\n" +
        "8CCrihFalJK0NRUmI1IY+JsAW+jCWxdpq0QhsWa6ELimujCkkA0VPauI0YXby69os+eT6Q4csw3d\n" +
        "malkix1w8Wr6zg4cs0uFu6lki4WgxvRKTiXvNM8qCVGvG2zYiYodZ+LXIt0Y0xQIdV13081vpFqj\n" +
        "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\n" +
        "3LjYiIwzN7+PMHHpZ+hUD1FdRDffAFUAgQurzlA0GU8mq7CxYt+d/R0GOnQHDZpt1h0glKjX3U5M\n" +
        "k5pPnmCU1DdbKP5fKaSJDxM1pp1DfldOTRc/Ntee5nudif7z3G86uiLADjjFSD1X6h+By4LTeK2o\n" +
        "idXr4KwEGRK1jtpa1ag03XxxdH12gtrJkQv1Qff37u//BFBLBwhhHbKaRggAAC8vAABQSwMEFAAI\n" +
        "CAgAYGh6RQAAAAAAAAAAAAAAAAwAAABtYW5pZmVzdC5yZGbNk81ugzAQhO88hWXO2EAvBQVyKMq5\n" +
        "ap/ANYZYBS/ymhLevo6TVlGkquqf1OOuRjPfjrSb7WEcyIuyqMFUNGMpJcpIaLXpKzq7Lrml2zra\n" +
        "2LYrH5od8WqDpZ8qunduKjlfloUtNwxsz7OiKHia8zxPvCLB1ThxSAzGtI4ICR6NQmn15HwaOc7i\n" +
        "CWZXUXTroJB59yA9i906qaCyCmG2Ur2HtiCRgUCNCUzKhHSDHLpOS8UzlvNROcGh7eLHYL3Tg6I8\n" +
        "YPArjs/Y3ogMpuVe4L2w7lyD33yVaHruY3p108Xx3yOUYJwy7k/quzt5/+f+Ls//GeKvtHZEbEDO\n" +
        "o2f6kOe08h9VR69QSwcItPdo0gUBAACDAwAAUEsDBBQAAAgAAGBoekUAAAAAAAAAAAAAAAAfAAAA\n" +
        "Q29uZmlndXJhdGlvbnMyL2ltYWdlcy9CaXRtYXBzL1BLAwQUAAAIAABgaHpFAAAAAAAAAAAAAAAA\n" +
        "GgAAAENvbmZpZ3VyYXRpb25zMi90b29scGFuZWwvUEsDBBQAAAgAAGBoekUAAAAAAAAAAAAAAAAc\n" +
        "AAAAQ29uZmlndXJhdGlvbnMyL3Byb2dyZXNzYmFyL1BLAwQUAAgICABgaHpFAAAAAAAAAAAAAAAA\n" +
        "JwAAAENvbmZpZ3VyYXRpb25zMi9hY2NlbGVyYXRvci9jdXJyZW50LnhtbAMAUEsHCAAAAAACAAAA\n" +
        "AAAAAFBLAwQUAAAIAABgaHpFAAAAAAAAAAAAAAAAGAAAAENvbmZpZ3VyYXRpb25zMi9mbG9hdGVy\n" +
        "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\n" +
        "BQYAAAAAEQARAHAEAABKHgAAAAA=";

    /**
     * predefined odt file in base64 format.
     * Having a DOCTYPE with an element in content.xml.
     */
    private static final String TEST_ODF_DOC_WITH_DOCTYPE =
        "UEsDBBQAAAgAAGBoekVexjIMJwAAACcAAAAIAAAAbWltZXR5cGVhcHBsaWNhdGlvbi92bmQub2Fz\n" +
        "aXMub3BlbmRvY3VtZW50LnRleHRQSwMEFAAACAAAYGh6RcYHdKvDBAAAwwQAABgAAABUaHVtYm5h\n" +
        "aWxzL3RodW1ibmFpbC5wbmeJUE5HDQoaCgAAAA1JSERSAAAAtQAAAQAIAgAAAHpBoIwAAASKSURB\n" +
        "VHic7dvLa1xVAMDheVYbbanVtopY8QUiKgqCLtyI4AMX7sSFW1f+jYIIokVRF258bGrRVFuxmtY0\n" +
        "tZnxTpKqIP4gotjC94Uk91zmQsL5MeecQGbL5XIEf2P2f/8AXNf0QdEHRR8UfVD0QdEHRR8UfVD0\n" +
        "QdEHRR8UfVD0QdEHZX99LJfL8Xg8fF0sFsNwMpnsDofrvfvL5XQyWd0Zxn/38M5o9/Kvr+K6sr8+\n" +
        "dqdz+JxMp6vpXS63F4vxeDJ87IyWQy9DOquLyXixHK1aGK9ev1PMaLRYDcarB8RxY/gn7x+/bl76\n" +
        "5NOPt0Y3P/XkEwcPHhjeNba3t2fT2ZXNjTPrPz74wL3Dnd2Wfg9gvGO3ku3F9mg0lcgNYd/7j2FS\n" +
        "52u3Xt66cGZjsnzv7fULm/fceey7ja1XX3zu/Xff+fTzs08/8/jGhZ9OnDh+8fLWlcub58/9MJ/P\n" +
        "D8zn0/l0WHouXbp47ufN1157/fBNyrgB7Ht9Gd4rxtPpobVD4x/Of3n23Ozg2kefnDl+/2MXfzx7\n" +
        "+pv1XzbOn/n69EenTr3x5lvff/XBZ198u3brkZPH7/jw3bdPPPzIyWO3r69/P8Q0lPIf/T78u/a/\n" +
        "vkxWU3vfQ4/e89BsPh4tJ6NhMRnWl0O33/HSy69sT2bDQvPSCy9e2tw6+fzLTz61sXbLLcMDzz3/\n" +
        "7FDVgdls68qVq1evThe/jkbz/+Y34t/0T/anQyVHjh67dmwZ7e4ihuHxu+7euVi98vDh1a70yG1H\n" +
        "R3uHmb1zy6E/bTtsPq5/+91/XJvt4ZCyN/7TzeUf/ywxnF12vi1G144vfzy/w/n2hrDfPvYmdFhl\n" +
        "/jqx+51scVz//P2Uog+KPij6oOiDog+KPij6oOiDog+KPij6oOiDog+KPij6oOiDog+KPij6oOiD\n" +
        "og+KPij6oOiDog+KPij6oOiDog+KPij6oOiDog+KPij6oOiDog+KPij6oOiDog+KPij6oOiDog+K\n" +
        "Pij6oOiDog+KPij6oOiDog+KPij6oOiDog+KPij6oOiDog+KPij6oOiDog+KPij6oOiDog+KPij6\n" +
        "oOiDog+KPij6oOiDog+KPij6oOiDog+KPij6oOiDog+KPij6oOiDog+KPij6oOiDog+KPij6oOiD\n" +
        "og+KPij6oOiDog+KPij6oOiDog+KPij6oOiDog+KPij6oOiDog+KPij6oOiDog+KPij6oOiDog+K\n" +
        "Pij6oOiDog+KPij6oOiDog+KPij6oOiDog+KPij6oOiDog+KPij6oOiDog+KPij6oOiDog+KPij6\n" +
        "oOiDog+KPij6oOiDog+KPij6oOiDog+KPij6oOiDog+KPij6oOiDog+KPij6oOiDog+KPij6oOiD\n" +
        "og+KPij6oOiDog+KPij6oOiDog+KPij6oOiDog+KPij6oOiDog+KPij6oOiDog+KPij6oOiDog+K\n" +
        "Pij6oOiDog+KPij6oOiDog+KPij6oOiDog+KPij6oOiDog+KPij6oOiDog+KPij6oOiDog+KPij6\n" +
        "oOiDog+KPij6oOiDog+KPii/AeVrBs9xBI2ZAAAAAElFTkSuQmCCUEsDBBQAAAgIALpwekV/JG/g\n" +
        "qgMAABYOAAALABwAY29udGVudC54bWxVVAkAAy/QdVQv0HVUdXgLAAEE6AMAAAToAwAApVdbb9s2\n" +
        "FH7vr9A0YG8KrXiXRo1dFE0CDEi6YvGAFcUeaIqyiVKiRlKW/e93SFo05ViOVr/YJs93Dj+eK337\n" +
        "flvyaEOlYqKaxenVJI5oRUTOqtUs/mvxkLyN38/f3P5w98fHxZfP91EhRPQV1veP90/3nxZ2/eHT\n" +
        "l2j+D6BEUTBCs1yQpqSVToioNHxHcEalMiedxY2sMoEVU1mFS6oyTTJR06rTykJ0Zhm5HaV3fLS6\n" +
        "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\n" +
        "y1utVxdHweYu71pWb/2uJNy42IiMMze/jzBx6WfoVA9RXUQ33wBVAIELq85QNBlPJquwsWLfnf0d\n" +
        "Bjp0Bw2abdYdIJSo191OTJOaT55glNQ3Wyj+XymkiQ8TNaadQ35XTk0XPzbXnuZ7nYn+89xvOroi\n" +
        "wA44xUg9V+ofgcuC03itqInV6+CsBBkStY7aWtWoNN18cXR9doLayZEL9UH39+7v/wRQSwMEFAAA\n" +
        "CAgAYGh6RbT3aNIFAQAAgwMAAAwAAABtYW5pZmVzdC5yZGbNk81ugzAQhO88hWXO2EAvBQVyKMq5\n" +
        "ap/ANYZYBS/ymhLevo6TVlGkquqf1OOuRjPfjrSb7WEcyIuyqMFUNGMpJcpIaLXpKzq7Lrml2zra\n" +
        "2LYrH5od8WqDpZ8qunduKjlfloUtNwxsz7OiKHia8zxPvCLB1ThxSAzGtI4ICR6NQmn15HwaOc7i\n" +
        "CWZXUXTroJB59yA9i906qaCyCmG2Ur2HtiCRgUCNCUzKhHSDHLpOS8UzlvNROcGh7eLHYL3Tg6I8\n" +
        "YPArjs/Y3ogMpuVe4L2w7lyD33yVaHruY3p108Xx3yOUYJwy7k/quzt5/+f+Ls//GeKvtHZEbEDO\n" +
        "o2f6kOe08h9VR69QSwMEFAAACAAAYGh6RQAAAAAAAAAAAAAAAB8AAABDb25maWd1cmF0aW9uczIv\n" +
        "aW1hZ2VzL0JpdG1hcHMvUEsDBBQAAAgAAGBoekUAAAAAAAAAAAAAAAAaAAAAQ29uZmlndXJhdGlv\n" +
        "bnMyL3Rvb2xwYW5lbC9QSwMEFAAACAAAYGh6RQAAAAAAAAAAAAAAABwAAABDb25maWd1cmF0aW9u\n" +
        "czIvcHJvZ3Jlc3NiYXIvUEsDBBQAAAgIAGBoekUAAAAAAgAAAAAAAAAnAAAAQ29uZmlndXJhdGlv\n" +
        "bnMyL2FjY2VsZXJhdG9yL2N1cnJlbnQueG1sAwBQSwMEFAAACAAAYGh6RQAAAAAAAAAAAAAAABgA\n" +
        "AABDb25maWd1cmF0aW9uczIvZmxvYXRlci9QSwMEFAAACAAAYGh6RQAAAAAAAAAAAAAAABoAAABD\n" +
        "b25maWd1cmF0aW9uczIvc3RhdHVzYmFyL1BLAwQUAAAIAABgaHpFAAAAAAAAAAAAAAAAGAAAAENv\n" +
        "bmZpZ3VyYXRpb25zMi90b29sYmFyL1BLAwQUAAAIAABgaHpFAAAAAAAAAAAAAAAAGgAAAENvbmZp\n" +
        "Z3VyYXRpb25zMi9wb3B1cG1lbnUvUEsDBBQAAAgAAGBoekUAAAAAAAAAAAAAAAAYAAAAQ29uZmln\n" +
        "dXJhdGlvbnMyL21lbnViYXIvUEsDBBQAAAgIAGBoekUdgPNZHAEAAD4EAAAVAAAATUVUQS1JTkYv\n" +
        "bWFuaWZlc3QueG1stZTBbsMgDIbvfYqI6xTYeppQ0h4q7Qm6B2DESZHARGCq9u1HqrXJNGVqtO5m\n" +
        "Y/P/nzBQbU/OFkcI0Xis2Qt/ZgWg9o3Brmbv+7fylW03q8opNC1EktegyPsw3tKapYDSq2iiROUg\n" +
        "StLS94CN18kBkvzeLy9Ot2wCsGabVTH6tcZCmfeH89jdJmvLXtGhZmJOZFx20BhV0rmHmqm+t0Yr\n" +
        "ym3iiA2/APMpJyc4ERNLGPaH5D5QGRsFXUPeYzfDYJzqQAz1RS7aIw18+RxnhAdyMZQX6UYgysOO\n" +
        "Dxd2QOrxtHS28A+sX2s8NO0dVyd3PS322HlsTZfCRSKuhdIaLOTUB6FTCL8P929edz6HmHBA4Mlw\n" +
        "PVUYzCvx4w/YfAJQSwECFAAUAAAIAABgaHpFXsYyDCcAAAAnAAAACAAAAAAAAAAAAAAAAAAAAAAA\n" +
        "bWltZXR5cGVQSwECFAAUAAAIAABgaHpFxgd0q8MEAADDBAAAGAAAAAAAAAAAAAAAAABNAAAAVGh1\n" +
        "bWJuYWlscy90aHVtYm5haWwucG5nUEsBAh4DFAAACAgAunB6RX8kb+CqAwAAFg4AAAsAGAAAAAAA\n" +
        "AQAAALSBRgUAAGNvbnRlbnQueG1sVVQFAAMv0HVUdXgLAAEE6AMAAAToAwAAUEsBAhQAFAAACAgA\n" +
        "YGh6RRazbl/iBQAAbycAAAwAAAAAAAAAAAAAAAAANQkAAHNldHRpbmdzLnhtbFBLAQIUABQAAAgI\n" +
        "AGBoekV45BuyvwEAAMwDAAAIAAAAAAAAAAAAAAAAAEEPAABtZXRhLnhtbFBLAQIUABQAAAgIAGBo\n" +
        "ekVhHbKaRggAAC8vAAAKAAAAAAAAAAAAAAAAACYRAABzdHlsZXMueG1sUEsBAhQAFAAACAgAYGh6\n" +
        "RbT3aNIFAQAAgwMAAAwAAAAAAAAAAAAAAAAAlBkAAG1hbmlmZXN0LnJkZlBLAQIUABQAAAgAAGBo\n" +
        "ekUAAAAAAAAAAAAAAAAfAAAAAAAAAAAAAAAAAMMaAABDb25maWd1cmF0aW9uczIvaW1hZ2VzL0Jp\n" +
        "dG1hcHMvUEsBAhQAFAAACAAAYGh6RQAAAAAAAAAAAAAAABoAAAAAAAAAAAAAAAAAABsAAENvbmZp\n" +
        "Z3VyYXRpb25zMi90b29scGFuZWwvUEsBAhQAFAAACAAAYGh6RQAAAAAAAAAAAAAAABwAAAAAAAAA\n" +
        "AAAAAAAAOBsAAENvbmZpZ3VyYXRpb25zMi9wcm9ncmVzc2Jhci9QSwECFAAUAAAICABgaHpFAAAA\n" +
        "AAIAAAAAAAAAJwAAAAAAAAAAAAAAAAByGwAAQ29uZmlndXJhdGlvbnMyL2FjY2VsZXJhdG9yL2N1\n" +
        "cnJlbnQueG1sUEsBAhQAFAAACAAAYGh6RQAAAAAAAAAAAAAAABgAAAAAAAAAAAAAAAAAuRsAAENv\n" +
        "bmZpZ3VyYXRpb25zMi9mbG9hdGVyL1BLAQIUABQAAAgAAGBoekUAAAAAAAAAAAAAAAAaAAAAAAAA\n" +
        "AAAAAAAAAO8bAABDb25maWd1cmF0aW9uczIvc3RhdHVzYmFyL1BLAQIUABQAAAgAAGBoekUAAAAA\n" +
        "AAAAAAAAAAAYAAAAAAAAAAAAAAAAACccAABDb25maWd1cmF0aW9uczIvdG9vbGJhci9QSwECFAAU\n" +
        "AAAIAABgaHpFAAAAAAAAAAAAAAAAGgAAAAAAAAAAAAAAAABdHAAAQ29uZmlndXJhdGlvbnMyL3Bv\n" +
        "cHVwbWVudS9QSwECFAAUAAAIAABgaHpFAAAAAAAAAAAAAAAAGAAAAAAAAAAAAAAAAACVHAAAQ29u\n" +
        "ZmlndXJhdGlvbnMyL21lbnViYXIvUEsBAhQAFAAACAgAYGh6RR2A81kcAQAAPgQAABUAAAAAAAAA\n" +
        "AAAAAAAAyxwAAE1FVEEtSU5GL21hbmlmZXN0LnhtbFBLBQYAAAAAEQARAIgEAAAaHgAAAAA=";


    @BeforeClass
    public static void setUpClass() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        tokenRSA = generateToken();
    }

    private static MockedCryptoToken generateToken() throws Exception {
        final KeyPair signerKeyPair = CryptoUtils.generateRSA(1024);
        final Certificate[] certChain =
                new Certificate[] {new JcaX509CertificateConverter().getCertificate(new CertBuilder().
                        setSelfSignKeyPair(signerKeyPair).
                        setSignatureAlgorithm("SHA1withRSA")
                        .build())};
        final Certificate signerCertificate = certChain[0];
        return new MockedCryptoToken(signerKeyPair.getPrivate(), signerKeyPair.getPublic(), signerCertificate, Arrays.asList(certChain), "BC");
    }

    /**
     * Test signing with an RSA key.
     * 
     * @throws Exception
     */
    @Test
    public void testSignOdt() throws Exception {
        testBasicODFSign(TEST_ODF_DOC);
    }

    /**
     * Tests that a document with a DOCTYPE is not allowed.
     * @throws Exception
     */
    @Test
    @SuppressWarnings("ThrowableResultIgnored")
    public void testDTDNotAllowed() throws Exception {
        LOG.info("testDTDNotAllowed");
        try {
            testBasicODFSign(TEST_ODF_DOC_WITH_DOCTYPE);
            fail("Should have thrown IllegalRequestException as the document contained a DTD");
        } catch (SignServerException expected) {
            if (expected.getCause() instanceof SAXParseException) {
                if (!expected.getCause().getMessage().contains("DOCTYPE")) {
                    LOG.error("Wrong exception message", expected);
                    fail("Should be error about doctype: " + expected.getMessage());
                }
            } else {
                LOG.error("Wrong exception cause", expected);
                fail("Expected SAXParseException but was: " + expected);
            }
        }
    }

    private void testBasicODFSign(final String document) throws Exception {
        WorkerConfig config = new WorkerConfig();

        ODFSigner instance = new MockedODFSigner(tokenRSA);
        instance.init(4711, config, null, null);
        final RequestContext requestContext = new RequestContext();
        requestContext.put(RequestContext.TRANSACTION_ID, "0000-100-1");

        GenericSignRequest request = new GenericSignRequest(100, Base64.decode(document.getBytes(StandardCharsets.UTF_8)));
        GenericSignResponse res = (GenericSignResponse) instance.processData(request, requestContext);

        // Check certificate
        final Certificate signercert = res.getSignerCertificate();
        assertNotNull("Signer certificate", signercert);
    }

}
