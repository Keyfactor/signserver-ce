/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.module.ades;

import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

/**
 * Unit tests for the AdESService class.
 *
 * @author Andrey Sergeev
 * @version $Id$
 */
public class AdESServiceUnitTest {

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    @Test
    public void shouldFailOnNullAdESSignatureFormat() {
        // given
        expectedException.expect(NullPointerException.class);
        expectedException.expectMessage("AdESSignatureFormat is required.");
        // when
        new AdESService(null, new CommonCertificateVerifier());
    }
}
