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
package org.signserver.rest.api;

import javax.ws.rs.ApplicationPath;
import javax.ws.rs.core.Application;
import org.eclipse.microprofile.openapi.annotations.OpenAPIDefinition;
import org.eclipse.microprofile.openapi.annotations.info.Info;

/**
 * Configuration for the "SignServer REST Interface" JAX-RS application.
 *
 * Note: Remember to increase the version number in the info object appropriately
 * using semantic versioning when updating the API and/or the OpenAPI spec.
 *
 * Versioning scheme:
 * - Using semantic versioning https://semver.org/spec/v2.0.0.html
 * - Syntax: MAJOR.MINOR.PATCH
 * - Increase MAJOR version when you make incompatible API changes
 * - Increase MINOR version when you add functionality in a backward compatible manner
 * - Increase PATCH version when you make backward compatible bug fixes to the
 *   API or improvements/clarifications to the OpenAPI documentation
 *
 */
@ApplicationPath("")
@OpenAPIDefinition(
        info = @Info(
                title = "SignServer REST Interface",
                version = "1.1.0"
        )
)
public class ApplicationConfig extends Application {
}
