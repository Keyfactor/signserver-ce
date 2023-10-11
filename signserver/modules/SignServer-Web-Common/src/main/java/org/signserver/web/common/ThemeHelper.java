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
package org.signserver.web.common;

import org.signserver.common.CompileTimeSettings;

public class ThemeHelper {

    private static ThemeHelper instance;

    public static ThemeHelper getInstance() {
        if (instance == null) {
            instance = new ThemeHelper();
        }
        return instance;
    }

    public String getTheme() {
        final String theme = CompileTimeSettings.getInstance().getProperty(CompileTimeSettings.WEB_THEME, "default").trim();
        final String edition = CompileTimeSettings.getInstance().getProperty(CompileTimeSettings.SIGNSERVER_EDITION);
        switch (theme) {
            case "keyfactor":
                return "enterprise";
            case "":
            case "default":
                return "ee".equalsIgnoreCase(edition) ? "enterprise" : "community";
        }
        return theme;
    }

}
