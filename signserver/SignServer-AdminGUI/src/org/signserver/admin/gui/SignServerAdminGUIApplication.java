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
package org.signserver.admin.gui;

import java.awt.SplashScreen;
import java.util.Hashtable;
import javax.naming.Context;
import javax.naming.InitialContext;
import javax.swing.JOptionPane;
import org.apache.log4j.Logger;
import org.jdesktop.application.Application;
import org.jdesktop.application.SingleFrameApplication;
import org.signserver.ejb.interfaces.IGlobalConfigurationSession;
import org.signserver.ejb.interfaces.IWorkerSession;

/**
 * The main class of the application.
 *
 * @author markus
 * @version $Id$
 */
public class SignServerAdminGUIApplication extends SingleFrameApplication {

    /** Logger for this class. */
    private static Logger LOG
            = Logger.getLogger(SignServerAdminGUIApplication.class);

    private static IGlobalConfigurationSession.IRemote gCSession;
    private static IWorkerSession.IRemote sSSession;

    /**
     * At startup create and show the main frame of the application.
     */
    @Override protected void startup() {
        show(new MainView(this));
    }

    /**
     * This method is to initialize the specified window by injecting resources.
     * Windows shown in our application come fully initialized from the GUI
     * builder, so this additional configuration is not needed.
     */
    @Override protected void configureWindow(java.awt.Window root) {
    }

    /**
     * A convenient static getter for the application instance.
     * @return the instance of SignServerDesktopApplication1
     */
    public static SignServerAdminGUIApplication getApplication() {
        return Application.getInstance(SignServerAdminGUIApplication.class);
    }

    /**
     * Main method launching the application.
     */
    public static void main(String[] args) {
        LOG.debug("SignServer Administration GUI startup");

        final SplashScreen splash = SplashScreen.getSplashScreen();
        if (splash == null) {
            LOG.debug("No splash screen available.");
        }


        try {
            Context context = getInitialContext();
            gCSession = (IGlobalConfigurationSession.IRemote) context.lookup(
                    IGlobalConfigurationSession.IRemote.JNDI_NAME);
            sSSession = (IWorkerSession.IRemote) context.lookup(
                    IWorkerSession.IRemote.JNDI_NAME);

            launch(SignServerAdminGUIApplication.class, args);
        } catch (Exception ex) {
            LOG.error("Startup error", ex);
            JOptionPane.showMessageDialog(null,
                    "Startup failed. Are the application server running?\n"
                    + ex.getMessage(),
                    "SignServer Administration GUI startup",
                    JOptionPane.ERROR_MESSAGE);
        }
    }

    public static IWorkerSession.IRemote getWorkerSession() {
        return sSSession;
    }

    public static IGlobalConfigurationSession.IRemote getGlobalConfigurationSession() {
        return gCSession;
    }

    private static Context getInitialContext() throws Exception {
        Hashtable<String, String> props = new Hashtable<String, String>();
        props.put(Context.INITIAL_CONTEXT_FACTORY,
                        "org.jnp.interfaces.NamingContextFactory");
        props.put(Context.URL_PKG_PREFIXES,
                        "org.jboss.naming:org.jnp.interfaces");
        props.put(Context.PROVIDER_URL, "jnp://localhost:1099");
        Context ctx = new InitialContext(props);
        return ctx;
    }
}
