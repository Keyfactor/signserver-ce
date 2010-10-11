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
import javax.naming.NamingException;
import javax.swing.JOptionPane;
import org.apache.log4j.Logger;
import org.ejbca.util.CertTools;
import org.jdesktop.application.Application;
import org.jdesktop.application.SingleFrameApplication;
import org.signserver.adminws.AdminWebService;
import org.signserver.client.api.ISigningAndValidation;
import org.signserver.client.api.SigningAndValidationEJB;
import org.signserver.client.api.SigningAndValidationWS;
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

    private static AdminWebService adminWS;
    private static ISigningAndValidation clientWS;

    private enum Protocol {
        EJB,
        WS
    }
    private static Protocol protocol;

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

        if (args.length > 0 && "-ws".equalsIgnoreCase(args[0])) {
            protocol = Protocol.WS;
        } else {
            protocol = Protocol.EJB;
        }

        try {
            launch(SignServerAdminGUIApplication.class, args);
        } catch (Exception ex) {
            displayException(ex);
        }
    }

    /**
     * @return The administration interface either EJB remote or web services.
     */
    public static AdminWebService getAdminWS() {
        if (adminWS == null) {
            if (Protocol.WS == protocol) {
                
                CertTools.installBCProvider();

                final ConnectDialog dlg = new ConnectDialog(null, true);
                dlg.setVisible(true);
                adminWS = dlg.getWS();
                
            } else {
                try {
                    adminWS = new AdminLayerEJBImpl();
                } catch (NamingException ex) {
                    LOG.error("Startup error", ex);
                    JOptionPane.showMessageDialog(null,
                        "Startup failed. Are the application server running?\n"
                        + ex.getMessage(),
                        "SignServer Administration GUI startup",
                        JOptionPane.ERROR_MESSAGE);
                    System.exit(1);
                }
            }
        }
        return adminWS;
    }

    /**
     * @return The client interface either EJB remote or web services.
     */
    public static ISigningAndValidation getClientWS() {
        if (clientWS == null) {
            if (Protocol.WS == protocol) {
                clientWS = new SigningAndValidationWS("localhost", 8443, true);
            } else {
                try {
                    clientWS = new SigningAndValidationEJB();
                } catch (NamingException ex) {
                    displayException(ex);
                }
            }
        }
        return clientWS;
    }

    private static void displayException(final Exception ex) {
        LOG.error("Startup error", ex);
        JOptionPane.showMessageDialog(null,
                    "Startup failed. Are the application server running?\n"
                    + ex.getMessage(),
                    "SignServer Administration GUI startup",
                    JOptionPane.ERROR_MESSAGE);
    }

}
