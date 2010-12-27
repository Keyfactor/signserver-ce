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
import java.io.File;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.swing.JOptionPane;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.GnuParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.log4j.Logger;
import org.ejbca.util.CertTools;
import org.jdesktop.application.Application;
import org.jdesktop.application.SingleFrameApplication;
import org.signserver.admin.gui.adminws.gen.AdminWS;
import org.signserver.client.api.ISigningAndValidation;
import org.signserver.client.api.SigningAndValidationEJB;
import org.signserver.client.api.SigningAndValidationWS;

/**
 * The main class of the application.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class SignServerAdminGUIApplication extends SingleFrameApplication {

    /** Logger for this class. */
    private static Logger LOG
            = Logger.getLogger(SignServerAdminGUIApplication.class);

    private static final String OPTION_WS = "ws";
    private static final String OPTION_HELP = "help";
    private static final String OPTION_CONNECTFILE = "connectfile";
    private static final String OPTION_DEFAULTCONNECTFILE = "defaultconnectfile";

    private static AdminWS adminWS;
    private static ISigningAndValidation clientWS;

    private static File connectFile;
    private static File defaultConnectFile;

    /** The command line options. */
    private static final Options OPTIONS;

     static {
        OPTIONS = new Options();
        OPTIONS.addOption(OPTION_WS, false, "Connect using web services");
        OPTIONS.addOption(OPTION_HELP, false, "Displays this message");
        OPTIONS.addOption(OPTION_CONNECTFILE, true,
                "Configuration file to read WS connection properties from");
        OPTIONS.addOption(OPTION_DEFAULTCONNECTFILE, true,
                "Default WS connection configuration file");
    }

    private static void printUsage() {
        final HelpFormatter formatter = new HelpFormatter();
        formatter.printHelp("admingui <options>", OPTIONS);
    }

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

        try {
            // Parse the command line
            final CommandLine line = new GnuParser().parse(OPTIONS, args);
            if (line.hasOption(OPTION_HELP)) {
                printUsage();
            } else {
                if (line.hasOption(OPTION_WS)) {
                    protocol = Protocol.WS;
                } else {
                    if (isNamingContextAvailable()) {
                        protocol = Protocol.EJB;
                    } else {
                        JOptionPane.showMessageDialog(null,
                            "Application server libraries not detected."
                            + "\n\nTo connect to a locally running SignServer instance "
                            + "\nplease append the appropriate application server "
                            + "\nJAR-files and if needed a jndi.properties file."
                            + "\n\nTo connect using web services invoke this command "
                            + "\nwith the argument \"-ws\".");
                        protocol = Protocol.WS;
                    }
                }
                if (line.hasOption(OPTION_CONNECTFILE)) {
                    connectFile = new File(
                            line.getOptionValue(OPTION_CONNECTFILE));
                }
                if (line.hasOption(OPTION_DEFAULTCONNECTFILE)) {
                    defaultConnectFile = new File(
                            line.getOptionValue(OPTION_DEFAULTCONNECTFILE));
                }

                try {
                    launch(SignServerAdminGUIApplication.class, args);
                } catch (Exception ex) {
                    displayException(ex);
                }
            }
        } catch (ParseException ex) {
            throw new IllegalArgumentException(ex.getLocalizedMessage(), ex);
        }
    }

    private static boolean isNamingContextAvailable() {
        boolean result;
        try {
            final InitialContext ignored = new InitialContext(); //NOPMD
            result = true;
        } catch (NamingException ex) {
            result = false;
        }
        return result;
    }

    /**
     * @return The administration interface either EJB remote or web services.
     */
    public static AdminWS getAdminWS() {
        if (adminWS == null) {
            if (Protocol.WS == protocol) {
                
                CertTools.installBCProvider();

                final ConnectDialog dlg = new ConnectDialog(null, true,
                        connectFile, defaultConnectFile);
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
