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
package org.signserver.cli;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;
import org.signserver.common.CompileTimeSettings;

import org.signserver.common.InvalidWorkerIdException;

/**
 * Implements the signserver command line interface
 *
 * @version $Id$
 */
public class signserver {

    private ISignServerCommandFactory signServerCommandFactory;
    
    protected signserver(String[] args) {
        try {
            String hostname = checkHostParameter(args);
            if (hostname != null) {
                args = removeHostParameters(args);
            }

            IAdminCommand cmd = getCommand(args);

            if (cmd != null) {
                if (cmd.getCommandType() == IAdminCommand.TYPE_EXECUTEONMASTER) {
                    if (hostname == null) {
                        hostname = getMasterHostname();
                    }
                    System.out.println("===========================================");
                    System.out.println("  Executing Command on host : " + hostname);
                    System.out.println("===========================================\n\n");
                    cmd.execute(hostname);
                } else {
                    if (cmd.getCommandType() == IAdminCommand.TYPE_EXECUTEONALLNODES) {
                        String[] hostnames = getAllHostnames();
                        for (int i = 0; i < hostnames.length; i++) {
                            IAdminCommand c = getCommand(args);
                            System.out.println("===========================================");
                            System.out.println("Executing Command on host : " + hostnames[i]);
                            System.out.println("===========================================\n\n");
                            c.execute(hostnames[i]);
                        }
                    } else {
                        cmd.execute(null);
                    }
                }

            } else {
                getSignServerCommandFactory().outputHelp(System.out);
                System.exit(-1);
            }
        } catch (IllegalAdminCommandException e) {
            System.out.println(e.getMessage());
            System.exit(-1);
        } catch (ErrorAdminCommandException e) {
            if (e.getCause() instanceof InvalidWorkerIdException) {
                System.out.println(e.getMessage());
                System.exit(-1);
            }
            System.out.println(e.getMessage());
            e.printStackTrace();
            System.out.println("Caused by :");
            e.getCause().printStackTrace();
            System.exit(-2);
        } catch (IOException e) {
            e.printStackTrace();
            System.exit(-2);
        }
    }

    /**
     * Main
     *
     * @param args command line arguments
     */
    public static void main(String[] args) {
        new signserver(args);
    }

    protected IAdminCommand getCommand(String[] args) {
        return getSignServerCommandFactory().getCommand(args);
    }

    private String getMasterHostname() throws IOException {
        Properties props = getProperties();
        String hostname = props.getProperty("hostname.masternode");
        return hostname;
    }

    private String[] getAllHostnames() throws IOException {
        Properties props = getProperties();
        String hosts = props.getProperty("hostname.allnodes");

        return hosts.split(";");
    }

    private Properties getProperties() throws IOException {
        String propsfile = "conf/signserver_cli.properties";

        File unixConfigFile = new File("/etc/signserver/signserver.conf");
        File windowsConfigFile = new File(System.getenv("SYSTEMROOT") + "/signserver.conf");
        File mailSignerUnixConfigFile = new File("/etc/mailsigner/mailsigner.conf");
        File mailSignerWindowsConfigFile = new File(System.getenv("SYSTEMROOT") + "/mailsigner.conf");
        File legacyFile = new File("signserver_cli.properties");
        if (unixConfigFile.exists()) {
            propsfile = "/etc/signserver/signserver.conf";
        } else if (windowsConfigFile.exists()) {
            propsfile = System.getenv("SYSTEMROOT") + "/signserver.conf";
        } else if (mailSignerUnixConfigFile.exists()) {
                propsfile = "/etc/mailsigner/mailsigner.conf";
        } else if (mailSignerWindowsConfigFile.exists()) {
            propsfile = System.getenv("SYSTEMROOT") + "/mailsigner.conf";
        } else if (System.getenv("SIGNSERVER_HOME") != null) {
                propsfile = System.getenv("SIGNSERVER_HOME") + "/" + propsfile;
        } else if (System.getenv("SIGNSRV_HOME") != null) {
            propsfile = System.getenv("SIGNSRV_HOME") + "/" + propsfile;
        } else if (legacyFile.exists()) {
            propsfile = legacyFile.getAbsolutePath();
        }

        InputStream is = new FileInputStream(propsfile);
        Properties properties = new Properties();
        properties.load(is);
        is.close();
        return properties;
    }

    /**
     * Method that checks if a '-host host' parameter exists 
     * and return the given hostname.
     * @return hostname or null if host param didn't exist
     */
    private static String checkHostParameter(String[] args) {
        String retval = null;

        for (int i = 0; i < args.length - 1; i++) {
            if (args[i].equalsIgnoreCase("-host")) {
                retval = args[i + 1];
                break;
            }
        }

        return retval;
    }

    /**
     * Method that checks if a '-host host' parameter exist and removes the parameters
     * and returns a new args array
     * @return a args arrray with -host paramter removed
     */
    private static String[] removeHostParameters(String[] args) {
        String[] retval = null;
        boolean found = false;
        int index = 0;
        for (int i = 0; i < args.length - 1; i++) {
            if (args[i].equalsIgnoreCase("-host")) {
                index = i;
                found = true;
                break;
            }
        }

        if (found) {
            String newargs[] = new String[args.length - 2];
            for (int i = 0; i < args.length; i++) {
                if (i < index) {
                    newargs[i] = args[i];
                }
                if (i > index + 1) {
                    newargs[i - 2] = args[i];
                }
            }
            retval = newargs;
        }
        return retval;
    }

    private ISignServerCommandFactory getSignServerCommandFactory() {
        if (signServerCommandFactory == null) {
            final String commandFactoryClass =
                    CompileTimeSettings.getInstance().getProperty(
                    CompileTimeSettings.SIGNSERVERCOMMANDFACTORY);
            if (commandFactoryClass == null) {
                signServerCommandFactory = new DefaultSignServerCommandFactory();
            } else {
                try {
                    final Class<?> c = this.getClass().getClassLoader().loadClass(commandFactoryClass);
                    signServerCommandFactory = (ISignServerCommandFactory) c.newInstance();
                } catch (Exception e) {
                    System.out.println("Error instanciating SignServerCommandFactory.");
                    e.printStackTrace();
                }
            }
        }
        return signServerCommandFactory;
    }
}
    

//signserver
