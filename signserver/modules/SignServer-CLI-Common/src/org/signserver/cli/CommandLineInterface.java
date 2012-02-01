package org.signserver.cli;

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


import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Properties;
import java.util.ServiceConfigurationError;
import java.util.ServiceLoader;
import org.apache.log4j.Logger;

import org.signserver.cli.spi.Command;
import org.signserver.cli.spi.CommandFactory;
import org.signserver.cli.spi.CommandFactoryContext;
import org.signserver.cli.spi.CommandFailureException;
import org.signserver.cli.spi.IllegalCommandArgumentsException;

/**
 * Implements the signserver command line interface
 *
 * @version $Id$
 */
public class CommandLineInterface {
    
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(CommandLineInterface.class);

    private ServiceLoader<? extends CommandFactory> loader;
    private Class<? extends CommandFactory> factoryClazz;
    private Properties cliProperties;
    
    private PrintStream out = System.out;
    private PrintStream err = System.err;

    private CommandFactoryContext factoryContext;
    
    public void setFactoryClass(Class<? extends CommandFactory> factoryClazz) {
        loader = ServiceLoader.load(factoryClazz);
    }
    
    public PrintStream getErr() {
        return err;
    }

    public void setErr(PrintStream err) {
        this.err = err;
    }

    public PrintStream getOut() {
        return out;
    }

    public void setOut(PrintStream out) {
        this.out = out;
    }
    
    public int execute(final String[] args) throws IllegalCommandArgumentsException, CommandFailureException, IOException {
        int resultCode = 0;
        
        if (loader == null) {
            loader = ServiceLoader.load(CommandFactory.class);
        }
        
        factoryContext = new CommandFactoryContext(getProperties(), getOut(), getErr());

        Command cmd = getCommand(args);

        if (cmd != null) {
            final int shift;
            if (cmd.getCommandGroup() == null) {
                shift = 1;
            } else {
                shift = 2;
            }
            // Run with args without the name of the command and sub command
            cmd.execute(Arrays.copyOfRange(args, shift, args.length));
        } else {
            if (args.length > 0) {
                outputHelp(out, args[0], getCommands(args[0]));
            } else {
                outputHelp(out, null, null);
            }
            resultCode = -1;
        }

        return resultCode;
    }

    /**
     * Main
     *
     * @param args command line arguments
     */
    public static void main(String[] args) throws IOException {
        try {
            CommandLineInterface cli = new CommandLineInterface();
            int returnCode = cli.execute(args);
            System.exit(returnCode);
        } catch (IllegalCommandArgumentsException ex) {
            LOG.error(ex.getMessage());
        } catch (CommandFailureException ex) {
            LOG.error(ex.getMessage());
        }
    }

    protected Command getCommand(String[] args) throws CommandFailureException {
        Command result = null;
        try {
            Iterator<? extends CommandFactory> iterator = loader.iterator();
            while (result == null && iterator.hasNext()) {
                CommandFactory factory = iterator.next();
                if (LOG.isTraceEnabled()) {
                    LOG.trace("Trying factory: " + factory.getClass().getName());
                }
                if (!factory.isInitialized()) {
                    factory.init(factoryContext);
                }
                result = factory.getCommand(args);
            }
        } catch (ServiceConfigurationError error) {
            throw new CommandFailureException("Error loading command factories", error);
        }
        return result;
    }
    
    protected List<Command> getCommands(String group) {
        LinkedList<Command> result = null;
        Iterator<? extends CommandFactory> iterator = loader.iterator();
        while (iterator.hasNext()) {
            CommandFactory factory = iterator.next();
            if (!factory.isInitialized()) {
                factory.init(factoryContext);
            }
            Collection<Command> commands = factory.getSubCommands(group);
            if (commands != null) {
                if (result == null) {
                    result = new LinkedList<Command>();
                }
                result.addAll(commands);
            }
        }
        return result;
    }

    private Properties getProperties() throws IOException {
        if (cliProperties == null) {
            Properties properties = new Properties();
            InputStream in = null; 
            try {
                in = getClass().getResourceAsStream("/signserver_cli.properties");
                if (in != null) {
                    properties.load(in);
                }
                cliProperties = properties;
            } finally {
                if (in != null) {
                    try {
                        in.close();
                    } catch (IOException ex) {
                        LOG.error("Failed to close configuration", ex);
                    }
                }
            }
        }
        return cliProperties;
    }
    
    private void outputHelp(PrintStream out, String group, List<Command> commands) {
        out.print("Missing or invalid argument.");
        
        if (commands == null) {
            commands = new LinkedList<Command>();
            
            List<String> commandGroups = new LinkedList<String>();
            Iterator<? extends CommandFactory> iterator = loader.iterator();
            while (iterator.hasNext()) {
                CommandFactory factory = iterator.next();
                commands.addAll(factory.getTopLevelCommands());
                commandGroups.addAll(factory.getCommandGroups());
            }

            if (commandGroups.size() > 0) {
                out.print(" Use one of [");
   
                Collections.sort(commandGroups);
                out.print(commandGroups.get(0));
                for (int i = 1; i < commandGroups.size(); i++) {
                    out.print(" | ");
                    out.print(commandGroups.get(i));
                }
                out.println("] to see additional sub commands.");
                out.println("Or use one of:");
            } else {
                out.println(" Use on of:");
            }
        } else  {
            out.println(" Available sub commands for '" + group + "':");
        }
        
        Collections.sort(commands, new Comparator<Command>() {
            @Override
            public int compare(Command o1, Command o2) {
                return o1.getCommand().compareTo(o2.getCommand());
            }
        });
        
        for (Command command : commands) {
            out.println(String.format("  %-30s %s", command.getCommand(), command.getDescription()));
        }
    }

}
