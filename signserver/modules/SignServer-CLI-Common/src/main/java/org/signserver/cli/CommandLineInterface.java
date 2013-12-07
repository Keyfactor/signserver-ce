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


import java.io.PrintStream;
import java.util.*;
import org.apache.log4j.Logger;
import org.signserver.cli.spi.*;

/**
 * Implements the signserver command line interface
 *
 * @version $Id$
 */
public class CommandLineInterface {
    
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(CommandLineInterface.class);
    
    public static final int RETURN_SUCCESS = 0;
    public static final int RETURN_INVALID_ARGUMENTS = -1;
    public static final int RETURN_ERROR = -2;

    private ServiceLoader<? extends CommandFactory> loader;
    private Properties configuration;
    
    private PrintStream out = System.out;
    private PrintStream err = System.err;

    private CommandFactoryContext factoryContext;

    public CommandLineInterface() {
        this(AbstractCommandFactory.class, new Properties());
    }
    
    public CommandLineInterface(Class<? extends CommandFactory> factoryClazz) {
        this(factoryClazz, new Properties());
    }
    
    public CommandLineInterface(Class<? extends CommandFactory> factoryClazz, Properties configuration) {
        this.loader = ServiceLoader.load(factoryClazz);
        this.configuration = configuration;
    }
    
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
    
    public int execute(final String... args) throws UnexpectedCommandFailureException {
        int resultCode;
        
        if (loader == null) {
            loader = ServiceLoader.load(CommandFactory.class);
        }
        
        factoryContext = new CommandFactoryContext(getConfiguration(), getOut(), getErr());

        Command cmd = getCommand(args);

        if (cmd != null) {
            try {
                final int shift;
                if (cmd.getCommandGroup() == null) {
                    shift = 1;
                } else {
                    shift = 2;
                }
                // Run with args without the name of the command and sub command
                resultCode = cmd.execute(Arrays.copyOfRange(args, shift, args.length));
            } catch (IllegalCommandArgumentsException ex) {
                out.println(ex.getMessage());
                out.println(cmd.getUsages());
                resultCode = RETURN_INVALID_ARGUMENTS;
            } catch (CommandFailureException ex) {
                out.println(ex.getMessage());
                if (ex.getExitCode() == null) {
                    resultCode = RETURN_ERROR;
                } else {
                    resultCode = ex.getExitCode();
                }
            }
        } else {
            if (args.length > 0) {
                outputHelp(out, args[0], getCommands(args[0]));
            } else {
                outputHelp(out, null, null);
            }
            resultCode = RETURN_INVALID_ARGUMENTS;
        }

        return resultCode;
    }

    /**
     * Main
     *
     * @param args command line arguments
     */
    public static void main(String[] args) throws UnexpectedCommandFailureException {
        CommandLineInterface cli = new CommandLineInterface();
        int returnCode = cli.execute(args);
        System.exit(returnCode);
    }

    protected Command getCommand(String[] args) throws UnexpectedCommandFailureException {
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
            throw new UnexpectedCommandFailureException("Error loading command factories", error);
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

    public Properties getConfiguration() {
        return configuration;
    }
    
    public void setConfiguration(Properties cliProperties) {
        this.configuration = cliProperties;
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
                out.println(" Use one of:");
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
