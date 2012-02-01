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
package org.signserver.cli.spi;

import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;


/**
 *
 * @author Markus Kilås
 */
public abstract class AbstractCommandFactory implements CommandFactory {
    
    private Map<String, Class<? extends AbstractCommand>> commands = new HashMap<String, Class<? extends AbstractCommand>>();
    private Map<String, Map<String, Class<? extends AbstractCommand>>> subCommands = new HashMap<String, Map<String, Class<? extends AbstractCommand>>>();
    
    private String usagePrefix = "";
    
    private CommandFactoryContext factoryContext;
    
    @Override
    public void init(CommandFactoryContext context) {
        this.factoryContext = context;
        registerCommands();
    }

    @Override
    public boolean isInitialized() {
        return factoryContext != null;
    }
    
    protected abstract void registerCommands();
    
    protected void put(String command, Class<? extends AbstractCommand> clazz) {
        commands.put(command, clazz);
    }
    protected void put(String group, String subCommand, Class<? extends AbstractCommand> clazz) {
        Map<String, Class<? extends AbstractCommand>> subCommandMap = subCommands.get(group);
        if (subCommandMap == null) {
            subCommandMap = new HashMap<String, Class<? extends AbstractCommand>>();
            subCommands.put(group, subCommandMap);
        }
        subCommandMap.put(subCommand, clazz);
    }
    
    @Override
    public Command getCommand(final String... args) {
        if (args.length < 1) {
            return null;
        }
        String commandName = null;
        String commandGroupName = null;
        StringBuilder usage = new StringBuilder();
        usage.append(usagePrefix).append(" ");
        Class<? extends AbstractCommand> clazz = commands.get(args[0]);
        if (clazz == null) {
            Map<String, Class<? extends AbstractCommand>> commandGroup = subCommands.get(args[0]);
            if (commandGroup != null) {
                if (args.length < 2) {
                    return null;
                }
                clazz = commandGroup.get(args[1]);
                commandName = args[1];
                commandGroupName = args[0];
                usage.append(args[0]).append(" ").append(commandName);
            }
        } else {
            commandName = args[0];
            usage.append(commandName);
        }
        if (clazz != null) {
            try {
                CommandContext context = new CommandContext(commandGroupName, commandName, factoryContext);
                context.setUsagePrefix(usage.toString());
                AbstractCommand command = clazz.newInstance();
                command.init(context);
                return command;
            } catch (InstantiationException ex) {
                throw new RuntimeException(ex);
            } catch (IllegalAccessException ex) {
                throw new RuntimeException(ex);
            }
        } else {
            return null;
        }
    }

    @Override
    public Collection<Command> getTopLevelCommands() {
        final LinkedList<Command> result = new LinkedList<Command>();
        for (String name : commands.keySet()) {
            Command command = getCommand(name);
            result.add(command);
        }
        return result;
    }

    @Override
    public Collection<String> getCommandGroups() {
        return subCommands.keySet();
    }

    @Override
    public Collection<Command> getSubCommands(String group) {
        final Collection<Command> result;
        Map<String, Class<? extends AbstractCommand>> commandsInGroup = subCommands.get(group);
        if (commandsInGroup == null) {
            result = null;
        } else {
            result = new LinkedList<Command>();
            for (String command : commandsInGroup.keySet()) {
                result.add(getCommand(group, command));
            }
        }
        return result;
    }
    
    
}
