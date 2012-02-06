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
    
    private Map<String, CommandEntry> commands = new HashMap<String, CommandEntry>();
    private Map<String, Map<String, CommandEntry>> subCommands = new HashMap<String, Map<String, CommandEntry>>();
    
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
        put(command, clazz, true);
    }
    protected void put(String group, String subCommand, Class<? extends AbstractCommand> clazz) {
        put(group, subCommand, clazz, true);
    }
    
    protected void put(String command, Class<? extends AbstractCommand> clazz, boolean visible) {
        commands.put(command, new CommandEntry(clazz, visible));
    }
    protected void put(String group, String subCommand, Class<? extends AbstractCommand> clazz, boolean visible) {
        Map<String, CommandEntry> subCommandMap = subCommands.get(group);
        if (subCommandMap == null) {
            subCommandMap = new HashMap<String, CommandEntry>();
            subCommands.put(group, subCommandMap);
        }
        subCommandMap.put(subCommand, new CommandEntry(clazz, visible));
    }
    
    @Override
    public Command getCommand(final String[] args) {
        return getCommand(args, false);
    }
    
    private Command getCommand(final String[] args, boolean onlyVisible) {
        if (args.length < 1) {
            return null;
        }
        String commandName = null;
        String commandGroupName = null;
        StringBuilder usage = new StringBuilder();
        usage.append(usagePrefix).append(" ");
        CommandEntry entry = commands.get(args[0]);
        if (entry == null) {
            Map<String, CommandEntry> commandGroup = subCommands.get(args[0]);
            if (commandGroup != null) {
                if (args.length < 2) {
                    return null;
                }
                entry = commandGroup.get(args[1]);
                if (entry != null && (entry.isVisible() || !onlyVisible)) {
                    commandName = args[1];
                    commandGroupName = args[0];
                    usage.append(args[0]).append(" ").append(commandName);
                }
            }
        } else if (entry.isVisible()) {
            commandName = args[0];
            usage.append(commandName);
        }
        if (entry != null && (entry.isVisible() || !onlyVisible)) {
            try {
                CommandContext context = new CommandContext(commandGroupName, commandName, factoryContext);
                context.setUsagePrefix(usage.toString());
                AbstractCommand command = entry.getCommandClazz().newInstance();
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
            Command command = getCommand(new String[] { name }, true);
            if (command != null) {
                result.add(command);
            }
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
        Map<String, CommandEntry> commandsInGroup = subCommands.get(group);
        if (commandsInGroup == null) {
            result = null;
        } else {
            result = new LinkedList<Command>();
            for (String command : commandsInGroup.keySet()) {
                Command c = getCommand(new String[] { group, command }, true);
                if (c != null) {
                    result.add(c);
                }
            }
        }
        return result;
    }
 
    private static class CommandEntry {
        private Class<? extends AbstractCommand> commandClazz;
        private boolean visible;

        public CommandEntry(Class<? extends AbstractCommand> commandClazz, boolean visible) {
            this.commandClazz = commandClazz;
            this.visible = visible;
        }

        public Class<? extends AbstractCommand> getCommandClazz() {
            return commandClazz;
        }

        public boolean isVisible() {
            return visible;
        }
        
    }
    
}
