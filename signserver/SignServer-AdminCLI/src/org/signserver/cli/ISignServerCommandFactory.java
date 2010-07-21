package org.signserver.cli;

import java.io.PrintStream;

public interface ISignServerCommandFactory {

	/**
	 * Returns an Admin Command object based on contents in args[0].
	 *
	 * @param args array of arguments typically passed from main().
	 *
	 * @return Command object or null if args[0] does not specify a valid command.
	 */
	public abstract IAdminCommand getCommand(String[] args); // getCommand

	public abstract void outputHelp(PrintStream out);

}