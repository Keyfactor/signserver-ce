
package org.signserver.client.cli.defaultimpl;

import java.io.Console;
import org.signserver.cli.spi.CommandFailureException;

/**
 * Default implementation of a console password reader, using System.console()
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public class DefaultConsolePasswordReader implements ConsolePasswordReader {

    final Console console = System.console();
    
    @Override
    public char[] readPassword() throws CommandFailureException {
        if (console != null) {
            return console.readPassword();
        } else {
            throw new CommandFailureException("Failed to read password");
        }
    }
}
