/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package org.signserver.client.cli;

import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.ResourceBundle;
import org.apache.log4j.Logger;

/**
 *
 * @author markus
 */
public class Main {

     /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(Main.class);

    /** ResourceBundle with internationalized StringS. */
    private static final ResourceBundle TEXTS =
            ResourceBundle.getBundle("org/signserver/client/cli/ResourceBundle");

    private static final List<String> COMMANDS = Arrays.asList(
            "signdocument",
            "validatedocument",
            "timestamp",
            "validatecertificate");


    /** No instances of this class. */
    private Main() { }
 
    /**
     * @param args the command line arguments
     */
    public static void main(final String[] args) {

        if (args.length == 0) {
            printUsage(COMMANDS);
        } else if ("signdocument".equals(args[0])) {
            DocumentSignerCLI.main(args);
        } else if ("timestamp".equals(args[0])) {
            try {
                org.signserver.client.TimeStampClient.main(
                        Arrays.copyOfRange(args, 1, args.length));
            } catch (Exception ex) {
                LOG.error(ex, ex);
            }
        } else {
            printUsage(COMMANDS);
        }
        
    }

    private static void printUsage(List<String> commands) {
        final StringBuilder sb = new StringBuilder();
        sb.append("usage:");
        sb.append(" ");
        sb.append("signserverclient");
        sb.append(" ");
        sb.append("<");
        for (final Iterator<String> it = commands.iterator(); it.hasNext();) {
            sb.append(it.next());
            if(it.hasNext()) {
                sb.append(" | ");
            }
        }
        sb.append(">");
        LOG.info(sb.toString());
    }

}
