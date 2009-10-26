
JARS

openxml4j-signaturepatched jar is a signature patched version of openxml4j library from http://sourceforge.net/projects/openxml4j/. Patch applied to revision 534 to
of openxml4j (https://openxml4j.svn.sourceforge.net).  Used by ooxmlsigner to sign open office xml documents. License : LGPL

jaxen-1.1.jar is from http://jaxen.codehaus.org/index.html. Used by openxml4j for xml processing. License :  Apache-style open source license  (quote from http://jaxen.codehaus.org/faq.html)

xercesImpl.jar is from http://xerces.apache.org/xerces2-j/ .Used by openxml4j for xml processing.  License :  Apache Software License.




NOTE : signserver.sh and signserver.cmd specify -Djava.endorsed.dirs=lib/endorsed when running. This is done for runtime to pick the jars in this directory instead of equivalent (but maybe outdated jars) in classpath (as is the case with xmlsec). Ant copies the jars in this directory to JBOSS_HOME/lib/endorsed so jboss does the same when running. openxml4j-signaturepatched.jar is placed in same directory as xmlsec is, since it implements TransformServiceProvider and Classloader needs it to be in same place as xmlsec .