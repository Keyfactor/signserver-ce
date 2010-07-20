The TimeStampResponseGenerator.java is originaly from Bouncy Castle version
1.44 and patched with
markus_primekey-bouncycastle-tsp-timeNotAvailable-patch1.diff see DSS-191.

Change committed to Bouncy Castle CVS Jan 14 2010,
TimeStampResponseGenerator.java version 1.3.

Another change is the addition of the generateFailResponse method that also 
will be submitted as a patch.

This file and TimeStampResponseGenerator.java can be removed when using a
Bouncy Castle release that includes the mentioned changes.

More information and license can be found at http://www.bouncycastle.org.
