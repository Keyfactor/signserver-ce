xades4j - A Java library for XAdES signature services
https://code.google.com/p/xades4j

The direct link we had for the upstream binary ZIP release doesn't seem to work
for the new 1.3.1 and 1.3.2 releases (when changing the version number, the old
link to 1.3.0 is still working).

The 1.3.2 patch has been made against a git checkout using the git commit with
hash 388c7ea

0235ba8b489512805ac13a8f9ea77a1ca5ebe3e8  lib/aopalliance.jar
a4c67006178262122e93121e94fff306fcf0cda1  lib/guice-2.0.jar
bfa4c1036fd7dc58019d0aeaec3faf4e8a685474  lib/guice-multibindings-2.0.jar

We have patched XAdES4j, see vendor branch and DSS-686. New checksum:
3c4ab3b5171d1560df36cab9c29583968b210d3e  xades4j-1.3.2-signserver.jar

A patch between the upstream sources for 1.3.2 and the version compiled for
SignServer is located at lib/ext/xades4j-1.3.2-signserver-patch.diff