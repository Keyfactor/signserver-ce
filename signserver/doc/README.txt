Documentation
-------------

The main documentation for SignServer is available in the Manual:
- doc/htdocs/index.html: The SignServer manual. 

Note: The manual is available directly in the binary distribution. In other
distributions it needs to be built first.

Other supporting documents:
- README.txt: This document.
- RELEASE_NOTES.txt: Important information specific to each release.
- UPGRADE.txt: Instructions for upgrading from one version to an other.
- DEVELOP.txt: Information about developing and contributing to SignSignServer.

Online resources:
- https://www.signserver.org: The project web site also including the manual
  but not necessarly the one for this version.


Building the Documentation from Source
--------------------------------------

When using the binary distribution this section can be skipped.

For the non-binary downloads, or if the sources are checked out directly from 
the Subversion (SVN) source code repository, then the documentation needs to 
be built before being available in doc/htdocs/index.html.

The documentation is built using the Maven tool. First make sure you have a secure
build environment. At minimum this could mean that the URL for the Central
repository is specified with HTTTPS. See sample-maven-settings.xml for an example
on how one can override the default Maven settings.

Building the manual:
$ cd modules/SignServer-Doc
$ mvn install


Opening the SignServer Manual
------------------------------

$ firefox doc/htdocs/index.html

See the Installation Guide for how to continue.


License Information
-------------------
  
SignServer is released under the LGPL license that you can find more
information about at http://www.opensource.org/licenses/lgpl-license.php.

Third party licensies are available at https://signserver.org/license.html.
