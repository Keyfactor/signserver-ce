SignServer Dependencies
-----------------------

For a list of each library file included and which project they belongs to see
jars-list.txt.

For a list of each project and their license see projects.list.txt.


Developer procedures for updating/checking the dependencies
-----------------------------------------------------------

1) Run the command to update the list of jar-files:
 $ ./update-jars-list.sh

2) Inspect jars-list.txt
 - Compare it to the checked in version (svn diff)
 - For new files add which project it belongs to in the last column
 - Check that the checksum matches an upstream release

3) Run the command to update the list of projects:
 $ ./update-projects-list.sh

4) Inspect projects-list.txt
 - Compare it to the checked in version (svn diff)
 - For new projects add the relevant information

5) Commit the changes

6) During QA the changes are reviewed


As a side note, checksums can also be verified using:
$ cat jars-list.txt | cut -d ";" -f 1,3 | sha256sum -c
