SignServer Dependencies
-----------------------

For a list of each library file included and which project they belongs to see
jars-list.txt.

For a list of each project and their license see projects.list.txt.


Developer procedures for updating/checking the dependencies
-----------------------------------------------------------

1) Run the command to update the list of jar-files:
$ ./list-jar-files.sh > jar-files.txt

2) Inspect jar-files.txt
 - Compare it to the checked in version
 - For new files add which project it belongs to in the last column
 - Check that the checksum matches an upstream release

3) Run the command to update the list of projects:
 - ./list-projects.sh > projects.txt

4) Inspect projects.txt
 - Compare it to the checked in version
 - For new projects add the relevant information

5) Commit the changes

6) During QA the changes are reviewed


As a side note, checksums can also be verified using:
$ cat jar-files.txt | cut -d " " -f 1,3 | sha256sum -c
