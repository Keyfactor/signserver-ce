CESeCore is from cesecore.eu SVN revision 1488.

The jars can be built in the CESeCore project using:
$ ant archive-client archive-entity archive-ejb

Some files/classes are filtered from the jars at deployment time as we don't use
all functionality of CESeCore.
