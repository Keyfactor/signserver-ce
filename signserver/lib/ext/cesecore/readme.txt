CESeCore is from cesecore.eu SVN revision 1488.

We build the CESeCore jars with some classes removed. Patch for being able to 
exclude files from the jars:
--------
Index: build-ejb.xml
===================================================================
--- build-ejb.xml	(revision 1419)
+++ build-ejb.xml	(working copy)
@@ -44,19 +44,19 @@
 	</target>
 
 	<target name="archive-ejb" description="Construct an EJB JAR file." depends="test:unit, handleintres, archive-entity">
-		<jar destfile="${build.dir}/cesecore-ejb_${version}.jar" basedir="${classes-ejb.dir}" includes="**/*.class **/*.xml **/*.properties">
-			<zipfileset prefix="META-INF" dir="${resources.dir}/appserver" includes="*.xml"/>	
+		<jar destfile="${build.dir}/cesecore-ejb_${version}.jar" basedir="${classes-ejb.dir}" includes="**/*.class **/*.xml **/*.properties" excludes="${archive.excludes}">
+			<zipfileset prefix="META-INF" dir="${resources.dir}/appserver" includes="*.xml" excludes="${archive.excludes}"/>	
 		</jar>
 	</target>
 
 
 	<target name="archive-entity" description="Construct a JPA entity jar file." depends="archive-client, handlepersistence, handleorm, handlecache">
-		<jar destfile="${build.dir}/cesecore-entity_${version}.jar" basedir="${classes-entity.dir}" includes="**/*.class **/*.xml" />
+		<jar destfile="${build.dir}/cesecore-entity_${version}.jar" basedir="${classes-entity.dir}" includes="**/*.class **/*.xml" excludes="${archive.excludes}" />
 	</target>
 
 	<target name="archive-client" description="Construct a jar file with common class files.">
 		<copy file="${src.dir}/profilemappings.properties" tofile="${classes-client.dir}/profilemappings.properties" failonerror="true" overwrite="true"/>
-		<jar destfile="${build.dir}/cesecore-client_${version}.jar" basedir="${classes-client.dir}" includes="**/*.class **/*.xml **/*.properties" />
+		<jar destfile="${build.dir}/cesecore-client_${version}.jar" basedir="${classes-client.dir}" includes="**/*.class **/*.xml **/*.properties" excludes="${archive.excludes}"/>
 	</target>
 
 </project>
--------

The jars can then be built using:

$ ant -Dskip.test=true archive-client archive-entity archive-ejb -Darchive.excludes="**/*/persistence.xml, jboss.xml, **/*/CrlStoreSessionBean*.class, **/*/CrlCreateSessionBean*.class, **/*/CertificateKeyAssociationSessionBean*.class, **/*/CaTokenSessionBean*.class, **/*/CaSessionBean*.class, **/*/IntegratedOcspResponseGeneratorSessionBean*.class, **/*/CertificateCreateSessionBean*.class, **/*/CertificateProfileSessionBean*.class, **/*/CertificateStoreSessionBean*.class, **/*/CertificateCreateSessionBean*.class, **/*/StandaloneOcspResponseGeneratorSessionBean*.class, **/*/CertificateKeyRetrievalSessionBean*.class, **/*/BackupSessionBean*.class, **/*/RestoreSessionBean*.class, **/*/QueuedAuditorSessionBean*.class, **/*/QueuedLoggerSessionBean*.class, **/*/LogManagementSessionBean*.class, **/*/TrustedTimeWatcherSessionBean*.class, **/*/InternalLogManagementSessionBean*.class, **/*/SchedulerSessionBean*.class, **/*/AccessTreeUpdateSessionBean*.class, **/*/RoleAccessSessionBean*.class, **/*/RoleManagementSessionBean*.class, **/*/AccessUserAspectManagerSessionBean*.class, **/*/AccessRuleManagementSessionBean*.class, **/*/CryptoTokenSessionBean*.class, **/*/CryptoTokenManagementSessionBean*.class"

TODO: Move the exclusion of classes to our build-script instead so we can use the original jars
