 
                              P H O E N I X
                        
                               4.0
                                
                      
  What is it?
  -----------

  It is meta-server - a server kernel on top of which other servers are built.

  Where is it?
  ------------

  http://jakarta.apache.org/avalon/phoenix

  What is related to it?
  ----------------------

  http://jakarta.apache.org/avalon - the parent project for Phoenix.

  http://jakarta.apache.org/avalon/framework - a service framework initiative.
  
  http://jakarta.apache.org/avalon/cornerstone - a set of reusable components that 
  Phoenix server applications may use.

  http://jakarta.apache.org/avalon/apps - a set of complete and in-progress
  applications for Phoenix.

  http://jakarta.apache.org/james - a mail server that runs as a Phoenix 
  server application.

  Requirements
  ------------

  -JDK1.3 or above
  -To build form CVS you must set JAVA_HOME to the jdk dir (eg:/usr/bin/jdk1.3 or 
   c:\jdk1.3)
   
  Note for JDK1.4 users, please remove xerces.jar from Phoenix's lib dir.  This is 
  because JDK 1.4 comes with xerces, and Phoenix may object to two versions in the 
  classpath.   
   
  Distribution
  ------------
  Distribution contains the following:
  -phoenix-engine.jar       The Phoenix kernel
  -phoenix-loader.jar       Phoenix loader

  Distributions built above JDK1.3 will include the following:
  -xerces.jar               Any SAX2 parser will work. By default Xerces is used.

  Installation Instructions and Documentation
  -------------------------------------------

  Phoenix is a framework that loads and runs servers. Without a server 
  plugged into it, it doesn't do anything. To run it just execute run.bat 
  or run.sh in the distribution bin folder. See docs/ subdirectory for further
  documentation.

  Licensing and legal issues
  --------------------------

  For other legal and licensing issues, please read the included documentation.

  Thanks for using Phoenix.

                                           The Apache Jakarta Project
                                           http://jakarta.apache.org/                                         
                                           
  
