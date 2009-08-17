
  Introduction
----------------------------------------------------------
The SignServer MailSigner is an application framework used 
to perform various 'batch'-like processing on e-mails.
It is mainly used for cryptographic related operations and 
have support for different HSM modules. .

The MailSigner comes with a predefined module used for
digitally sign outgoing e-mails.

Thank you for using the SignServer

   The SignServer project management team:
     Philip Vendil
     Henrik Andreasson
          

  Next Step
----------------------------------------------------------
The next step is to upload the module(s) containing the
MailSigner workers that you need. All the modules that
is included in the project is in the INSTALL_DIR/modules.

For instance, if you are going to setup a simple mail signer
you should issue the following command from the workstation
that you installed the signservermgmt package:
cd INSTALL_DIR
mailsigner.sh module add modules/simplemailsigner.mar demo

'demo' means that the MailSigner will configure a 
worker with soft test keys. Then give the command 
'mailsigner.sh reload all' and it
will be ready to process requests.

See the documentation for each separate module for
more details.

  License
----------------------------------------------------------  
The SignServer is released under the LGPL v 2.1 license 
that you can find more information about at: 
http://www.opensource.org/licenses/lgpl-2.1.php

 More Information
----------------------------------------------------------
More documentation and information about the 
SignServer is found at http://www.signserver.org.

There you find a Installation Guide on how to setup 
and SignServer Cluster on CentOS and a Users Manual
on how to configure the SignServer and develop your
own customized modules that fits your organization.

 Support
----------------------------------------------------------
For community support have the SignServer project
two mailing lists:

signserver-announce@lists.sourceforge.net
   Low traffic list about new releases and patches.
   
signserver-develop@lists.sourceforge.net
   Mailing list regaringing develop issues.
   
Go to http://sourceforge.net/mail/?group_id=190195
if you want to subscribe.

The community also have a IRC channel called
#signserver at freenode.irc.net

Commercial support of the SignServer is given by the
company PrimeKey Solutions AB in Sweden. Visit
http://www.primekey.se for more information.
  
