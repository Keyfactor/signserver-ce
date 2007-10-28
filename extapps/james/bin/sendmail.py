#!/usr/bin/python
#
#    Licensed to the Apache Software Foundation (ASF) under one
#    or more contributor license agreements.  See the NOTICE file
#    distributed with this work for additional information
#    regarding copyright ownership.  The ASF licenses this file
#    to you under the Apache License, Version 2.0 (the
#    "License"); you may not use this file except in compliance
#    with the License.  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing,
#    software distributed under the License is distributed on an
#    "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
#    KIND, either express or implied.  See the License for the
#    specific language governing permissions and limitations
#    under the License.    
#
# --------------------------------------------------------------------------
#
# This is a simple mail client intended to suffice as the required
# "sendmail" client on typical UNIX-style systems.  It requires an
# SMTP SMTP server for handling the e-mail that users and system
# utilities may send via "sendmail".
#
# To install, symlink from /usr/{[s]bin,lib[exec]}/sendmail or similar
# for the particular deployment.
#
# --------------------------------------------------------------------------


import smtplib
import socket
import os
import sys
import getopt


def Usage():
    print "sendmail [-f <from_addr>][-F <full name>][-t][-h]"
    sys.exit(0)


def ProcessHeaders(headers, to_addrs, extract, fullname, from_addr):
    hasFrom = False
    for header in headers:
        if header.startswith("To:"):
            if extract:

                #to = header[3:]
                #to_addrs.append(to[("<" + to).rfind("<"):(to + ">").find(">")])

                allRecipientsString = header[3:]
                allRecipientsArray = allRecipientsString.split(',')
                
                for recipient in allRecipientsArray:

                  to_addrs.append(recipient[("<" + recipient).rfind("<"):(recipient + ">").find(">")])

        elif header.startswith("From:"):
            hasFrom = True
           
    if hasFrom:
        header = "Sender"
    else:
        header = "From"

    if fullname:
        headers.insert(0, "%s: %s <%s>" % (header,fullname, from_addr))
    else:
        headers.insert(0, "%s: %s" % (header, from_addr))

    return headers, to_addrs


def main(argv):
    try:
        optlist, list = getopt.getopt(sys.argv[1:], 'f:F:hti')
    except getopt.GetoptError:
        Usage()
        print >> sys.stderr, "called exception"
        sys.exit(2)

    to_addrs = list
    
    try:
        from_addr = os.environ['USER'] + '@' + socket.getfqdn()
    except KeyError:
        from_addr = "nobody@" + socket.getfqdn()
        
        
    fullname = ""
    extract = False

    for opt, value in optlist:
        if opt == '-h':
            Usage()
        elif opt == '-t':
            extract = True
        elif opt == '-F':
            fullname = value
        elif opt == '-f':
            from_addr = value

    print "Enter message, end with ^D (Unix) or ^Z (Windows):"

    processedHeaders = False
    msg = []

    while 1:
        try:
            line = raw_input()
        except EOFError:
            break
        if not line and not processedHeaders:
            msg, to_addrs = ProcessHeaders(msg, to_addrs, extract, fullname, from_addr)
            processedHeaders = True
        msg.append(line)

    msg = "\r\n".join(msg)

    if not to_addrs:
        print >> sys.stderr, "Must specify recipients on command line, or use -t with To: headers in message"
        sys.exit(0)


    server = smtplib.SMTP('127.0.0.1')
    server.set_debuglevel(0)
    server.sendmail(from_addr, to_addrs, msg)
    server.quit()


if __name__ == '__main__':
    main(sys.argv)
