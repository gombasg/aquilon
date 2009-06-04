#!/usr/bin/env python2.5
# ex: set expandtab softtabstop=4 shiftwidth=4: -*- cpy-indent-level: 4; indent-tabs-mode: nil -*-
#
# Copyright (C) 2009  Contributor
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the EU DataGrid Software License.  You should
# have received a copy of the license with this program, and the
# license is published at
# http://eu-datagrid.web.cern.ch/eu-datagrid/license.html.
#
# THE FOLLOWING DISCLAIMER APPLIES TO ALL SOFTWARE CODE AND OTHER
# MATERIALS CONTRIBUTED IN CONNECTION WITH THIS PROGRAM.
#
# THIS SOFTWARE IS LICENSED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE AND ANY WARRANTY OF NON-INFRINGEMENT, ARE
# DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS
# BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
# OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
# OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
# BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
# LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. THIS
# SOFTWARE MAY BE REDISTRIBUTED TO OTHERS ONLY BY EFFECTIVELY USING
# THIS OR ANOTHER EQUIVALENT DISCLAIMER AS WELL AS ANY OTHER LICENSE
# TERMS THAT MAY APPLY.

'''Client for accessing aqd.

It uses knc by default for an authenticated connection, but can also
connect directly.

'''

import sys
import os
import urllib
import re
# Using this for gethostname for now...
import socket

BINDIR = os.path.dirname(os.path.realpath(sys.argv[0]))
sys.path.append(os.path.join(BINDIR, "..", "lib", "python2.5"))
import aquilon.client.depends

from twisted.python import log
from twisted.internet import reactor, error, utils, protocol, defer
from twisted.web import http, error as web_error

from aquilon.client.optparser import OptParser, ParsingError

return_code = 0

# FIXME: This should probably be broken out into its own file at some
# point.  The tricky part is making sure getPage is picked up correctly.
# The getPage method will need to handle different response types
# correctly, anyway.
class RESTResource(object):
    def __init__(self, uri, aquser):
        self.uri = uri
        self.aquser = aquser
    
    def get(self):
        return self._sendRequest('GET')

    def post(self, **kwargs):
        postData = urllib.urlencode(kwargs)
        mimeType = 'application/x-www-form-urlencoded'
        return self._sendRequest('POST', postData, mimeType)

    def put(self, data, mimeType):
        return self._sendRequest('PUT', data, mimeType)

    def delete(self):
        return self._sendRequest('DELETE')

    def _sendRequest(self, method, data="", mimeType=None):
        headers = {}
        if mimeType:
            headers['Content-Type'] = mimeType
        if data:
            headers['Content-Length'] = str(len(data))
        return getPage(self.uri,
                method=method, postdata=data, headers=headers, aquser=aquser)


class CommandPassThrough(protocol.ProcessProtocol):
    """Simple wrapper for running commands to immediately pass stdout
    and stderr to the console, and callback on the deferred when the
    command has finished.

    """

    def __init__(self, deferred):
        self.deferred = deferred
        self.outReceived = sys.stdout.write
        self.errReceived = sys.stderr.write

    def processEnded(self, reason):
        e = reason.value
        code = e.exitCode
        if e.signal:
            self.deferred.errback(e.signal)
        else:
            self.deferred.callback(code)


def cb_command_response(code):
    if code:
        print >>sys.stderr, "Return code: %d" % code
        globals()["return_code"] = code

def cb_command_error(signalNum):
    print >>sys.stderr, "Error running command, received signal %d" % signalNum
    globals()["return_code"] = 1

def gotPage(pageData, uri, expect, globalOptions):
    if expect == 'command':
        if globalOptions.get("noexec"):
            print pageData
            return
        d = defer.Deferred()
        p = CommandPassThrough(d)
        reactor.spawnProcess(p, "/bin/sh", ("/bin/sh", "-c", pageData),
                                os.environ, '.')
        d = d.addCallbacks(cb_command_response, cb_command_error)
        return d
    else:
        if globalOptions.get("httpinfo"):
            print >>sys.stderr, "[OK] %s" % uri
        if pageData:
            format = ""
            if globalOptions.get("format"):
                format = globalOptions.get("format")
            if format == "proto":
                    sys.stdout.write(pageData)
            else:
                print pageData


class CustomAction(object):
    """Any custom code that needs to be written to run before contacting
    the server can go here for now.

    Each method should expect to add to the commandOptions object, and
    should have a name that matches the corresponding custom tag in the
    xml option parsing file.

    Code here will run before the reactor starts, and can safely block.
    """

    def __init__(self, action):
        m = getattr(self, action, None)
        if not m:
            raise AquilonError("Internal Error: Unknown action '%s' attempted"
                    % action)
        self.run = m

    def create_bundle(self, commandOptions):
        from subprocess import Popen, PIPE
        from re import search
        from tempfile import mkstemp
        from base64 import b64encode

        p = Popen(("git", "fetch"), stderr=2)
        p.wait()  ## wait for return, but it's okay if this fails
        p = Popen(("git", "status"), stdout=PIPE, stderr=2)
        (out, err) = p.communicate()
        # Looks like git status returns with "1" if there is nothing to commit.
        #if p.returncode:
        #    sys.stdout.write(out)
        #    print >>sys.stderr, "Error running git status, returncode %d" \
        #            % p.returncode
        #    sys.exit(1)
        if not search("nothing to commit", out):
            print >>sys.stderr, "Not ready to commit: %s" % out
            sys.exit(1)

        p = Popen(("git", "log", "origin/master..HEAD"), stdout=PIPE, stderr=2)
        (out,err) = p.communicate()

        if out:
            print >>sys.stdout, "\nThe following changes will be included in this push:\n"
            print >>sys.stdout, "------------------------"
            print >>sys.stdout, str(out)
            print >>sys.stdout, "------------------------"
        else:
            print >>sys.stdout, "\nYou haven't made any changes on this branch\n"
            sys.exit(0)
            
        (handle, filename) = mkstemp()
        try:
            rc = Popen(("git", "bundle", "create", filename, "origin/master..HEAD"),
                        stdout=1, stderr=2).wait()
            if rc:
                print >>sys.stderr, \
                        "Error running git bundle create, returncode %d" % rc
                sys.exit(1)
    
            commandOptions["bundle"] = b64encode(file(filename).read())
        finally:
            os.unlink(filename)


def handleFailure(failure, uri, globalOptions):
    """Final stop handling for all errors - this will return success
    and let the reactor stop cleanly."""
    if failure.check(error.ProcessTerminated):
        print >>sys.stderr, "Communications subprocess terminated:%s" % \
                failure.getErrorMessage()
    elif failure.check(web_error.Error):
        if globalOptions.get("httpinfo"):
            print >>sys.stderr, "[%s] %s" % (failure.value.status, uri)
        print >>sys.stderr, "%s: %s" % (
            http.RESPONSES.get(int(failure.value.status)),
            failure.value.response)
        # Quick hack... failure codes will usually be 4xx or 5xx...
        # maybe it will help to encode that in the return code.
        try:
            globals()["return_code"] = int(failure.value.status) / 100
        except ValueError, e:
            # No big deal - return_code will be set to 1 later.
            pass
    else:
        msg = failure.getErrorMessage()
        if msg.find("Connection refused") >= 0:
            print >>sys.stderr, "Failed to connect to %(aqhost)s port %(aqport)s: Connection refused." % globalOptions
        elif msg.find("Unknown host") >= 0:
            print >>sys.stderr, "Failed to connect to %(aqhost)s: Unknown host." % globalOptions
        else:
            print >>sys.stderr, "Error: %s" % msg
    if not globals()["return_code"]:
        globals()["return_code"] = 1

def quoteOptions(options):
    return "&".join([ urllib.quote(k) + "=" + urllib.quote(v) for k, v in options.iteritems() ])

if __name__ == "__main__":
    parser = OptParser( os.path.join( BINDIR, '..', 'etc', 'input.xml' ) )
    try:
        (command, transport, commandOptions, globalOptions) = \
                parser.getOptions()
    except ParsingError, e:
        print >>sys.stderr, '%s: Option parsing error: %s' % (sys.argv[0],
                                                              e.error)
        print >>sys.stderr, '%s: Try --help for usage details.' % (sys.argv[0])
        sys.exit(1)

    if globalOptions.get('debug'):
        log.startLogging(sys.stderr)
        globalOptions['httpinfo'] = True

    # Setting this as a global default.  It might make sense to set
    # the default to the current running user when running out of a
    # shadow, though.
    default_aquser = "cdb"

    # Default for /ms/dist
    if re.match(r"/ms(/.(global|local)/[^/]+)?/dist/", BINDIR):
        default_aqhost = "nyaqd1"
    # Default for /ms/dev
    elif re.match(r"/ms(/.(global|local)/[^/]+)?/dev/", BINDIR):
        default_aqhost = "nyaqd1"
    else:
        default_aqhost = socket.gethostname()

    if globalOptions.get('noauth'):
        default_aqport = "6901"
    else:
        default_aqport = "6900"

    host = globalOptions.get('aqhost') or default_aqhost
    port = globalOptions.get('aqport') or default_aqport
    aquser = globalOptions.get('aquser') or default_aquser

    # Save these in case there are errors...
    globalOptions["aqhost"] = host
    globalOptions["aqport"] = port

    if transport is None:
        print >>sys.stderr, "Unimplemented command ", command
        exit(1)

    # Convert unicode options to strings
    newOptions = {}
    for k, v in commandOptions.iteritems():
        newOptions[str(k)] = str(v)
    commandOptions = newOptions
    # Should maybe have an input.xml flag on which global options
    # to include... for now it's just debug.
    if globalOptions.get("debug", None):
        commandOptions["debug"] = str(globalOptions["debug"])

    # Quote options so that they can be safely included in the URI
    cleanOptions = {}
    for k, v in commandOptions.iteritems():
        cleanOptions[k] = urllib.quote(v)

    # Decent amount of magic here...
    # Even though the server connection might be tunneled through
    # knc, the easiest way to consistently address the server is with
    # a URL.  That's the first half.
    # The relative URL defined by transport.path comes from the xml
    # file used for options definitions.  This is a standard python
    # string formatting, with references to the options that might
    # be given on the command line.
    uri = str('http://%s:%s/' % (host, port) + transport.path % cleanOptions)

    # Add the formatting option into the string.  This is only tricky if
    # a query operator has been specified, otherwise it would just be
    # tacking on (for example) .html to the uri.
    # Do not apply any formatting for commands (transport.expect == 'command').
    if globalOptions.has_key('format') and not transport.expect:
        extension = '.' + urllib.quote(globalOptions["format"])

        query_index = uri.find('?')
        if query_index > -1:
            uri = uri[:query_index] + extension + uri[query_index:]
        else:
            uri = uri + extension

    # import getPage depending on the connection requirements
    if globalOptions.get('usesock'):
        from aquilon.client.socketwrappers import getPage
    elif globalOptions.get('noauth'):
        from aquilon.client.ncwrappers import getPage
    else:
        from aquilon.client.kncwrappers import getPage

    # run custom command if there's one
    if transport.custom:
        action = CustomAction(transport.custom)
        action.run(commandOptions)

    if transport.method == 'get':
        # Fun hackery here to get optional parameters into the path...
        # First, figure out what was already included in the path,
        # looking for %(var)s.
        c = re.compile(r'(?<!%)%\(([^)]*)\)s')
        exclude = c.findall(transport.path)

        # Now, pull each of these out of the options.  This is not
        # strictly necessary, but simplifies the url.
        remainder = commandOptions.copy()
        for e in exclude:
            remainder.pop(e, None)

        if remainder:
            # Almost done.  Just need to account for whether the uri
            # already has a query string.
            if uri.find("?") >= 0:
                uri = uri + '&' + quoteOptions(remainder)
            else:
                uri = uri + '?' + quoteOptions(remainder)
        d = RESTResource(uri, aquser).get()

    elif transport.method == 'put':
        # FIXME: This will need to be more complicated.
        # In some cases, we may even need to call code here.
        putData = urllib.urlencode(commandOptions)
        mimeType = 'application/x-www-form-urlencoded'
        d = RESTResource(uri, aquser).put(putData, mimeType)

    elif transport.method == 'delete':
        # Again, all command line options should be in the URI already.
        d = RESTResource(uri, aquser).delete()

    elif transport.method == 'post':
        d = RESTResource(uri, aquser).post(**commandOptions)

    else:
        print >>sys.stderr, "Unhandled transport method ", transport.method
        sys.exit(1)

    d = d.addCallback(gotPage, uri, transport.expect, globalOptions)
    d = d.addErrback(handleFailure, uri, globalOptions)
    d = d.addCallback(lambda _: reactor.stop())

    #import pdb
    #pdb.set_trace()
    reactor.run()
    # The global variable return_code gets set in the various error handlers.
    sys.exit(return_code)

