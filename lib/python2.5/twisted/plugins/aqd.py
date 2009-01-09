# ex: set expandtab softtabstop=4 shiftwidth=4: -*- cpy-indent-level: 4; indent-tabs-mode: nil -*-
# Copyright (C) 2008 Morgan Stanley
#
# This module is part of Aquilon
"""Provide a twistd plugin for aqd to start up."""

import os
import sys
import logging
from logging import Handler

# This is done by the wrapper script.
#import aquilon.server.depends

from zope.interface import implements
from twisted.python import usage, log
from twisted.plugin import IPlugin
from twisted.application import strports
from twisted.application.service import IServiceMaker, MultiService
from twisted.runner.procmon import ProcessMonitor
from twisted.internet import reactor
from ms.modulecmd import Modulecmd, ModulecmdExecError

from aquilon.config import Config
from aquilon.server.kncwrappers import KNCSite
from aquilon.server.anonwrappers import AnonSite

# This gets imported dynamically to avoid loading libraries before the
# config file has been parsed.
#from aquilon.server.resources import RestServer


class Options(usage.Options):
    optFlags = [
                ["noauth", None, "Do not start the knc listener."],
                ["usesock", None, "use a unix socket to connect"],
            ]
    optParameters = [
                ["config", None, "Configuration file to use."],
            ]


class BridgeLogHandler(Handler):
    """Allow python logging messages to be funneled into the twisted log."""
    def emit(self, record):
        log.msg(record.getMessage())


def log_module_load(cmd, mod):
    """Wrapper for logging Modulecmd actions and errors."""
    try:
        log.msg("Loading module %s." % mod)
        cmd.load(mod)
        log.msg("Module %s loaded successfully." % mod)
    except ModulecmdExecError, e:
        log.msg("Failed loading module %s, return code %d and stderr '%s'." %
                (mod, e.exitcode, e.stderr))


class AQDMaker(object):
    implements(IServiceMaker, IPlugin)
    tapname = "aqd"
    description = "Aquilon Daemon"
    options = Options

    def makeService(self, options):
        config = Config(configfile=options["config"])

        # Set up the environment...
        m = Modulecmd()
        log_module_load(m, config.get("broker", "CheckNet_module"))
        if config.has_option("database", "module"):
            log_module_load(m, config.get("database", "module"))
        sys.path.append(config.get("protocols", "directory"))

        # Set this up before the aqdb libs get imported...
        rootlog = logging.getLogger()
        rootlog.addHandler(BridgeLogHandler())
        rootlog.setLevel(logging.NOTSET)
        for logname in config.options("logging"):
            logvalue = config.get("logging", logname)
            # Complain if a config value is out of whack...
            if logvalue not in logging._levelNames:
                # ...but ignore it if it is a default (accidently
                # polluting the section).
                if not config.defaults().has_key(logname):
                    log.msg("For config [logging]/%s, "
                            "%s not a valid log level." % (logname, logvalue))
                continue
            logging.getLogger(logname).setLevel(logging._levelNames[logvalue])

        # Dynamic import means that we can parse config options before
        # importing aqdb.  This is a hack until aqdb can be imported without
        # firing up database connections.
        resources = __import__("aquilon.server.resources", globals(), locals(),
                ["RestServer"], -1)
        RestServer = getattr(resources, "RestServer")

        restServer = RestServer(config)
        openSite = AnonSite(restServer)

        # twisted is nicely changing the umask for us when the process is
        # set to daemonize.  This sets it back.
        restServer.set_umask()
        reactor.addSystemEventTrigger('after', 'startup', restServer.set_umask)

        if options["usesock"]:
            return strports.service("unix:%s/aqdsock:mode=600"
                    % config.get("broker", "basedir"), openSite)

        if options["noauth"]:
            return strports.service(config.get("broker", "openport"), openSite)

        sockname = os.path.join(config.get("broker", "rundir"), "kncsock")
        if os.path.exists(sockname):
            try:
                log.msg("Attempting to remove old socket '%s'" % sockname)
                os.remove(sockname)
                log.msg("Succeeded removing old socket.")
            except OSError, e:
                log.msg("Could not remove old socket '%s': %s" % (sockname, e))

        mon = ProcessMonitor()
        # FIXME: Should probably run krb5_keytab here as well.
        # and/or verify that the keytab file exists.
        mon.addProcess("knc", ["/usr/bin/env",
            "KRB5_KTNAME=FILE:/var/spool/keytabs/%s"
            % config.get("broker", "user"),
            config.get("broker", "knc"), "-lS", sockname,
            config.get("broker", "kncport")])
        mon.startService()
        reactor.addSystemEventTrigger('before', 'shutdown', mon.stopService)

        unixsocket = "unix:%s:mode=600" % sockname
        kncSite = KNCSite( restServer )

        # Not sure if we want to do this... if not, can just go back to
        # returning strports.service() for a single service.
        multiService = MultiService()
        multiService.addService(strports.service(unixsocket, kncSite))
        multiService.addService(strports.service(
            config.get("broker", "openport"), openSite))
        return multiService

serviceMaker = AQDMaker()
