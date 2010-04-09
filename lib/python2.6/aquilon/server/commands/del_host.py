# ex: set expandtab softtabstop=4 shiftwidth=4: -*- cpy-indent-level: 4; indent-tabs-mode: nil -*-
#
# Copyright (C) 2008,2009  Contributor
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
"""Contains the logic for `aq del host`."""


import os

from threading import Lock
from aquilon.exceptions_ import ArgumentError, ProcessException
from aquilon.server.broker import BrokerCommand
from aquilon.server.dbwrappers.host import (hostname_to_host,
                                            get_host_dependencies)
from aquilon.server.processes import (DSDBRunner, remove_file)
from aquilon.server.templates.index import build_index
from aquilon.server.templates.host import PlenaryHost
from aquilon.server.templates.service import PlenaryServiceInstanceServer
from aquilon.server.templates.base import (compileLock, compileRelease)

delhost_lock = Lock()


class CommandDelHost(BrokerCommand):

    required_parameters = ["hostname"]

    def render(self, session, logger, hostname, user, **arguments):
        # removing the plenary host requires a compile lock, however
        # we want to avoid deadlock by the fact that we're messing
        # with two locks here, so we want to be careful. We grab the
        # plenaryhost early on (in order to get the filenames filled
        # in from the db info before we delete it from the db. We then
        # hold onto those references until we've completed the db
        # cleanup and if all of that is successful, then we delete the
        # plenary file (which doesn't require re-evaluating any stale
        # db information) after we've released the delhost lock.
        delplenary = False

        logger.client_info("Acquiring lock to attempt to delete %s" % hostname)
        delhost_lock.acquire()
        bindings = [] # Any service bindings that we need to clean up afterwards
        try:
            logger.client_info("Acquired lock, attempting to delete %s" %
                               hostname)
            # Check dependencies, translate into user-friendly message
            dbhost = hostname_to_host(session, hostname)
            ph = PlenaryHost(dbhost, logger=logger)
            domain = dbhost.domain.name
            fqdn   = dbhost.fqdn
            deps = get_host_dependencies(session, dbhost)
            if (len(deps) != 0):
                deptext = "\n".join(["  %s"%d for d in deps])
                raise ArgumentError("cannot delete host '%s' due to the following dependencies:\n%s"%(hostname, deptext))

            archetype = dbhost.archetype.name
            dbmachine = dbhost.machine
            ip = dbhost.ip

            for binding in dbhost.templates:
                ### WARNING ###
                if (binding.service_instance):
                    bindings.append(binding.service_instance)
                logger.info("Before deleting host '%s', removing binding '%s'"
                            % (fqdn, binding.cfg_path))
                session.delete(binding)

            session.delete(dbhost)
            session.flush()
            delplenary = True

            if archetype != 'aurora' and ip is not None:
                try:
                    dsdb_runner = DSDBRunner(logger=logger)
                    dsdb_runner.delete_host_details(ip)
                except ProcessException, e:
                    raise ArgumentError("Could not remove host %s from dsdb: %s" %
                            (hostname, e))

            session.refresh(dbmachine)
        finally:
            logger.client_info("Released lock from attempt to delete %s" %
                               hostname)
            delhost_lock.release()

        # Only if we got here with no exceptions do we clean the template
        # Trying to clean up after any errors here is really difficult
        # since the changes to dsdb have already been made.
        if (delplenary):
            try:
                compileLock(logger=logger)
                ph.cleanup(domain, locked=True)
                # And we also want to remove the profile itself
                profiles = self.config.get("broker", "profilesdir")
                remove_file(os.path.join(profiles, fqdn+".xml"), logger=logger)
                # And the cached template created by ant
                remove_file(os.path.join(self.config.get("broker",
                                                         "quattordir"),
                                         "objects", fqdn + ".tpl"),
                            logger=logger)

                # Update any plenary client mappings
                for si in bindings:
                    logger.info("removing plenary from binding for %s" %
                                si.cfg_path)
                    plenary_info = PlenaryServiceInstanceServer(si.service, si,
                                                                logger=logger)
                    plenary_info.write(locked=True)

            finally:
                compileRelease(logger=logger)

            build_index(self.config, session, profiles, logger=logger)

        return