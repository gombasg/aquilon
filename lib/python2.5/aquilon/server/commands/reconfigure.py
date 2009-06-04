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
"""Contains a wrapper for `aq reconfigure`."""


from aquilon.server.broker import BrokerCommand
from aquilon.server.commands.make import CommandMake
from aquilon.server.dbwrappers.archetype import get_archetype
from aquilon.server.dbwrappers.host import hostname_to_host
from aquilon.server.dbwrappers.status import get_status
from aquilon.server.dbwrappers.personality import get_personality
from aquilon.aqdb.model import BuildItem
from aquilon.exceptions_ import ArgumentError


class CommandReconfigure(CommandMake):
    """The make command mostly contains the logic required."""

    required_parameters = ["hostname"]

    def render(self, session, hostname, os, archetype, personality,
               buildstatus, **arguments):
        """There is some duplication here with make.

        It seemed to be the cleanest way to allow hosts with non-compileable
        archetypes to use reconfigure for buildstatus and personality.

        """
        dbhost = hostname_to_host(session, hostname)

        dbarchetype = dbhost.archetype
        if archetype and archetype != dbhost.archetype.name:
            if not personality:
                raise ArgumentError("Changing archetype also requires "
                                    "specifying personality.")
            dbarchetype = get_archetype(session, archetype)
            # TODO: Once OS is a first class object this block needs
            # to check that either OS is also being reset or that the
            # OS is valid for the new archetype.

        if dbarchetype.is_compileable:
            # Check if make_aquilon has run.  (This is a lame check -
            # should really check to see if OS is set.)
            # If the error is not raised, we fall through to the end
            # of the method where MakeAquilon is called.
            builditem = session.query(BuildItem).filter_by(host=dbhost).first()
            if not builditem:
                raise ArgumentError("host %s has not been built. "
                                    "Run 'make' first." % hostname)
        # The rest of these conditionals currently apply to all
        # non-aquilon hosts.
        elif os:
            raise ArgumentError("Can only set os for compileable archetypes "
                                "like aquilon.")
        elif buildstatus or personality:
            if buildstatus:
                dbstatus = get_status(session, buildstatus)
                dbhost.status = dbstatus
            if personality:
                dbpersonality = get_personality(session, dbarchetype.name,
                                                personality)
                dbhost.personality = dbpersonality
            session.add(dbhost)
            return
        else:
            raise ArgumentError("Nothing to do.")

        return CommandMake.render(self, session=session, hostname=hostname,
                                  os=os, archetype=archetype,
                                  personality=personality,
                                  buildstatus=buildstatus, **arguments)


