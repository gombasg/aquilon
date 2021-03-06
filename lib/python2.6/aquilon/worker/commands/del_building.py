# -*- cpy-indent-level: 4; indent-tabs-mode: nil -*-
# ex: set expandtab softtabstop=4 shiftwidth=4:
#
# Copyright (C) 2008,2009,2010,2011,2012,2013  Contributor
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Contains the logic for `aq del building`."""


from aquilon.worker.processes import DSDBRunner
from aquilon.worker.broker import BrokerCommand  # pylint: disable=W0611
from aquilon.worker.commands.del_location import CommandDelLocation
from aquilon.worker.dbwrappers.location import get_location


class CommandDelBuilding(CommandDelLocation):

    required_parameters = ["building"]

    def render(self, session, logger, building, **arguments):

        dbbuilding = get_location(session, building=building)

        city = dbbuilding.city
        address = dbbuilding.address
        campus = dbbuilding.campus

        result = CommandDelLocation.render(self, session=session, name=building,
                                           type='building', **arguments)
        session.flush()

        dsdb_runner = DSDBRunner(logger=logger)

        if campus:
            dsdb_runner.del_campus_building(campus.name, building)
        dsdb_runner.del_building(building, city.name, address)
        dsdb_runner.commit_or_rollback()

        return result
