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
"""Contains the logic for `aq show network_environment`."""

from sqlalchemy.orm import joinedload, undefer

from aquilon.worker.broker import BrokerCommand  # pylint: disable=W0611
from aquilon.aqdb.model import NetworkEnvironment


class CommandShowNetworkEnvironmentNetworkEnvironment(BrokerCommand):

    required_parameters = ["network_environment"]

    def render(self, session, network_environment, **arguments):
        options = [undefer("comments"),
                   joinedload("dns_environment"),
                   undefer("dns_environment.comments")]
        dbnet_env = NetworkEnvironment.get_unique(session, network_environment,
                                                  compel=True,
                                                  query_options=options)

        return dbnet_env
