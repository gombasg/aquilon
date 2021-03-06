# -*- cpy-indent-level: 4; indent-tabs-mode: nil -*-
# ex: set expandtab softtabstop=4 shiftwidth=4:
#
# Copyright (C) 2009,2010,2011,2012,2013  Contributor
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

from aquilon.worker.broker import BrokerCommand  # pylint: disable=W0611
from aquilon.worker.commands.add_parameter import CommandAddParameter
from aquilon.worker.dbwrappers.parameter import set_parameter


class CommandUpdateParameter(CommandAddParameter):

    required_parameters = ['personality', 'path']

    def process_parameter(self, session, param_holder, feature, model, interface,
                          path, value, comments):

        dbparameter = set_parameter(session, param_holder, feature, model, interface,
                                    path, value, compel=True)
        if comments:
            dbparameter.comments = comments

        return dbparameter
