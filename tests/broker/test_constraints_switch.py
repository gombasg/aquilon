#!/usr/bin/env python2.6
# -*- cpy-indent-level: 4; indent-tabs-mode: nil -*-
# ex: set expandtab softtabstop=4 shiftwidth=4:
#
# Copyright (C) 2008,2009,2010,2012,2013  Contributor
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
"""Module for testing constraints in commands involving switches."""

import unittest

if __name__ == "__main__":
    import utils
    utils.import_depends()

from brokertest import TestBrokerCommand


class TestSwitchConstraints(TestBrokerCommand):

    def testdelmachineastor_switch(self):
        # Deprecated usage.
        command = "del switch --switch ut3c5n10"
        self.badrequesttest(command.split(" "))

    def testverifydelmachineastor_switchfailed(self):
        command = "show machine --machine ut3c5n10"
        out = self.commandtest(command.split(" "))
        self.matchoutput(out, "Blade: ut3c5n10", command)

    # This test doesn't make sense right now.
    #def testdeltor_switchasmachine(self):
    #    command = "del machine --machine ut3gd1r01.aqd-unittest.ms.com"
    #    self.badrequesttest(command.split(" "))

    def testverifydeltor_switchasmachinefailed(self):
        # Deprecated usage.
        command = "show switch --switch ut3gd1r01.aqd-unittest.ms.com"
        out = self.commandtest(command.split(" "))
        self.matchoutput(out, "Switch: ut3gd1r01", command)

    # Testing that del switch does not delete a blade....
    def testrejectut3c1n3(self):
        # Deprecated usage.
        self.badrequesttest(["del", "switch", "--switch", "ut3c1n3"])

    def testverifyrejectut3c1n3(self):
        command = "show machine --machine ut3c1n3"
        out = self.commandtest(command.split(" "))
        self.matchoutput(out, "Blade: ut3c1n3", command)

    def testdelprimaryinterface(self):
        command = ["del", "interface", "--interface", "xge49",
                   "--switch", "ut3gd1r04.aqd-unittest.ms.com"]
        out = self.badrequesttest(command)
        self.matchoutput(out, "holds the primary address", command)

    def testprimaryalias(self):
        command = ["add", "switch", "--switch", "alias2host.aqd-unittest.ms.com",
                   "--type", "misc", "--rack", "ut3", "--model", "uttorswitch",
                   "--ip", self.net.unknown[0].usable[-1]]
        out = self.badrequesttest(command)
        self.matchoutput(out, "Alias alias2host.aqd-unittest.ms.com cannot be "
                         "used for address assignment.", command)

    def testprimarybadip(self):
        good_ip = self.net.unknown[0].usable[13]
        bad_ip = self.net.unknown[0].usable[14]
        command = ["add", "switch", "--switch", "arecord13.aqd-unittest.ms.com",
                   "--type", "misc", "--rack", "ut3", "--model", "uttorswitch",
                   "--ip", bad_ip]
        out = self.badrequesttest(command)
        self.matchoutput(out,
                         "IP address %s is already in use by DNS record "
                         "arecord14.aqd-unittest.ms.com." % bad_ip,
                         command)


if __name__ == '__main__':
    suite = unittest.TestLoader().loadTestsFromTestCase(TestSwitchConstraints)
    unittest.TextTestRunner(verbosity=2).run(suite)
