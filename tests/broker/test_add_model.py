#!/usr/bin/env python2.5
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
"""Module for testing the add model command."""

import os
import sys
import unittest

if __name__ == "__main__":
    BINDIR = os.path.dirname(os.path.realpath(sys.argv[0]))
    SRCDIR = os.path.join(BINDIR, "..", "..")
    sys.path.append(os.path.join(SRCDIR, "lib", "python2.5"))

from brokertest import TestBrokerCommand


class TestAddModel(TestBrokerCommand):

    def testadduttorswitch(self):
        command = "add model --name uttorswitch --vendor hp --type tor_switch --cputype xeon_2500 --cpunum 1 --mem 8192 --disktype scsi --disksize 36 --nics 4"
        self.noouttest(command.split(" "))

    def testverifyadduttorswitch(self):
        command = "show model --name uttorswitch"
        out = self.commandtest(command.split(" "))
        self.matchoutput(out, "Vendor: hp Model: uttorswitch", command)
        self.matchoutput(out, "Type: tor_switch", command)
        self.matchoutput(out, "MachineSpecs for hp uttorswitch", command)
        self.matchoutput(out, "Cpu: xeon_2500 x 1", command)
        self.matchoutput(out, "Memory: 8192 MB", command)
        self.matchoutput(out, "NIC count: 4", command)
        self.matchoutput(out, "Disk: sda 36 GB DiskType scsi", command)

    def testverifyshowtypetorswitch(self):
        command = "show model --type tor_switch"
        out = self.commandtest(command.split(" "))
        self.matchoutput(out, "Vendor: hp Model: uttorswitch", command)

    def testverifyshowtypeblade(self):
        command = "show model --type blade"
        out = self.commandtest(command.split(" "))
        self.matchclean(out, "Vendor: hp Model: uttorswitch", command)

    def testverifyshowvendorhp(self):
        command = "show model --vendor hp"
        out = self.commandtest(command.split(" "))
        self.matchoutput(out, "Vendor: hp Model: uttorswitch", command)

    def testverifyshowvendoribm(self):
        command = "show model --vendor ibm"
        out = self.commandtest(command.split(" "))
        self.matchclean(out, "Vendor: hp Model: uttorswitch", command)

    def testverifyshowall(self):
        command = "show model --all"
        out = self.commandtest(command.split(" "))
        self.matchoutput(out, "Vendor: hp Model: uttorswitch", command)

    def testaddutchassis(self):
        command = "add model --name utchassis --vendor aurora_vendor --type chassis"
        self.noouttest(command.split(" "))

    def testverifyaddutchassis(self):
        command = "show model --name utchassis"
        out = self.commandtest(command.split(" "))
        self.matchoutput(out, "Vendor: aurora_vendor Model: utchassis", command)
        self.matchoutput(out, "Type: chassis", command)

    def testaddutblade(self):
        command = "add model --name utblade --vendor aurora_vendor --type blade"
        self.noouttest(command.split(" "))

    def testverifyaddutblade(self):
        command = "show model --name utblade"
        out = self.commandtest(command.split(" "))
        self.matchoutput(out, "Vendor: aurora_vendor Model: utblade", command)
        self.matchoutput(out, "Type: blade", command)


if __name__=='__main__':
    suite = unittest.TestLoader().loadTestsFromTestCase(TestAddModel)
    unittest.TextTestRunner(verbosity=2).run(suite)
