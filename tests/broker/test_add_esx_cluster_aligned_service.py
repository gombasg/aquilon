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
"""Module for testing the add esx cluster aligned service command."""

import os
import sys
import unittest

if __name__ == "__main__":
    BINDIR = os.path.dirname(os.path.realpath(sys.argv[0]))
    SRCDIR = os.path.join(BINDIR, "..", "..")
    sys.path.append(os.path.join(SRCDIR, "lib", "python2.5"))

from brokertest import TestBrokerCommand


class TestAddESXClusterAlignedService(TestBrokerCommand):

    def testaddesxmanagement(self):
        command = "add esx cluster aligned service --service esx_management"
        self.noouttest(command.split(" "))

    def testfailmissingservice(self):
        command = ["add_esx_cluster_aligned_service",
                   "--service=service-does-not-exist"]
        out = self.notfoundtest(command)
        self.matchoutput(out, "Service 'service-does-not-exist' not found",
                         command)

    def testverifyaddalignedservices(self):
        command = "show cluster_type --cluster_type esx"
        out = self.commandtest(command.split(" "))
        self.matchoutput(out, "Cluster Type: esx", command)
        self.matchoutput(out, "Aligned Service: esx_management", command)

    def testverifyshowclustertypeall(self):
        command = "show cluster_type --all"
        out = self.commandtest(command.split(" "))
        self.matchoutput(out, "Cluster Type: esx", command)
        self.matchoutput(out, "Aligned Service: esx_management", command)

    def testfailunknownclustertype(self):
        command = ["show_cluster_type",
                   "--cluster_type=cluster_type-does-not-exist"]
        out = self.notfoundtest(command)
        self.matchoutput(out,
                         "Cluster type 'cluster_type-does-not-exist' "
                         "not found.",
                         command)


if __name__=='__main__':
    suite = unittest.TestLoader().loadTestsFromTestCase(
        TestAddESXClusterAlignedService)
    unittest.TextTestRunner(verbosity=2).run(suite)
