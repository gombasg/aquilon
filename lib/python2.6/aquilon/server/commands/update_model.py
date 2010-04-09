# ex: set expandtab softtabstop=4 shiftwidth=4: -*- cpy-indent-level: 4; indent-tabs-mode: nil -*-
#
# Copyright (C) 2010  Contributor
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
"""Contains the logic for `aq update model`."""


from sqlalchemy.orm.session import object_session

from aquilon.exceptions_ import ArgumentError, UnimplementedError
from aquilon.server.broker import BrokerCommand, force_int
from aquilon.aqdb.model import Vendor, Model, Cpu, MachineSpecs, Machine, Disk
from aquilon.server.dbwrappers.cpu import get_unique_cpu
from aquilon.server.templates.base import PlenaryCollection
from aquilon.server.templates.machine import PlenaryMachineInfo


class CommandUpdateModel(BrokerCommand):

    required_parameters = ["name", "vendor"]

    # Quick hash of the arguments this method takes to the corresponding
    # aqdb label.
    argument_lookup = {'cpuname':'name', 'cpuvendor':'vendor',
                       'cpuspeed':'speed', 'cpunum':'cpu_quantity',
                       'mem':'memory', 'disktype':'disk_type',
                       'diskcontroller': 'controller_type',
                       'disksize': 'disk_capacity', 'nics':'nic_count'}

    def render(self, session, logger, name, vendor, comments, leave_existing,
               **arguments):
        for (arg, value) in arguments.items():
            # Cleaning the strings isn't strictly necessary but allows
            # for simple equality checks below.
            if arg in ['machine_type', 'cpuname', 'cpuvendor', 'disktype',
                       'diskcontroller']:
                if value is not None:
                    arguments[arg] = value.lower().strip()
            elif arg in ['cpuspeed', 'cpunum', 'mem', 'disksize', 'nics']:
                if value is not None:
                    arguments[arg] = force_int(arg, value)

        dbvendor = Vendor.get_unique(session, vendor, compel=True)
        dbmodel = Model.get_unique(session, name=name, vendor=dbvendor,
                                   compel=True)
                
        # For now, can't update machine_type.  There are too many spots
        # that special case things like aurora_node or virtual_machine to
        # know that the transistion is safe.  If there is enough need we
        # can always add those transitions later.
        if arguments['machine_type'] is not None:
            raise UnimplementedError("Cannot (yet) change a model's "
                                     "machine_type.")

        if comments:
            dbmodel.comments = comments
            # The comments also do not affect the templates.

        cpu_args = ['cpuname', 'cpuvendor', 'cpuspeed']
        cpu_info = dict([(self.argument_lookup[arg], arguments[arg])
                         for arg in cpu_args])
        cpu_values = [v for v in cpu_info.values() if v is not None]
        spec_args = ['cpunum', 'mem', 'disktype', 'diskcontroller',
                     'disksize', 'nics']
        specs = dict([(self.argument_lookup[arg], arguments[arg])
                      for arg in spec_args])
        spec_values = [v for v in specs.values() if v is not None]

        if not dbmodel.machine_specs:
            if cpu_values or spec_values:
                if not cpu_values or len(spec_values) < len(spec_args):
                    raise ArgumentError("Missing required parameters to store "
                                        "machine specs for the model.  Please "
                                        "give all CPU, disk, RAM, and NIC "
                                        "count information.")
                dbcpu = get_unique_cpu(session, **cpu_info)
                dbmachine_specs = MachineSpecs(model=dbmodel, cpu=dbcpu,
                                               **specs)
                session.add(dbmachine_specs)
            # Without previously existing specs, no way to know if
            # a machine had "old" defaults.
            return

        # Must have dbmodel.machine_specs after this point.
        dbmachines = set()
        fix_existing = not leave_existing

        if cpu_values:
            dbcpu = get_unique_cpu(session, **cpu_info)
            self.update_machine_specs(model=dbmodel, dbmachines=dbmachines,
                                      attr='cpu', value=dbcpu,
                                      fix_existing=fix_existing)

        for arg in ['mem', 'cpunum']:
            if arguments[arg] is not None:
                self.update_machine_specs(model=dbmodel, dbmachines=dbmachines,
                                          attr=self.argument_lookup[arg],
                                          value=arguments[arg],
                                          fix_existing=fix_existing)

        if arguments['disktype']:
            if fix_existing:
                raise ArgumentError("Please specify --leave_existing to "
                                    "change the model disktype.  This cannot "
                                    "be converted automatically.")
            dbmodel.machine_specs.disk_type = arguments['disktype']

        for arg in ['diskcontroller', 'disksize']:
            if arguments[arg]:
                self.update_disk_specs(model=dbmodel, dbmachines=dbmachines,
                                       attr=self.argument_lookup[arg],
                                       value=arguments[arg],
                                       fix_existing=fix_existing)

        if arguments['nics'] is not None:
            dbmodel.machine_specs.nic_count = arguments['nics']

        session.flush()

        plenaries = PlenaryCollection(logger=logger)
        for dbmachine in dbmachines:
            plenaries.append(PlenaryMachineInfo(dbmachine, logger=logger))
        plenaries.write()

        return

    def update_machine_specs(self, model, dbmachines,
                             attr=None, value=None, fix_existing=False):
        session = object_session(model)
        if fix_existing:
            oldattr = getattr(model.machine_specs, attr)
            filters = {'model':model, attr:oldattr}
            q = session.query(Machine).filter_by(**filters)
            for dbmachine in q.all():
                setattr(dbmachine, attr, value)
                dbmachines.add(dbmachine)

        setattr(model.machine_specs, attr, value)

    def update_disk_specs(self, model, dbmachines,
                          attr=None, value=None, fix_existing=False):
        session = object_session(model)
        if fix_existing:
            oldattr = getattr(model.machine_specs, attr)
            # disk_capacity => capacity
            disk_attr = attr.replace('disk_', '')
            filters = {disk_attr:oldattr}
            q = session.query(Disk)
            q = q.filter_by(**filters)
            q = q.join('machine')
            q = q.filter_by(model=model)
            for dbdisk in q.all():
                setattr(dbdisk, disk_attr, value)
                dbmachines.add(dbdisk.machine)

        setattr(model.machine_specs, attr, value)