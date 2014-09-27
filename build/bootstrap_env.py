#!/usr/bin/env python
# -*- cpy-indent-level: 4; indent-tabs-mode: nil -*-
# ex: set expandtab softtabstop=4 shiftwidth=4:
#
# Copyright (C) 2011,2012,2013,2014  Contributor
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

from __future__ import print_function

import os
import virtualenv
import textwrap
import re

# Dependencies we won't install into the virtual environment, either because
# they are not needed, or because they depend on native code that Python can't
# build itself
blacklist = ["protobuf", "cx_Oracle"]


def gather_deps(dir):
    depfiles = []
    for (dirpath, dirnames, filenames) in os.walk(dir):
        if 'depends.py' in filenames:
            depfiles.append(os.path.join(dirpath, 'depends.py'))
    dependencies = {}
    dep_re = re.compile(r"^\s*ms.version.addpkg\(\s*'(.*?)'\s*,\s*'(.*?)(-ms\d+)?'")
    for depfile in depfiles:
        with open(depfile) as f:
            for line in f:
                m = dep_re.search(line)
                if m:
                    (package, version, _) = m.groups()
                    if package.startswith('ms.'):
                        continue
                    if package in ['setuptools']:
                        continue
                    dependencies[package] = version
    return dependencies


def bootstrap(dependencies, dir):
    extra = textwrap.dedent("""
        import os, subprocess
        from tempfile import mkdtemp
        def extend_parser(optparse_parser):
            pass
        def adjust_options(options, args):
            pass
        def after_install(options, home_dir):
            easy_install = join(home_dir, 'bin', 'easy_install')
    """)

    for package in sorted(dependencies.keys()):
        if package in blacklist:
            continue
        extra += """
    if subprocess.call([easy_install, '%(package)s==%(deps)s']) == 0:
        pass
    elif subprocess.call([easy_install, 'python-%(package)s==%(deps)s']) == 0:
        pass
    elif subprocess.call([easy_install, '%(package)s']) == 0:
        pass
    else:
        subprocess.call([easy_install, 'python-%(package)s'])
        """ % {'package': package, 'deps': dependencies[package]}

    extra += "\n    subprocess.call([easy_install, '.'], cwd='%s')\n" % (
        os.path.join(dir, 'bootstrap_ms'))
    print(virtualenv.create_bootstrap_script(extra))


if __name__ == '__main__':
    dir = os.path.dirname(os.path.realpath(__file__))
    libdir = os.path.join(dir, '..', 'lib')
    dependencies = gather_deps(libdir)
    print(bootstrap(dependencies, dir))
