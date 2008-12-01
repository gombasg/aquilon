""" Archetype specifies the metaclass of the build """

from aquilon.aqdb.table_types.name_table import make_name_class

Archetype = make_name_class('Archetype','archetype')
archetype = Archetype.__table__
archetype.primary_key.name = 'archetype_pk'

table = archetype

def populate(sess, *args, **kw):
    if len(sess.query(Archetype).all()) > 0:
        return

    for a_name in ['aquilon', 'windows', 'aurora']:
        a = Archetype(name=a_name)
        sess.add(a)
    sess.commit()

    a = sess.query(Archetype).first()
    assert(a)

# Copyright (C) 2008 Morgan Stanley
# This module is part of Aquilon

# ex: set expandtab softtabstop=4 shiftwidth=4: -*- cpy-indent-level: 4; indent-tabs-mode: nil -*-
