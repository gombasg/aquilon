#!/ms/dist/python/PROJ/core/2.5.0/bin/python
# ex: set expandtab softtabstop=4 shiftwidth=4: -*- cpy-indent-level: 4; indent-tabs-mode: nil -*-
# $Header$
# $Change$
# $DateTime$
# $Author$
# Copyright (C) 2008 Morgan Stanley
#
# This module is part of Aquilon
""" The tables/objects/mappings related to configuration in aquilon """

import datetime

import sys
sys.path.append('../..')

from db import *
from aquilon import const

from sqlalchemy import Table, Integer, Sequence, String, ForeignKey
from sqlalchemy.orm import mapper, relation, deferred

import os
osuser = os.environ.get('USER')
qdir = os.path.join( '/var/tmp', osuser, 'quattor/' )
const.cfg_base=os.path.join('/var/tmp', osuser, 'quattor/')

def splitall(path):
    """
        Split a path into all of its parts.
    """
    allparts = []
    while 1:
        parts = os.path.split(path)
        if parts[0] == path:
            allparts.insert(0, parts[0])
            break
        elif parts[1] == path:
            allparts.insert(0, parts[1])
            break
        else:
            path = parts[0]
            allparts.insert(0, parts[1])
    return allparts

cfg_tld = mk_type_table('cfg_tld',meta)
cfg_tld.create(checkfirst=True)

class CfgTLD(aqdbType):
    """ Configuration Top Level Directory or 'cfg_tld' are really the high level
        namespace categories, or the directories in /var/quattor/template-king
            base      (only one for now)
            os        (major types (linux,solaris) prefabricated)
            hardware  entered by model (vendors + types prefabricated)
            services
            feature  also need groups
            final     (only one for now)
            personality is really just app (or service if its consumable too)
    """
    pass
mapper(CfgTLD, cfg_tld, properties={
    'creation_date' : deferred(cfg_tld.c.creation_date),
    'comments'      : deferred(cfg_tld.c.comments)})

cfg_path = Table('cfg_path',meta,
    Column('id', Integer, Sequence('cfg_path_id_seq'), primary_key=True),
    Column('cfg_tld_id', Integer, ForeignKey('cfg_tld.id'), nullable=False),
    Column('relative_path', String(255), index=True, nullable=False),
    Column('creation_date', DateTime, default=datetime.datetime.now),
    Column('last_used', DateTime, default=datetime.datetime.now),
    Column('comments',String(255),nullable=True),
    UniqueConstraint('cfg_tld_id','relative_path'))
#TODO: unique tld/relative_path
cfg_path.create(checkfirst=True)

class CfgPath(aqdbBase):
    """ Config path is a path which must fit into one of the predefined
        categories laid out in cfg_tld. Those higher level constructs need
        to be at the top of the path.(hardware, service, etc.)

        The individual config paths are created against this base class.
    """
    @optional_comments
    def __init__(self, tld, pth):
        if isinstance(tld, CfgTLD):
            self.tld = tld
        else:
            raise ArgumentError("First argument must be a CfgTLD")

        if isinstance(pth,str):
            pth = pth.lstrip('/').lower()
            self.relative_path = '/'.join(splitall(pth)[1:])
        else:
            raise TypeError('path must be a string')
            return
    def __str__(self):
        return '%s/%s'%(self.tld,self.relative_path)
    def __repr__(self):
        return '%s/%s'%(self.tld,self.relative_path)

mapper(CfgPath,cfg_path,properties={
    'tld': relation(CfgTLD,remote_side=cfg_tld.c.id,lazy=False),
    'creation_date':deferred(cfg_path.c.creation_date),
    'comments':deferred(cfg_path.c.comments)})


archetype = Table('archetype', meta,
    Column('id', Integer, Sequence('archetype_id_seq'), primary_key=True),
    Column('name', String(32), unique=True, nullable=True, index=True),
    Column('creation_date', DateTime, default=datetime.datetime.now),
    Column('comments', String(255), nullable=True))
archetype.create(checkfirst=True)

class Archetype(aqdbBase):
    """Describes high level template requirements for building hosts """
    @optional_comments
    def __init__(self,name,**kw):
        if isinstance(name,str):
            self.name=name.strip().lower()

mapper(Archetype,archetype, properties={
    'creation_date' : deferred(archetype.c.creation_date),
    'comments': deferred(archetype.c.comments)
})

#######POPULATION FUNCTIONS########
def populate_tld():
    if empty(cfg_tld):
        import os
        tlds=[]
        for i in os.listdir(const.cfg_base):
            if os.path.isdir(os.path.abspath(
                os.path.join(const.cfg_base,i ))) :
                    tlds.append(i)

        fill_type_table(cfg_tld, tlds)

def create_paths():
    s = Session()
    created=[]
    if empty(cfg_path):
        for root,dirs,files in os.walk(const.cfg_base):
            for d in dirs:
                c=os.path.join(root,d)
                if not d in created:
                    (a,b,c)=c.partition('quattor/')
                    tld=s.query(CfgTLD).filter_by(type=splitall(c)[0]).one()
                if c.find('/') >= 0:
                    try:
                        f=CfgPath(tld, c)
                        s.save(f)
                        created.append(c)
                    except Exception,e:
                        print e
                        s.rollback()
                        continue
        s.commit()
        print 'created configuration paths'

def create_aquilon_archetype():
    s = Session()
    if empty(archetype):
        print 'CREATING AQUILON'
        a=Archetype('aquilon')
        s.save(a)
        s.commit()
        print 'created aquilon archetype'
    s.close()

def get_quattor_src():
    """ ugly ugly way to initialize a quattor repo for import"""

    import os
    import exceptions
    if os.path.exists(const.cfg_base):
        return

    remote_dir = 'blackcomb:/var/tmp/daqscott/quattor/*'
    try:
        os.makedirs(const.cfg_base)
    except exceptions.OSError, e:
        pass
    print 'run "scp -r %s %s in a seperate window."'%(remote_dir,const.cfg_base)
    raw_input("When you've completed this, press any key")



if __name__ == '__main__':
    get_quattor_src()
    populate_tld()
    create_paths()
    create_aquilon_archetype()

    s=Session()

    a=s.query(CfgTLD).first()
    b=s.query(CfgPath).first()
    c=s.query(Archetype).first()

    assert(a)
    assert(b)
    assert(c)

""" Config Source Type are labels for the 'type' attribute in the
    config_source table, supplied to satisfy 2NF. Currently we support
    2 types of configuration, aqdb, and quattor. Later, we'll be supporting
    a new type, 'Cola'
"""
"""
###We're not using it yet, and it hangs out like a sore thumb in the schema.

cfg_source_type = mk_type_table('cfg_source_type',meta)
meta.create_all()


class CfgSourceType(aqdbType):
    "" Config Source Type are labels for the 'type' attribute in the
        config_source table, supplied to satisfy 2NF. Currently we support
        2 types of configuration, aqdb, and quattor. Later, we'll be supporting
        a new type, 'Cola'
    ""
mapper(CfgSourceType, cfg_source_type, properties={
    'creation_date' : deferred(cfg_source_type.c.creation_date)})


def populate_cst():
    if empty(cfg_source_type):
        fill_type_table(cfg_source_type,['quattor','aqdb'])
"""
