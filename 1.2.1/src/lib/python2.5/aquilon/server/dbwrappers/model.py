#!/ms/dist/python/PROJ/core/2.5.0/bin/python
# ex: set expandtab softtabstop=4 shiftwidth=4: -*- cpy-indent-level: 4; indent-tabs-mode: nil -*-
# $Header$
# $Change$
# $DateTime$
# $Author$
# Copyright (C) 2008 Morgan Stanley
#
# This module is part of Aquilon
"""Wrapper to make getting a model simpler."""


from sqlalchemy.exceptions import InvalidRequestError

from aquilon.exceptions_ import NotFoundException
from aquilon.aqdb.hardware import Model


def get_model(session, model):
    try:
        dbmodel = session.query(Model).filter_by(name=model).one()
    except InvalidRequestError, e:
        raise NotFoundException("Model %s not found: %s" % (model, e))
    return dbmodel


#if __name__=='__main__':