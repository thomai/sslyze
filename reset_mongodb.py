#!/usr/bin/env python

from pymongo import Connection

c = Connection()
c.drop_database('sslyze')
