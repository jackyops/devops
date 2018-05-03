#!/usr/bin/env python

import datetime
import os
import re

import yaml

PROJECT_ROOT = os.path.realpath(os.path.dirname(__file__))
os.environ["DJANGO_SETTINGS_MODULE"] = 'devops.settings'

import django
import time
django.setup()



import logging
logger = logging.getLogger("django")
