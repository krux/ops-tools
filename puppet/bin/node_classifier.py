#!/usr/bin/env python

import logging
import logging.handlers
import sys, os
import urllib
from optparse import OptionParser

handler = logging.handlers.SysLogHandler('/dev/log', 'daemon')
fmt     = logging.Formatter('%(filename)s[%(process)d]: %(levelname)s: %(message)s')
parser  = OptionParser()

handler.setFormatter(fmt)
logging.getLogger().addHandler(handler)

parser.add_option("-b", "--bucket", dest="bucket", help="S3 Bucket" )
parser.add_option("", "--log-level", dest="log_level", default="debug",
                  help="log level (as defined in python logging module)")
(options, args) = parser.parse_args()
logging.getLogger().setLevel(logging.getLevelName(options.log_level.upper()))

try:
    node_name = args[0]
except IndexError:
    logging.error("Need node")
    sys.exit(1)

if options.bucket is None:
    logging.error("Need S3 bucket")
    sys.exit(1)
    
s3_url = "https://%s.s3.amazonaws.com/%s" % (options.bucket, node_name)
logging.debug("Checking url %s" % (s3_url))

url    = urllib.urlopen(s3_url)
if url.code == 200:
    logging.info("Getting node configuration: %s" % (node_name))
    node_config = url.read()
    logging.debug("Node configuration (%s): %s" % (node_name, node_config))
    sys.stdout.write(node_config)
    sys.exit(0)
elif url.code == 404:
    logging.warning("Unkown node: %s" % (node_name))
    sys.exit(1)

else:
    logging.warning("Unkown url code for %s: %s" % (node_name, url.code))
    sys.exit(0)
