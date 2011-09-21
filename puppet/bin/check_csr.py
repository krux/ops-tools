#!/usr/bin/python

import logging
import logging.handlers
import re
import subprocess
import sys
import urllib
import yaml

from optparse import OptionParser

handler = logging.handlers.SysLogHandler('/dev/log', 'daemon')
fmt     = logging.Formatter('%(filename)s[%(process)d]: %(levelname)s: %(message)s')
parser  = OptionParser()
# dev001.example.com.0cf9e55e-919b-434b-ba60-d49955c2174c
UUID_RE = re.compile(r"[-\w]+\.[-\w]+.[-\w]+\.[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$") 

parser.add_option("", "--log-level", dest="log_level", default="info",
                  help="log level (as defined in python logging module)")
parser.add_option("-b", "--bucket", dest="bucket", help="S3 Bucket" )
                  
(options, args) = parser.parse_args()

handler.setFormatter(fmt)
logging.getLogger().addHandler(handler)
logging.getLogger().setLevel(logging.getLevelName(options.log_level.upper()))

if options.bucket is None:
    logging.error("Need S3 bucket")
    sys.exit(1)

try:
    csrs = subprocess.Popen(["puppet", "cert", "--list"], \
            stdout=subprocess.PIPE).communicate()[0]
except OSError, e:
    logging.error("Unable to run puppet cert --list: %s" % (e))
    sys.exit(1)

logging.debug("List of waiting csr: %s" % (csrs))
for certname in csrs.split("\n"):
    if certname == "":
        continue
    if not UUID_RE.match(certname):
        logging.warning("Non-standard csr: %s" % (certname))
        continue

    s3_url = "https://%s.s3.amazonaws.com/%s" % (options.bucket, certname)
    logging.debug("Checking url %s" % (s3_url))
    url    = urllib.urlopen( s3_url)

    if url.code == 200:
        logging.info("Signing request: %s" % (certname))
        try:
            subprocess.check_call(["puppet", "cert", "--sign", certname])
        except subprocess.CalledProcessError, e:
            logging.warning("Failed to sign csr (%s): %s" % (certname, e))

    elif url.code == 404:
        logging.warning("Unknown csr: %s" % (certname))

    else:
        logging.warning("Unkown return code for %s: %s" % (certname, url.code)) 
