#!/usr/bin/env kpython
"""
  %prog [--track] AMI-ID Puppet-Class [, Puppet-Class, ...]

See here for current Ubuntu 10.04 AMI numbers:

  http://uec-images.ubuntu.com/query/lucid/server/released.current.txt
  
Example:

  %prog -t m1.large -z us-east-1a -a 50 -H redis-dev001.krxd.net ami-2ec83147 s_redis
  
"""

### inspired by:
### http://ubuntumathiaz.wordpress.com/category/puppet/
### adapted from:
### http://bazaar.launchpad.net/~mathiaz/%2Bjunk/uec-ec2-puppet-config-tut2

import os
import sys

### this finds the boto path - add at the beginning or we find the system one
### use 'realpath' so we can use a symlink to this file in /usr/local/bin
### XXX now installed system wide
#sys.path.insert( 0, os.path.join( os.path.dirname(os.path.realpath(__file__)), "..", "lib", "boto-2.0b3" ) )

import logging
import os.path
import uuid
import boto
import yaml
import time
import pprint
import re

from optparse import OptionParser

MASTER_REGION = 'us-east-1'
MY_NAME       = os.path.basename(__file__)
MY_PATH       = os.path.dirname(os.path.realpath(__file__))
PP            = pprint.PrettyPrinter(indent=4)

parser = OptionParser(usage=__doc__)
parser.add_option("-c", "--config", dest="config",
                  help="Configuration filename",
                  default="%s/../../etc/user-data.yaml" % MY_PATH )
parser.add_option("", "--no-instance", dest="start_instance",
                  action="store_false", default=True,
                  help="Don't start any instance")
parser.add_option("-d", "--debug", dest="debug", action="store_true",
                  help="Turn on debugging output", default=False)
# parser.add_option("", "--track", dest="track",
#                   action="store_true", default=True,
#                   help="Track instance until it is running")
parser.add_option("-t", "--type", dest="type", default='m1.small',
                  help="Instance type (e.g. m1.small)")
parser.add_option("-s", "--security", dest="security", default=None,
                  help="Security group")
parser.add_option("-H", "--host", dest="host", default=None,
                  help="Client hostname")
parser.add_option("-F", "--force", dest="force", default=False, action="store_true",
                  help="Force instance creation regardless")
parser.add_option("-z", "--zone", dest="zone", default="%sa" % (MASTER_REGION),
                  help="Availability zone to launch into, eg: 'us-east-1d'")
parser.add_option("-a", "--attach", dest="attach", default=None,
                  help="EBS volume to attach, eg: 'vol-0532c86d' or size of volume to be created on demand, eg '50' for 50Gb")
parser.add_option( "", "--attach-device", dest="attach_device", default='/dev/sdf',
                  help="Device to attach the EBS volume to, eg: '/dev/sdk'" )
parser.add_option( "", "--environment", dest="environment", default='production',
                  help="Puppet environment to run in; production, staging, development" )
parser.add_option("-S", "--slave-of", dest="slave_of", default=None,
                  help="Slave of which master node?")
### uncomment to have ssh keys be provision from the file system, rather than the
### yaml configuration file
#parser.add_option("-p", "--pubkey", dest="pubkey", action="store",
#                  help="Path to SSH Public key to install for system user on instance",
#                  default='~/.ssh/id_rsa.pub')

(options, args) = parser.parse_args()

### turn on debugging?
if options.debug:
    logging.basicConfig(level=logging.DEBUG)
else:    
    logging.basicConfig(level=logging.INFO)

### load configuration
conf = yaml.load(open(options.config))
logging.debug("Configuration: %s" % (conf))

### check for ami
try:
    ami_id = args[0]
except IndexError:
    logging.error("Need AMI ID")
    sys.exit(1)
    
### check for host
if options.host == None:
    logging.error("Need a hostname")
    sys.exit(1)
    
### check for classes
### XXX should validate that these classes actually exist
try:
    classes = args[1:]
    assert len(classes)
except (IndexError, AssertionError):
    logging.error("Need at least one class")
    sys.exit(1)   

### the certname has to be known ahead of time, so insert it
### here rather than letting it depend on the instance id:
### example: dev001.example.com.0cf9e55e-919b-434b-ba60-d49955c2174c
### the UUID is needed to be appended so the certname is unique, so when
### we replace foo.krxd.net puppet won't think we already have a valid 
### cert for it, not create a new one but won't verify it on the new machine.
conf['puppet']['conf']['puppetd']['certname'] = certname = options.host + '.' + str( uuid.uuid4() )

### set the environment we were passed, as it defaults to 'production' if
### nothing is mentioned in the config file
conf['puppet']['conf']['puppetd']['environment'] = options.environment

### add the pubkey that we want the instance to use. The file has ssh-rsa fadfad==
### and we append the name of the application for identification purposes.
### XXX The value MUST BE A LIST, not a string or tuple for cloud-init to use it.
### What fun it was tracking THAT down.
### uncomment to have ssh keys be provision from the file system, rather than the
### yaml configuration file
#ssh_key_fh                  = open( options.pubkey, 'r' )
#conf['ssh_authorized_keys'] = [ "ssh-rsa %s %s" % ( ssh_key_fh.read(), MY_NAME ) ]
#ssh_key_fh.close()

### set the runcmd options for setting the hostname:
if not 'runcmd' in conf:
    conf['runcmd'] = [ ]

### runcmd runs at the end, after everything else from cloud-config has run
### that means that it can take several minutes after boot up until this has 
### been executed!
conf['runcmd'].append( "sudo echo %s > /etc/hostname" % options.host )
conf['runcmd'].append( "sudo hostname %s" % options.host )

### set up the universe/multiverse repositories
#if not 'apt_sources' in conf:
#    conf['apt_sources'] = [ ]
#

#conf['apt_sources'].append( { "source": "deb http://%s.ec2.archive.ubuntu.com/ubuntu/ #lucid restricted multiverse" % (apt_zone) } )
 
 
### create s3 connection
s3_conn     = boto.connect_s3()
bucket      = s3_conn.create_bucket( conf['aws']['s3_instance_bucket'] )
bucket.set_acl('public-read')
k           = boto.s3.key.Key(bucket)
k.key       = certname

### do we already have a host name matching this requested host registered in S3?
### if so, we will not continue deployment unless you provide a switch
abort = 0
for key in bucket.get_all_keys( prefix=options.host ):
    logging.warning( "Already found host %s/%s (created %s)" % (bucket.name, key.key, key.last_modified) )
    abort = 1

### check if THIS key already exists, error if it does
if k.exists(): 
    logging.warning("Entry %s already exists in S3 -- delete it first", certname)
    abort = 1
    
### should we abort? 
if abort and not options.force:
    logging.error( "Aborting instance creation due to previous errors" )
    sys.exit(1)

### connect to ec2, fire up the instance
ec2_zone    = options.zone
ec2_region  = re.match( "^(.+)?\w", ec2_zone ).group(1)

### Apparently, this can not be done in one call =/
#ec2_conn    = boto.connect_ec2( ec2_region )
tmp         = boto.connect_ec2( )
ec2_conn    = tmp.get_all_regions( filters = {"region-name": ec2_region} )[0].connect()

ami         = ec2_conn.get_all_images( ami_id )[0]
nc_conf     = { 
    "classes":      classes, 
    "parameters":   { 
        "certname":             certname, 
        "zone":                 ec2_zone,
        "puppet_environment":   options.environment,
        "instance_type":        options.type,
    }, 
}

### if the node is configured to be a slave, set it here
if options.slave_of is not None:
    nc_conf["parameters"]["node_is_slave_of"] = options.slave_of


### figure out what security group to use
sec_groups  = ec2_conn.get_all_security_groups()
try_sec     = re.sub( '^s_', '', classes[0] ) # replace the leading 
                                              # s_ for classes

### this is a known security group
sec_group = None
if options.security == None:
    for obj in sec_groups:
        if obj.name == try_sec:
            sec_group = try_sec

    ### we didn't find the gropu
    if sec_group == None:
        sec_group = "default"
else:
    sec_group = options.security

### there is a WEIRD bug where the auth_key of 'ssh-rsa fadfad== my_name.py'
### gets translated to ssh-rsa fadfad==\n       my_name.py' . I can't figure
### out why, and it makes no sense, so I'm just fixing it back up with a regex.
user_data   = "#cloud-config\n%s" % (yaml.dump(conf))
user_data   = re.sub( "(==)\s*\n\s*" + "(" + MY_NAME + ")", r'\1 \2', user_data )
run_args    = { "instance_type"   : options.type,
                "user_data"       : user_data,
                "security_groups" : [sec_group],
              }

### specific zone?
if options.zone is not None:
    run_args["placement"] = ec2_zone

logging.debug("Instance start up arguments: %s" % (run_args))

if options.start_instance:
    logging.info("Starting instance of ami %s - this may take a while" % (ami))
    reservation = ami.run(**run_args)
    instance    = reservation.instances[0]
    
    i = 0

    while instance.state == 'pending':
        
        ### print appends blanks or newlines =/
        sys.stdout.write( '.' )
        ### have to manually flush for it to show up
        sys.stdout.flush()

        ### try again in a few seconds
        time.sleep( 2 )

        ### we will only try so often
        i += 1
        if i > 30:
            logging.critical( "\nInstance %s not yet started: %s" %
                (instance.public_dns_name, instance.state) )
            sys.exit( 1 )

        ### update the status
        instance.update()

    ### add the instance id and security group to the meta data
    nc_conf["parameters"]["instance_id"]    = instance.id
    nc_conf["parameters"]["security_group"] = sec_group

    ### tag it with the hostname - casing matters here!
    ### there's no way to find out what sec group an
    ### instance is in from the instance object. It
    ### should work according to the API docs, but 
    ### boto keeps returning an empty group object:
    ### http://xrl.us/ec2secgroup
    instance.add_tag("Name", options.host) 
    instance.add_tag("SecurityGroup", sec_group) 

    ### if we got here, the instance is running
    logging.info( "\nStarted instance %s (%s)" % 
        (instance.public_dns_name, instance.state) )

    if options.attach:
        ### you want us to create a volume
        if re.match( "^\d+$", options.attach ):
            volume = ec2_conn.create_volume( options.attach, ec2_zone )

        ### you want to attach one
        else:
            vols     = ec2_conn.get_all_volumes( volume_ids=[options.attach] )
            volume   = vols[0]

        ### tag the volume with the hostname it's being attached to
        volume.add_tag( "Name", options.host ) 

        logging.info( "\nAttaching volume %s to instance %s - this may take a while" % 
            (volume.id, instance.id) )

        volume.attach( instance.id, options.attach_device )
        
        ### add this to the node classifier configuration
        ### the stringification is necessary, or it will be u'vol-xxxx'
        nc_conf["parameters"]["volume"] = str(volume.id)

        i = 0
        while volume.attachment_state() != u'attached':
            ### print appends blanks or newlines =/
            sys.stdout.write( '.' )
            ### have to manually flush for it to show up
            sys.stdout.flush()
        
            ### try again in a few seconds
            time.sleep( 2 )
        
            ### we will only try so often - attaching takes a long time though
            ### so be patient...
            i += 1
            if i > 30:
                logging.critical( "\nVolume %s still not attached to %s: %s" %
                    (volume.id, instance.id, volume.attachment_state()) )
        
            ### update the status
            volume.update()

        ### if we got here, the instance is running
        logging.info( "\nAttached volume %s" % (volume.id) )

    logging.info( "\n\nAdd these DNS entries:\n" )            
    logging.info( "\t%s => %s.\n" % (options.host, instance.public_dns_name) )
    #logging.info( "\tint.%s => %s\n" % (options.host, instance.private_dns_name) )
        
else:
    logging.info( "Instance not started. Use this as your userdata:\n" )
    print "%s\n" % (user_data)

### create the conf entry in s3. The name of the bucket lives in the
### aws specific section of cloud-config, so fish it out
k.set_contents_from_string( nc_conf )

k.set_acl('public-read')
logging.info( "Wrote configuration to S3 key: %s" % (certname) )


