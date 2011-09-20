#!/usr/bin/env python

"""
  Authorize Security groups in AWS
"""

### include this directory in the search path
import os, sys
sys.path.insert( 0, os.path.dirname(os.path.realpath(__file__)) )

import optparse, re, boto, boto.ec2, logging

from pprint                     import PrettyPrinter
from security_groups_config     import KSG_CONFIG, AWS_ACCOUNT_ID, MASTER_REGION

### Pretty printer for debugging purposes
PP = PrettyPrinter( indent = 4)

#print "%s %s %s" % ( proto, target_sg, rule_map )
def authorize_ips( ec2, config, filter=None, regions=boto.ec2.regions() ): 

  fdict = {}
  if filter is not None:
    fdict['group-name'] = filter
  
  for region in regions:
    logging.info( "Processing region %s" % (region.name) )

    #if region.name != MASTER_REGION:
    #    continue


    con    = region.connect()    
    all_sg = con.get_all_security_groups( filters=fdict )
      
    ### tcp => { ... }  
    for proto, sg_map in config.iteritems():
  
      logging.debug( "Processing protocol: %s" % (proto) )
  
      ### krux-foo => { 1.2.3.4 => 42 }
      for target_sg_list, rule_map in sg_map.iteritems():
     
        logging.debug( "Target security group(s): %s" % (target_sg_list) )
      
        ### The target list is either *, a string, or a tuple
        ### in case of * we expand it to all_sg, otherwise we
        ### can just iterate
        if target_sg_list == "*":
  
          ### these are already sg objects
          for target_sg_obj in all_sg:
            authorize_rule_map( ec2=con, proto=proto, rule_map=rule_map, 
                                sg=target_sg_obj.name, all_sg=all_sg )
  
        ### if it's a string, using an iterator will return 1 char of the
        ### string in a loop. So check for it explicitly
        elif type(target_sg_list) is str:
          authorize_rule_map( ec2=con, proto=proto, rule_map=rule_map, 
                              sg=target_sg_list, all_sg=all_sg )
         
        else:
          ### these are names
          for target_sg in target_sg_list:
            authorize_rule_map( ec2=con, proto=proto, rule_map=rule_map, 
                                sg=target_sg, all_sg=all_sg )


def authorize_rule_map( ec2, proto, sg, rule_map, all_sg ):

  ### we only authorize krux labeled security groups
  #if not re.match( "krux|default|ElasticMapReduce", sg ):
  #  logging.warn( "  SG %s is not a krux group, skipping" % sg )
  #  return None 

  for src_sg_list, port_list in rule_map.iteritems():

    #logging.info( "  Source security group(s): %s" % ( " ".join(src_sg_list) ) )
 
    ### The target list is either *, a string, or a tuple
    ### in case of * we expand it to all_sg, otherwise we
    ### can just iterate
    if src_sg_list == "*":

      ### these are already sg objects
      for src_sg_obj in all_sg:
        authorize_ports( ec2=ec2, proto=proto, ports=port_list,
                         sg=sg, src=src_sg_obj.name, all_sg=all_sg )

    ### if it's a string, using an iterator will return 1 char of the
    ### string in a loop. So check for it explicitly
    elif type(src_sg_list) is str:
      authorize_ports( ec2=ec2, proto=proto, ports=port_list,
                       sg=sg, src=src_sg_list, all_sg=all_sg )

    else:
      ### these are names
      for src_sg in src_sg_list:
        authorize_ports( ec2=ec2, proto=proto, ports=port_list,
                         sg=sg, src=src_sg, all_sg=all_sg )
  
  
def authorize_ports( ec2, proto, ports, sg, src, all_sg ):

  ### we expect a list of ports. single entry is single
  ### port. if it's a tuple, it's a range. if it's a *
  ### it's all
  for r in ports:
    range = ( None, None )
      
    if r == "*":
      range = ( 1, 65535 )
    elif type( r ) is tuple:
      range = r
    else:
      range = (r, r)

    ### what are we authorizing?
    logging.info( "  Authorizing to %s:%s: %s:%s %s-%s" %
                  ( ec2.region.name, sg, proto, src, range[0], range[1] ) )

    ### the target is either a security group or an ip
    if re.search( "^[.\d/]+$", src ): 

      ### if it's an ip, make sure it's in slash notation    
      if not re.search( "/", src ):
        src = "%s/32" % ( src )

      try:
        rv = ec2.authorize_security_group( sg, 
                                      ip_protocol = proto,
                                      from_port   = range[0],
                                      to_port     = range[1],
                                      cidr_ip     = src )
        if not rv:
          logging.error( "  Failed to authorize %s -> %s" % ( src, sg ) ) 
        
          #pass

      except boto.exception.EC2ResponseError as (errstr):  
        ### don't care about InvalidPermission.Duplicate errors
        if not re.search( "InvalidPermission.Duplicate", errstr.body ):
          logging.error( "  Failed: %s" % errstr )

    ### we are authorizing a security group, so just use name 
    ### and and owner ID:
    else:

      ### we only authorize krux labeled security groups
      #if not re.match( "krux|default|ElasticMapReduc", src ):
      #  logging.warn( "  SG %s is not a krux group, skipping" % src )
      #  return None 

      try:
        rv = ec2.authorize_security_group( sg, 
            src_security_group_name     = src,
            ip_protocol                 = proto,
            from_port                   = range[0],
            to_port                     = range[1],
            src_security_group_owner_id = AWS_ACCOUNT_ID )

        if not rv:
          logging.error( "  Failed to authorize %s -> %s" % ( src, sg ) ) 
    
      except boto.exception.EC2ResponseError as (errstr):
        ### don't care about InvalidPermission.Duplicate errors
        if not re.search( "InvalidPermission.Duplicate", errstr.body ):
          logging.error( "  Failed: %s" % errstr )

def sync_groups( ec2, master_region=MASTER_REGION, regions=boto.ec2.regions() ):
    mr_con = ec2.get_all_regions( filters = {"region-name": master_region} )[0].connect()
    groups = mr_con.get_all_security_groups()
    cons   = map( lambda r: r.connect(), regions )

    ### take a look at all regions, one by one    
    for region in cons:
        my_name     = region.region.name
        my_groups   = region.get_all_security_groups()
        my_lookup   = dict(map( lambda k: (k.name,k), my_groups ))

        ### now copy everything from the master region to the target
        logging.info( "Syncing security groups from %s to %s" % (master_region, my_name) )

        ### don't try to copy from the master region to the master region
        if my_name == master_region:
            logging.warn( "  Target region same as source region (%s) - skipping" %
                          (master_region) )
            continue

        ### make sure this region has all the groups the master region has too
        for group in groups:

            ### now let's see if this group already exists. If it does,
            ### boto would throw an error trying to set it up, so skip it
            if group.name in my_lookup:
                logging.info("  Group %s already exists in %s" % (group.name, my_name) )
                continue

            ### Can't copy ElasticMapReduce-master and friends and 
            ### won't copy non-krux labeled groups
            #if not re.match( "krux", group.name ):
            #    logging.warn("  Group %s is not a krux group, skipping" % group.name )
            #    continue

            ### group doesn't exist yet, so create it
            logging.info("  Creating group %s in %s" % (group.name, my_name) )    
            region.create_security_group( group.name, group.description )



if __name__ == '__main__':
  parser = optparse.OptionParser( usage = __doc__ )
  parser.add_option("-d", "--debug", dest="debug", action="store_true",
                    help="Turn on debugging output", default=False)
  parser.add_option("-f", "--filter", dest="filter", action="store",
                    help="Only operate on groups matching this filter", default=None)
  parser.add_option("-I", "--no-icmp", dest="icmp", action="store_false",
                    help="Don't process ICMP directives", default=True)
  parser.add_option("-U", "--no-update", dest="update", action="store_false",
                    help="Don't update security group rules", default=True)
  parser.add_option("-r", "--master-region", dest="region", action="store",
                    help="Master regions (for copying purposes)", default=MASTER_REGION)
  parser.add_option("-S", "--no-sync-groups", dest="sync", action="store_false",
                    help="Do not sync security groups from master region to other regions", default=True)
 
  (options, args) = parser.parse_args()

  ### connect to ec2, set the log level
  ec2       = boto.connect_ec2()

  ### boto throws exceptions whenever you do an action again:
  
  ### here's how to turn that off:
  ### http://stackoverflow.com/questions/1661275/disable-boto-logging-without-modifying-the-boto-files
  log_level = None
  if options.debug:
    log_level = logging.DEBUG  
  else:
    log_level = logging.INFO
    logging.getLogger('boto').setLevel(logging.CRITICAL)

  logging.basicConfig( level = log_level )

  ### should we skip ICMP?
  if options.icmp is False:  
    del KSG_CONFIG['icmp']

  ### make sure all regions have the groups as defined in the masetr region
  if options.sync is True:
    sync_groups( ec2, master_region = options.region )    

  ### update security groups?
  if options.update is True:
    authorize_ips( ec2 = ec2, config = KSG_CONFIG, filter = options.filter )
