#!/usr/bin/env python

# Simple [boto3](https://github.com/boto/boto3) based EC2 manipulation tool
#
# To start an instance, create a yaml file with the following format:
#
# frankfurt:
# - subnet-azb:
#   - type: t2.micro
#     image: image-tagname
#     name: myinstance
#     key: mykey
#     data: 10
#     ipaddr: 10.1.1.2
#     sg: [ssh-icmp-reply, http-https]
#
# where `data` is the size, in GB of an optional secondary block device
# hardcoded to be referenced as `/dev/xvdb`
#
# In this file you can list many instances after the subnet, multiples subnets
# after the region, and also multiples regions.
#
# $ ./script.py create /path/to/file.yaml
# $ ./script.py rm <aws instance id>
# $ ./script.py ls

import boto3
import os
import sys
import yaml
import time

if len(sys.argv) < 2:
    print "usage: {0} <function> [arguments]"
    sys.exit(1)

def init_session(r = None):
    s = boto3.session.Session(profile_name=r)
    return s.resource('ec2')

def ls():
    ec2 = init_session()
    print("instance_id\tinstance_type\tpublic_ip\tprivate_ip\tname")
    instances = ec2.instances.filter(Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])

    for instance in instances:
        name = []
        for i in instance.tags:
            if i['Key'] == 'Name':
                name.append(i['Value'])
        print("%-10s\t%-10s\t%-15s\t%-15s\t%s" %(instance.id, instance.instance_type, instance.public_ip_address, instance.private_ip_address, ",".join(list(
name))))

def get_id_from_tag(ec2obj, tag):
    for o in ec2obj.filter(Filters=[{'Name': 'tag:Name', 'Values': [tag]}]):
        return o.id

    return None

def mktag(val):
    return [{'Key': 'Name', 'Value': val}]

def create():
    if len(sys.argv) < 3:
        print("usage: {0} create <path/to/description.yaml>")
        sys.exit(1)

    try:
        with open(sys.argv[2], 'r') as f:
            y = yaml.load(f.read())
    except IOError:
        print "{0} not found.".format(sys.argv[2])
        sys.exit(1)

    for profile_in_region in y: # loop through regions
        print "profile_in_region: " + profile_in_region
        ec2 = init_session(profile_in_region)
        for azlst in y[profile_in_region]: # loop through AZ list
            for az in azlst: # loop through AZ
                print "az: " + az

                for instance in azlst[az]:

                    if 'awsid' in instance:
                        reply = raw_input(
                            '{0} exists as {1}, continue? [y/N] '.format(
                                instance['name'], instance['awsid']
                            )
                        )
                        if reply[0] != 'y':
                            continue

                    image = get_id_from_tag(ec2.images, instance['image'])
                    sg = []
                    for sglist in instance['sg']:
                        sg.append(get_id_from_tag(ec2.security_groups, sglist))
                    subnet = get_id_from_tag(ec2.subnets, az)

                    if 'data' in instance:
                        blockdevmap = [
                            {
                                'DeviceName': '/dev/xvdb',
                                'Ebs': {
                                    'VolumeSize': instance['data'],
                                    'DeleteOnTermination': True,
                                }
                            }
                        ]
                    else:
                        blockdevmap = []

                    print("creating instance {0}".format(instance['image']))
                    rc = ec2.create_instances(
                        ImageId = image,
                        MinCount = 1,
                        MaxCount = 1,
                        KeyName = instance['key'],
                        SecurityGroupIds = sg,
                        InstanceType = instance['type'],
                        BlockDeviceMappings = blockdevmap,
                        SubnetId = instance['subnet'],
                        PrivateIpAddress = instance['ipaddr']
                    )

                    iid = rc[0].id

                    print(
                        "tagging instance id {0} to {1}".format(
                            iid, instance['name']
                        )
                    )
                    # give the instance a tag name
                    ec2.create_tags(
                        Resources = [iid],
                        Tags = mktag(instance['name'])
                    )

                    instance['awsid'] = iid
                    with open(sys.argv[2], 'w') as f:
                        yaml.dump(y, f, default_flow_style=False)

                    if not blockdevmap:
                        continue

                    devlst = []
                    print("waiting for block devices to rise")
                    while not devlst:
                        devlst = ec2.Instance(iid).block_device_mappings
                        time.sleep(1)

                    for dev in devlst:
                        dname = dev['DeviceName'][5:]
                        print(
                            "tagging volume {0} to {1}_{2}".format(
                                dev['Ebs']['VolumeId'],
                                dname,
                                instance['name']
                            )
                        )
                        ec2.create_tags(
                            Resources = [dev['Ebs']['VolumeId']],
                            Tags = mktag(
                                '{0}_{1}'.format(
                                        dname, instance['name']
                                )
                            )
                        )

def rm():
    if len(sys.argv) < 3:
        print("usage: {0} rm <aws instance id>")
        sys.exit(1)

    ec2 = init_session()

    try:
        ec2.instances.filter(InstanceIds=[sys.argv[2]]).terminate()
    except:
        print('error while terminating {0}'.format(sys.argv[2]))
        sys.exit(1)


if __name__ == '__main__':
    getattr(sys.modules[__name__], sys.argv[1])()