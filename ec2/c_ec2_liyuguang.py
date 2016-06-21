
import boto3
import os
import sys
import yaml
import time
from pymongo import MongoClient
import json as jsonModule
from IPy import IP
from botocore.client import ClientError

iplist = ['52.35.247.128/26','52.35.248.64/26','52.35.248.128/26']
profile = 'cm-overseas'

def init_session(profile = None, service = None, level = None, region=None):
    s = boto3.session.Session(profile_name=profile, region_name=region)
    if level == 'client':
        return s.client(service)
    elif level == 'resource':
        return s.resource(service)

def yaml_load():

    path = sys.path[0]
    site = path + "/site.yml"

    try:
        with open(site, 'r') as f:
            y = yaml.load(f.read())
    except IOError:
        print "{0} not found.".format("site.yml")
        sys.exit(1)
    return y

def tag_instances_and_ebs(ec2client, instanceid, launchinfo):

    json_tags = launchinfo['tags']
    owners = ','.join(json_tags['owners'])

    print("Tagging instance %s ..." %(instanceid))
    ec2client.create_tags(
        Resources = [instanceid],
        Tags = [
            {
                'Key': 'Name', 'Value': json_tags['Name']
            },
            {
                'Key': 'owners', 'Value': owners
            },
            {
                'Key': 'department', 'Value': json_tags['department']
            },
            {
                'Key': 'product', 'Value': json_tags['product']
            }
        ]
    )

    # wait for block devices to show up
    devlst = []
    while not devlst:
        devlst = ec2client.describe_instances(InstanceIds=[instanceid])['Reservations'][0]['Instances'][0]['BlockDeviceMappings']
        time.sleep(1)

    print("Tagging volumes for instance %s ..." %(instanceid))
    for dev in devlst:
        ec2client.create_tags(
            Resources = [dev['Ebs']['VolumeId']],
            Tags = [
                {
                    'Key': 'owners', 'Value': owners
                },
                {
                    'Key': 'department', 'Value': json_tags['department']
                },
                {
                    'Key': 'product', 'Value': json_tags['product']
                }
            ]
        )

def associate_eip(ec2client, instid, launchinfo):
    json_tags = launchinfo['tags']
    address = ''
    allocationId = ''

    addresses_dict = ec2client.describe_addresses(
            Filters=[
                {'Name': 'domain', 'Values': ['vpc']}
            ]
        )

    for eip_dict in addresses_dict['Addresses']:
        # If eip is not associated to an instance
        if 'InstanceId' not in eip_dict:
            print("Existing EIP %s is available ..." %(eip_dict['PublicIp']))
            # res is a container that contains boolean if ip is in the iplist
            res = map(lambda x:eip_dict['PublicIp'] in IP(x),iplist)
            if json_tags['product'] == 'bigdata':
                print 'This instance is for big data.'
                if True in set(res):
                    address = eip_dict['PublicIp']
                    allocationId = eip_dict['AllocationId']
                    break
                else:
                    pass
                    print 'bigdata pass'
            else:
                if True in set(res):
                    pass
                else:
                    address = eip_dict['PublicIp']
                    allocationId = eip_dict['AllocationId']
                    break

    if address == '':
        print("There is no available EIP so allocate a new one.")
        c_ip = ec2client.allocate_address(Domain='vpc')
        address = c_ip['PublicIp']
        allocationId = c_ip['AllocationId']

    print("Associating eip %s to instances %s ..." %(address, instid))
    ec2client.associate_address(
            InstanceId=instid,
            AllocationId = allocationId,
            AllowReassociation = True
        )

    return address

def iam_role_exists(iamresource, role_name):
    try:
        iamresource.meta.client.get_role(RoleName=role_name)
        return True
    except ClientError:
        return None

def setup_iam_role(iamresource, role_name):
    basic_role_policy = {
        'Statement': [
            {
                'Principal': {
                    'Service': ['ec2.amazonaws.com']
                },
                'Effect': 'Allow',
                'Action': ['sts:AssumeRole']
            }
        ]
    }

    iamresource.create_role(
        RoleName = role_name,
        AssumeRolePolicyDocument = jsonModule.dumps(basic_role_policy)
    )

'''
ToDo:

To ensure faster instance launches, break up large requests into smaller batches. 
For example, create five separate launch requests for 100 instances each instead 
of one launch request for 500 instances.
'''
def launch_instances(launchinfo):
    region          = launchinfo['region']
    launchconf      = yaml_load()
    json_tags       = launchinfo['tags']
    ec2client       = init_session(profile, 'ec2', 'client', region)
    iamresource     = init_session(profile, 'iam', 'resource', region)
    mail            = launchinfo['applyuser']
    volume_size     = int(launchinfo['stype']['dataspace'])
    volume_type     = launchinfo['stype']['type']
    subnet_id       = launchinfo['azone']
    ami_id          = launchconf['info'][region]['hvm_image']
    instance_count  = int(launchinfo['count'])
    instance_type   = launchinfo['type']
    sg_id           = launchconf['info'][region]['base_sec_group']
    sg              = []
    sg.append(sg_id)

    if volume_type == "gp2":
        blockdevmap = [
            {
                'DeviceName': '/dev/sdb',
                'Ebs': {
                    'VolumeSize': volume_size,
                    'DeleteOnTermination': True,
                    'VolumeType': 'gp2'
                }
            }
        ]
    elif volume_type == "io1":
        # The parameter iops must be specified for io1 volumes.
        iops = int(launchinfo['stype']['iops'])
        blockdevmap = [
            {
                'DeviceName': '/dev/sdb',
                'Ebs': {
                    'VolumeSize': volume_size,
                    'DeleteOnTermination': True,
                    'VolumeType': 'io1',
                    'Iops': iops
                }
            }
        ]
    else:
        blockdevmap = []

    # Take the instance Name as role name and instance profile name
    role_name = json_tags['Name'] 
    if iam_role_exists(iamresource, role_name):
        print('Role %s already exist, use it ...' %(role_name))
    else:
        print('Creating new role %s ...' %(role_name))
        setup_iam_role(iamresource, role_name)
        iamresource.meta.client.create_instance_profile(InstanceProfileName=role_name)
        iamresource.meta.client.add_role_to_instance_profile(
            InstanceProfileName=role_name,
            RoleName=role_name
        )
        # Wait for the instance profile to be available
        # waiter = iamresource.meta.client.get_waiter('instance_profile_exists')
        # waiter.wait(InstanceProfileName=role_name)
        print('Waiting for the instance profile to be available ...')
        time.sleep(10)

    print("Launching %s %s instances in region %s with following parameters:" %(instance_count, instance_type, region))
    print("\tami: %s" %(ami_id))
    print("\tSecurity Group: %s" %(sg))
    print("\tSubnet: %s" %(subnet_id))
    print("\tIAM role: %s" %(role_name))
    reservations = ec2client.run_instances(
        ImageId = ami_id,
        MinCount = instance_count,
        MaxCount = instance_count,
        SecurityGroupIds = sg,
        InstanceType = instance_type,
        BlockDeviceMappings = blockdevmap,
        SubnetId = subnet_id,
        Monitoring = {
            'Enabled': True
        },
        IamInstanceProfile = {'Name': role_name}
    )

    instids = []
    resources=[]
    ipaddrs = ''

    for instance in reservations['Instances']:
        instids.append(instance['InstanceId'])
    # Waiting for instances turn to running state, this is required for associate ip
    print('Waiting for instance %s turn to running state ...' %(instids))
    waiter = ec2client.get_waiter('instance_running')
    waiter.wait(InstanceIds=instids)

    for instid in instids:
        # Tag the instance and attached volumes
        tag_instances_and_ebs(ec2client, instid, launchinfo)

        # Associate eip 
        ipaddr = ''
        if launchinfo['EIP'] == 'Yes':
            ipaddr = associate_eip(ec2client, instid, launchinfo)
            ipaddrs = ipaddrs + "," + ipaddr

        instinfo={}
        instinfo['InstanceId']=instid
        instinfo['PrivateIpAddress']=instance['PrivateIpAddress']
        instinfo['PublicIpAddress']=ipaddr
        resources.append(instinfo)

    ipaddrs = "'%s'" % (ipaddrs[1:])
    instids = ','.join(instids) # Turn list to string
    data = "{'id':'%s','ipaddr':%s,'inst_id':'%s','applyuser':'%s'}" % (launchinfo['id'], ipaddrs, instids, mail)

    con = MongoClient("ksmgr.liebaopay.com", 27017)
    db = con.kaws
    collection = db.create_ec2
    j = eval(data)
    collection.save(j)

    print '##' # This line is needed by by kaws/admin/ec2admin.py -- > eval(output.split('##')[-1]) 
    res={}
    res['info']=resources
    res['Name']=json_tags['Name']
    print res

if __name__ == '__main__':

    #data = {"count": "1", "EIP": "Yes", "applyuser": "liyuguang", "azone": "subnet-a9df80f0", "tags": {"department": "UserDev", "owners": ["liyuguang"], "product": "Liveme", "Name": "liyuguang-test"}, "region": "us-west-1", "need": "ec2", "type": "t2.micro", "id": "576110287cda090c862f60d9", "stype": {"dataspace": "50", "type": "gp2"}}
    #json = jsonModule.dumps(data)

    with open("/tmp/recv.log","ab") as f:
        f.write(sys.argv[1])
        f.write("\n")

    launchinfo = eval(sys.argv[1])
    launch_instances(launchinfo)