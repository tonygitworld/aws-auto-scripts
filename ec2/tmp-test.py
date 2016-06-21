import boto3

client = boto3.client('ec2')

#eip = client.allocate_address(Domain='vpc')
#print eip

#client.associate_address(InstanceId='i-bc5c3130', PublicIp=eip['PublicIp'])
'''
addresses_dict = client.describe_addresses(Filters=[
                {'Name': 'domain', 'Values': ['vpc']}
                #{'Name': 'association-id', 'Values': []}
            ])

for eip_dict in addresses_dict['Addresses']:
    print eip_dict['PublicIp']
    if 'InstanceId' in eip_dict:
   		print eip_dict['InstanceId']

volumes = client.describe_volumes(Filters=[
                {'Name': 'attachment.instance-id', 'Values': ['i-bc5c3130']}
                #{'Name': 'association-id', 'Values': []}
            ])

volumes = client.describe_instances(InstanceIds=['i-bc5c3130'])['Reservations'][0]['Instances'][0]['BlockDeviceMappings']

for dev in volumes:
    client.create_tags(
        Resources = [dev['Ebs']['VolumeId']],
        Tags = [
            {
                'Key': 'Name', 'Value': 'tony'
            }
        ]
    )



pipaddrs = ''
for instance in rc['Instances']:

        print instance['InstanceId']
        print instance['PrivateIpAddress']
        print instance['PrivateIpAddress']

        pipaddrs = pipaddrs + "," + instance['PrivateIpAddress']



list1 = ['1', '2', '3']
str1 = ','.join(list1)
print str1


response = client.describe_instance_status(
	    InstanceIds=[
	        'i-ad452a21',
	    ]
    )

print response['InstanceStatuses'][0]['InstanceState']['Name']


waiter = client.get_waiter('instance_running')
waiter.wait(InstanceIds=['i-bf573833'])

print ok


ipaddrs = "52.30.14.227,52.49.134.43"
print ipaddrs
ipaddrs = "'%s'" % (ipaddrs[1:])
print ipaddrs

instids = ["i-9e8fe012","i-918fe01d"]
instids = ','.join(instids) # Turn list to string
print instids
instids = "'%s'" % (instids[1:])
print instids



import json


from botocore.client import ClientError

role_name = 'tony-test-2'
iam = boto3.resource('iam')

# print iam.meta.client.list_instance_profiles()

# profile = iam.meta.client.get_instance_profile(InstanceProfileName='role_name')
# print profile
# print iam.meta.client.list_instance_profiles_for_role(RoleName='tony-test')

basic_role_policy = {
    'Statement': [
        {
            'Principal': {
                'Service': ['ec2.amazonaws.com']
            },
            'Effect': 'Allow',
            'Action': ['sts:AssumeRole']
        },
    ]
}

def iam_role_exists(role_name):
    try:
        iam.meta.client.get_role(RoleName=role_name)
        return True
    except ClientError:
        return None

def setup_iam_role(role_name):
    role = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(basic_role_policy)
    )
    return role

role = ''
if iam_role_exists(role_name):
    role = iam.Role(role_name)
else:
    role = setup_iam_role(role_name)

print role.name

profile = iam.meta.client.create_instance_profile(InstanceProfileName=role_name)

#print iam.meta.client.get_instance_profile(InstanceProfileName=role_name)

iam.meta.client.add_role_to_instance_profile(
    InstanceProfileName=role_name,
    RoleName=role_name
)

print iam.meta.client.list_instance_profiles_for_role(RoleName=role_name)

iam = boto3.resource('iam')
#print iam.meta.client.get_instance_profile(InstanceProfileName="cm_launcher_monitor")
#profile = iam.meta.client.list_instance_profiles_for_role(RoleName="cm_launcher_monitor")
#print profile['InstanceProfiles'][0]['Arn']


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


role_name = "cm_8"

import json

iam.create_role(
    RoleName = role_name,
    AssumeRolePolicyDocument = json.dumps(basic_role_policy)
)

profile = iam.meta.client.create_instance_profile(InstanceProfileName=role_name)
#print profile
print profile['InstanceProfile']['Arn']

iam.meta.client.add_role_to_instance_profile(
    InstanceProfileName=role_name,
    RoleName=role_name
)

#print iam.meta.client.list_instance_profiles_for_role(RoleName=role_name)
#print iam.meta.client.get_instance_profile(InstanceProfileName=role_name)

#region          = json['region']
#mail            = json['applyuser']
volume_size     = 10 #json['stype']['dataspace']
subnet_id       = 'subnet-5c3bde04' #json['azone']
ami_id          = 'ami-c39604b0' #instance_info['info'][region]['hvm_image']
instance_count  = 1 #json['count']
instance_type   = 't2.micro' #json['type']
sg_id           = 'sg-3803a65f' #s['info'][region]['base_sec_group']
sg              = []
sg.append(sg_id)

print("creating instance ...")
rc = boto3.client('ec2').run_instances(
    ImageId = ami_id,
    MinCount = instance_count,
    MaxCount = instance_count,
    SecurityGroupIds = sg,
    InstanceType = instance_type,
    SubnetId = subnet_id,
    Monitoring = {
        'Enabled': True
    },
    IamInstanceProfile = {'Name': 'cm_8'}
)



import json

data = {"count": 1, "EIP": "Yes", "applyuser": "liyuguang", "azone": "subnet-5c3bde04", "tags": {"department": "browser", "owners": ["renshumeng"], "product": "bigda", "Name": "cml1"}, "region": "eu-west-1", "need": "ec2", "type": "t2.micro", "id": "", "stype": {"dataspace": 10, "type": "gp2"}}
json = json.dumps(data)

with open("/tmp/recv.log","ab") as f:
        f.write(json)
        f.write("\n")


#c_ip = client.allocate_address(Domain='vpc')
#print c_ip['AllocationId']

addresses_dict = client.describe_addresses(
            Filters=[
                {'Name': 'domain', 'Values': ['vpc']}
            ]
        )

print addresses_dict




aws_console = "aws --region eu-west-1  elasticache create-replication-group  --replication-group-id tony-test-redis  "\
            "--num-cache-clusters 1   --engine  redis "\
            "--replication-group-description tony-test  "\
            "--cache-node-type cache.t2.micro"\
            #"--cache-subnet-group-name %s " \
            #"--security-group-id  %s  " \


import subprocess
import json

class Command():
    @staticmethod
    def Subprocess(str):
        str = str + ' ' + '--profile cm-overseas'
        res_buf = ''
        print "%s" % str
        p = subprocess.Popen(str, shell=True, stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        while True:
            buff = p.stdout.readline()
            if buff == '' and p.poll() != None:
                 break
            if buff == '':
                  continue;
            res_buf += buff
        return res_buf

aws_console = "aws --region ap-southeast-2 elasticache create-replication-group  --replication-group-id tony-redis  "\
            "--num-cache-clusters 1  --engine  redis "\
            "--replication-group-description tony-test  "\
            "--cache-node-type cache.t2.micro "\
            "--notification-topic-arn arn:aws:sns:ap-southeast-2:331956261250:liyuguang-test" \
            #"--security-group-id  %s  " \

res1 = Command.Subprocess(aws_console)



aws_console = "aws --region %s  elasticache  create-cache-cluster  --engine %s "\
            "--engine-version %s --port %s "  \
            "--cache-cluster-id %s  --cache-node-type %s    --num-cache-nodes %s "\
            "--cache-subnet-group-name %s " \
            "--security-group-id  %s  " \
            "--cache-parameter-group-name %s  --preferred-availability-zone %s   "\
            "--tags  Key=department,Value=\"%s\"  Key=owners,Value=\"%s\" Key=product,Value=\"%s\" " \
            " Key=name,Value=\"%s\"  Key=use,Value=\"%s\" " \
            "--notification-topic-arn  %s " \

cmd = aws_console %("region","engine_type","engine_version", \
            "engine_port","cluster_name",'node_type','num-cache-nodes','vpc-name',\
            'sec-name',
            #s['info']['snapshot-retention-limit'],
            parameter_name,\
            'az',json['tag_department'],\
            json['tag_owners'],json['tag_product'],json['tag_name'],json['tag_use']),\
            s['info'][region]['sns-topic']

'''

import tornado.ioloop
import tornado.web

class MainHandler(tornado.web.RequestHandler):
    def get(self):
        self.write("Hello, world")

def make_app():
    return tornado.web.Application([
        (r"/", MainHandler),
    ])

if __name__ == "__main__":
    app = make_app()
    app.listen(8888)
    tornado.ioloop.IOLoop.current().start()