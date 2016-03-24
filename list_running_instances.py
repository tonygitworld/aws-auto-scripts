
import sys
import boto3

print("instance_id\tinstance_type\tpublic_ip\tprivate_ip\tname")
ec2 = boto3.resource('ec2')
instances = ec2.instances.filter(
    Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])

for instance in instances:
    name = []
    for i in instance.tags:
        if i['Key'] == 'Name':
            name.append(i['Value'])
    print("%-10s\t%-10s\t%-15s\t%-15s\t%s" %(instance.id, instance.instance_type, instance.public_ip_address, instance.private_ip_address, ",".join(list(
name))))

