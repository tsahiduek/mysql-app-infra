
#!/usr/bin/env python3

from aws_cdk import (
    aws_ec2,
    aws_ecs,
    aws_iam,
    aws_ssm,
    aws_autoscaling,
    core
)
from os import getenv


class ImportedResources(core.Construct):

    def __init__(self, scope: core.Construct, id: str, **kwargs):
        super().__init__(scope, id, **kwargs)
        environment = self.node.try_get_context("env")
        environment = "" if not environment else environment

        vpc_stack_name = 'octank-support-vpc'

        vpc_name = '{}/OctankSupportVPC'
        self.vpc = aws_ec2.Vpc.from_lookup(
            self,  'vpc', vpc_name=vpc_name.format(vpc_stack_name))


class OctankSupportECS(core.Stack):

    def __init__(self, scope: core.Stack, id: str, **kwargs):
        super().__init__(scope, id, **kwargs)

        environment = self.node.try_get_context("env")
        environment = "" if not environment else environment

        group_name = self.node.try_get_context("group")
        group_name = "OctankSupport" if not group_name else group_name

        self.base = ImportedResources(self, self.stack_name)

        # Creating ECS Cluster in the VPC created above
        self.ecs_cluster = aws_ecs.Cluster(
            self, 'OctankSupport',
            vpc=self.base.vpc,
            cluster_name='OctankSupport'
        )

        # ECS EC2 Capacity
        self.asg = self.ecs_cluster.add_capacity(
            "ECSEC2Capacity",
            instance_type=aws_ec2.InstanceType(
                instance_type_identifier='t2.small'),
            min_capacity=0,
            max_capacity=10
        )

        # Adding service discovery (AWS CloudMap) namespace to cluster
        self.ecs_cluster.add_default_cloud_map_namespace(
            name='support.octank.local',
        )

        # Namespace details as CFN output
        self.namespace_outputs = {
            'ARN': self.ecs_cluster.default_cloud_map_namespace.private_dns_namespace_arn,
            'NAME': self.ecs_cluster.default_cloud_map_namespace.private_dns_namespace_name,
            'ID': self.ecs_cluster.default_cloud_map_namespace.private_dns_namespace_id,
        }

        # Cluster Attributes
        self.cluster_outputs = {
            'NAME': self.ecs_cluster.cluster_name,
            'SECGRPS': str(self.ecs_cluster.connections.security_groups)
        }

        # ???
        # # When enabling EC2, we need the security groups "registered" to the cluster for imports in other service stacks
        # if self.ecs_cluster.connections.security_groups:
        #     self.cluster_outputs['SECGRPS'] = str(
        #         [x.security_group_id for x in self.ecs_cluster.connections.security_groups][0])

        # # Security Group for port 8080 services
        # self.services_8080_sec_group = aws_ec2.SecurityGroup(
        #     # self, 'FrontendToBackendSecurityGroup',
        #     self, 'ELBToBackendSecurityGroup',
        #     allow_all_outbound=True,
        #     description='Security group for LB to talk to octicketing applicatoin',
        #     vpc=self.base.vpc
        # )

        # # Allow inbound 8080 from ALB to Frontend Service
        # self.sec_grp_ingress_self_8080 = aws_ec2.CfnSecurityGroupIngress(
        #     self, 'InboundSecGrp8080',
        #     ip_protocol='TCP',
        #     source_security_group_id=self.services_8080_sec_group.security_group_id,
        #     from_port=8080,
        #     to_port=8080,
        #     group_id=self.services_8080_sec_group.security_group_id
        # )

        # All Outputs required for other stacks to build
        core.CfnOutput(
            self, 'NSArn', value=self.namespace_outputs['ARN'], export_name=group_name+'NSARN')
        core.CfnOutput(
            self, 'NSName', value=self.namespace_outputs['NAME'], export_name=group_name+'NSNAME')
        core.CfnOutput(
            self, 'NSId', value=self.namespace_outputs['ID'], export_name=group_name+'NSID')

        #    value=self.services_8080_sec_group.security_group_id, export_name='SecGrpId')
        core.CfnOutput(self, 'ECSClusterName',
                       value=self.cluster_outputs['NAME'], export_name=group_name+'ECSClusterName')
        # core.CfnOutput(self, 'ServicesSecGrp',
        #                value=self.services_8080_sec_group.security_group_id, export_name=group_name+'ServicesSecGrp')
