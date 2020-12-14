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


class OctankSupportInfra(core.Stack):

    def __init__(self, scope: core.Stack, id: str, **kwargs):
        super().__init__(scope, id, **kwargs)

        environment = 'dev'
        support_group_cluster_name = 'octank-support'

        resource_name = support_group_cluster_name + '-' + environment

        # This resource alone will create a private/public subnet in each AZ as well as nat/internet gateway(s)
        self.vpc = aws_ec2.Vpc(
            self, 'OctankSupportVPC',
            cidr='10.0.0.0/24',
            max_azs=3
        )

        # Creating ECS Cluster in the VPC created above
        self.ecs_cluster = aws_ecs.Cluster(
            self, resource_name,
            vpc=self.vpc,
            cluster_name=resource_name
        )

        # Adding service discovery namespace to cluster
        self.ecs_cluster.add_default_cloud_map_namespace(
            name='support.octank.local',
            # name=resource_name + '-services',
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
            # 'SECGRPS': str(self.ecs_cluster.connections.security_groups)
        }

        # Security Group for port 8080 services
        self.services_8080_sec_group = aws_ec2.SecurityGroup(
            # self, 'FrontendToBackendSecurityGroup',
            self, 'ELBToBackendSecurityGroup',
            allow_all_outbound=True,
            description='Security group for LB to talk to octicketing applicatoin',
            vpc=self.vpc
        )

        # Allow inbound 8080 from ALB to Frontend Service
        self.sec_grp_ingress_self_8080 = aws_ec2.CfnSecurityGroupIngress(
            self, 'InboundSecGrp8080',
            ip_protocol='TCP',
            source_security_group_id=self.services_8080_sec_group.security_group_id,
            from_port=8080,
            to_port=8080,
            group_id=self.services_8080_sec_group.security_group_id
        )

        # All Outputs required for other stacks to build
        core.CfnOutput(
            self, 'NSArn', value=self.namespace_outputs['ARN'], export_name='NSARN')
        core.CfnOutput(
            self, 'NSName', value=self.namespace_outputs['NAME'], export_name='NSNAME')
        core.CfnOutput(
            self, 'NSId', value=self.namespace_outputs['ID'], export_name='NSID')

        #    value=self.services_8080_sec_group.security_group_id, export_name='SecGrpId')
        core.CfnOutput(self, 'ECSClusterName',
                       value=self.cluster_outputs['NAME'], export_name='ECSClusterName')
        core.CfnOutput(self, 'ServicesSecGrp',
                       value=self.services_8080_sec_group.security_group_id, export_name='ServicesSecGrp')
