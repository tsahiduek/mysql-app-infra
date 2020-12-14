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

        environment = self.node.try_get_context("env")
        environment = "" if not environment else environment

        # This resource alone will create a private/public subnet in each AZ as well as nat/internet gateway(s)
        self.vpc = aws_ec2.Vpc(
            self, 'OctankSupportVPC' + environment,
            cidr='10.0.0.0/16',
            max_azs=2,
            enable_dns_hostnames=True,
            enable_dns_support=True,
            subnet_configuration=[
                aws_ec2.SubnetConfiguration(
                    name="Public",
                    subnet_type=aws_ec2.SubnetType.PUBLIC,
                    cidr_mask=24
                ),
                aws_ec2.SubnetConfiguration(
                    name="Private",
                    subnet_type=aws_ec2.SubnetType.PRIVATE,
                    cidr_mask=24
                ),
                aws_ec2.SubnetConfiguration(
                    name="Isolated",
                    subnet_type=aws_ec2.SubnetType.ISOLATED,
                    cidr_mask=24
                ),
            ],
        )

        # All Outputs required for other stacks to build
        core.CfnOutput(
            self, 'OctankSupportVPCID', value=self.vpc.vpc_id, export_name='OctankSupportVPCID')
