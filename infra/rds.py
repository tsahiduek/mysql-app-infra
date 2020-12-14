#!/usr/bin/env python3

from aws_cdk import (
    aws_ec2,
    aws_rds,
    aws_iam,
    aws_secretsmanager,
    core
)


class ImportedResources(core.Construct):

    def __init__(self, scope: core.Construct, id: str, **kwargs):
        super().__init__(scope, id, **kwargs)
        environment = self.node.try_get_context("env")
        environment = "" if not environment else environment

        vpc_stack_name = 'octank-support-vpc'
        # vpc_id = core.Fn.import_value('OctankSupportVPCID')

        vpc_name = '{}/OctankSupportVPC'
        self.vpc = aws_ec2.Vpc.from_lookup(
            self,  'vpc', vpc_name=vpc_name.format(vpc_stack_name))


class OctankSupportRds(core.Stack):
    def __init__(self, app: core.App, id: str, **kwargs) -> None:
        super().__init__(app, id, **kwargs)
        self.platform_resources = ImportedResources(self, self.stack_name)

        self.rds_security_group = aws_ec2.SecurityGroup(
            self, "rds-security-group", vpc=self.platform_resources.vpc, allow_all_outbound=True)
        self.rds_security_group.add_ingress_rule(
            peer=aws_ec2.Peer.ipv4(self.platform_resources.vpc.vpc_cidr_block), connection=aws_ec2.Port.tcp(3306))

        my_secret = aws_secretsmanager.Secret.from_secret_name(
            self, "DBSecret", "support/octicketing/rds")

        self.rds = aws_rds.DatabaseInstance(
            self, "support-rds",
            database_name="support_db",
            instance_identifier='support-db',
            credentials=aws_rds.Credentials.from_secret(my_secret),
            engine=aws_rds.DatabaseInstanceEngine.mysql(
                version=aws_rds.MysqlEngineVersion.VER_5_6
            ),
            vpc=self.platform_resources.vpc,
            port=3306,
            instance_type=aws_ec2.InstanceType.of(
                aws_ec2.InstanceClass.BURSTABLE3,
                aws_ec2.InstanceSize.MICRO,
            ),
            removal_policy=core.RemovalPolicy.DESTROY,
            security_groups=[self.rds_security_group],
            deletion_protection=False

        )

        self.db_auth_policy_stmt = aws_iam.PolicyStatement(
            effect=aws_iam.Effect.ALLOW, actions=["rds-db:connect"], resources=[self.rds.instance_arn])
        policy_doc = aws_iam.PolicyDocument()
        policy_doc.add_statements(self.db_auth_policy_stmt)
        self.db_auth_policy = aws_iam.Policy(self, 'db-auth-policy',
                                             policy_name='RdsDbAuthPolicy',
                                             statements=[self.db_auth_policy_stmt])

        self.db_auth_role = aws_iam.Role(self, "db-auth-role",
                                         role_name='RdsDbAuthRole',
                                         assumed_by=aws_iam.ServicePrincipal(
                                             'ec2.amazonaws.com')
                                         )
        self.db_auth_role.add_to_policy(self.db_auth_policy_stmt)
