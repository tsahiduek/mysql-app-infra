from aws_cdk import (
    core,
    aws_ec2,
    aws_ecs,
    aws_servicediscovery,
    aws_elasticloadbalancingv2 as elbv2,
)


class ImportedResources(core.Construct):

    def __init__(self, scope: core.Construct, id: str, **kwargs):
        super().__init__(scope, id, **kwargs)
        environment = self.node.try_get_context("env")
        environment = "" if not environment else environment

        vpc_stack_name = 'octank-support-vpc'

        vpc_name = '{}/OctankSupportVPC'
        self.vpc = aws_ec2.Vpc.from_lookup(
            self,  'vpc', vpc_name=vpc_name.format(vpc_stack_name))


class OcticketingALBBlueGreen(core.Stack):

    def __init__(self, scope: core.Construct, id: str,  **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        self.platform_resources = ImportedResources(self, self.stack_name)

        group_name = self.node.try_get_context("group")
        group_name = "OctankSupport" if not group_name else group_name

        # =============================================================================
        #  Application Loadbalancer configuration
        # =============================================================================
        self.alb_security_group = aws_ec2.SecurityGroup(
            self, "octicketing-alb-sg-bg", vpc=self.platform_resources.vpc, allow_all_outbound=True)
        # Creating an application load balancer, listener and two target groups for Blue/Green deployment
        self.alb = elbv2.ApplicationLoadBalancer(self, "octicketing-bg",
                                                 load_balancer_name='octicketing-bg',
                                                 vpc=self.platform_resources.vpc,
                                                 security_group=self.alb_security_group,
                                                 internet_facing=True
                                                 )

        self.albProdListener = self.alb.add_listener(
            'albProdListener', port=80)

        self.albTestListener = self.alb.add_listener(
            'albTestListener', port=8080)

        self.albProdListener.connections.allow_default_port_from_any_ipv4(
            'Allow traffic from everywhere on port 80')
        self.albTestListener.connections.allow_default_port_from_any_ipv4(
            'Allow traffic from everywhere on port 8080')

        # Target group 1
        self.blueGroup = elbv2.ApplicationTargetGroup(self, "blueGroup",
                                                      vpc=self.platform_resources.vpc,
                                                      protocol=elbv2.ApplicationProtocol.HTTP,
                                                      port=8080,
                                                      target_type=elbv2.TargetType.IP,
                                                      health_check={
                                                          "path": "/",
                                                          "timeout": core.Duration.seconds(10),
                                                          "interval": core.Duration.seconds(15),
                                                          "healthy_http_codes": "200,404"
                                                      }
                                                      )

        # Target group 2
        self.greenGroup = elbv2.ApplicationTargetGroup(self, "greenGroup",
                                                       vpc=self.platform_resources.vpc,
                                                       protocol=elbv2.ApplicationProtocol.HTTP,
                                                       port=8080,
                                                       target_type=elbv2.TargetType.IP,
                                                       health_check={
                                                           "path": "/",
                                                           "timeout": core.Duration.seconds(10),
                                                           "interval": core.Duration.seconds(15),
                                                           "healthy_http_codes": "200,404"
                                                       }
                                                       )
        # Registering the blue target group with the production listener of load balancer
        self.albProdListener.add_target_groups("blueTarget",  # priority=1, path_patterns=["/"],
                                               target_groups=[self.blueGroup])
        # Registering the green target group with the test listener of load balancer
        self.albTestListener.add_target_groups("greenTarget",  # priority=1, path_patterns=["/"],
                                               target_groups=[self.greenGroup])

        core.CfnOutput(
            self, 'ALBARN', value=self.alb.load_balancer_arn, export_name=group_name+'ALBarn')
        core.CfnOutput(
            self, 'ALBName', value=self.alb.load_balancer_name, export_name=group_name+'ALBName')
        core.CfnOutput(
            self, 'ALBFullName', value=self.alb.load_balancer_full_name, export_name=group_name+'ALBFullName')
        core.CfnOutput(
            self, 'ALBSGID', value=core.Fn.select(0, self.alb.load_balancer_security_groups), export_name=group_name+'ALBSgId')
        core.CfnOutput(
            self, 'BlueTgARN', value=self.blueGroup.target_group_arn, export_name=group_name+'BlueTgARN')
        core.CfnOutput(
            self, 'GreenTgARN', value=self.greenGroup.target_group_arn, export_name=group_name+'GreenTgARN')

        core.CfnOutput(
            self, 'BlueTgName', value=self.blueGroup.target_group_name, export_name=group_name+'BlueTgName')
        core.CfnOutput(
            self, 'GreenTgName', value=self.greenGroup.target_group_name, export_name=group_name+'GreenTgName')
        core.CfnOutput(
            self, 'BlueTgFullName', value=self.greenGroup.target_group_full_name, export_name=group_name+'BlueTgFullName')
        core.CfnOutput(
            self, 'GreenTgFullName', value=self.greenGroup.target_group_full_name, export_name=group_name+'GreenTgFullName')
        core.CfnOutput(
            self, 'ProdListenerARN', value=self.albProdListener.listener_arn, export_name=group_name+'ProdListenerARN')
        core.CfnOutput(
            self, 'TestListenerARN', value=self.albTestListener.listener_arn, export_name=group_name+'TestListenerARN')
