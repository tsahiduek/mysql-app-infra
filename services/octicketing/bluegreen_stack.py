from aws_cdk import (
    aws_ecr,
    core,
    aws_codecommit,
    aws_codebuild,
    aws_ecs,
    aws_iam,
    aws_ec2,
    aws_servicediscovery,
    aws_secretsmanager,
    aws_lambda,
    aws_elasticloadbalancingv2 as elbv2,
    aws_codedeploy as codedeploy,
    aws_codepipeline as codepipeline,
    aws_codepipeline_actions,
    aws_s3 as s3,
    aws_cloudwatch,
    aws_logs
)


class ImportedResources(core.Construct):

    def __init__(self, scope: core.Construct, id: str, **kwargs):
        super().__init__(scope, id, **kwargs)
        environment = self.node.try_get_context("env")
        environment = "" if not environment else environment

        group_name = self.node.try_get_context("group")
        group_name = "OctankSupport" if not group_name else group_name

        vpc_stack_name = 'octank-support-vpc'
        # vpc_id = core.Fn.import_value('OctankSupportVPCID')

        vpc_name = '{}/OctankSupportVPC'
        self.vpc = aws_ec2.Vpc.from_lookup(
            self,  'vpc', vpc_name=vpc_name.format(vpc_stack_name))

        self.sd_namespace = aws_servicediscovery.PrivateDnsNamespace.from_private_dns_namespace_attributes(
            self, "SDNamespace",
            namespace_name=core.Fn.import_value(group_name+'NSNAME'),
            namespace_arn=core.Fn.import_value(group_name+'NSARN'),
            namespace_id=core.Fn.import_value(group_name+'NSID')
        )

        self.ecs_cluster = aws_ecs.Cluster.from_cluster_attributes(
            self, "ECSCluster",
            cluster_name=core.Fn.import_value(group_name + 'ECSClusterName'),
            security_groups=[],
            vpc=self.vpc,
            default_cloud_map_namespace=self.sd_namespace
        )

        alb_arn = core.Fn.import_value(group_name+'ALBarn')
        alb_sg_id = core.Fn.import_value(group_name+'ALBSgId')
        self.alb = elbv2.ApplicationLoadBalancer.from_application_load_balancer_attributes(self, 'ALB',
                                                                                           load_balancer_arn=alb_arn,
                                                                                           security_group_id=alb_sg_id
                                                                                           )
        self.alb_name = core.Fn.import_value(group_name+'ALBName')
        self.alb_full_name = core.Fn.import_value(group_name+'ALBFullName')

        self.blue_target = elbv2.ApplicationTargetGroup.from_target_group_attributes(
            self, 'BlueTarget', target_group_arn=core.Fn.import_value(group_name+'BlueTgARN'))
        self.green_target = elbv2.ApplicationTargetGroup.from_target_group_attributes(
            self, 'GreenTarget', target_group_arn=core.Fn.import_value(group_name+'GreenTgARN'))

        self.blue_target_name = core.Fn.import_value(group_name+'BlueTgName')
        self.green_target_name = core.Fn.import_value(group_name+'GreenTgName')

        self.blue_target_full_name = core.Fn.import_value(
            group_name+'BlueTgFullName')
        self.green_target_full_name = core.Fn.import_value(
            group_name+'GreenTgFullName')

        self.prod_listener = elbv2.ApplicationListener.from_application_listener_attributes(self, 'ProdListener',
                                                                                            security_group=aws_ec2.SecurityGroup.from_security_group_id(
                                                                                                self, "ProdHttp", alb_sg_id),
                                                                                            listener_arn=core.Fn.import_value(group_name+'ProdListenerARN'))
        self.test_listener = elbv2.ApplicationListener.from_application_listener_attributes(self, 'TestListener',
                                                                                            security_group=aws_ec2.SecurityGroup.from_security_group_id(
                                                                                                self, "TestHttp", alb_sg_id),
                                                                                            listener_arn=core.Fn.import_value(group_name+'TestListenerARN'))


class BlueGreen(core.Stack):

    def __init__(self, scope: core.Construct, id: str, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)
        self.platform_resources = ImportedResources(self, self.stack_name)

        ###

        ECS_APP_NAME = "octicketing-microservice"
        ECS_DEPLOYMENT_GROUP_NAME = "octicketingECSBlueGreen"
        ECS_DEPLOYMENT_CONFIG_NAME = "CodeDeployDefault.ECSLinear10PercentEvery1Minutes"
        ECS_DEPLOYMENT_CONFIG_ALL = "CodeDeployDefault.ECSAllAtOnce"
        ECS_TASKSET_TERMINATION_WAIT_TIME = 10
        ECS_TASK_FAMILY_NAME = "octicketing-service"
        ECS_APP_LOG_GROUP_NAME = "/ecs/" + ECS_TASK_FAMILY_NAME

        DUMMY_APP_NAME = "hello-world-microservice"
        DUMMY_TASK_FAMILY_NAME = "hello-world-service"
        DUMMY_APP_LOG_GROUP_NAME = "/ecs/dummy-" + ECS_TASK_FAMILY_NAME
        DUMMY_CONTAINER_IMAGE = self.account + ".dkr.ecr." + \
            self.region + ".amazonaws.com/hello-world:latest"
        Dmmuyvare = ""
        # =============================================================================
        # ECR and CodeCommit repositories for the Blue/ Green deployment
        # =============================================================================

        # ECR repository for the docker images
        self.octicketing_ecr_repo = aws_ecr.Repository(
            self, "OcticketingECRRepo",
            repository_name=ECS_APP_NAME,
            removal_policy=core.RemovalPolicy.DESTROY
        )

        self.octicketing_code_repo = aws_codecommit.Repository(
            self, ECS_APP_NAME + "-bg", repository_name=ECS_APP_NAME + "-bg", description=ECS_APP_NAME + "blue-green service repository")
        core.CfnOutput(self, 'BGRepoName',
                       value=self.octicketing_code_repo.repository_name, export_name='OcticketingBGRepoName')
        core.CfnOutput(self, 'BGRepoARN',
                       value=self.octicketing_code_repo.repository_arn, export_name='OcticketingBGRepoARN')

        # =============================================================================
        #   CODE BUILD and ECS TASK ROLES for the Blue/ Green deployment
        # =============================================================================

        # IAM role for the Code Build project
        codeBuildServiceRole = aws_iam.Role(self, "codeBuildServiceRole",
                                            assumed_by=aws_iam.ServicePrincipal(
                                                'codebuild.amazonaws.com')
                                            )
        inlinePolicyForCodeBuild = aws_iam.PolicyStatement(
            effect=aws_iam.Effect.ALLOW,
            actions=[
                "ecr:GetAuthorizationToken",
                "ecr:BatchCheckLayerAvailability",
                "ecr:InitiateLayerUpload",
                "ecr:BatchGetImage",
                "ecr:GetDownloadUrlForLayer",
                "ecr:UploadLayerPart",
                "ecr:CompleteLayerUpload",
                "ecr:PutImage"
            ],
            resources=["*"]
        )

        codeBuildServiceRole.add_to_policy(inlinePolicyForCodeBuild)

        # ECS task role
        ecsTaskRole = aws_iam.Role(self, "ecsTaskRoleForWorkshop",
                                   assumed_by=aws_iam.ServicePrincipal(
                                       'ecs-tasks.amazonaws.com')
                                   )

        ecsTaskRole.add_managed_policy(aws_iam.ManagedPolicy.from_aws_managed_policy_name(
            "service-role/AmazonECSTaskExecutionRolePolicy"))
        ecsTaskRole.add_managed_policy(aws_iam.ManagedPolicy.from_aws_managed_policy_name(
            "SecretsManagerReadWrite"))

        # =============================================================================
        # CODE DEPLOY APPLICATION for the Blue/ Green deployment
        # =============================================================================

        # Creating the code deploy application
        codeDeployApplication = codedeploy.EcsApplication(
            self, "OcticketingCodeDeploy")

        # Creating the code deploy service role
        codeDeployServiceRole = aws_iam.Role(self, "codeDeployServiceRole",
                                             assumed_by=aws_iam.ServicePrincipal(
                                                 'codedeploy.amazonaws.com')
                                             )
        codeDeployServiceRole.add_managed_policy(
            aws_iam.ManagedPolicy.from_aws_managed_policy_name("AWSCodeDeployRoleForECS"))

        # IAM role for custom lambda function
        customLambdaServiceRole = aws_iam.Role(self, "codeDeployCustomLambda",
                                               assumed_by=aws_iam.ServicePrincipal(
                                                   'lambda.amazonaws.com')
                                               )

        inlinePolicyForLambda = aws_iam.PolicyStatement(
            effect=aws_iam.Effect.ALLOW,
            actions=[
                "iam:PassRole",
                "sts:AssumeRole",
                "codedeploy:List*",
                "codedeploy:Get*",
                "codedeploy:UpdateDeploymentGroup",
                "codedeploy:CreateDeploymentGroup",
                "codedeploy:DeleteDeploymentGroup"
            ],
            resources=["*"]
        )

        customLambdaServiceRole.add_managed_policy(
            aws_iam.ManagedPolicy.from_aws_managed_policy_name('service-role/AWSLambdaBasicExecutionRole'))
        customLambdaServiceRole.add_to_policy(inlinePolicyForLambda)

        # Custom resource to create the deployment group
        createDeploymentGroupLambda = aws_lambda.Function(self, 'createDeploymentGroupLambda',
                                                          code=aws_lambda.Code.from_asset(
                                                              "custom_resources"),
                                                          runtime=aws_lambda.Runtime.PYTHON_3_8,
                                                          handler='create_deployment_group.handler',
                                                          role=customLambdaServiceRole,
                                                          description="Custom resource to create deployment group",
                                                          memory_size=128,
                                                          timeout=core.Duration.seconds(
                                                              60)
                                                          )

        # ================================================================================================
        # CloudWatch Alarms for 4XX errors
        blue4xxMetric = aws_cloudwatch.Metric(
            namespace='AWS/ApplicationELB',
            metric_name='HTTPCode_Target_4XX_Count',
            dimensions={
                "TargetGroup": self.platform_resources.blue_target_full_name,
                "LoadBalancer": self.platform_resources.alb_full_name
            },
            statistic="sum",
            period=core.Duration.minutes(1)
        )

        self.blue_targetAlarm = aws_cloudwatch.Alarm(self, "blue4xxErrors",
                                                     alarm_name="Blue_4xx_Alarm",
                                                     alarm_description="CloudWatch Alarm for the 4xx errors of Blue target group",
                                                     metric=blue4xxMetric,
                                                     threshold=1,
                                                     evaluation_periods=1
                                                     )

        green4xxMetric = aws_cloudwatch.Metric(
            namespace='AWS/ApplicationELB',
            metric_name='HTTPCode_Target_4XX_Count',
            dimensions={
                "TargetGroup": self.platform_resources.green_target_full_name,
                "LoadBalancer": self.platform_resources.alb_full_name
            },
            statistic="sum",
            period=core.Duration.minutes(1)
        )
        self.green_targetAlarm = aws_cloudwatch.Alarm(self, "green4xxErrors",
                                                      alarm_name="Green_4xx_Alarm",
                                                      alarm_description="CloudWatch Alarm for the 4xx errors of Green target group",
                                                      metric=green4xxMetric,
                                                      threshold=1,
                                                      evaluation_periods=1
                                                      )

        # ================================================================================================
        # DUMMY TASK DEFINITION for the initial service creation
        # This is required for the service being made available to create the CodeDeploy Deployment Group
        # ================================================================================================
        sampleTaskDefinition = aws_ecs.FargateTaskDefinition(self, "sampleTaskDefn",
                                                             family=DUMMY_TASK_FAMILY_NAME,
                                                             cpu=256,
                                                             memory_limit_mib=1024,
                                                             task_role=ecsTaskRole,
                                                             execution_role=ecsTaskRole
                                                             )

        sampleContainerDefn = sampleTaskDefinition.add_container("sampleAppContainer",
                                                                 image=aws_ecs.ContainerImage.from_registry(
                                                                     DUMMY_CONTAINER_IMAGE),
                                                                 logging=aws_ecs.AwsLogDriver(
                                                                     log_group=aws_logs.LogGroup(self, "sampleAppLogGroup",
                                                                                                 log_group_name=DUMMY_APP_LOG_GROUP_NAME,
                                                                                                 removal_policy=core.RemovalPolicy.DESTROY
                                                                                                 ),
                                                                     stream_prefix=DUMMY_APP_NAME
                                                                 ),
                                                                 docker_labels={
                                                                     "name": DUMMY_APP_NAME
                                                                 }
                                                                 )

        port_mapping = aws_ecs.PortMapping(
            container_port=8080,
            protocol=aws_ecs.Protocol.TCP
        )

        sampleContainerDefn.add_port_mappings(port_mapping)

        # ================================================================================================
        # ECS task definition using ECR image
        # Will be used by the CODE DEPLOY for Blue/Green deployment
        # ================================================================================================
        OcticketingTaskDef = aws_ecs.FargateTaskDefinition(self, "appTaskDefn",
                                                           family=ECS_TASK_FAMILY_NAME,
                                                           cpu=256,

                                                           memory_limit_mib=1024,
                                                           task_role=ecsTaskRole,
                                                           execution_role=ecsTaskRole
                                                           )

        # =============================================================================
        octicketing_cont_def = OcticketingTaskDef.add_container("OcticketingAppContainer",
                                                                image=aws_ecs.ContainerImage.from_ecr_repository(
                                                                    self.octicketing_ecr_repo, "latest"),
                                                                logging=aws_ecs.AwsLogDriver(
                                                                    log_group=aws_logs.LogGroup(self, "OcticketingAppLogGroup",
                                                                                                log_group_name=ECS_APP_LOG_GROUP_NAME,
                                                                                                removal_policy=core.RemovalPolicy.DESTROY
                                                                                                ),
                                                                    stream_prefix=ECS_APP_NAME
                                                                ),
                                                                docker_labels={
                                                                    "name": ECS_APP_NAME
                                                                }
                                                                )
        octicketing_cont_def.add_port_mappings(port_mapping)

        # =============================================================================
        # ECS SERVICE for the Blue/ Green deployment
        # =============================================================================

        OcticketingAppService = aws_ecs.FargateService(self, "OcticketingAppService",
                                                       cluster=self.platform_resources.ecs_cluster,
                                                       task_definition=sampleTaskDefinition,
                                                       health_check_grace_period=core.Duration.seconds(
                                                           10),
                                                       platform_version=aws_ecs.FargatePlatformVersion.VERSION1_4,
                                                       desired_count=1,
                                                       deployment_controller={
                                                           "type": aws_ecs.DeploymentControllerType.CODE_DEPLOY
                                                       },
                                                       service_name=ECS_APP_NAME
                                                       )

        OcticketingAppService.connections.allow_from(
            self.platform_resources.alb, aws_ec2.Port.tcp(80))
        OcticketingAppService.connections.allow_from(
            self.platform_resources.alb, aws_ec2.Port.tcp(8080))
        OcticketingAppService.attach_to_application_target_group(
            self.platform_resources.blue_target)

        # =============================================================================
        # CODE DEPLOY - Deployment Group CUSTOM RESOURCE for the Blue/ Green deployment
        # =============================================================================

        core.CustomResource(self, 'customEcsDeploymentGroup',
                            service_token=createDeploymentGroupLambda.function_arn,
                            properties={
                                "ApplicationName": codeDeployApplication.application_name,
                                "DeploymentGroupName": ECS_DEPLOYMENT_GROUP_NAME,
                                "DeploymentConfigName": ECS_DEPLOYMENT_CONFIG_NAME,
                                "ServiceRoleArn": codeDeployServiceRole.role_arn,
                                "BlueTargetGroup": self.platform_resources.blue_target_name,
                                "GreenTargetGroup": self.platform_resources.green_target_name,
                                "ProdListenerArn": self.platform_resources.prod_listener.listener_arn,
                                "TestListenerArn": self.platform_resources.test_listener.listener_arn,
                                "EcsClusterName": self.platform_resources.ecs_cluster.cluster_name,
                                "EcsServiceName": OcticketingAppService.service_name,
                                "TerminationWaitTime": ECS_TASKSET_TERMINATION_WAIT_TIME,
                                "BlueGroupAlarm": self.blue_targetAlarm.alarm_name,
                                "GreenGroupAlarm": self.green_targetAlarm.alarm_name,
                            }
                            )

        ecsDeploymentGroup = codedeploy.EcsDeploymentGroup.from_ecs_deployment_group_attributes(self, "ecsDeploymentGroup",
                                                                                                application=codeDeployApplication,
                                                                                                deployment_group_name=ECS_DEPLOYMENT_GROUP_NAME,
                                                                                                deployment_config=codedeploy.EcsDeploymentConfig.from_ecs_deployment_config_name(
                                                                                                    self, "ecsDeploymentConfig", ECS_DEPLOYMENT_CONFIG_NAME)
                                                                                                )
        # =============================================================================
        # CODE BUILD PROJECT for the Blue/ Green deployment
        # =============================================================================

        # Creating the code build project
        OcticketingAppcodebuild = aws_codebuild.Project(self, "OcticketingAppcodebuild",
                                                        role=codeBuildServiceRole,
                                                        environment=aws_codebuild.BuildEnvironment(
                                                            build_image=aws_codebuild.LinuxBuildImage.STANDARD_4_0,
                                                            compute_type=aws_codebuild.ComputeType.SMALL,
                                                            privileged=True,
                                                            environment_variables={
                                                              'REPOSITORY_URI': {
                                                                  'value': self.octicketing_ecr_repo.repository_uri,
                                                                  'type': aws_codebuild.BuildEnvironmentVariableType.PLAINTEXT
                                                              },
                                                                'TASK_EXECUTION_ARN': {
                                                                  'value': ecsTaskRole.role_arn,
                                                                  'type': aws_codebuild.BuildEnvironmentVariableType.PLAINTEXT
                                                              },
                                                                'TASK_FAMILY': {
                                                                  'value': ECS_TASK_FAMILY_NAME,
                                                                  'type': aws_codebuild.BuildEnvironmentVariableType.PLAINTEXT
                                                              }
                                                            }
                                                        ),
                                                        source=aws_codebuild.Source.code_commit(
                                                            repository=self.octicketing_code_repo)
                                                        )

        # =============================================================================
        # CODE PIPELINE for Blue/Green ECS deployment
        # =============================================================================

        codePipelineServiceRole = aws_iam.Role(self, "codePipelineServiceRole",
                                               assumed_by=aws_iam.ServicePrincipal(
                                                   'codepipeline.amazonaws.com')
                                               )

        inlinePolicyForCodePipeline = aws_iam.PolicyStatement(
            effect=aws_iam.Effect.ALLOW,
            actions=[
                "iam:PassRole",
                "sts:AssumeRole",
                "codecommit:Get*",
                "codecommit:List*",
                "codecommit:GitPull",
                "codecommit:UploadArchive",
                "codecommit:CancelUploadArchive",
                "codebuild:BatchGetBuilds",
                "codebuild:StartBuild",
                "codedeploy:CreateDeployment",
                "codedeploy:Get*",
                "codedeploy:RegisterApplicationRevision",
                "s3:Get*",
                "s3:List*",
                "s3:PutObject"
            ],
            resources=["*"]
        )

        codePipelineServiceRole.add_to_policy(inlinePolicyForCodePipeline)

        sourceArtifact = codepipeline.Artifact('sourceArtifact')
        buildArtifact = codepipeline.Artifact('buildArtifact')

        # S3 bucket for storing the code pipeline artifacts
        OcticketingAppArtifactsBucket = s3.Bucket(self, "OcticketingAppArtifactsBucket",
                                                  encryption=s3.BucketEncryption.S3_MANAGED,
                                                  block_public_access=s3.BlockPublicAccess.BLOCK_ALL
                                                  )

        # S3 bucket policy for the code pipeline artifacts
        denyUnEncryptedObjectUploads = aws_iam.PolicyStatement(
            effect=aws_iam.Effect.DENY,
            actions=["s3:PutObject"],
            principals=[aws_iam.AnyPrincipal()],
            resources=[OcticketingAppArtifactsBucket.bucket_arn+"/*"],
            conditions={
                "StringNotEquals": {
                    "s3:x-amz-server-side-encryption": "aws:kms"
                }
            }
        )

        denyInsecureConnections = aws_iam.PolicyStatement(
            effect=aws_iam.Effect.DENY,
            actions=["s3:*"],
            principals=[aws_iam.AnyPrincipal()],
            resources=[OcticketingAppArtifactsBucket.bucket_arn+"/*"],
            conditions={
                "Bool": {
                    "aws:SecureTransport": "false"
                }
            }
        )

        OcticketingAppArtifactsBucket.add_to_resource_policy(
            denyUnEncryptedObjectUploads)
        OcticketingAppArtifactsBucket.add_to_resource_policy(
            denyInsecureConnections)

        # Code Pipeline - CloudWatch trigger event is created by CDK
        codepipeline.Pipeline(self, "ecsBlueGreen",
                              role=codePipelineServiceRole,
                              artifact_bucket=OcticketingAppArtifactsBucket,
                              stages=[
                                  codepipeline.StageProps(
                                      stage_name='Source',
                                      actions=[
                                          aws_codepipeline_actions.CodeCommitSourceAction(
                                              action_name='Source',
                                              repository=self.octicketing_code_repo,
                                              output=sourceArtifact,
                                          )
                                      ]
                                  ),
                                  codepipeline.StageProps(
                                      stage_name='Build',
                                      actions=[
                                          aws_codepipeline_actions.CodeBuildAction(
                                              action_name='Build',
                                              project=OcticketingAppcodebuild,
                                              input=sourceArtifact,
                                              outputs=[buildArtifact]
                                          )
                                      ]
                                  ),
                                  codepipeline.StageProps(
                                      stage_name='Deploy',
                                      actions=[
                                          aws_codepipeline_actions.CodeDeployEcsDeployAction(
                                              action_name='Deploy',
                                              deployment_group=ecsDeploymentGroup,
                                              app_spec_template_input=buildArtifact,
                                              task_definition_template_input=buildArtifact,
                                          )
                                      ]
                                  )
                              ]
                              )

        # =============================================================================
        # Export the outputs
        # =============================================================================
        core.CfnOutput(self, "ecsBlueGreenCodeRepo",
                       description="Demo app code commit repository",
                       export_name="ecsBlueGreenDemoAppRepo",
                       value=self.octicketing_code_repo.repository_clone_url_http
                       )
