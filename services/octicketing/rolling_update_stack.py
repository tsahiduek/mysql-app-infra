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

        # alb_arn = core.Fn.import_value(group_name+'ALBarn')
        # alb_sg_id = core.Fn.import_value(group_name+'ALBSgId')
        # self.alb = elbv2.ApplicationLoadBalancer.from_application_load_balancer_attributes(self, 'ALB',
        #                                                                                    load_balancer_arn=alb_arn,
        #                                                                                    security_group_id=alb_sg_id
        #                                                                                    )
        # self.alb_name = core.Fn.import_value(group_name+'ALBName')
        # self.alb_full_name = core.Fn.import_value(group_name+'ALBFullName')


class RollingUpdate(core.Stack):

    def __init__(self, scope: core.Construct, id: str, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)
        self.platform_resources = ImportedResources(self, self.stack_name)

        ###

        ECS_APP_NAME_SHORT = "octi-ru"
        ECS_APP_NAME = "octicketing-ru"
        # ECS_DEPLOYMENT_GROUP_NAME = "octicketingECSBlueGreen"
        # ECS_DEPLOYMENT_CONFIG_NAME = "CodeDeployDefault.ECSLinear10PercentEvery1Minutes"
        # ECS_DEPLOYMENT_CONFIG_ALL = "CodeDeployDefault.ECSAllAtOnce"
        ECS_TASKSET_TERMINATION_WAIT_TIME = 10
        ECS_TASK_FAMILY_NAME = "octicketing-ru-service"
        ECS_APP_LOG_GROUP_NAME = "/ecs/" + ECS_TASK_FAMILY_NAME

        DUMMY_APP_NAME = "hello-world-microservice"
        DUMMY_TASK_FAMILY_NAME = "hello-world-service"
        DUMMY_APP_LOG_GROUP_NAME = "/ecs/dummy-" + ECS_TASK_FAMILY_NAME
        DUMMY_CONTAINER_IMAGE = self.account + ".dkr.ecr." + \
            self.region + ".amazonaws.com/hello-world:latest"
        # =============================================================================
        # ECR and CodeCommit repositories for the Blue/ Green deployment
        # =============================================================================

        # ECR repository for the docker images
        self.octicketing_ecr_repo = aws_ecr.Repository(
            self, ECS_APP_NAME_SHORT + "-repo",
            repository_name=ECS_APP_NAME,
            removal_policy=core.RemovalPolicy.DESTROY
        )

        self.octicketing_code_repo = aws_codecommit.Repository(
            self, ECS_APP_NAME, repository_name=ECS_APP_NAME, description=ECS_APP_NAME + "rolling update demo service repository")
        # core.CfnOutput(self, 'BGRepoName',
        #                value=self.octicketing_code_repo.repository_name, export_name='OcticketingBGRepoName')
        # core.CfnOutput(self, 'BGRepoARN',
        #                value=self.octicketing_code_repo.repository_arn, export_name='OcticketingBGRepoARN')

        # =============================================================================
        #   CODE BUILD and ECS TASK ROLES
        # =============================================================================

        # IAM role for the Code Build project
        codeBuildServiceRole = aws_iam.Role(self, ECS_APP_NAME + "codeBuildServiceRole",
                                            assumed_by=aws_iam.ServicePrincipal(
                                                'codebuild.amazonaws.com')
                                            )
        # ecr:BatchGetImage
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
        ecsTaskRole = aws_iam.Role(self, ECS_APP_NAME + "ecsTaskRoleForWorkshop",
                                   assumed_by=aws_iam.ServicePrincipal(
                                       'ecs-tasks.amazonaws.com')
                                   )

        ecsTaskRole.add_managed_policy(aws_iam.ManagedPolicy.from_aws_managed_policy_name(
            "service-role/AmazonECSTaskExecutionRolePolicy"))
        ecsTaskRole.add_managed_policy(aws_iam.ManagedPolicy.from_aws_managed_policy_name(
            "SecretsManagerReadWrite"))
        # ================================================================================================
        # ALB and Listener and Targetgroup
        # ================================================================================================
        self.alb_security_group = aws_ec2.SecurityGroup(
            self, ECS_APP_NAME + "-alb-sg-ru", vpc=self.platform_resources.vpc, allow_all_outbound=True)
        # Creating an application load balancer, listener and two target groups for Blue/Green deployment
        self.alb = elbv2.ApplicationLoadBalancer(self, ECS_APP_NAME + "alb",
                                                 load_balancer_name=ECS_APP_NAME,
                                                 vpc=self.platform_resources.vpc,
                                                 security_group=self.alb_security_group,
                                                 internet_facing=True
                                                 )
        self.rolling_update_service_listener = self.alb.add_listener(
            ECS_APP_NAME + '-listner', port=80)

        self.rolling_update_service_listener.connections.allow_default_port_from_any_ipv4(
            'Allow traffic from everywhere on port 8090')

        # rolling update target group
        self.rolling_update_target_group = elbv2.ApplicationTargetGroup(self, ECS_APP_NAME + "-tg",
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
        self.rolling_update_service_listener.add_target_groups(ECS_APP_NAME + "-add-tg",
                                                               target_groups=[self.rolling_update_target_group])

        # ================================================================================================
        # DUMMY TASK DEFINITION for the initial service creation
        # This is required for the service being made available to create the CodeDeploy Deployment Group
        # ================================================================================================
        sampleTaskDefinition = aws_ecs.FargateTaskDefinition(self, ECS_APP_NAME+"sampleTaskDefn",
                                                             family=DUMMY_TASK_FAMILY_NAME,
                                                             cpu=256,
                                                             memory_limit_mib=1024,
                                                             task_role=ecsTaskRole,
                                                             execution_role=ecsTaskRole
                                                             )

        sampleContainerDefn = sampleTaskDefinition.add_container(ECS_APP_NAME + "sampleAppContainer",
                                                                 image=aws_ecs.ContainerImage.from_registry(
                                                                     DUMMY_CONTAINER_IMAGE),
                                                                 logging=aws_ecs.AwsLogDriver(
                                                                     log_group=aws_logs.LogGroup(self, ECS_APP_NAME + "sampleAppLogGroup",
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
        self.oticketing_task_def_ru = aws_ecs.FargateTaskDefinition(self, ECS_APP_NAME + "task-def",
                                                                    family=ECS_TASK_FAMILY_NAME,
                                                                    cpu=256,

                                                                    memory_limit_mib=1024,
                                                                    task_role=ecsTaskRole,
                                                                    execution_role=ecsTaskRole
                                                                    )

        # =============================================================================
        self.octicketing_cont_def = self.oticketing_task_def_ru.add_container(ECS_APP_NAME + "OcticketingAppContainer",
                                                                              image=aws_ecs.ContainerImage.from_ecr_repository(
                                                                                  self.octicketing_ecr_repo, "latest"),
                                                                              logging=aws_ecs.AwsLogDriver(
                                                                                  log_group=aws_logs.LogGroup(self, ECS_APP_NAME + "OcticketingAppLogGroup",
                                                                                                              log_group_name=ECS_APP_LOG_GROUP_NAME,
                                                                                                              removal_policy=core.RemovalPolicy.DESTROY
                                                                                                              ),
                                                                                  stream_prefix=ECS_APP_NAME
                                                                              ),
                                                                              docker_labels={
                                                                                  "name": ECS_APP_NAME
                                                                              }
                                                                              )
        self.octicketing_cont_def.add_port_mappings(port_mapping)

        # =============================================================================
        # ECS SERVICE for the Blue/ Green deployment
        # =============================================================================
        # OcticketingAppService = aws_ecs.FargateService(self, "OcticketingAppService",
        #                                                cluster=self.platform_resources.ecs_cluster,
        #                                                task_definition=self.oticketing_task_def_ru,
        #                                                health_check_grace_period=core.Duration.seconds(
        #                                                    10),
        #                                                desired_count=0,
        #                                                deployment_controller={
        #                                                    "type": aws_ecs.DeploymentControllerType.CODE_DEPLOY
        #                                                },
        #                                                service_name=ECS_APP_NAME
        #                                                )
        OcticketingAppService = aws_ecs.FargateService(self, ECS_APP_NAME + "OcticketingAppService",
                                                       cluster=self.platform_resources.ecs_cluster,
                                                       task_definition=sampleTaskDefinition,
                                                       health_check_grace_period=core.Duration.seconds(
                                                           10),
                                                       platform_version=aws_ecs.FargatePlatformVersion.VERSION1_4,
                                                       desired_count=1,
                                                       #    deployment_controller={
                                                       #        "type": aws_ecs.DeploymentControllerType.CODE_DEPLOY
                                                       #    },
                                                       service_name=ECS_APP_NAME
                                                       )

        OcticketingAppService.connections.allow_from(
            self.alb, aws_ec2.Port.tcp(8080))
        OcticketingAppService.attach_to_application_target_group(
            self.rolling_update_target_group)

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
                                  )
                              ]
                              )
