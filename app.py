#!/usr/bin/env python3

from aws_cdk import core
from infra import (
    vpc,
    ecs,
    rds
)

from services.octicketing import(
    alb_bg,
    rolling_update_stack,
    bluegreen_stack

)
from os import getenv


_env = core.Environment(account=getenv('CDK_DEFAULT_ACCOUNT'),
                        region=getenv('CDK_DEFAULT_REGION'))
app = core.App()

vpc.OctankSupportInfra(app, 'octank-support-vpc', env=_env)
ecs.OctankSupportECS(app, 'octank-support-ecs', env=_env)
rds.OctankSupportRds(app, 'octank-support-rds', env=_env)
alb_bg.OcticketingALBBlueGreen(app, 'octicketing-alb-bg', env=_env)
bluegreen_stack.BlueGreen(app, 'octicketing-bluegreen', env=_env)
rolling_update_stack.RollingUpdate(app, 'octicketing-rolling-update', env=_env)

app.synth()
