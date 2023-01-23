# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from ..samples.microservices import tinymicro, tinymicro_deception_v1, tinymicro_deception_latest
from . import cyberbattle_env


class CyberBattleTinyMicro(cyberbattle_env.CyberBattleEnv):
    """CyberBattle simulation on a tiny environment. (Useful for debugging purpose)"""

    def __init__(self, **kwargs):
        super().__init__(
            initial_environment=tinymicro.new_environment(),
            **kwargs)


class CyberBattleTinyMicroV1(cyberbattle_env.CyberBattleEnv):
    """CyberBattle simulation on a tiny environment. (Useful for debugging purpose)"""

    def __init__(self, **kwargs):
        super().__init__(
            initial_environment=tinymicro_deception_v1.new_environment(),
            **kwargs)


class CyberBattleTinyMicroLatest(cyberbattle_env.CyberBattleEnv):
    """CyberBattle simulation on a tiny environment. (Useful for debugging purpose)"""

    def __init__(self, **kwargs):
        super().__init__(
            initial_environment=tinymicro_deception_latest.new_environment(),
            **kwargs)
