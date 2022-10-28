# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from ..samples.microservices import tinymicro
from . import cyberbattle_env


class CyberBattleTinyMicro(cyberbattle_env.CyberBattleEnv):
    """CyberBattle simulation on a tiny environment. (Useful for debugging purpose)"""

    def __init__(self, **kwargs):
        super().__init__(
            initial_environment=tinymicro.new_environment(),
            **kwargs)
