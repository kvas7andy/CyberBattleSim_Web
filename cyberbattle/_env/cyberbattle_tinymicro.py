# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from ..samples.microservices import tinymicro, tinymicro_deception_dp_only, tinymicro_deception_full
from ..samples.microservices import tinymicro_deception_ht1, tinymicro_deception_ht2, tinymicro_deception_ht3, tinymicro_deception_ht4
from ..samples.microservices import tinymicro_deception_ht12, tinymicro_deception_ht13, tinymicro_deception_ht14
from ..samples.microservices import tinymicro_deception_ht23, tinymicro_deception_ht24, tinymicro_deception_ht34
from ..samples.microservices import tinymicro_deception_ht123, tinymicro_deception_ht1234
from . import cyberbattle_env


class CyberBattleTinyMicroHT(cyberbattle_env.CyberBattleEnv):
    """CyberBattle simulation on a tiny environment. (Useful for debugging purpose)"""

    def __init__(self, initial_environment, **kwargs):
        super().__init__(
            initial_environment=initial_environment,
            **kwargs)


class CyberBattleTinyMicro(cyberbattle_env.CyberBattleEnv):
    """CyberBattle simulation on a tiny environment. (Useful for debugging purpose)"""

    def __init__(self, **kwargs):
        super().__init__(
            initial_environment=tinymicro.new_environment(),
            **kwargs)


class CyberBattleTinyMicroHT1(cyberbattle_env.CyberBattleEnv):
    """CyberBattle simulation on a tiny environment. (Useful for debugging purpose)"""

    def __init__(self, **kwargs):
        super().__init__(
            initial_environment=tinymicro_deception_ht1.new_environment(),
            **kwargs)


class CyberBattleTinyMicroHT12(cyberbattle_env.CyberBattleEnv):
    """CyberBattle simulation on a tiny environment. (Useful for debugging purpose)"""

    def __init__(self, **kwargs):
        super().__init__(
            initial_environment=tinymicro_deception_ht12.new_environment(),
            **kwargs)


class CyberBattleTinyMicroHT13(cyberbattle_env.CyberBattleEnv):
    """CyberBattle simulation on a tiny environment. (Useful for debugging purpose)"""

    def __init__(self, **kwargs):
        super().__init__(
            initial_environment=tinymicro_deception_ht13.new_environment(),
            **kwargs)


class CyberBattleTinyMicroHT14(cyberbattle_env.CyberBattleEnv):
    """CyberBattle simulation on a tiny environment. (Useful for debugging purpose)"""

    def __init__(self, **kwargs):
        super().__init__(
            initial_environment=tinymicro_deception_ht14.new_environment(),
            **kwargs)


class CyberBattleTinyMicroHT23(cyberbattle_env.CyberBattleEnv):
    """CyberBattle simulation on a tiny environment. (Useful for debugging purpose)"""

    def __init__(self, **kwargs):
        super().__init__(
            initial_environment=tinymicro_deception_ht23.new_environment(),
            **kwargs)


class CyberBattleTinyMicroHT24(cyberbattle_env.CyberBattleEnv):
    """CyberBattle simulation on a tiny environment. (Useful for debugging purpose)"""

    def __init__(self, **kwargs):
        super().__init__(
            initial_environment=tinymicro_deception_ht24.new_environment(),
            **kwargs)


class CyberBattleTinyMicroHT34(cyberbattle_env.CyberBattleEnv):
    """CyberBattle simulation on a tiny environment. (Useful for debugging purpose)"""

    def __init__(self, **kwargs):
        super().__init__(
            initial_environment=tinymicro_deception_ht34.new_environment(),
            **kwargs)


class CyberBattleTinyMicroHT123(cyberbattle_env.CyberBattleEnv):
    """CyberBattle simulation on a tiny environment. (Useful for debugging purpose)"""

    def __init__(self, **kwargs):
        super().__init__(
            initial_environment=tinymicro_deception_ht123.new_environment(),
            **kwargs)


class CyberBattleTinyMicroHT1234(cyberbattle_env.CyberBattleEnv):
    """CyberBattle simulation on a tiny environment. (Useful for debugging purpose)"""

    def __init__(self, **kwargs):
        super().__init__(
            initial_environment=tinymicro_deception_ht1234.new_environment(),
            **kwargs)


class CyberBattleTinyMicroHT2(cyberbattle_env.CyberBattleEnv):
    """CyberBattle simulation on a tiny environment. (Useful for debugging purpose)"""

    def __init__(self, **kwargs):
        super().__init__(
            initial_environment=tinymicro_deception_ht2.new_environment(),
            **kwargs)


class CyberBattleTinyMicroHT3(cyberbattle_env.CyberBattleEnv):
    """CyberBattle simulation on a tiny environment. (Useful for debugging purpose)"""

    def __init__(self, **kwargs):
        super().__init__(
            initial_environment=tinymicro_deception_ht3.new_environment(),
            **kwargs)


class CyberBattleTinyMicroHT4(cyberbattle_env.CyberBattleEnv):
    """CyberBattle simulation on a tiny environment. (Useful for debugging purpose)"""

    def __init__(self, **kwargs):
        super().__init__(
            initial_environment=tinymicro_deception_ht4.new_environment(),
            **kwargs)


class CyberBattleTinyMicroFull(cyberbattle_env.CyberBattleEnv):
    """CyberBattle simulation on a tiny environment. (Useful for debugging purpose)"""

    def __init__(self, **kwargs):
        super().__init__(
            initial_environment=tinymicro_deception_full.new_environment(),
            **kwargs)


class CyberBattleTinyMicroDPLatest(cyberbattle_env.CyberBattleEnv):
    """CyberBattle simulation on a tiny environment. (Useful for debugging purpose)"""

    def __init__(self, **kwargs):
        super().__init__(
            initial_environment=tinymicro_deception_dp_only.new_environment(),
            **kwargs)
