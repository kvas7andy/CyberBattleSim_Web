# %%
# !pip install stable-baselines3[extra]

# %%
import torch as th
from typing import cast
from cyberbattle._env.cyberbattle_env import CyberBattleEnv
from cyberbattle._env.cyberbattle_toyctf import CyberBattleToyCtf
from cyberbattle._env.cyberbattle_tiny import CyberBattleTiny
from cyberbattle._env.cyberbattle_tinymicro import CyberBattleTinyMicroFull

import logging
import sys
from stable_baselines3.a2c.a2c import A2C
from stable_baselines3.ppo.ppo import PPO
from stable_baselines3.common.env_util import make_vec_env
from stable_baselines3.common.monitor import Monitor
from stable_baselines3.common.callbacks import BaseCallback
from stable_baselines3.common.logger import TensorBoardOutputFormat
from stable_baselines3.common.vec_env import DummyVecEnv, SubprocVecEnv, VecEnv
from cyberbattle._env.flatten_wrapper import FlattenObservationWrapper, FlattenActionWrapper
import os
# th.cuda.set_device('cuda:3')
device = th.device("cuda" if th.cuda.is_available() else "cpu")
# th.cuda.set_device(device)
retrain = ['a2c']


class SummaryWriterCallback(BaseCallback):
    '''
    Snippet skeleton from Stable baselines3 documentation here:
    https://stable-baselines3.readthedocs.io/en/master/guide/tensorboard.html#directly-accessing-the-summary-writer
    '''

    def _on_training_start(self):
        self._log_freq = 10  # log every 10 calls

        output_formats = self.logger.output_formats
        # Save reference to tensorboard formatter object
        # note: the failure case (not formatter found) is not handled here, should be done with try/except.
        self.tb_formatter = next(formatter for formatter in output_formats if isinstance(formatter, TensorBoardOutputFormat))

    def _on_step(self) -> bool:
        '''
        Log my_custom_reward every _log_freq(th) to tensorboard for each environment
        '''
        if self.n_calls % self._log_freq == 0:
            rewards = self.locals['rewards']
            for i in range(self.locals['env'].num_envs):
                self.tb_formatter.writer.add_scalar("rewards/env #{}".format(i + 1),
                                                    rewards[i],
                                                    self.n_calls)


# %%

logging.basicConfig(stream=sys.stdout, level=logging.ERROR, format="%(levelname)s: %(message)s")

# %%
env = CyberBattleTinyMicroFull(
    maximum_node_count=12,
    maximum_total_credentials=10,
    observation_padding=True,
    throws_on_invalid_actions=False,
)


# %%
env1 = FlattenActionWrapper(env)

# %%
# MultiBinary
#  'action_mask',
#  'customer_data_found',
# MultiDiscrete space
#  'nodes_privilegelevel',
#  'leaked_credentials',
#  'credential_cache_matrix'
#  'discovered_nodes_properties',

ignore_fields = [
    # DummySpace
    '_credential_cache',
    '_discovered_nodes',
    '_explored_network',
]
env2 = FlattenObservationWrapper(cast(CyberBattleEnv, env1), ignore_fields=ignore_fields)

log_dir = os.path.join('/logs/exper/stablebaselines', str(env))


def return_env(env) -> CyberBattleEnv:
    return cast(CyberBattleEnv, env)


if __name__ == "__main__":
    env3 = make_vec_env(FlattenObservationWrapper, n_envs=4, vec_env_cls=SubprocVecEnv,
                        env_kwargs=dict(env=cast(CyberBattleEnv, env1), ignore_fields=ignore_fields), monitor_dir=log_dir)
    env_last = env3  # Monitor(env3, log_dir)

# %%
    if 'a2c' in retrain:
        model_a2c = A2C("MultiInputPolicy", env_last, tensorboard_log=log_dir, verbose=1).learn(
            1e4, callback=SummaryWriterCallback())  # logger=None
        model_a2c.save('a2c_trained_toyctf')

    # %%
    if 'ppo' in retrain:
        model_ppo = PPO("MultiInputPolicy", env2, tensorboard_log=log_dir, verbose=1).learn(
            1000, progress_bar=True)
        model_ppo.save('ppo_trained_toyctf')

    # %%
    model = A2C("MultiInputPolicy", env2).load('a2c_trained_toyctf')
    # model = PPO("MultiInputPolicy", env2).load('ppo_trained_toyctf')

    # %%
    obs = env2.reset()
    for i in range(100):
        action, _states = model.predict(obs, deterministic=True)
        obs, reward, done, info = env2.step(action)

    env2.render()
    env2.close()
