# ---
# jupyter:
#   jupytext:
#     cell_metadata_filter: tags,title,-all
#     cell_metadata_json: true
#     text_representation:
#       extension: .py
#       format_name: percent
#       format_version: '1.3'
#       jupytext_version: 1.6.0
# ---

# %%
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Notebook used for debugging purpose to train the
the DQL agent and then run it one step at a time.
"""

# pylint: disable=invalid-name

# %%
import sys
import os
import logging
import gym
from cyberbattle.agents.baseline.agent_wrapper import ActionTrackingStateAugmentation, AgentWrapper, Verbosity
import cyberbattle.agents.baseline.agent_dql as dqla
import cyberbattle.agents.baseline.agent_wrapper as w
import cyberbattle.agents.baseline.learner as learner

import pandas as pd
import torch

# torch.cuda.set_device('cuda:3')
log_level_dict = {"info": logging.INFO, "error": logging.ERROR, "debug": logging.DEBUG, "warn": logging.WARN, }
logging.basicConfig(stream=sys.stdout, level=log_level_dict[os.environ["LOG_LEVEL"]], format="%(levelname)s: %(message)s")
LOGGER = logging.getLogger('agent_dql')
# LOGGER.setLevel(logging.ERROR)


# %% {"tags": ["parameters"]}
gymid = 'CyberBattleTinyMicro-v0'
log_dir = 'logs/exper/debug'
log_dir = os.path.join(log_dir, gymid)
os.makedirs(log_dir, exist_ok=True)


# %%
# Load the gym environment

ctf_env = gym.make(gymid)

iteration_count = ctf_env.spec.max_episode_steps
training_episode_count = 50
train_while_exploit = False

ep = w.EnvironmentBounds.of_identifiers(
    maximum_node_count=12,
    maximum_total_credentials=10,
    identifiers=ctf_env.identifiers
)

# %%
# Evaluate the Deep Q-learning agent
learning_rate = 0.01  # 0.01
gamma = 0.015  # 0.015
epsilon_exponential_decay = 5000
dqn_learning_run = learner.epsilon_greedy_search(
    cyberbattle_gym_env=ctf_env,
    environment_properties=ep,
    learner=dqla.DeepQLearnerPolicy(
        ep=ep,
        gamma=gamma,
        replay_memory_size=10000,
        target_update=5,
        batch_size=512,
        learning_rate=learning_rate  # torch default learning rate is 1e-2
    ),
    episode_count=training_episode_count,
    iteration_count=iteration_count,
    epsilon=0.90,
    epsilon_exponential_decay=epsilon_exponential_decay,
    epsilon_minimum=0.10,
    verbosity=Verbosity.Quiet,
    render=False,
    plot_episodes_length=False,
    title="DQL"
)

# %%
# initialize the environment

logging.info("Now evaluate trained network")

current_o = ctf_env.reset()
wrapped_env = AgentWrapper(ctf_env, ActionTrackingStateAugmentation(ep, current_o))
l = dqn_learning_run['learner']

# %%
# Use the trained agent to run the steps one by one

max_steps = iteration_count
verbosity = Verbosity.Normal
l.train_while_exploit = train_while_exploit
l.policy_net.eval()

log_results = os.environ["LOG_RESULTS"]

# next action suggested by DQL agent
h = []
done = False
cum_reward = 0
for i in range(max_steps):
    if done:
        break
    # run the suggested action
    action_style, next_action, _ = l.exploit(wrapped_env, current_o)

    if next_action is None:
        print("Next action == None, returned with aciton_style: ", action_style)
        break
    current_o, reward, done, _ = wrapped_env.step(next_action)
    cum_reward += reward
    action_str, reward_str = wrapped_env.pretty_print_internal_action(next_action, output_reward_str=True)
    h.append((i,  # ctf_env.get_explored_network_node_properties_bitmap_as_numpy(current_o),
              reward, cum_reward,
              action_str, action_style, reward_str))  # "\t action  validity: " +
    # if verbosity == Verbosity.Verbose or (verbosity == Verbosity.Normal and reward > 0) or not i % 10:
    # print(f"Step: {i}\t", end="")
    # if verbosity == Verbosity.Verbose:
    #     print(f"network_bitmap_explore: {h[-1][0]}")
    # print(f"reward:{h[-1][1]}\t cumulative reward: {cum_reward}\t next_action: {h[-1][2]}\t reward_string: {h[-1][3]}")

df = pd.DataFrame(h, columns=["Step", "Reward", "Cumulative Reward", "Next action", "Processes by", "Reward string"])
df.set_index("Step")
print(df.to_string())

if log_results:
    os.makedirs(log_dir, exist_ok=True)
    df.to_csv(os.path.join(log_dir, f'exploit_train_{train_while_exploit}_{training_episode_count}_episodes_output.csv'),
              index=False)
print(f'len: {len(h)}, cumulative reward: {cum_reward}')

# %%
ctf_env.render(filename=None if not log_results else
               os.path.join(log_dir, f'exploit_train_{train_while_exploit}_{training_episode_count}_episodes_output_result.png'))
