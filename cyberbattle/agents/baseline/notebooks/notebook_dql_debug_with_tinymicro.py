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
import datetime
from IPython.display import display
from cyberbattle.agents.baseline.agent_wrapper import ActionTrackingStateAugmentation, AgentWrapper, Verbosity
import cyberbattle.agents.baseline.agent_dql as dqla
import cyberbattle.agents.baseline.agent_wrapper as w
import cyberbattle.agents.baseline.learner as learner

import pandas as pd
from dotenv import load_dotenv

load_dotenv()

# %% {"tags": ["parameters"]}
gymid = 'CyberBattleTinyMicro-v0'
log_dir = 'logs/exper/dql_debug'
# convert the datetime object to string of specific format
datetime_str = datetime.datetime.now().strftime("%y%m%d_%H%M%S")
log_dir = os.path.join(log_dir, gymid, datetime_str)

log_results = os.getenv("LOG_RESULTS", 'False').lower() in ('true', '1', 't')

if log_results:
    os.makedirs(log_dir, exist_ok=True)

# torch.cuda.set_device('cuda:3')
log_level_dict = {"info": logging.INFO, "error": logging.ERROR, "debug": logging.DEBUG, "warn": logging.WARN, }
logging.basicConfig(level=log_level_dict[os.environ["LOG_LEVEL"]],
                    format="[%(asctime)s] %(levelname)s: %(message)s", datefmt='%H:%M:%S',
                    handlers=[logging.StreamHandler(sys.stdout)] + ([logging.FileHandler(os.path.join(log_dir, 'logfile.txt'))] if log_results else []))

LOGGER = logging.getLogger()
# LOGGER.setLevel(logging.ERROR)

# %%
# Load the gym environment

ctf_env = gym.make(gymid)
ctf_env.spec.max_episode_steps = 50

iteration_count = ctf_env.spec.max_episode_steps
training_episode_count = 50
train_while_exploit = True
exploit_train = "exploit_train"   # "exploit_manual"

ep = w.EnvironmentBounds.of_identifiers(
    maximum_node_count=7,
    maximum_total_credentials=1,
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

# logging.basicConfig(level=logging.INFO)
# LOGGER = logging.getLogger('actions')
LOGGER.setLevel(logging.INFO)

LOGGER.info("Logging into directory " + log_dir)
LOGGER.info("")
LOGGER.info("Now evaluate trained network")

current_o = ctf_env.reset()
wrapped_env = AgentWrapper(ctf_env, ActionTrackingStateAugmentation(ep, current_o))
l = dqn_learning_run['learner']

# %%
# Use the trained agent to run the steps one by one

max_steps = iteration_count
verbosity = Verbosity.Normal
l.train_while_exploit = train_while_exploit
l.policy_net.eval()

# next action suggested by DQL agent
h = []
done = False
cum_reward = 0
for i in range(max_steps):
    LOGGER.info("")
    if done:
        break
    # run the suggested action
    action_style, next_action, _ = l.exploit(wrapped_env, current_o)

    if next_action is None:
        LOGGER.info(f"Inference ended with error: next action == None, returned with aciton_style {action_style}")
        break
    current_o, reward, done, info = wrapped_env.step(next_action)
    cum_reward += reward
    action_str, reward_str = wrapped_env.internal_action_to_pretty_print(next_action, output_reward_str=True)
    h.append((i,  # ctf_env.get_explored_network_node_properties_bitmap_as_numpy(current_o),
              reward, cum_reward,
              action_str, action_style, info['precondition_str'], info['profile_str'], info["reward_string"]))  # "\t action  validity: " +
    # if verbosity == Verbosity.Verbose or (verbosity == Verbosity.Normal and reward > 0) or not i % 10:
    # print(f"Step: {i}\t", end="")
    # if verbosity == Verbosity.Verbose:
    #     print(f"network_bitmap_explore: {h[-1][0]}")
    # print(f"reward:{h[-1][1]}\t cumulative reward: {cum_reward}\t next_action: {h[-1][2]}\t reward_string: {h[-1][3]}")

df = pd.DataFrame(h, columns=["Step", "Reward", "Cumulative Reward", "Next action", "Processed by", "Precondition", "Profile", "Reward string"])
df.set_index("Step", inplace=True)
pd.set_option("max_colwidth", 80)
display(df)

if log_results:
    os.makedirs(log_dir, exist_ok=True)
    df.to_csv(os.path.join(log_dir, f'{exploit_train}_{train_while_exploit*"train_while_exploit"}_step{i}_trainepisodes{training_episode_count}_episodes_output.csv'),
              index=False)
print(f'len: {len(h)}, cumulative reward: {cum_reward}')

# %%
wrapped_env.render(filename=None if not log_results else
                   os.path.join(log_dir, f'{exploit_train}_{train_while_exploit*"train_while_exploit"}_step{i}_trainepisodes{training_episode_count}_episodes_output_result.png'))
