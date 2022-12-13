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
import cyberbattle.agents.baseline.agent_wrapper as w

import pandas as pd
from dotenv import load_dotenv

load_dotenv()

# %% {"tags": ["parameters"]}
gymid = 'CyberBattleTinyMicro-v0'
log_dir = 'logs/exper/debug'
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
ctf_env.spec.max_episode_steps = 40

iteration_count = ctf_env.spec.max_episode_steps
training_episode_count = None
train_while_exploit = False
exploit_train = "exploit_manual"   # "exploit_train"

ep = w.EnvironmentBounds.of_identifiers(
    maximum_node_count=7,
    maximum_total_credentials=1,
    identifiers=ctf_env.identifiers
)


LOGGER.setLevel(logging.INFO)

LOGGER.info("Logging into directory " + log_dir)
LOGGER.info("")

ctf_env_2 = gym.make(gymid, env_bounds=ep)

current_o = ctf_env_2.reset()
wrapped_env = AgentWrapper(ctf_env_2, ActionTrackingStateAugmentation(ep, current_o))


max_steps = iteration_count
verbosity = Verbosity.Normal


# !!! Track Profiles data yourself and make EXACT string for profiles, etc. do not forget about found properties, like id, roles.
# Choosing ip.local means
# 1) we found ip.local and registered as self.__ip_local flag;
# 2) the profiles are still writen with ip = None, but you can use ip.local in profile_str to turn on/off SSRF action
manual_commands = [
    {'local': ['client_browser', 'ScanPageSource']},
    {'local': ['client_browser', 'ScanBlockRegister']},
    {'remote': ['client_browser', 'POST_/v2/register', "username.NoAuth", ""]},
    {'remote': ['client_browser', 'GET_/v2/calendar', "username.patient&id.UUIDfake", ""]},
    {'remote': ['client_browser', 'GET_/v2/users', "username.LisaGWhite", "username"]},
    {'remote': ['client_browser', 'GET_/v2/messages', "username.LisaGWhite&id.994D5244&roles.isDoctor", ""]},
    {'remote': ['client_browser', 'GET_/v2/users', "username.MarioDFiles", "username"]},
    {'remote': ['client_browser', 'GET_/v2/messages', "username.MarioDFiles&id.F5BCFE9D&roles.isDoctor", ""]},
    # {'remote': ['client_browser', 'GET_/v2/users', "username.LisaGWhite&id.994D5244&roles.isDoctor", ""]},
    {'remote': ['client_browser', 'GET_/v2/users', "username.LisaGWhite&id.994D5244&roles.isDoctor&ip.local", ""]},
    # {'remote': ['client_browser', 'GET_/v2/users', "username.MarioDFiles&id.F5BCFE9D&roles.isDoctor&ip.local", "username"]},
    # {'remote': ['client_browser', 'GET_/v2/messages', "username.LisaGWhite&id.994D5244&roles.isDoctor&ip.local", ""]},
    {'remote': ['client_browser', 'GET_/v2/documents', "username.JamesMPaterson&id.68097B9D&roles.isChemist", ""]},
]

h = []
done = False
cum_reward = 0
for i in range(min(max_steps, len(manual_commands))):
    wrapped_env.render(mode='rgb_array', filename=None if not log_results else
                       os.path.join(log_dir, f'{exploit_train}_{train_while_exploit*"train_while_exploit"}_step{i}_trainepisodes{training_episode_count}_episodes_output_result.png'))
    LOGGER.info("")
    if done:
        break
    # run the suggested action
    action_style, next_action, _ = wrapped_env.pretty_print_to_internal_action(manual_commands[i])

    if next_action is None:
        LOGGER.info(f"Inference ended with error: next action == None, returned with aciton_style {action_style}")
        break
    current_o, reward, done, info = wrapped_env.step(next_action)
    cum_reward += reward
    action_str, reward_str = wrapped_env.internal_action_to_pretty_print(next_action, output_reward_str=True)
    h.append((i,  # wrapped_env.get_explored_network_node_properties_bitmap_as_numpy(current_o),
              reward, cum_reward,
              action_str, action_style, info['precondition_str'], info['profile_str'], info["reward_string"]))

df = pd.DataFrame(h, columns=["Step", "Reward", "Cumulative Reward", "Next action", "Processed by", "Precondition", "Profile", "Reward string"])
df.set_index("Step", inplace=True)
pd.set_option("max_colwidth", 80)
display(df)

if log_results:
    os.makedirs(log_dir, exist_ok=True)
    df.to_csv(os.path.join(log_dir, f'{exploit_train}_{train_while_exploit*"train_while_exploit"}_step{i}_trainepisodes{training_episode_count}_episodes_actions.csv'))  # ,
    # index=False)
print(f'len: {len(h)}, cumulative reward: {cum_reward}')

# %%
wrapped_env.render(mode='rgb_array' if not log_results else 'human', filename=None if not log_results else
                   os.path.join(log_dir, f'{exploit_train}_{train_while_exploit*"train_while_exploit"}_trainepisodes{training_episode_count}_episodes_discovered_network.png'))
