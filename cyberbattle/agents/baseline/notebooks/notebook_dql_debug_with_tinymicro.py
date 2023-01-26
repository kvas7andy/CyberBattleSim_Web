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
#     kernelspec:
#       display_name: python3
#       language: python
#       name: python3
# ---

# %%
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Notebook used for debugging purpose to train the
the DQL agent and then run it one step at a time.
"""

# pylint: disable=invalid-name

# %%
import os
from dotenv import load_dotenv
import pandas as pd
import datetime
import cyberbattle.agents.baseline.learner as learner
import cyberbattle.agents.baseline.agent_wrapper as w
import cyberbattle.agents.baseline.agent_dql as dqla
import logging
from cyberbattle.agents.baseline.agent_wrapper import ActionTrackingStateAugmentation, AgentWrapper, Verbosity
from IPython.display import display
import gym
from cyberbattle.simulation.config import configuration, logger

load_dotenv()


# %% tags=['parameters']
max_episode_steps = 50
log_results = os.getenv("LOG_RESULTS", 'False').lower() in ('true', '1', 't')
gymid = os.getenv("GYMID", 'CyberBattleTinyMicro-v0')
log_level = os.getenv('LOG_LEVEL', "info")
iteration_count = None
training_episode_count = None
train_while_exploit = os.getenv("TRAIN_WHILE_EXPLOIT", 'True').lower() in ('true', '1', 't')
exploit_train = "exploit_train"   # "exploit_manual"
eval_episode_count = int(os.getenv('EVAL_EPISODE_COUNT', 0))
eval_freq = int(os.getenv('EVAL_FREQ', 0))
epsilon_exponential_decay = int(os.getenv('EPS_EXP_DECAY', max_episode_steps * 4000))  # 5000
mean_reward_window = int(os.getenv('MEAN_REWARD_WINDOW', 10))

log_dir = 'logs/exper/' + "notebook_dql_debug_with_tinymicro"
# convert the datetime object to string of specific format
datetime_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
log_dir = os.path.join(log_dir, gymid, datetime_str)
checkpoint_date = None

# %%
iteration_count = max_episode_steps if iteration_count is None else iteration_count
os.environ['TRAINING_EPISODE_COUNT'] = os.getenv('TRAINING_EPISODE_COUNT', 1000) if training_episode_count is None else training_episode_count
training_episode_count = int(os.environ['TRAINING_EPISODE_COUNT'])
checkpoint_date = checkpoint_date if checkpoint_date else os.getenv('CHECKPOINT_DATE', '20230124_085534')
os.environ['LOG_DIR'] = log_dir
os.environ['LOG_RESULTS'] = str(log_results).lower()

os.makedirs(log_dir, exist_ok=True) if log_results else ''

configuration.update_globals(log_dir, gymid, log_level, log_results)
configuration.update_logger()

# if os.environ['RUN_IN_SILENT_MODE'] in ['true']:
#     f = open(os.devnull, 'w')
#     sys.stdout = f

# progressbar.streams.wrap_stderr()

# %%
ctf_env = gym.make(gymid)
ep = w.EnvironmentBounds.of_identifiers(
    maximum_node_count=ctf_env.bounds.maximum_node_count,  # either we identify from configuration, or by ourselves
    maximum_total_credentials=1,
    identifiers=ctf_env.identifiers
)

ctf_env = gym.make(gymid, env_bounds=ep)
ctf_env.spec.max_episode_steps = max_episode_steps


# if not log_results:
#     lhStdout = logger.handlers[0]  # stdout is the only handler initially
#     logger.removeHandler(lhStdout)
# %%
# Evaluate the Deep Q-learning agent

os.makedirs(os.path.join(log_dir, 'training'), exist_ok=True) if log_results else ''

learning_rate = 0.01  # 0.01
gamma = 0.015  # 0.015
dqn_learning_run = learner.epsilon_greedy_search(
    cyberbattle_gym_env=ctf_env,
    environment_properties=ep,
    learner=dqla.DeepQLearnerPolicy(
        ep=ep,
        gamma=gamma,
        replay_memory_size=10000,
        target_update=5,
        batch_size=512,  # TODO increase?
        learning_rate=learning_rate,  # torch default learning rate is 1e-2
        train_while_exploit=train_while_exploit
    ),
    episode_count=training_episode_count,
    iteration_count=iteration_count,
    epsilon=0.90,
    epsilon_exponential_decay=epsilon_exponential_decay,
    epsilon_minimum=0.10,
    eval_episode_count=eval_episode_count,
    eval_freq=eval_freq,
    mean_reward_window=mean_reward_window,
    verbosity=Verbosity.Quiet,
    render=False,
    render_last_episode_rewards_to=os.path.join(log_dir, 'training') if log_results else None,
    plot_episodes_length=False,
    title="DQL",
    save_model_filename=log_results * os.path.join(log_dir, 'training',
                                                   f"{exploit_train}_{train_while_exploit * 'ExploitUdpates'}_te{training_episode_count}_best.tar")
)

if log_results:
    configuration.writer.close()
# %%
# initialize the environment

# current_o = ctf_env_2.reset()
# wrapped_env = AgentWrapper(ctf_env_2, ActionTrackingStateAugmentation(ep, current_o))
DQL_agent = dqn_learning_run['learner']
logger.setLevel(logging.INFO) if log_results else ''

if log_results:
    logger.info("Saving model to directory " + log_dir)
    DQL_agent.save(os.path.join(log_dir, f"{exploit_train}_{train_while_exploit*'ExploitUdpates'}_te{training_episode_count}_final.tar"))


logger.info("")
logger.info("Now evaluate trained network")
# %%
# Use the trained agent to run the steps one by one

max_steps = iteration_count
verbosity = Verbosity.Normal
DQL_agent.load_best(os.path.join(log_dir, 'training'))
DQL_agent.train_while_exploit = train_while_exploit
DQL_agent.policy_net.eval()

current_o = ctf_env.reset()
wrapped_env = AgentWrapper(ctf_env, ActionTrackingStateAugmentation(ep, current_o))
# %%
# Evaluate DQL agent 10 times
for n_trial in range(10):
    # next action suggested by DQL agent
    h = []
    done = False
    total_reward = 0
    df = None
    current_o = wrapped_env.reset()
    for i in range(max_steps):
        logger.info(f"Step {i}")
        if done:
            break
        # run the suggested action
        action_style, next_action, _ = DQL_agent.exploit(wrapped_env, current_o)

        if next_action is None:
            logger.info(f"Inference ended with error: next action == None, returned with aciton_style {action_style}")
            break
        current_o, reward, done, info = wrapped_env.step(next_action)
        total_reward += reward
        action_str, reward_str = wrapped_env.internal_action_to_pretty_print(next_action, output_reward_str=True)
        h.append((i,  # wrapped_env.get_explored_network_node_properties_bitmap_as_numpy(current_o),
                  reward, total_reward,
                  action_str, action_style, info['precondition_str'], info['profile_str'], info["reward_string"]))  # "\t action  validity: " +

        df = pd.DataFrame(h, columns=["Step", "Reward", "Cumulative Reward", "Next action", "Processed by", "Precondition", "Profile", "Reward string"])
        df.set_index("Step", inplace=True)
        if log_results:
            df.to_csv(os.path.join(log_dir, f'{exploit_train}_{train_while_exploit*"ExploitUdpates"}_evaln{n_trial}_te{training_episode_count}_actions.csv'))

    print(f'len: {len(h)}, total reward: {total_reward}')
    pd.set_option("max_colwidth", 10**3)
    if df is not None:
        display(df)

    # %% if not log_results else 'human'w
    wrapped_env.render(mode='rgb_array', filename=None if not log_results else
                       os.path.join(log_dir, f'{exploit_train}_{train_while_exploit*"ExploitUdpates"}_evaln{n_trial}_te{training_episode_count}_network.png'))
