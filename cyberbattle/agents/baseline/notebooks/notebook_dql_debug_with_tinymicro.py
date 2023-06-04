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

# # %%
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Notebook used for debugging purpose to train the
the DQL agent and then run it one step at a time.
"""

# pylint: disable=invalid-name

# # %%
import os
from dotenv import load_dotenv, dotenv_values
import pandas as pd
import numpy as np
import random
import torch
import datetime
import time

import cyberbattle.agents.baseline.learner as learner
import cyberbattle.agents.baseline.agent_wrapper as w
import cyberbattle.agents.baseline.agent_tabularqlearning as a
import cyberbattle.agents.baseline.agent_dql as dqla
from cyberbattle.simulation.actions import Reward, Penalty
import logging
from cyberbattle.agents.baseline.agent_wrapper import ActionTrackingStateAugmentation, AgentWrapper, Verbosity
from IPython.display import display
import gym
import yaml
import json
from cyberbattle.simulation.config import configuration, logger

load_dotenv()


# %% tags=['parameters']
max_episode_steps = 50
log_results = os.getenv("LOG_RESULTS", 'False').lower() in ('true', '1', 't')
gymid = os.getenv("GYMID", 'CyberBattleTinyMicro-v0')
log_level = os.getenv('LOG_LEVEL', "info")
seed = float(os.getenv('SEED', 0))
iteration_count = None
honeytokens_on = None
training_episode_count = None
train_while_exploit = os.getenv("TRAIN_WHILE_EXPLOIT", 'True').lower() in ('true', '1', 't')
reward_clip = os.getenv("REWARD_CLIP", 'False').lower() in ('true', '1', 't')
eval_episode_count = int(os.getenv('EVAL_EPISODE_COUNT', 0))
eval_freq = int(os.getenv('EVAL_FREQ', 0))
epsilon_exponential_decay = int(os.getenv('EPS_EXP_DECAY', 2000))  # 5000
mean_reward_window = int(os.getenv('MEAN_REWARD_WINDOW', 10))
papermill_as_main = False
only_eval_summary = False
# Algorithm specific parameters
learning_rate = 0.001  # 0.01
gamma = float(os.getenv('GAMMA', 0.5))  # 0.015
# %%
os.environ['LOG_RESULTS'] = str(log_results).lower()
exploit_train = "exploittrain" * train_while_exploit + "exploitinfer" * (1 - train_while_exploit)


# %%
def main(gymid=gymid, training_episode_count=training_episode_count,
         eval_episode_count=eval_episode_count, iteration_count=iteration_count,
         epsilon_exponential_decay=epsilon_exponential_decay, seed=seed,
         reward_clip=reward_clip, gamma=gamma, log_results=log_results, args=None):
    if args is not None:
        training_episode_count = args.training_episode_count
        eval_episode_count = args.eval_episode_count
        iteration_count = args.iteration_count
        gymid = args.gymid
        reward_clip = args.reward_clip
        epsilon_exponential_decay = args.eps_exp_decay
        seed = args.seed
        gamma = args.gamma
        log_results = args.log_results
        run_random_agent = args.run_random_agent
        run_qtabular = args.run_qtabular
    else:
        run_random_agent = False
        run_qtabular = False

    if not seed:
        seed = time.time()
    seed = round(seed)

    configuration.log_results = log_results

    iteration_count = max_episode_steps if iteration_count is None else iteration_count
    os.environ['TRAINING_EPISODE_COUNT'] = os.getenv('TRAINING_EPISODE_COUNT', 1000) if training_episode_count is None else str(training_episode_count)
    training_episode_count = int(os.environ['TRAINING_EPISODE_COUNT'])

    os.environ["GYMID"] = str(gymid)
    os.environ['SEED'] = str(seed)
    os.environ['GAMMA'] = str(gamma)
    os.environ['REWARD_CLIP'] = str(log_results).lower()

    log_dir = '/logs/exper/' + "notebook_dql_debug_with_tinymicro"
    if run_random_agent:
        log_dir = os.path.join(log_dir, 'random_agent')
    elif run_qtabular:
        log_dir = os.path.join(log_dir, 'qtabular')
    # convert the datetime object to string of specific format
    datetime_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    log_dir = os.path.join(log_dir, gymid, datetime_str)
    os.environ['LOG_DIR'] = log_dir

    os.makedirs(log_dir, exist_ok=True) if log_results else ''
    configuration.update_globals(log_dir, gymid, log_level, log_results)
    configuration.update_logger()

    # if os.environ['RUN_IN_SILENT_MODE'] in ['true']:
    #     f = open(os.devnull, 'w')
    #     sys.stdout = f

    # progressbar.streams.wrap_stderr()

    # # %%
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
    # # %%
    # Evaluate the Deep Q-learning agent

    os.makedirs(os.path.join(log_dir, 'training'), exist_ok=True) if log_results else ''
    env_config = json.loads(json.dumps(dotenv_values()))
    env_config = {k: os.getenv(k, v) for k, v in env_config.items()}  #
    if configuration.log_results:
        with open(os.path.join(log_dir, 'training', '.env.data.yml'), 'w') as outfile:
            yaml.dump(env_config, outfile, default_flow_style=False)
        with open(os.path.join(log_dir, 'training', '.env.data'), 'w') as outfile:
            outfile.write("\n".join(k + "=" + str(v) for k, v in env_config.items()))
        logger.info(f"Loading env variables!\n{str(env_config)}")

    # We need to sample with  actions.__process_outcome() but TBH its simpler to assume we have min = minimum(Penalty + Penalty.REPEAT) & max = WinningReward
    reward_clip_tuple = None if not reward_clip else (min([Penalty.REPEAT + int(value) for _, value in vars(Penalty).items() if isinstance(value, int) or isinstance(value, float)]),
                                                      max([int(value) for _, value in vars(Reward).items() if isinstance(value, int) or isinstance(value, float)]))
    if reward_clip:
        logger.info("Make a reward_clipping to [-1, 1]")

    if run_random_agent:
        random_run = learner.epsilon_greedy_search(
            cyberbattle_gym_env=ctf_env,
            environment_properties=ep,
            learner=learner.RandomPolicy(),
            episode_count=training_episode_count,
            iteration_count=iteration_count,
            epsilon=1.0,  # purely random
            render=False,
            verbosity=Verbosity.Quiet,
            title="Random search"
        )
        agent = random_run['learner']
        n_episodes = len(random_run["all_episodes_rewards"])
    elif run_qtabular:
        random_run = learner.epsilon_greedy_search(
            cyberbattle_gym_env=ctf_env,
            environment_properties=ep,
            learner=a.QTabularLearner(ep, gamma=gamma, learning_rate=0.90, exploit_percentile=100),
            episode_count=training_episode_count,
            iteration_count=iteration_count,
            epsilon=1.0,  # purely random
            render=False,
            verbosity=Verbosity.Quiet,
            title="Tabular Q-learning"
        )
        agent = random_run['learner']
        n_episodes = len(random_run["all_episodes_rewards"])
    else:
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
                train_while_exploit=train_while_exploit,
                reward_clip=reward_clip_tuple
            ),
            episode_count=training_episode_count,
            iteration_count=iteration_count,
            epsilon=0.90,
            epsilon_exponential_decay=epsilon_exponential_decay,
            epsilon_minimum=0.10,
            eval_episode_count=eval_episode_count,
            eval_freq=eval_freq,
            mean_reward_window=mean_reward_window,
            seed=seed,
            verbosity=Verbosity.Quiet,
            render=False,
            render_last_episode_rewards_to=os.path.join(log_dir, 'training') if log_results else None,
            plot_episodes_length=False,
            title="DQL",
            only_eval_summary=only_eval_summary,
            save_model_filename=log_results * os.path.join(log_dir, 'training',
                                                           f"{exploit_train}_te{training_episode_count}.tar")
        )
        agent = dqn_learning_run['learner']
        n_episodes = len(dqn_learning_run["all_episodes_rewards"])
    # # %%
    # initialize the environment

    # current_o = ctf_env_2.reset()
    # wrapped_env = AgentWrapper(ctf_env_2, ActionTrackingStateAugmentation(ep, current_o))

    logger.setLevel(logging.INFO) if log_results else ''

    if log_results:
        logger.info("Saving model to directory " + log_dir)
        agent.save(os.path.join(log_dir, f"{exploit_train}_te{n_episodes}_final.tar"))

    logger.info("")
    logger.info("Now evaluate trained network")
    # # %%
    # Use the trained agent to run the steps one by one

    max_steps = iteration_count
    # verbosity = Verbosity.Normal
    agent.load_best(os.path.join(log_dir, 'training'))
    agent.train_while_exploit = train_while_exploit
    agent.eval()

    current_o = ctf_env.reset()
    wrapped_env = AgentWrapper(ctf_env, ActionTrackingStateAugmentation(ep, current_o))
    # # %%
    # Evaluate DQL agent 10 times
    eval_h = []
    for n_trial in range(10):
        seed = time.time_ns()
        # set seeding
        torch.manual_seed(np.uint(seed))
        random.seed(seed)
        np.random.seed(np.uint32(seed))

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
            action_style, next_action, _ = agent.exploit(wrapped_env, current_o)

            if next_action is None:
                logger.info(f"Inference ended with error: next action == None, returned with aciton_style {action_style}")
                break
            current_o, reward, done, info = wrapped_env.step(next_action)
            total_reward += reward
            action_str, reward_str = wrapped_env.internal_action_to_pretty_print(next_action, output_reward_str=True)
            h.append((i,  # wrapped_env.get_explored_network_node_properties_bitmap_as_numpy(current_o),
                      reward, total_reward,
                      action_str, action_style, info['precondition_str'], info['profile_str'], info["reward_string"]))  # "\t action  validity: " +

        eval_h += [h]
        df = pd.DataFrame(h, columns=["Step", "Reward", "Cumulative Reward", "Next action", "Processed by", "Precondition", "Profile", "Reward string"])
        df.set_index("Step", inplace=True)
        if log_results:
            df.to_csv(os.path.join(log_dir, f'{exploit_train}_evaln{n_trial}_te{training_episode_count}_actions.csv'))
            configuration.writer.add_scalar("evaluation" + "/10trials_total_reward", eval_h[-1][-1][2], n_episodes + n_trial)

        print(f'len: {len(h)}, total reward: {total_reward}')
        pd.set_option("max_colwidth", 10**3)
        if df is not None:
            display(df)

        # if not log_results else 'human'w
        wrapped_env.render(mode='rgb_array', filename=None if not log_results else
                           os.path.join(log_dir, f'{exploit_train}_evaln{n_trial}_te{training_episode_count}_network.png'))

    if log_results:
        for step in range(1, max_steps + 1):
            step_rewards = np.array([val[step][2] for val in eval_h if len(val) > step])
            configuration.writer.add_histogram("10trials_step_reward", step_rewards, step, bins="auto") if step_rewards.size else ''

        configuration.writer.close()
        logger.info("Ending of simulation!")


# %%
if papermill_as_main:
    main()


if __name__ == "__main__":
    main()
