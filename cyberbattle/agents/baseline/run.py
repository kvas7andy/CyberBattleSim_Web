#!/usr/bin/python3.9

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# -*- coding: utf-8 -*-
"""CLI to run the baseline Deep Q-learning and Random agents
   on a sample CyberBattle gym environment and plot the respective
   cummulative rewards in the terminal.

Example usage:

    python -m run --training_episode_count 50  --iteration_count 9000 --rewardplot_width 80  --chain_size=20 --ownership_goal 1.0

"""
import torch
import gym
import logging
import sys
import asciichartpy
import argparse
import cyberbattle._env.cyberbattle_env as cyberbattle_env
from cyberbattle.agents.baseline.agent_wrapper import Verbosity
import cyberbattle.agents.baseline.agent_dql as dqla
import cyberbattle.agents.baseline.agent_wrapper as w
import cyberbattle.agents.baseline.plotting as p
import cyberbattle.agents.baseline.learner as learner
from cyberbattle.agents.baseline.notebooks import notebook_dql_debug_with_tinymicro as training_module
from cyberbattle.agents.baseline.notebooks import notebook_debug_tinymicro as evaluation_module


parser = argparse.ArgumentParser(description='Run simulation with DQL baseline agent.')

parser.add_argument('--train', action='store_true', help='Run training code (DQL agent)')
parser.add_argument('--no_train', dest='train', action='store_false', help='Run training code (DQL agent)')
parser.add_argument('--eval', action='store_true', help='Run evaluation code (DQL agent)')
parser.add_argument('--eval_type', default='manual', help='Evaluation type of DQL agent')
parser.add_argument('--log_results', action='store_true', help='Turn on logging of results to the file')
parser.add_argument('--no-log_results', dest='log_results', action='store_false', help='do not reults to the file')
parser.set_defaults(train=True)
parser.set_defaults(eval=False)


parser.add_argument('--training_episode_count', default=2000, type=int,
                    help='number of training epochs')

parser.add_argument('--eval_episode_count', default=10, type=int,
                    help='number of evaluation epochs')

parser.add_argument('--iteration_count', default=50, type=int,
                    help='number of simulation iterations for each epoch')

parser.add_argument('--reward_goal', default=2180, type=int,
                    help='minimum target rewards to reach for the attacker to reach its goal')

parser.add_argument('--ownership_goal', default=1.0, type=float,
                    help='percentage of network nodes to own for the attacker to reach its goal')

parser.add_argument('--rewardplot_width', default=80, type=int,
                    help='width of the reward plot (values are averaged across iterations to fit in the desired width)')

parser.add_argument('--chain_size', default=4, type=int,
                    help='size of the chain of the CyberBattleChain sample environment')

parser.add_argument('--gymid', default='CyberBattleTinyMicro-v100', type=str,
                    help='Gym environment name to run in a simulator')

parser.add_argument('--eps_exp_decay', default=2000, type=int,
                    help='Relative number of episodes to pass, after which epsilon_minimum reached')

parser.add_argument('--reward_clip', action='store_true', help='Apply reward clipping to [-1, 1]')
parser.set_defaults(reward_clip=False)

parser.add_argument('--random_agent', dest='run_random_agent', action='store_true', help='run the random agent as a baseline for comparison')
parser.add_argument('--no-random_agent', dest='run_random_agent', action='store_false', help='do not run the random agent as a baseline for comparison')
parser.set_defaults(run_random_agent=True)

args = parser.parse_args()

if args.train:
    training_module.main(args=args)
elif args.eval:
    evaluation_module.main(args=args)
else:
    logging.basicConfig(stream=sys.stdout, level=logging.ERROR, format="%(levelname)s: %(message)s")

    print(f"torch cuda available={torch.cuda.is_available()}")

    cyberbattlechain = gym.make('CyberBattleChain-v0',
                                size=args.chain_size,
                                attacker_goal=cyberbattle_env.AttackerGoal(
                                    own_atleast_percent=args.ownership_goal,
                                    reward=args.reward_goal))

    ep = w.EnvironmentBounds.of_identifiers(
        maximum_total_credentials=22,
        maximum_node_count=22,
        identifiers=cyberbattlechain.identifiers
    )

    all_runs = []

    # Run Deep Q-learning
    dqn_learning_run = learner.epsilon_greedy_search(
        cyberbattle_gym_env=cyberbattlechain,
        environment_properties=ep,
        learner=dqla.DeepQLearnerPolicy(
            ep=ep,
            gamma=0.015,
            replay_memory_size=10000,
            target_update=10,
            batch_size=512,
            learning_rate=0.01),  # torch default is 1e-2
        episode_count=args.training_episode_count,
        iteration_count=args.iteration_count,
        epsilon=0.90,
        render=True,
        # epsilon_multdecay=0.75,  # 0.999,
        epsilon_exponential_decay=5000,  # 10000
        epsilon_minimum=0.10,
        verbosity=Verbosity.Quiet,
        title="DQL"
    )

    all_runs.append(dqn_learning_run)

    if args.run_random_agent:
        random_run = learner.epsilon_greedy_search(
            cyberbattlechain,
            ep,
            learner=learner.RandomPolicy(),
            episode_count=args.eval_episode_count,
            iteration_count=args.iteration_count,
            epsilon=1.0,  # purely random
            render=False,
            verbosity=Verbosity.Quiet,
            title="Random search"
        )
        all_runs.append(random_run)

    colors = [asciichartpy.red, asciichartpy.green, asciichartpy.yellow, asciichartpy.blue]

    print("Episode duration -- DQN=Red, Random=Green")
    print(asciichartpy.plot(p.episodes_lengths_for_all_runs(all_runs), {'height': 30, 'colors': colors}))

    print("Cumulative rewards -- DQN=Red, Random=Green")
    c = p.averaged_cummulative_rewards(all_runs, args.rewardplot_width)
    print(asciichartpy.plot(c, {'height': 10, 'colors': colors}))
