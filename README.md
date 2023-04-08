# Web Application version of CyberBattleSim
Authors: Kvasov Andrei, Sahin Merve, Hebert Cedric

Research project on the development of high-fidelity simulator for cloud active defense occured on the web application layer.

## Introduction

Repository mainly consists of source files of the microservices simulator ([cyberbattle](cyberbattle)) and files running DQL training ([notebooks](cyberbattle/agents/baseline/notebooks/)).

In progress:
1. Honeytokens experiments
2. Action mask usage by NN, ref. [update_action_mask()](cyberbattle/_env/cyberbattle_env.py#L747).
3.  [stablebaselines](notebooks/stable-baselines-agent.py) A2C, PPO
4. ...

## Installation

### Creating & running docker container
Modification of the original section [Recreating the Docker image](#recreating-the-docker-image) 

#### Recreating the Docker image

```bash
docker build -t cyberbattle:1.1 .
docker run -it -d -v {absolute_path_at_server}:/logs/exper --gpus all --rm cyberbattle:1.1 bash
```
This will run the container in detached mode, so you can connect to it via VSCODE later, and for saved experiments link folder `dir_for_log_at_server` to the container's internal `/logs/exper`.

For installation of additional python modules (for example, pandas) update [requirements.txt](requirements.txt)

Known issues:
- **Do not update gym** without sync with `gymnasium` repository: recent repository [migration compatibility](https://gymnasium.farama.org/content/gym_compatibility/) with `gymnasium` should be handled with exceptional attention OR delegate the migration to original repository [microsoft/CyberBattleSim](https://github.com/microsoft/CyberBattleSim). Now it is upstream remote so you can easilty `git pull upstream main` to get updates.

### VsCode

To interact with container, run its python modules, bash scripts and jupyter notebooks, **use VSCODE** as your main instrument. Both original and current simualtor version have NO ability to forward any port from container to the host through server, thus it is **impossible** to connect to jupyter notebook server running inside container.

For VSCODE install 2 necessary extensions: Remote SSH, Remote Explorer. _Optionally_ install Jupyter, GitLens extensions.

#### Connecting and checking the container
If there is no necessity in using ssh-key for login, pass 1.1 and 5.
1. In Remote SSH, within SSH tab -> "gear" symbol,  configure `~/.ssh/config` file on the host with this fields:
```bash
Host NAME 
    HostName IP_ADRESS
    User USERNAME 
    IdentityFile PATH_TO_PRIVATE_SSH_KEY 
    ForwardAgent yes
```
1.1  With `ForwardAgent` and `Identityfile` ssh configuration will pass ssh keys shared with github (enterprise) account.
2. Go to Remote Explorer tab -> choose Remote from the drop down box -> choose NAME to connect to as remote server -> Connect and open inside window or separately
3. In any VSCODE window open Remote Explorer tab -> choose Containers -> Choose running container of cyberbattlesim ([creat and run docker section])(#running-docker-container)
4. Go to Explorer tab -> open Folder "/root" OR open presaved workspace `exproot.code-workspace` which also includes `/logs/exper` directory to view the experiment results (more detailed further).
5. Check Github push/pull within VSCODE, setup SSH key

Firstly, while connected to server only.
 **To check that SSH forwarding from local computer is setup, run:**
1) `echo "$SSH_AUTH_SOCK"` to see if the agent was forwarded
2) `ssh-add -L` and check the lines include ssh-key credentials. 
3) If there is "no identity found" output from 2), please try to include in `config` this:
  ```bash
  Host NAME
    ...
    LocalForward localhost:23750 /var/run/docker.sock 
  ```
Secondly, create & run docker container, connect to it & connect github account using ssh-key. Next step: try pull/push/fetch from remote github. If any issues occur, post additional actions here during troubleshooting.

Use Source Control tab and make fetch/pull/push action within VSCODE. If you enounter issues you can always a) work in VSCODE with terminal; b) copy ssh-key inside .ssh of container; 

## Running the simulator

From now on work only inside VSCODE, although it is still possible to connect to remote server with container using terminal, i.e. use command line same way it is described below. 

1. Open folder "/root"
2. You can check if any files uncommited in Source Control, and try pull for updates
3. Training files [section](#running-training-files)
4. Testing agnets performance in simulator [section](#testing-simulator-with-manual-commands-and-learned-agent) 

### Project structure

|    Part   | Files | Description    |
| :---:        |    :----:   |          :---: |
| Running the simulator for test & training procedure  | agents/baseline/notebooks: 1) training - [notebook_dql_debug_with_tinymicro.py](cyberbattle/agents/baseline/notebooks/notebook_dql_debug_with_tinymicro.py) + [learner.py](cyberbattle/agents/baseline/learner.py) + [run.py](cyberbattle/agents/baseline/run.py); 2) testing [notebook_debug_tinymicro.py](cyberbattle/agents/baseline/notebooks/notebook_debug_tinymicro.py)      | Training & testing scripts usage in sections for [training](#running-training-files) & [testing](#testing-simulator-code-and-sundew-environment); [learner.py](cyberbattle/agents/baseline/learner.py) includes training process code inside [epsilon_greedy_search(..)](cyberbattle/agents/baseline/learner.py#L345) & evaluation code in [evaluate_model(...)](cyberbattle/agents/baseline/learner.py#L155)  |
| Running experiments   | ./run_exper_[...].sh       | Bash files runnning experiments as separate pipelines of: 1) converting .py file to .ipynb jupter notebook file + 2) running it with `papermill` with `-p parameter_name parameter_value`  |
| Simulator description      |   [actions.py](cyberbattle/simulation/actions.py), [model.py](cyberbattle/simulation/model.py), [cyberbattle_env.py](cyberbattle/_env/cyberbattle_env.py)  | Most of funcitonality is divided through files cyberbattle_env.py (gym environment with observations, action_masks, render, etc.), model.py (building blocks of cloud web application model), actions.py (agents actions & processing the reward)  |
| Logging & configuration files | [config.py](cyberbattle/simulation/config.py), [.env](.env) + other .env.data, .env.yml in training saved in exper/.../training folders  |  Include environment variables, processed wile training & testing in [notebook_dql_debug_with_tinymicro.py](cyberbattle/agents/baseline/notebooks/notebook_dql_debug_with_tinymicro.py) &  notebook_debug_tinymicro.py](cyberbattle/agents/baseline/notebooks/notebook_debug_tinymicro.py)ww |
| Types of attacking agents     | agents/baseline/: [agent_dql.py](cyberbattle/agents/baseline/agent_dql.py)  + [agent_wrapper.py](cyberbattle/agents/baseline/agent_wrapper.py)    |  Policy network  & update procedures for DQN + general feature engineering |
| Types of environments  | cyberbattle/samples/: [microservices/](cyberbattle/samples/microservices)        | Set of `tinymicro[...].py` files with web application configurations, including honeytokens ([[...]_ht1](cyberbattle/samples/microservices/tinymicro_deception_ht1.py), [[...]_ht2](cyberbattle/samples/microservices/tinymicro_deception_ht2.py), [[...]_ht123](cyberbattle/samples/microservices/tinymicro_deception_ht123.py), ..., [full](cyberbattle/samples/microservices/tinymicro_deception_full.py))      |


### Running training files

Lets open terminal and start in `/root` folder, `~` 
### Running through command line (wihtout papermill)

Main file to use is `notebook_dql_debug_with_tinymicro.py` as:
```bash
# using .env only
python cyberbattle/agents/baseline/notebooks/notebook_dql_debug_with_tinymicro.py

# changing parameters from default using argparse in run.py
python cyberbattle/agents/baseline/run.py {--train} {--log_restuls} --gymid CyberBattleTinyMicro-v2 --reward_clip --eps_exp_decay 2000
```

For both commands the output will be decided depending on `log_results = True` flag wihtin .env `LOG_RESULTS` or `--log_results` as `run.py` parameters, although neither `--log_results` nor `--train` are necessary to be set (true by default). 

Other parameters to tune are:
- `iteration_count:int` number of steps per episode (default 50, form environment initial configuartions in [__init__.py](cyberbattle/__init__.py#L55) `max_episode_steps`)
- `training_episode_count:int` number of episodes to train on, which actually defines number of steps: `training_steps_count = training_episode_count* iteration_count`
- `eval_freq:int` & `eval_episode_count:int` to define how frequently to pause training to evaluate model without exploration & for how many episodes to evaluate.
- `epsilon_exponential_decay:int` (.env: `EPS_EXP_DECAY`) is episode number on which you want epsilon-greedy policy to be minimum on exploration (`epsilon_minimum = 0.1`)
- `reward_clip:bool` (in progress) flag defines if we want our rewards to be scaled & clipped to [-1, 1], which potentially let DQN converge faster and monotonically (not always the case, reason for this is large winning_reward)

During trianing you can see log of each episode in command line if `log_results=True`:

```log
Episode    1|Iteration 50|steps_done:     50|reward: -1058.0|last_reward_at: 25|done_at: 50|loss: ----|epsilon:   0.9|best_eval_mean: -1.79769e+308|Elapsed Time: 0:00:00||###########|
Episode    2|Iteration 50|steps_done:    100|reward:  -941.0|last_reward_at: 46|done_at: 50|loss: ----|epsilon: 0.898|best_eval_mean: -1.79769e+308|Elapsed Time: 0:00:00||###########|
Episode    3|Iteration 50|steps_done:    150|reward:  -948.0|last_reward_at:  3|done_at: 50|loss: ----|epsilon: 0.896|best_eval_mean: -1.79769e+308|Elapsed Time: 0:00:00||###########|
Episode    4|Iteration 50|steps_done:    200|reward:  -976.0|last_reward_at: 32|done_at: 50|loss: ----|epsilon: 0.894|best_eval_mean: -1.79769e+308|Elapsed Time: 0:00:00||###########|
Episode    5|Iteration 50|steps_done:    250|reward: -1007.0|last_reward_at:  3|done_at: 50|loss: ----|epsilon: 0.892|best_eval_mean: -1.79769e+308|Elapsed Time: 0:00:00||###########|
Episode    6|Iteration 50|steps_done:    300|reward:  -992.0|last_reward_at: 26|done_at: 50|loss: ----|epsilon:  0.89|best_eval_mean: -1.79769e+308|Elapsed Time: 0:00:00||###########| 
Episode    7|Iteration 50|steps_done:    350|reward:  -997.0|last_reward_at:  8|done_at: 50|loss: ----|epsilon: 0.888|best_eval_mean: -1.79769e+308|Elapsed Time: 0:00:00||###########| 
Episode    8|Iteration 50|steps_done:    400|reward:  -991.0|last_reward_at: 44|done_at: 50|loss: ----|epsilon: 0.886|best_eval_mean: -1.79769e+308|Elapsed Time: 0:00:00||###########|
Episode    9|Iteration 50|steps_done:    450|reward: -1151.0|last_reward_at:  4|done_at: 50|loss: ----|epsilon: 0.884|best_eval_mean: -1.79769e+308|Elapsed Time: 0:00:00||###########|
Episode   10|Iteration 50|steps_done:    500|reward: -1180.0|last_reward_at:  3|done_at: 50|loss: ----|epsilon: 0.882|best_eval_mean: -1.79769e+308|Elapsed Time: 0:00:00||###########|
Episode   11|Iteration 50|steps_done:    550|reward: -1055.0|last_reward_at:  7|done_at: 50|loss: 0.00828|epsilon:  0.88|best_eval_mean: -1.79769e+308|Elapsed Time: 0:00:01||########|
Episode   12|Iteration 50|steps_done:    600|reward: -1092.0|last_reward_at: 29|done_at: 50|loss: 0.00327|epsilon: 0.878|best_eval_mean: -1.79769e+308|Elapsed Time: 0:00:01||########|
Episode   13|Iteration 50|steps_done:    650|reward: -1136.0|last_reward_at:  5|done_at: 50|loss: 0.0016|epsilon: 0.876|best_eval_mean: -1.79769e+308|Elapsed Time: 0:00:01||#########|
Episode   14|Iteration 50|steps_done:    700|reward: -1069.0|last_reward_at: 44|done_at: 50|loss: 0.00151|epsilon: 0.874|best_eval_mean: -1.79769e+308|Elapsed Time: 0:00:01||########|
...............................................
Episode 5754|Iteration 13|steps_done:  99967|reward:   314.0|last_reward_at: 13|done_at: 13|loss: 0.000187|epsilon: 0.105|best_eval_mean:  349.0|Elapsed Time: 0:00:01||###           |
Episode 5755|Iteration 12|steps_done:  99979|reward:   335.0|last_reward_at: 12|done_at: 12|loss: 0.00134|epsilon: 0.105|best_eval_mean:  349.0|Elapsed Time: 0:00:00||###            |
Episode 5756|Iteration 14|steps_done:  99993|reward:   283.0|last_reward_at: 14|done_at: 14|loss: 8.7e-05|epsilon: 0.105|best_eval_mean:  349.0|Elapsed Time: 0:00:01||####           |
Episode 5757|Iteration 12|steps_done: 100005|reward:   335.0|last_reward_at: 12|done_at: 12|loss: 0.000123|epsilon: 0.105|best_eval_mean:  349.0|Elapsed Time: 0:00:01||###           |
```



The output is stored in `/logs/exper/notebook_dql_debug_with_tinymicro/[gymid]/[auto_day_time]/`, where you can see 

1) `logfile.log` with all actions logged depending on `log_level` parameter (.env: `LOG_LEVEL`), choose btw "info", "debug", "warning".
2) `training/` folder with 
   - `.env.data` copy of config at the time of running the experiments;  
   - `.tar` parameters snapshots on different steps of learning of DQN. `[...]_best.tar` is generally the last step saved, as it is conditioned on runnning `best_eval_running_mean` parameter.
     - some of the `.tar` filenames include `_eval_`, which are checkpoints on evaluation times. 
     - both eval OR train snapshots of parameters are saved, when `best_eval_running_mean` OR `best_running_mean` is outperformed by current total_reward. `mean_reward_window` defines how many previous evaluations OR training episodes are taking into account
    - `events.out.tfevents...` file is a monitoring log for tensorboard, which you can view using tensorboard server opened at this logfile with 2 ways:
      - `tensorboard --logdir=/logs/exper/notebook_dql_debug_with_tinymicro/ --port=6006` and forwarding port with `PORTS` tab in VSCODE bottom pane
      - click to "Launch TensorBoard Session" near any tensorboard import line within the code, for example in [config.py](cyberbattle/simulation/config.py#L6). It is VSCODE functionality to automatically run tensorboard within the project and forward the port.
      - To fasten logging, optionally, limit writing of summary only on evaluation steps by setting `only_eval_summary` variable to True.
    - `.csv` outputs and `.png` files generated at the end of training for results on  10 evaluation episodes

### Running through .sh experiments files (with papermill)
Example of bash file for conducting experiments is `~/run_exper_ht_gradual_increase.sh` with the lines of form:
```bash
cat $INPUT_DIR/notebook_dql_debug_with_tinymicro.py | jupytext --to ipynb --set-kernel - | papermill $OUTPUT_DIR/notebook_dql_debug_tiny_ht_gradual_increase.ipynb -p gymid 'CyberBattleTinyMicro-v12' -p training_episode_count  2000  -p reward_clip $REWARD_CLIP # -p iteration_count 20 -p eval_episode_count 10
```

which define the pipeline of converting `.py` training file to jupyternotebook, then using `papremill` which can change the parameters of the algorithm by adding new cell into `.ipynb`. Include any python variable defined inside `notebook_dql_debug_with_tinymicro.py` with `-p` keyword.

The visual outputs better check generated `logfile.log` file as the cmd outputs do not include training progressbar.

### Testing simulator with manual commands and learned agent

To test the algorithm use either [notebook_debug_tinymicro.py](cyberbattle/agents/baseline/notebooks/notebook_debug_tinymicro.py) or [run.py](cyberbattle/agents/baseline/run.py) with `--eval --no-train`.

For inputs same configuration file `.env` and same argparse parameters for `run.py` are used, including new parameter:
- `checkpoint_date` (.env: `CHECKPOINT_DATE`) date in for `[date]_[time]` from which to get learned parameters;
- `checkpoint_name` (.env: `CHECKPOINT`) which can be set to `best` to take the `[...]_best.tar` learned parameters OR `[stepnumber]` as the specific parameter saved at the `[stepnumber]` OR `manual` to use predefined commands (listed in [notebook_debug_tinymicro.py](cyberbattle/agents/baseline/notebooks/notebook_debug_tinymicro.py)). 



## Environments configurations 

### Changing web application configuration

For reference on the microservice, which is configured here refer to the repository of "sundew/myMedicalPortal" (no link).

All configuration of environments are stored in `cyberbattle/samples/`, inside [microservices/](cyberbattle/samples/microservices).

Take for example this file [tinymicro_deception_ht1.py](cyberbattle/samples/microservices/tinymicro_deception_ht1.py).

To make another configuration from it there are several rules to apply:

1) **nodes**: in `nodes` dict add any endpoint with key as name string and value as `m.NodeInfo(...)`.
- Only nodes with `agent_installed=True` are initially known to the attacker and can be used as `source_node` for actions associated with `local` or `remote` vulnerability.
- nodes can have multiple preconditions, each `precondition` is associated with related outcome at the same index in the `outcome` list. `Reward strings` can be either same for every precondition OR different (then of type list).
- discover them with [model.LeakedNodesId](cyberbattle/simulation/model.py#L293)
2) **properties**: 
 - property name cannot start with dot "." or include any special symbol except underscore "_"
 - each node has its own properties, which are infered not from `property` parameter, but from properties included in its `preconditions`. Property parameter can extend the properties list to the one, not included in any precondition.
 - `global_properties` are shared through each of the node\endpoints
 - `initial_proeprties` include properties known from the start of each episode (only can include `global_properties`)
 - properties should be discovered with outcome [model.ProbeSucceeded](cyberbattle/simulation/model.py#L244)
2) **precondition**:
 - either list or one precondition (same for `outcome` with corresponding indexing)
 - include only "&" between property names ("~" NOT boolean to not include property), or profile properties, like `username.[...]`, `id.[...]`, `roles.[...]` (several roles can be included), `ip.local`
3) **profiles**:
- Any profile can be represented by string `username.NAME&id.ID&roles.ROLE1&roles.ROLE2&ip.[NONE|local]`
- discover new profile properties with outcome [model.LeakedProfiles](cyberbattle/simulation/model.py#L252)
4) **outcome**
 - either list or one precondition (same for `precondition` with corresponding indexing)
 - use `model.concatenate_outcomes(...)` to construct concatenated outcome  from other types and initialise with arguments from included outcome types.
 - `model.ExploitFailed` can include special cost of error and triggers error of [ErrorType.OTHER](cyberbattle/simulation/actions.py#L453) during `__process_outcome` in [actions.py](cyberbattle/simulation/actions.py#L408), while `ProbeFailed` does not.
5) **global_vulnerabilities**: are included separately as vulnerabilities, which are remote and appleid to each `target_node`, thus increase Action Space considerably
6) **honeytokens**: name tokens as string key in dictionary as in the example of [tinymicro_deception_ht1.py](cyberbattle/samples/microservices/tinymicro_deception_ht1.py#L15):
```python
ht_on = {"HT1_v2tov1": True, "HT2_phonebook": False, "HT3_state": False, "HT4_cloudactivedefense": False}
```

This is used inside configuration to choose if we include this honeytoken in the configuration by adding outcome [model.DetectionPoint](cyberbattle/simulation/model.py#L301) with parameter `detection_point_name`. The `_deception_tracker` part of `observation` dictionary will include the trigger steps of each included detection point, afterward separated as DetectionPoints (DPs) and HoneyTokens (HT).

```python
observation, reward, done, info = env .step(gym_action)
```
7) To end simulation either `max_episode_steps` passed OR attacker chooses action with outcome [model.CustomerData](cyberbattle/simulation/model.py#L207) and `ctf_flag=True`.
8) [Reward](cyberbattle/simulation/actions.py#L74) and [Penalty](cyberbattle/simulation/actions.py#L36) classes define rewards gained after successful actions and penalty cost for triggering errors. `Reward.WINNING_REWARD` defines the reward, which substitutes the last action reward when ctf flag is captured described in point 7).

###  RL hyperparameters & DQN training

1) Experiments with `reward_clip=[True|False]`, which feeds DQN with scaled to [-1, 1] rewards after processing all outcomes from action. **Result**: DQN is optimized actions faster, although diverge loss
2) Experiments were made with `gamma=[0.015|0.1|0.25|0.7|0.9]`, when closer to 1, takes long-term influence of previous rewards, as discounted factor of cumulative rewards to learn onto. **Results**: weirdly, with increasing `gamma` from intial 0.015 value up to 0.25 learned becomes smoother in loss optimizer, but with 0.7 or 0.9 learning diverges, so that learning long-term relationship becomes harder and probably, because of the ctf flag capturing `winning_reward` is too large. **TODO:** test on `winning_reward == 0`, which basically is ok, because in this case we still want to end episode s earky as possible (because of repeats will penalize us).
![](docs/.attachments/reward_clip_gamma_results.png)

<br />
<br />
<br />
<br />
<br />
<br />


# Appendix
# CyberBattleSim [microsoft repository](https://github.com/microsoft/CyberBattleSim)

> April 8th, 2021: See the [announcement](https://www.microsoft.com/security/blog/2021/04/08/gamifying-machine-learning-for-stronger-security-and-ai-models/) on the Microsoft Security Blog.

CyberBattleSim is an experimentation research platform to investigate the interaction
of automated agents operating in a simulated abstract enterprise network environment.
The simulation provides a high-level abstraction of computer networks
and cyber security concepts.
Its Python-based Open AI Gym interface allows for the training of
automated agents using reinforcement learning algorithms.

The simulation environment is parameterized by a fixed network topology
and a set of vulnerabilities that agents can utilize
to move laterally in the network.
The goal of the attacker is to take ownership of a portion of the network by exploiting
vulnerabilities that are planted in the computer nodes.
While the attacker attempts to spread throughout the network,
a defender agent watches the network activity and tries to detect
any attack taking place and mitigate the impact on the system
by evicting the attacker. We provide a basic stochastic defender that detects
and mitigates ongoing attacks based on pre-defined probabilities of success.
We implement mitigation by re-imaging the infected nodes, a process
abstractly modeled as an operation spanning over multiple simulation steps.

To compare the performance of the agents we look at two metrics: the number of simulation steps taken to
attain their goal and the cumulative rewards over simulation steps across training epochs.

## Project goals

We view this project as an experimentation platform to conduct research on the interaction of automated agents in abstract simulated network environments. By open-sourcing it, we hope to encourage the research community to investigate how cyber-agents interact and evolve in such network environments.

The simulation we provide is admittedly simplistic, but this has advantages. Its highly abstract nature prohibits direct application to real-world systems thus providing a safeguard against potential nefarious use of automated agents trained with it.
At the same time, its simplicity allows us to focus on specific security aspects we aim to study and quickly experiment with recent machine learning and AI algorithms.

For instance, the current implementation focuses on
the lateral movement cyber-attacks techniques, with the hope of understanding how network topology and configuration affects them. With this goal in mind, we felt that modeling actual network traffic was not necessary. This is just one example of a significant limitation in our system that future contributions might want to address.

On the algorithmic side, we provide some basic agents as starting points, but we
would be curious to find out how state-of-the-art reinforcement learning algorithms compare to them. We found that the large action space
intrinsic to any computer system is a particular challenge for
Reinforcement Learning, in contrast to other applications such as video games or robot control. Training agents that can store and retrieve credentials is another challenge faced when applying RL techniques
where agents typically do not feature internal memory.
These are other areas of research where the simulation could be used for benchmarking purposes.

Other areas of interest include the responsible and ethical use of autonomous
cyber-security systems: How to design an enterprise network that gives an intrinsic
advantage to defender agents? How to conduct safe research aimed at defending enterprises against autonomous cyber-attacks while preventing nefarious use of such technology?

## Documentation

Read the [Quick introduction](/docs/quickintro.md) to the project.

## Build status

| Type | Branch | Status |
| ---  | ------ | ------ |
| CI   | master | ![.github/workflows/ci.yml](https://github.com/microsoft/CyberBattleSim/workflows/.github/workflows/ci.yml/badge.svg) |
| Docker image | master | ![.github/workflows/build-container.yml](https://github.com/microsoft/CyberBattleSim/workflows/.github/workflows/build-container.yml/badge.svg) |

## Benchmark

See [Benchmark](/docs/benchmark.md).

## Setting up a dev environment

It is strongly recommended to work under a Linux environment, either directly or via WSL on Windows.
Running Python on Windows directly should work but is not supported anymore.

Start by checking out the repository:

   ```bash
   git clone https://github.com/microsoft/CyberBattleSim.git
   ```

### On Linux or WSL

The instructions were tested on a Linux Ubuntu distribution (both native and via WSL). Run the following command to set-up your dev environment and install all the required dependencies (apt and pip packages):

```bash
./init.sh
```

The script installs python3.9 if not present. If you are running a version of Ubuntu older than 20, it will automatically add an additional apt repository to install python3.9.

The script will create a [virtual Python environment](https://docs.python.org/3/library/venv.html) under a `venv` subdirectory, you can then
run Python with `venv/bin/python`.

> Note: If you prefer Python from a global installation instead of a virtual environment then you can skip the creation of the virtual environment by running the script with `./init.sh -n`. This will instead install all the Python packages on a system-wide installation of Python 3.9.

#### Windows Subsystem for Linux

The supported dev environment on Windows is via WSL.
You first need to install an Ubuntu WSL distribution on your Windows machine,
and then proceed with the Linux instructions (next section).

#### Git authentication from WSL

To authenticate with Git, you can either use SSH-based authentication or
alternatively use the credential-helper trick to automatically generate a
PAT token. The latter can be done by running the following command under WSL
([more info here](https://docs.microsoft.com/en-us/windows/wsl/tutorials/wsl-git)):

```ps
git config --global credential.helper "/mnt/c/Program\ Files/Git/mingw64/libexec/git-core/git-credential-manager.exe"
```

#### Docker on WSL

To run your environment within a docker container, we recommend running `docker` via Windows Subsystem on Linux (WSL) using the following instructions:
[Installing Docker on Windows under WSL](https://docs.docker.com/docker-for-windows/wsl-tech-preview/)).

### Windows (unsupported)

This method is not maintained anymore, please prefer instead running under
a WSL subsystem Linux environment.
But if you insist you want to start by installing [Python 3.9](https://www.python.org/downloads/windows/) then in a Powershell prompt run the `./init.ps1` script.

## Getting started quickly using Docker

The quickest method to get up and running is via the Docker container.

> NOTE: For licensing reasons, we do not publicly redistribute any
> build artifact. In particular, the docker registry `spinshot.azurecr.io` referred to
> in the commands below is kept private to the
> project maintainers only.
>
> As a workaround, you can recreate the docker image yourself using the provided `Dockerfile`, publish the resulting image to your own docker registry and replace the registry name in the commands below.

### Running from Docker registry

```bash
commit=7c1f8c80bc53353937e3c69b0f5f799ebb2b03ee
docker login spinshot.azurecr.io
docker pull spinshot.azurecr.io/cyberbattle:$commit
docker run -it spinshot.azurecr.io/cyberbattle:$commit python -m cyberbattle.agents.baseline.run
```

### Recreating the Docker image

```bash
docker build -t cyberbattle:1.1 .
docker run -it -v "$(pwd)":/source --rm cyberbattle:1.1 python -m cyberbattle.agents.baseline.run
```

## Check your environment

Run the following commands to run a simulation with a baseline RL agent:

```bash
python cyberbattle/agents/baseline/run.py --training_episode_count 5 --eval_episode_count 3 --iteration_count 100 --rewardplot_width 80  --chain_size=4 --ownership_goal 0.2

python cyberbattle/agents/baseline/run.py --training_episode_count 5 --eval_episode_count 3 --iteration_count 100 --rewardplot_width 80  --chain_size=4 --reward_goal 50 --ownership_goal 0
```

If everything is setup correctly you should get an output that looks like this:

```bash
torch cuda available=True
###### DQL
Learning with: episode_count=1,iteration_count=10,ϵ=0.9,ϵ_min=0.1, ϵ_expdecay=5000,γ=0.015, lr=0.01, replaymemory=10000,
batch=512, target_update=10
  ## Episode: 1/1 'DQL' ϵ=0.9000, γ=0.015, lr=0.01, replaymemory=10000,
batch=512, target_update=10
Episode 1|Iteration 10|reward:  139.0|Elapsed Time: 0:00:00|###################################################################|
###### Random search
Learning with: episode_count=1,iteration_count=10,ϵ=1.0,ϵ_min=0.0,
  ## Episode: 1/1 'Random search' ϵ=1.0000,
Episode 1|Iteration 10|reward:  194.0|Elapsed Time: 0:00:00|###################################################################|
simulation ended
Episode duration -- DQN=Red, Random=Green
   10.00  ┼
Cumulative rewards -- DQN=Red, Random=Green
  194.00  ┼      ╭──╴
  174.60  ┤      │
  155.20  ┤╭─────╯
  135.80  ┤│     ╭──╴
  116.40  ┤│     │
   97.00  ┤│    ╭╯
   77.60  ┤│    │
   58.20  ┤╯ ╭──╯
   38.80  ┤  │
   19.40  ┤  │
    0.00  ┼──╯
```

## Jupyter notebooks

To quickly get familiar with the project, you can open one of the provided Jupyter notebooks to play interactively with
the gym environments. Just start jupyter with `jupyter notebook`, or
`venv/bin/jupyter notebook` if you are using a virtual environment setup.

- 'Capture The Flag' toy environment notebooks:
  - [Random agent](notebooks/toyctf-random.ipynb)
  - [Interactive session for a human player](notebooks/toyctf-blank.ipynb)
  - [Interactive session - fully solved](notebooks/toyctf-solved.ipynb)

- Chain environment notebooks:
  - [Random agent](notebooks/chainnetwork-random.ipynb)

- Other environments:
  - [Interactive session with a randomly generated environment](notebooks/randomnetwork.ipynb)
  - [Random agent playing on randomly generated networks](notebooks/c2_interactive_interface.ipynb)

- Benchmarks:

  The following notebooks show benchmark evaluation of the baseline agents on various environments.

  > The source `.py`-versions of the notebooks are best viewed in VSCode or in Jupyter with the [Jupytext extension](https://jupytext.readthedocs.io/en/latest/install.html).
  The `notebooks` folder contains the corresponding `.ipynb`-notebooks
  with the entire output and plots. These can be regenerated via [papermill](https://pypi.org/project/papermill/) using this [bash script](cyberbattle/agents/baseline/notebooks/runall.sh)
  .

    - Benchmarking on a given environment: [source](cyberbattle/agents/baseline/notebooks/notebook_benchmark.py): [output (Chain)](notebooks/notebook_benchmark-chain.ipynb), [output (Capture the flag)](notebooks/notebook_benchmark-toyctf.ipynb)
    - Benchmark on chain environments with a basic defender: [source](cyberbattle/agents/baseline/notebooks/notebook_withdefender.py),
    [output](notebooks/notebook_withdefender.ipynb);
    - DQL transfer learning evaluation: [source](cyberbattle/agents/baseline/notebooks/notebook_dql_transfer.py), [output](notebooks/notebook_dql_transfer.ipynb);
    - Epsilon greedy with credential lookups: [source](cyberbattle/agents/baseline/notebooks/notebook_randlookups.py), [output](notebooks/notebook_randlookups.ipynb);
    - Tabular Q Learning: [source](cyberbattle/agents/baseline/notebooks/notebook_tabularq.py); [output](notebooks/notebook_tabularq.ipynb)

## How to instantiate the Gym environments?

The following code shows how to create an instance of the OpenAI Gym environment `CyberBattleChain-v0`, an environment based on a [chain-like network structure](cyberbattle/samples/chainpattern/chainpattern.py), with 10 nodes (`size=10`) where the agent's goal is to either gain full ownership of the network (`own_atleast_percent=1.0`) or
break the 80% network availability SLA (`maintain_sla=0.80`), while the network is being monitored and protected by the basic probalistically-modelled defender (`defender_agent=ScanAndReimageCompromisedMachines`):

```python
import cyberbattle._env.cyberbattle_env

cyberbattlechain_defender =
  gym.make('CyberBattleChain-v0',
      size=10,
      attacker_goal=AttackerGoal(
          own_atleast=0,
          own_atleast_percent=1.0
      ),
      defender_constraint=DefenderConstraint(
          maintain_sla=0.80
      ),
      defender_agent=ScanAndReimageCompromisedMachines(
          probability=0.6,
          scan_capacity=2,
          scan_frequency=5))
```

To try other network topologies, take example on [chainpattern.py](cyberbattle/samples/chainpattern/chainpattern.py) to define your own set of machines and vulnerabilities, then add an entry in [the module initializer](cyberbattle/__init__.py) to declare and register the Gym environment.

## Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

### Ideas for contributions

Here are some ideas on how to contribute: enhance the simulation (event-based, refined the simulation, …), train an RL algorithm on the existing simulation,
implement benchmark to evaluate and compare novelty of agents, add more network generative modes to train RL-agent on, contribute to the doc, fix bugs.

See also the [wiki for more ideas](https://github.com/microsoft/CyberBattleGym/wiki/Possible-contributions).

## Citing this project

```bibtex
@misc{msft:cyberbattlesim,
  Author = {Microsoft Defender Research Team.}
  Note = {Created by Christian Seifert, Michael Betser, William Blum, James Bono, Kate Farris, Emily Goren, Justin Grana, Kristian Holsheimer, Brandon Marken, Joshua Neil, Nicole Nichols, Jugal Parikh, Haoran Wei.},
  Publisher = {GitHub},
  Howpublished = {\url{https://github.com/microsoft/cyberbattlesim}},
  Title = {CyberBattleSim},
  Year = {2021}
}
```

## Note on privacy

This project does not include any customer data.
The provided models and network topologies are purely fictitious.
Users of the provided code provide all the input to the simulation
and must have the necessary permissions to use any provided data.

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft
trademarks or logos is subject to and must follow
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.
