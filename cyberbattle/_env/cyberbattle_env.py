# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Anatares OpenGym Environment"""


import time
import copy
import logging
import sys
import networkx
from networkx import convert_matrix
from typing import NamedTuple, Optional, Tuple, List, Dict, TypeVar, TypedDict, cast, OrderedDict
# from collections import OrderedDict

import numpy
import gym
from gym import spaces
from gym.utils import seeding

import plotly.graph_objects as go
from plotly.subplots import make_subplots

from cyberbattle._env.defender import DefenderAgent
from cyberbattle.simulation.model import PortName, PrivilegeLevel
from cyberbattle.simulation.actions import Reward
from ..simulation import commandcontrol, model, actions
from .discriminatedunion import DiscriminatedUnion
from cyberbattle.simulation.config import logger

# logger = logging.getLogger(__name__)

# Used to allocate a discrete space value representing a field that
# is 'Not Applicable' (of value 0 by convention)
NA = 1

# Value defining an unused space slot
UNUSED_SLOT = numpy.int32(0)
# Value defining a used space slot
USED_SLOT = numpy.int32(1)


# Action Space dictionary type
# The actual action space is later defined as a 'spaces.Dict(x)' where x:ActionSpaceDict
ActionSpaceDict = TypedDict(
    'ActionSpaceDict', {'local_vulnerability': spaces.Space,  # type: ignore
                        'remote_vulnerability': spaces.Space,  # type: ignore
                        'connect': spaces.Space  # type: ignore
                        })

# The type of a sample from the Action space
Action = TypedDict(
    'Action', {'local_vulnerability': numpy.ndarray,
               # adding the generic type causes runtime
               # TypeError `'type' object is not subscriptable'`
               'remote_vulnerability': numpy.ndarray,
               'connect': numpy.ndarray
               }, total=False)

# Type of a sample from the ActionMask space
ActionMask = TypedDict(
    'ActionMask', {'local_vulnerability': numpy.ndarray,
                   'remote_vulnerability': numpy.ndarray,
                   'connect': numpy.ndarray
                   })

# Type of a sample from the Observation space
Observation = TypedDict(
    'Observation', {

        # ---------------------------------------------------------
        # Outcome of the action just executed
        # ---------------------------------------------------------

        # number of new nodes discovered
        'newly_discovered_nodes_count': numpy.int32,

        # number of new nodes discovered
        'newly_discovered_profiles_count': numpy.int32,

        # whether a lateral move was just performed
        'lateral_move': numpy.int32,

        # whether customer data were just discovered
        'customer_data_found': Tuple[numpy.int32],

        # 0 if there were no probing attempt
        # 1 if an attempted probing failed
        # 2 if an attempted probing succeeded
        'probe_result': numpy.int32,

        # whether an exploit ended with error or not
        'exploit_result': numpy.int32,

        # whether an escalation was completed and to which level
        'escalation': numpy.int32,

        # whether Cusomer leak is connected with CTF flag
        'ctf_flag': numpy.int32,

        # whether SSRF now is possible
        'ip_local_disclosure': numpy.int32,

        # credentials that were just discovered after executing an action
        'leaked_credentials': Tuple[numpy.ndarray, ...],  # type: ignore

        # bitmask indicating which action are valid in the current state
        'action_mask': ActionMask,

        # ---------------------------------------------------------
        # State information aggregated over all actions executed so far
        # ---------------------------------------------------------

        # size of the credential stack (number of tuples in `credential_cache_matrix` that are not zeros)
        'credential_cache_length': int,

        # total nodes discovered so far
        'discovered_node_count': int,

        # total profiles discovered so far
        'discovered_profiles_count': int,

        # Matrix of properties for all the discovered nodes
        'discovered_nodes_properties': Tuple[numpy.ndarray, ...],

        # Node privilege level on every discovered node (e.g., 0 if not owned, 1 owned, 2  admin, 3 for system)
        'nodes_privilegelevel': numpy.ndarray,

        # Tuple encoding of the credential cache matrix.
        # It consists of `bounds.maximum_total_credentials` tuples
        # of numpy array of shape (2)
        # where only the first `credential_cache_length` tuples are populated.
        #
        # Each tuple represent a discovered credential,
        # the credential index is given by its tuple index (i.e., order of discovery)
        # Each tuple is of the form: (target_node_discover_index, port_index)
        'credential_cache_matrix': Tuple[numpy.ndarray, ...],

        # ---------------------------------------------------------
        # Raw information fields coming from the simulation environment
        # that are not encoded as gym spaces (were previously in the 'info' field)
        # ---------------------------------------------------------

        # internal IDs of the credentials in the cache
        '_credential_cache': List[model.CachedCredential],

        # Mapping node index to internal IDs of all nodes discovered so far.
        # The external node index used by the agent to refer to a node
        # is defined as the index of the node in this array
        '_discovered_nodes': List[model.NodeID],

        # Mapping profile index to internal IDs of all nodes discovered so far.
        # The external node index used by the agent to refer to a node
        # is defined as the index of the node in this array
        '_discovered_profiles': List[model.Profile],

        # The subgraph of nodes discovered so far with annotated edges
        # representing interactions that took place during the simulation. (See
        # actions.EdgeAnnotation)
        '_explored_network': networkx.DiGraph,

        # Trecker of detection points included for deception strategy
        '_deception_tracker': OrderedDict[str, model.DeceptionTracker]

    })


# Information returned to gym by the step function
StepInfo = TypedDict(
    'StepInfo', {
        'description': str,
        'duration_in_ms': float,
        'step_count': int,
        'network_availability': float,
        'profile_str': str,
        'precondition_str': str,
        'reward_string': str
    })


class OutOfBoundIndexError(Exception):
    """The agent attempted to reference an entity (node or a vulnerability) with an invalid index"""


Key = TypeVar('Key')
Value = TypeVar('Value')


def inverse_dict(self: Dict[Key, Value]) -> Dict[Value, Key]:
    """Inverse a dictionary"""
    return {v: k for k, v in self.items()}


class DummySpace(spaces.Space):
    """This class ensures that the values in the gym.spaces.Dict space are derived from gym.Space"""

    def __init__(self, sample: object):
        self._sample = sample

    def contains(self, obj: object) -> bool:
        return True

    def sample(self) -> object:
        return self._sample


def sourcenode_of_action(x: Action) -> int:
    """Return the source node of a given action"""
    if 'local_vulnerability' in x:
        return x['local_vulnerability'][0]
    elif 'remote_vulnerability' in x:
        return x['remote_vulnerability'][0]

    assert 'connect' in x
    return x['connect'][0]


class EnvironmentBounds(NamedTuple):
    """Define global bounds posisibly shared by a set of CyberBattle gym environments

    maximum_node_count            - Maximum number of nodes in a given network
    maximum_total_credentials     - Maximum number of credentials in a given network
    maximum_discoverable_credentials_per_action - Maximum number of credentials
                                                    that can be returned at a time by any action

    port_count            - Unique protocol ports
    property_count        - Unique node property names
    local_attacks_count   - Unique local vulnerabilities
    remote_attacks_count  - Unique remote vulnerabilities
    """
    maximum_total_credentials: int
    maximum_node_count: int
    maximum_profiles_count: int
    maximum_discoverable_credentials_per_action: int
    maximum_vulnerability_variables: int

    port_count: int
    property_count: int
    local_attacks_count: int
    remote_attacks_count: int

    @classmethod
    def of_identifiers(cls,
                       identifiers: model.Identifiers,
                       maximum_total_credentials: int,
                       maximum_node_count: int,
                       maximum_discoverable_credentials_per_action: Optional[int] = None,
                       minimum_profiles_count: Optional[int] = 1,
                       maximum_vulnerability_variables: Optional[int] = 1,
                       remote_attacks_count: Optional[int] = 1
                       ):
        if not maximum_discoverable_credentials_per_action:
            maximum_discoverable_credentials_per_action = maximum_total_credentials
        maximum_profiles_count = max((len(identifiers.profile_usernames) + 1 * ('NoAuth' not in identifiers.profile_usernames)) * 2, minimum_profiles_count)  # TOCHECK (... + 1) * 2 because NoAuth & the "ip.local"

        # Checking the maximum number of vulnerabilities for each node, identify which vuln names they have. This includes global vulns
        vulnerabilities_dict = {}
        for vuln in identifiers.remote_vulnerabilities + identifiers.local_vulnerabilities:
            if vuln.split(':')[0] not in vulnerabilities_dict.keys():
                vulnerabilities_dict[vuln.split(':')[0]] = [vuln.split(':')[-1]]
            else:
                vulnerabilities_dict[vuln.split(':')[0]] += [vuln.split(':')[-1]]

        maximum_vulnerability_variables = max(max(len(set(variables)) for variables in vulnerabilities_dict.values()), maximum_vulnerability_variables)
        return EnvironmentBounds(
            maximum_total_credentials=maximum_total_credentials,
            maximum_node_count=max(maximum_node_count, len(vulnerabilities_dict)),
            maximum_profiles_count=maximum_profiles_count,
            maximum_discoverable_credentials_per_action=maximum_discoverable_credentials_per_action,
            maximum_vulnerability_variables=maximum_vulnerability_variables,
            port_count=max(1, len(identifiers.ports)),
            property_count=len(identifiers.properties),
            local_attacks_count=len(identifiers.local_vulnerabilities),
            remote_attacks_count=maximum_node_count * maximum_profiles_count * maximum_vulnerability_variables
            # max(len(identifiers.remote_vulnerabilities), remote_attacks_count)
        )


class AttackerGoal(NamedTuple):
    """Define conditions to be simultanesouly met for the attacker to win.
    If field values are not specified the default is to target full ownership
    of the network nodes.
    """
    # Include goal to reach at least the specifed cumulative total reward after
    reward: float = -sys.float_info.max
    # Include goal to bring the availability to lower that the specified SLA value
    low_availability: float = 1.0
    # Include goal to own at least the specified number of nodes.
    own_atleast: int = 0
    # Include goal to own at least the specified percentage of the network nodes.
    # Set to 1.0 to define goal as the ownership of all network nodes.
    own_atleast_percent: float = 1.0
    # CTF_flag acquiring goal, necessary to check internal
    ctf_flag: bool = False


class DefenderGoal(NamedTuple):
    """Define conditions to be simultanesouly met for the defender to win."""
    # Met if attacker is evicted from all the network nodes
    eviction: bool


class DefenderConstraint(NamedTuple):
    """Define constraints to be maintained by the defender at all time."""
    maintain_sla: float


class CyberBattleEnv(gym.Env):
    """OpenAI Gym environment interface to the CyberBattle simulation.

    # Actions

        Run a local attack:            `(source_node x local_vulnerability_to_exploit)`
        Run a remote attack command:   `(source_node x target_node x profile x vulnerability_variable)`
        Connect to a remote node:      `(source_node x target_node x target_port x credential_index_from_cache)`

    # Observation

       See type `Observation` for a full description of the observation space.
       It includes:
       - How many new nodes were discovered
       - Whether lateral move succeeded
       - Whether customer data were found
       - Whehter escalation attempt succeeded
       - Matrix of all node properties discovered so far
       - List of leaked credentials

    # Information
       - Action mask indicating the subset of valid actions at the current state

    # Termination

    The simulation ends if either the attacker reaches its goal (e.g. full network ownership),
    the defender reaches its goal (e.g. full eviction of the attacker)
    or if one of the defender's constraints is not met (e.g. SLA).
    """

    metadata = {'render.modes': ['human', 'rgb_array', 'text', None]}

    @property
    def environment(self) -> model.Environment:
        return self.__environment

    def __reset_environment(self) -> None:
        self.__environment: model.Environment = copy.deepcopy(self.__initial_environment)
        self.__discovered_nodes: List[model.NodeID] = []
        self.__discovered_profiles: List[model.Profile] = [model.Profile(username="NoAuth")]
        self.__deception_tracker: OrderedDict[str, model.DeceptionTracker] = OrderedDict(
            [(name, model.DeceptionTracker(name)) for name in self.identifiers.detection_point_names])
        self.__owned_nodes_indices_cache: Optional[List[int]] = None
        self.__credential_cache: List[model.CachedCredential] = []
        self.__episode_rewards: List[float] = []
        # The actuator used to execute actions in the simulation environment
        self._actuator = actions.AgentActions(self.__environment, throws_on_invalid_actions=self.__throws_on_invalid_actions)
        self._actuator = actions.AgentActions(self.__environment, throws_on_invalid_actions=self.__throws_on_invalid_actions)
        self._defender_actuator = actions.DefenderAgentActions(self.__environment)

        self.__stepcount = 0
        self.__start_time = time.time()
        self.__done = False
        self.__ip_local = False

        for node_id, node_data in self.__environment.nodes():
            if node_data.agent_installed:
                self.__discovered_nodes.append(node_id)

    @property
    def name(self) -> str:
        return "CyberBattleEnv"

    @property
    def identifiers(self) -> model.Identifiers:
        return self.__environment.identifiers

    @property
    def bounds(self) -> EnvironmentBounds:
        return self.__bounds

    def validate_environment(self, environment: model.Environment):
        """Validate that the size of the network and associated constants fits within
        the dimensions bounds set for the CyberBattle gym environment"""
        # assert environment.identifiers.ports
        assert environment.identifiers.properties
        assert environment.identifiers.local_vulnerabilities
        assert environment.identifiers.remote_vulnerabilities

        node_count = len(environment.network.nodes.items())
        if node_count > self.__bounds.maximum_node_count:
            raise ValueError(f"Network node count ({node_count}) exceeds "
                             f"the specified limit of {self.__bounds.maximum_node_count}.")

        # Maximum number of credentials that can possibly be returned by any action
        effective_maximum_credentials_per_action = max([
            len(vulnerability.outcome.credentials)
            for _, node_info in environment.nodes()
            for _, vulnerability in node_info.vulnerabilities.items()
            if isinstance(vulnerability.outcome, model.LeakedCredentials)], default=0)

        if effective_maximum_credentials_per_action > self.__bounds.maximum_discoverable_credentials_per_action:
            raise ValueError(
                f"Some action in the environment returns {effective_maximum_credentials_per_action} "
                f"credentials which exceeds the maximum number of discoverable credentials "
                f"of {self.__bounds.maximum_discoverable_credentials_per_action}")

        refeerenced_ports = model.collect_ports_from_environment(environment)
        undefined_ports = set(refeerenced_ports).difference(environment.identifiers.ports)
        if undefined_ports:
            raise ValueError(f"The network has references to undefined port names: {undefined_ports}")

        referenced_properties = model.collect_properties_from_nodes(environment.nodes(), environment.vulnerability_library)
        undefined_properties = set(referenced_properties).difference(environment.identifiers.properties)
        undefined_among_initial_properties = set(environment.identifiers.initial_properties) - set(referenced_properties)
        if undefined_properties or undefined_among_initial_properties:
            raise ValueError(f"The network has references to undefined property names: {undefined_properties.union(undefined_among_initial_properties)}")

        local_vulnerabilities = \
            model.collect_vulnerability_ids_from_nodes_bytype(
                environment.nodes(),
                environment.vulnerability_library,
                model.VulnerabilityType.LOCAL
            )

        undefined_local_vuln = set(local_vulnerabilities).difference(environment.identifiers.local_vulnerabilities)
        if undefined_local_vuln:
            raise ValueError(f"The network has references to undefined local"
                             f" vulnerability names: {undefined_local_vuln}")

        remote_vulnerabilities = \
            model.collect_vulnerability_ids_from_nodes_bytype(
                environment.nodes(),
                environment.vulnerability_library,
                model.VulnerabilityType.REMOTE
            )

        undefined_remote_vuln = set(remote_vulnerabilities).difference(environment.identifiers.remote_vulnerabilities)
        if undefined_remote_vuln:
            raise ValueError(f"The network has references to undefined remote"
                             f" vulnerability names: {undefined_remote_vuln}")

    # number of distinct privilege levels
    privilege_levels = model.PrivilegeLevel.MAXIMUM + 1

    def __init__(self,
                 initial_environment: model.Environment,
                 maximum_total_credentials: int = 1000,
                 maximum_node_count: int = None,
                 maximum_discoverable_credentials_per_action: int = 5,
                 minimum_profiles_count: int = 1,
                 maximum_vulnerability_variables: int = 1,
                 env_bounds: Optional[EnvironmentBounds] = None,
                 defender_agent: Optional[DefenderAgent] = None,
                 attacker_goal: Optional[AttackerGoal] = AttackerGoal(own_atleast_percent=1.0),
                 defender_goal=DefenderGoal(eviction=True),
                 defender_constraint=DefenderConstraint(maintain_sla=0.0),
                 winning_reward=Reward.WINNING_REWARD,  # 1000.0,
                 losing_reward=0.0,
                 renderer='',
                 observation_padding=False,
                 throws_on_invalid_actions=True,
                 ):
        """Arguments
        ===========
        environment               - The CyberBattle network simulation environment
        maximum_total_credentials - Maximum total number of credentials used in a network
        maximum_node_count        - Largest possible size of the network
        maximum_discoverable_credentials_per_action - Maximum number of credentials returned by a given action
        attacker_goal             - Target goal for the attacker to win and stop the simulation.
        defender_goal             - Target goal for the defender to win and stop the simulation.
        defender_constraint       - Constraint to be maintain by the defender to keep the simulation running.
        winning_reward            - Reward granted to the attacker if the simulation ends because the attacker's goal is reached.
        losing_reward             - Reward granted to the attacker if the simulation ends because the Defender's goal is reached.
        renderer                  - the matplotlib renderer (e.g. 'png')
        observation_padding       - whether to padd all the observation fields to their maximum size. For instance this will pad the credential matrix
                                    to fit in `maximum_node_count` rows. Turn on this flag for gym agent that expects observations of fixed sizes.
        throws_on_invalid_actions - whether to raise an exception if the step function attempts an invalid action (e.g., running an attack from a node that's not owned)
                                    if set to False a negative reward is returned instead.
        """

        self.__node_count = len(initial_environment.network.nodes.items())
        if maximum_node_count is None:
            maximum_node_count = self.__node_count

        # maximum number of entities in a given environment
        if env_bounds:
            self.__bounds = env_bounds
        else:
            self.__bounds = EnvironmentBounds.of_identifiers(
                maximum_total_credentials=maximum_total_credentials,
                maximum_node_count=maximum_node_count,
                maximum_discoverable_credentials_per_action=maximum_discoverable_credentials_per_action,
                minimum_profiles_count=minimum_profiles_count,
                maximum_vulnerability_variables=max([maximum_vulnerability_variables] +  # maximum_vulnerability_variables,
                                                    [len(node_info.vulnerabilities) for _, node_info in initial_environment.nodes()]),
                identifiers=initial_environment.identifiers)

        self.validate_environment(initial_environment)
        self.__attacker_goal: Optional[AttackerGoal] = attacker_goal
        self.__defender_goal: DefenderGoal = defender_goal
        self.__defender_constraint: DefenderConstraint = defender_constraint
        self.__WINNING_REWARD = winning_reward
        self.__LOSING_REWARD = losing_reward
        self.__renderer = renderer
        self.__observation_padding = observation_padding
        self.__throws_on_invalid_actions = throws_on_invalid_actions

        self.viewer = None

        self.__initial_environment: model.Environment = initial_environment

        # number of entities in the environment network
        self.__defender_agent = defender_agent

        self.__reset_environment()

        # The Space object defining the valid actions of an attacker.
        local_vulnerabilities_count = self.__bounds.local_attacks_count
        maximum_node_count = self.__bounds.maximum_node_count
        maximum_profiles_count = self.__bounds.maximum_profiles_count
        maximum_vulnerability_variables = self.__bounds.maximum_vulnerability_variables
        property_count = self.__bounds.property_count
        port_count = self.__bounds.port_count

        action_spaces: ActionSpaceDict = {
            "local_vulnerability": spaces.MultiDiscrete(
                # source_node_id, vulnerability_id
                [maximum_node_count, local_vulnerabilities_count]),
            "remote_vulnerability": spaces.MultiDiscrete(
                # source_node_id, target_node_id, vulnerability_id
                [maximum_node_count, maximum_node_count, maximum_profiles_count, maximum_vulnerability_variables]),
            "connect": spaces.MultiDiscrete(
                # source_node_id, target_node_id, target_port, credential_id
                # (by index of discovery: 0 for initial node, 1 for first discovered node, ...)
                [maximum_node_count, maximum_node_count, port_count, maximum_total_credentials])
        }

        self.action_space = DiscriminatedUnion(cast(dict, action_spaces))  # type: ignore

        # The observation space returning the outcome of each possible action
        self.observation_space = spaces.Dict({
            # how many new nodes were discovered
            'newly_discovered_nodes_count': spaces.Discrete(NA + maximum_node_count),
            # successuflly moved to the target node (1) or not (0)
            'lateral_move': spaces.Discrete(2),
            # boolean: 1 if customer secret data were discovered, 0 otherwise
            'customer_data_found': spaces.MultiBinary(1),
            # whether an attempted probing succeeded or not
            'probe_result': spaces.Discrete(3),
            # whether an attempted exploit succeeded or not
            'exploit_result': spaces.Discrete(2),
            # Esclation result
            'escalation': spaces.Discrete(model.PrivilegeLevel.MAXIMUM + 1),
            # CTF_flag obtained on this stage
            'ctf_flag': spaces.Discrete(2),
            # IP disclosed, local network reachable by attacker
            'ip_local_disclosure': spaces.Discrete(2),
            # Array of slots describing credentials that were leaked
            'leaked_credentials': spaces.Tuple(
                # the 1st component indicates if the slot is used or not (SLOT_USED or SLOT_UNSUED)
                # the 2nd component gives the credential unique index (external identifier exposed to the agent) # [x] how agent knows about specific credentials chosen?
                # the 3rd component gives the target node ID
                # the 4th component gives the port number
                #
                #  The actual credential secret is not returned by the environment.
                #  To use the credential as a parameter to another action the agent should refer to it by its index # [x] Note it, credentials refered by indexes
                #                                                                                                   from predefined exposed external identifier
                #  e.g. (UNUSED_SLOT,_,_,_) encodes an empty slot
                #       (USED_SLOT,1,56,22) encodes a leaked credential identified by its index 1,
                #          that was used to authenticat to target node 56 on port number 22 (e.g. SSH)

                [spaces.MultiDiscrete([NA + 1, self.__bounds.maximum_total_credentials,
                                       maximum_node_count, port_count])]
                * self.__bounds.maximum_discoverable_credentials_per_action),

            # Boolean bitmasks defining the subset of valid actions in the current state.
            # (1 for valid, 0 for invalid). Note: a valid action is not necessariliy guaranteed to succeed.
            # For instance it is a valid action to attempt to connect to a remote node with incorrect credentials,
            # even though such action would 'fail' and potentially yield a negative reward.
            "action_mask": spaces.Dict({
                "local_vulnerability":
                    spaces.MultiBinary([maximum_node_count, local_vulnerabilities_count]),
                "remote_vulnerability":
                    spaces.MultiBinary([maximum_node_count, maximum_node_count, maximum_profiles_count, maximum_vulnerability_variables]),
                "connect":
                    spaces.MultiBinary([maximum_node_count, maximum_node_count, port_count, maximum_total_credentials])
            }),

            # size of the credential stack
            'credential_cache_length': spaces.Discrete(maximum_total_credentials),

            # total nodes discovered so far
            'discovered_node_count': spaces.Discrete(maximum_node_count),

            # total nodes discovered so far
            'discovered_profiles_count': spaces.Discrete(maximum_profiles_count),

            # Matrix of properties for all the discovered nodes
            # 3 values for each matrix cell: unset (0), set (1), unknown (2)
            'discovered_nodes_properties': spaces.Tuple([spaces.MultiDiscrete([3] * property_count)] * maximum_node_count),

            # Escalation level on every discovered node (e.g., 0 if not owned, 1 for admin, 2 for system)
            'nodes_privilegelevel': spaces.MultiDiscrete([CyberBattleEnv.privilege_levels] * maximum_node_count),

            # Encoding of the credential cache of shape: (credential_cache_length, 2)
            #
            # Each row represent a discovered credential,
            # the credential index is given by the row index (i.e. order of discovery)
            # A row is of the form: (target_node_discover_index, port_index)
            'credential_cache_matrix': spaces.Tuple(
                [spaces.MultiDiscrete([maximum_node_count, port_count])] * self.__bounds.maximum_total_credentials),

            # ---------------------------------------------------------
            # Fields that were previously in the 'info' dict:
            # ---------------------------------------------------------

            # internal IDs of the credentials in the cache
            '_credential_cache': DummySpace(sample=[model.CachedCredential('Sharepoint', "HTTPS", "ADPrincipalCreds")]),

            # internal IDs of nodes discovered so far
            '_discovered_nodes': DummySpace(sample=['node1', 'node0', 'node2']),

            # internal IDs of nodes discovered so far
            '_discovered_profiles': DummySpace(sample=[model.Profile(username="user")]),

            # The subgraph of nodes discovered so far with annotated edges
            # representing interactions that took place during the simulation. (See
            # actions.EdgeAnnotation)
            '_explored_network': DummySpace(sample=networkx.DiGraph()),

            # Detection points dict to track if NN agent wants to
            '_deception_tracker': DummySpace(sample=OrderedDict([('fake_detection_point_name', model.DeceptionTracker('fake_detection_point_name'))])),
        })

        # reward_range: A tuple corresponding to the min and max possible rewards
        self.reward_range = (-float('inf'), float('inf'))

    def __local_vulnerabilityid_to_index(self, vulnerability_id: model.VulnerabilityID) -> int:
        """Return the local vulnerability identifier from its internal encoding index"""
        return [vulnerability.split(":")[-1] for vulnerability in self.__initial_environment.identifiers.local_vulnerabilities].index(vulnerability_id)

    def __index_to_local_vulnerabilityid(self, vulnerability_index: int) -> model.VulnerabilityID:
        """Return the local vulnerability identifier from its internal encoding index"""
        return self.__initial_environment.identifiers.local_vulnerabilities[vulnerability_index].split(":")[-1]

    def __indexvariableid_nodeid_to_vulnerabilities(self, node: model.NodeID, vtype: Optional[model.VulnerabilityType] = None) -> model.VulnerabilityLibrary:
        if vtype:
            return OrderedDict([(k, v) for k, v in self.__initial_environment.get_node(node).vulnerabilities.items() if v.type == vtype])
        else:
            return self.__initial_environment.get_node(node).vulnerabilities

    def __indexvariableid_nodeid_to_remote_vulnerabilityid(self, node: model.NodeID, vulnerability_index: int) -> model.VulnerabilityID:
        """Return the remote vulnerability identifier from its internal encoding index"""
        target_node_vulns = self.__indexvariableid_nodeid_to_vulnerabilities(node, model.VulnerabilityType.REMOTE)
        if vulnerability_index < len(target_node_vulns):
            return list(target_node_vulns.keys())[vulnerability_index].split(":")[-1]
        else:
            # count from the end [..., max(from_nodes), global_vul1 global_vuln2, ...]
            return list(self.__environment.vulnerability_library.keys())[-1 + vulnerability_index - (self.bounds.maximum_vulnerability_variables - 1)]

    def __nodeid_remote_vulnerabilityid_to_vulnerability_index(self, node: model.NodeID, vulnerabilty_id: model.VulnerabilityID, vtype: model.VulnerabilityType) -> int:
        """Return the remote vulnerability identifier from its internal encoding index"""
        return [v_id.split(":")[-1] for v_id, v_info in self.__indexvariableid_nodeid_to_vulnerabilities(node, vtype).items()].index(vulnerabilty_id)

    def __index_to_port_name(self, port_index: int) -> model.PortName:
        """Return the port name identifier from its internal encoding index"""
        return self.__initial_environment.identifiers.ports[port_index]

    def __portname_to_index(self, port_name: PortName) -> int:
        """Return the internal encoding index of a given port name"""
        return self.__initial_environment.identifiers.ports.index(port_name)

    def __profile_index_to_profile(self, profile_index: int) -> model.Profile:
        try:
            local = profile_index >= self.bounds.maximum_profiles_count // 2
            profile = copy.copy(self.__discovered_profiles[profile_index % (self.bounds.maximum_profiles_count // 2)])
            profile.ip = "local" if local else None
        except (OutOfBoundIndexError, IndexError, KeyError):
            return profile_index
        else:
            return profile

    def __internal_node_id_from_external_node_index(self, node_external_index: int) -> model.NodeID:
        """"Return the internal environment node ID corresponding to the specified
        external node index that is exposed to the Gym agent
                0 -> ID of inital node
                1 -> ID of first discovered node
                ...

        """
        try:
            # Ensures that the specified node is known by the agent
            if node_external_index < 0:
                raise OutOfBoundIndexError(f"Node index must be positive, given {node_external_index}")

            length = len(self.__discovered_nodes)
            if node_external_index >= length:
                raise OutOfBoundIndexError(
                    f"Node index ({node_external_index}) is invalid; only {length} nodes discovered so far.")

            node_id = self.__discovered_nodes[node_external_index]
        except (OutOfBoundIndexError, IndexError, KeyError):
            return node_external_index
        else:
            return node_id

    def __find_external_index(self, node_id: model.NodeID) -> int:
        """Find the external index associated with the specified node ID"""
        return self.__discovered_nodes.index(node_id)

    def find_external_index(self, node_id: model.NodeID) -> int:
        """Find the external index associated with the specified node ID"""
        return self.__discovered_nodes.index(node_id) if node_id in self.__discovered_nodes else None

    def __agent_owns_node(self, node_id: model.NodeID) -> bool:
        node = self.__environment.get_node(node_id)
        pwned: bool = node.agent_installed
        return pwned

    def apply_mask(self, action: Action, mask: Optional[ActionMask] = None) -> bool:
        """Apply the action mask to a specific action. Returns true just if the action
        is permitted."""
        if mask is None:
            mask = self.compute_action_mask()
        field_name = DiscriminatedUnion.kind(action)
        field_mask, coordinates = mask[field_name], action[field_name]  # type: ignore
        return bool(field_mask[tuple(coordinates)])

    def __get_blank_action_mask(self) -> ActionMask:
        """Return a blank action mask"""
        max_node_count = self.bounds.maximum_node_count  # property of self.__bounds
        local_vulnerabilities_count = self.__bounds.local_attacks_count
        maximum_profiles_count = self.__bounds.maximum_profiles_count
        maximum_vulnerability_variables = self.__bounds.maximum_vulnerability_variables
        port_count = self.__bounds.port_count
        local = numpy.zeros(
            shape=(max_node_count, local_vulnerabilities_count), dtype=numpy.int32)
        remote = numpy.zeros(
            shape=(max_node_count, max_node_count, maximum_profiles_count, maximum_vulnerability_variables), dtype=numpy.int32)
        connect = numpy.zeros(
            shape=(max_node_count, max_node_count, port_count, self.__bounds.maximum_total_credentials), dtype=numpy.int32)
        return ActionMask(
            local_vulnerability=local,
            remote_vulnerability=remote,
            connect=connect
        )

# TODO initialize depending on variables?
    # def __init__action_mask(self, bitmask: ActionMask) -> None:

    def __update_action_mask(self, bitmask: ActionMask) -> None:
        """Update an action mask based on the current state"""
        local_vulnerabilities_count = self.__bounds.local_attacks_count
        port_count = self.__bounds.port_count

        # Compute the vulnerability action bitmask
        #
        # The agent may attempt exploiting vulnerabilities
        # from any node that it owns
        for source_node_id in self.__discovered_nodes:
            if self.__agent_owns_node(source_node_id):
                source_index = self.__find_external_index(source_node_id)

                # Local: since the agent owns the node, all its local vulnerabilities are visible to it
                for vulnerability_index in range(local_vulnerabilities_count):
                    vulnerability_id = self.__index_to_local_vulnerabilityid(vulnerability_index)
                    node_vulnerable = vulnerability_id in self.__environment.vulnerability_library or \
                        vulnerability_id in self.__environment.get_node(
                            source_node_id).vulnerabilities

                    if node_vulnerable:
                        bitmask["local_vulnerability"][source_index, vulnerability_index] = 1

                # Remote: all its remote vulnerabilities
                for target_node_id in self.__discovered_nodes:
                    if source_node_id == target_node_id:
                        continue
                    target_index = self.__find_external_index(target_node_id)
                    vulnerabilities = self.__indexvariableid_nodeid_to_vulnerabilities(target_node_id, vtype=model.VulnerabilityType.REMOTE)
                    bitmask["remote_vulnerability"][source_index,
                                                    target_index,
                                                    :len(self.__discovered_profiles),
                                                    :len(vulnerabilities)] = 1

                    if len(self.__initial_environment.vulnerability_library):
                        bitmask["remote_vulnerability"][source_index,
                                                        target_index,
                                                        :len(self.__discovered_profiles),
                                                        -len(self.__initial_environment.vulnerability_library):] = 1
                    if self.__ip_local:
                        max_profiles_count = bitmask["remote_vulnerability"].shape[2]
                        bitmask["remote_vulnerability"][source_index,
                                                        target_index,
                                                        max_profiles_count // 2: max_profiles_count // 2 + len(self.__discovered_profiles),
                                                        :len(vulnerabilities)] = 1

                        if len(self.__initial_environment.vulnerability_library):
                            bitmask["remote_vulnerability"][source_index,
                                                            target_index,
                                                            max_profiles_count // 2: max_profiles_count // 2 + len(self.__discovered_profiles),
                                                            -len(self.__initial_environment.vulnerability_library):] = 1

                    bitmask["connect"][source_index,
                                       target_index,
                                       :port_count,
                                       :len(self.__credential_cache)] = 1

    def compute_action_mask(self) -> ActionMask:
        """Compute the action mask for the current state"""
        bitmask = self.__get_blank_action_mask()
        self.__update_action_mask(bitmask)
        return bitmask

    # def encoding_map(self):
    #   nodes_mapping = {node_index: self.__internal_node_id_from_external_node_index(node_index) for node_index in self.__discovered_nodes}

    def pretty_print_to_internal_action(self, pretty_print_dict: Dict) -> Action:
        action_type = next(iter(pretty_print_dict))
        action_value = pretty_print_dict[action_type]
        if action_type == "local":
            return "manual", {'local_vulnerability': [self.__find_external_index(action_value[0]),
                                                      self.__local_vulnerabilityid_to_index(action_value[1])]}, None  # ChosenActionMetadata
        elif action_type == "remote":
            profile = model.Profile(**model.profile_str_to_dict(action_value[2]))
            ip_local_flag = profile.ip == "local"
            profile.ip = None
            return "manual", {'remote_vulnerability': [self.__find_external_index(action_value[0]), self.__find_external_index(action_value[1]),
                                                       (self.bounds.maximum_profiles_count // 2 * ip_local_flag) + self.__discovered_profiles.index(profile),
                                                       self.__nodeid_remote_vulnerabilityid_to_vulnerability_index(action_value[1], action_value[3],
                                                                                                                   vtype=model.VulnerabilityType.REMOTE)]}, None
        else:
            return "manual", {'connect': [self.__find_external_index(action_value[0]), self.__find_external_index(action_value[1]),
                                          self.__portname_to_index(action_value[2]),
                                          self.__credential_cache.index(model.CachedCredential(node=action_value[1], port=action_value[2], credential=action_value[3]))]}, None

    def internal_action_to_pretty_print(self, action: Action, output_reward_str=False) -> str:
        """Pretty print an action with internal node and vulnerability identifiers"""
        assert 1 == len(action.keys())
        assert DiscriminatedUnion.kind(action) != ''
        action_str, reward_str = "", "'"
        # try:
        if "local_vulnerability" in action:
            source_node_index, vulnerability_index = action['local_vulnerability']
            vuln_id = self.__index_to_local_vulnerabilityid(vulnerability_index)
            node_id = self.__internal_node_id_from_external_node_index(source_node_index)
            action_str = f"local_vulnerability(`{node_id}, {vuln_id})"
            node_info = self.environment.get_node(node_id)
            if vuln_id in node_info.vulnerabilities:
                reward_str = node_info.vulnerabilities[vuln_id].reward_string
        elif "remote_vulnerability" in action:
            source_node, target_node, profile_index, vulnerability_variable_index = action["remote_vulnerability"]
            source_node_id = self.__internal_node_id_from_external_node_index(source_node)
            target_node_id = self.__internal_node_id_from_external_node_index(target_node)
            profile = self.__profile_index_to_profile(profile_index)
            profile_username = profile.username if profile is not profile_index else ""
            vulnerable_variable_id = self.__indexvariableid_nodeid_to_remote_vulnerabilityid(target_node_id, vulnerability_variable_index)
            action_str = f"remote_vulnerability(`{source_node_id}, `{target_node_id}, {profile_username} ,'{vulnerable_variable_id}')"
            if target_node is not target_node:
                node_info = self.environment.get_node(target_node_id)
                if vuln_id in node_info.vulnerabilities:
                    reward_str = node_info.vulnerabilities[vuln_id].reward_string
        elif "connect" in action:
            source_node, target_node, port_index, credential_cache_index = action["connect"]
            assert credential_cache_index >= 0
            if credential_cache_index >= len(self.__credential_cache):
                return "connect(invalid)"
            source_node_id = self.__internal_node_id_from_external_node_index(source_node)
            target_node_id = self.__internal_node_id_from_external_node_index(target_node)
            action_str = f"connect(`{source_node_id}, `{target_node_id}, {self.__index_to_port_name(port_index)}, {self.__credential_cache[credential_cache_index].credential})"
        # except (OutOfBoundIndexError, IndexError):
        #     action_str = "\n".join(f"{k} (`{v})" for k, v in action.items())  # will be only one action in dict, anyway
        #     # logging.error(f"Out of bounding box error: {str(error)}\nAction: {action_str}")
        # finally:
        if action_str:
            if output_reward_str:
                return action_str, reward_str
            else:
                return action_str,
        raise ValueError("Invalid discriminated union value: " + str(action))

    def __execute_action(self, action: Action) -> actions.ActionResult:
        # Assert that the specified action is consistent (i.e., defining a single action type)
        assert 1 == len(action.keys())

        assert DiscriminatedUnion.kind(action) != ''

        if "local_vulnerability" in action:
            source_node_index, vulnerability_index = action['local_vulnerability']

            return self._actuator.exploit_local_vulnerability(
                self.__internal_node_id_from_external_node_index(source_node_index),
                self.__index_to_local_vulnerabilityid(vulnerability_index))

        elif "remote_vulnerability" in action:
            source_node, target_node, profile_index, vulnerability_variable_index = action["remote_vulnerability"]
            source_node_id = self.__internal_node_id_from_external_node_index(source_node)
            target_node_id = self.__internal_node_id_from_external_node_index(target_node)
            profile = self.__profile_index_to_profile(profile_index)

            observation = self.obs
            if not self.is_action_valid(action, observation['action_mask']):
                logger.warning(f"INVALID ACTION, through suspiciousness r={actions.Penalty.SUPSPICIOUSNESS} for action={action}")
                return actions.ActionResult(reward=actions.Penalty.SUPSPICIOUSNESS, outcome=None, precondition="", profile="", reward_string="")

            result = self._actuator.exploit_remote_vulnerability(
                source_node_id,
                target_node_id,
                profile,
                self.__indexvariableid_nodeid_to_remote_vulnerabilityid(target_node_id, vulnerability_variable_index))

            return result

        elif "connect" in action:
            source_node, target_node, port_index, credential_cache_index = action["connect"]
            if credential_cache_index < 0 or credential_cache_index >= len(self.__credential_cache):
                return actions.ActionResult(reward=-1, outcome=None)

            source_node_id = self.__internal_node_id_from_external_node_index(source_node)
            target_node_id = self.__internal_node_id_from_external_node_index(target_node)

            result = self._actuator.connect_to_remote_machine(
                source_node_id,
                target_node_id,
                self.__index_to_port_name(port_index),
                self.__credential_cache[credential_cache_index].credential)

            return result

        raise ValueError("Invalid discriminated union value: " + str(action))

    def __get_blank_observation(self) -> Observation:
        observation = Observation(
            newly_discovered_nodes_count=numpy.int32(0),
            newly_discovered_profiles_count=numpy.int32(0),
            leaked_credentials=tuple(
                [numpy.array([UNUSED_SLOT, 0, 0, 0], dtype=numpy.int32)]
                * self.__bounds.maximum_discoverable_credentials_per_action),
            lateral_move=numpy.int32(0),
            customer_data_found=(numpy.int32(0),),
            escalation=numpy.int32(PrivilegeLevel.NoAccess),
            ctf_flag=numpy.int32(0),
            ip_local_disclosure=numpy.int32(0),
            action_mask=self.__get_blank_action_mask(),
            probe_result=numpy.int32(0),
            exploit_result=numpy.int32(0),
            credential_cache_matrix=tuple([numpy.zeros((2))] * self.__bounds.maximum_total_credentials),
            credential_cache_length=0,
            discovered_node_count=len(self.__discovered_nodes),
            discovered_profiles_count=len(self.__discovered_profiles),
            discovered_nodes_properties=tuple(
                [numpy.full((self.__bounds.property_count,), 2, dtype=numpy.int32)] * self.__bounds.maximum_node_count),

            nodes_privilegelevel=numpy.zeros((self.bounds.maximum_node_count,), dtype=numpy.int32),

            # raw data not actually encoded as a proper gym numeric space
            # (were previously returned in the 'info' dict)
            _credential_cache=self.__credential_cache.copy(),
            _discovered_nodes=self.__discovered_nodes.copy(),
            _discovered_profiles=self.__discovered_profiles.copy(),
            _explored_network=self.__get_explored_network(),
            _deception_tracker=self.__deception_tracker.copy()
        )

        return observation

    def __pad_array_if_requested(self, o, pad_value, desired_length) -> numpy.ndarray:
        """Pad an array observation with provided padding if the padding option is enabled
        for this environment"""
        if self.__observation_padding:
            padding = numpy.full((desired_length - len(o)), pad_value, dtype=numpy.int32)
            return numpy.concatenate((o, padding))
        else:
            return o

    def __pad_tuple_if_requested(self, o, row_shape, desired_length) -> Tuple[numpy.ndarray, ...]:
        """Pad a tuple observation with provided padding if the padding option is enabled
        for this environment"""
        if self.__observation_padding:
            padding = [numpy.zeros(row_shape, dtype=numpy.int32)] * (desired_length - len(o))
            return tuple(o + padding)
        else:
            return tuple(o)

    def __property_vector(self, node_id: model.NodeID, node_info: model.NodeInfo) -> numpy.ndarray:
        """Property vector for specified node
        each cell is either 1 if the property is set, 0 if unset, and 2 if unknown (node is not owned by the agent yet)
        """
        properties_indices = list(self._actuator.get_discovered_properties(node_id))

        is_owned = self._actuator.get_node_privilegelevel(node_id) >= PrivilegeLevel.LocalUser

        if is_owned:
            # if the node is owned then we know all its properties
            vector = numpy.full((self.__bounds.property_count), 0, dtype=numpy.int32)
        else:
            # otherwise we don't know anything about not discovered properties => 2 should be the default value
            vector = numpy.full((self.__bounds.property_count), 2, dtype=numpy.int32)

        vector[properties_indices] = 1
        return vector

    def __get_property_matrix(self) -> Tuple[numpy.ndarray]:
        """Return the Node-Property matrix,
        where  0 means the property is not set for that node
               1 means the property is set for that node
               2 means the property status is unknown

        e.g.: [ 1 0 0 1 ]
                2 2 2 2
                0 1 0 1 ]
         1st row: set and unset properties for the 1st discovered and owned node
         2nd row: no known properties for the 2nd discovered node
         3rd row: properties of 3rd discovered and owned node"""
        property_discovered = [
            self.__property_vector(node_id, node_info)
            for node_id, node_info in self._actuator.discovered_nodes()
        ]
        return self.__pad_tuple_if_requested(property_discovered, self.__bounds.property_count, self.__bounds.maximum_node_count)

    def __get__owned_nodes_indices(self) -> List[int]:
        """Get list of indices of all owned nodes"""
        if self.__owned_nodes_indices_cache is None:
            owned_nodeids = self._actuator.get_nodes_with_atleast_privilegelevel(PrivilegeLevel.LocalUser)
            self.__owned_nodes_indices_cache = [self.__find_external_index(n) for n in owned_nodeids]

        return self.__owned_nodes_indices_cache

    def __get_privilegelevel_array(self) -> numpy.ndarray:
        """Return the node escalation level array,
        where  0 means that the node is not owned
               1 if the node is owned
               2 if the node is owned and escalated to admin
               3 if the node is owned and escalated to SYSTEM
               ... further escalation levels defined by the network
        """
        privilegelevel_array = numpy.array([
            int(self._actuator.get_node_privilegelevel(node))
            for node in self.__discovered_nodes], dtype=numpy.int32)

        return self.__pad_array_if_requested(privilegelevel_array, PrivilegeLevel.NoAccess, self.__bounds.maximum_node_count)

    def __observation_reward_from_action_result(self, result: actions.ActionResult) -> Tuple[Observation, float]:
        obs = self.__get_blank_observation()
        outcome = result.outcome

        if isinstance(outcome, model.LeakedNodesId):
            # update discovered nodes
            newly_discovered_nodes_count = 0
            for node in outcome.discovered_nodes:
                if node not in self.__discovered_nodes:
                    self.__discovered_nodes.append(node)
                    newly_discovered_nodes_count += 1

            obs['newly_discovered_nodes_count'] = numpy.int32(newly_discovered_nodes_count)

        elif isinstance(outcome, model.LeakedCredentials):
            # update discovered nodes and credentials
            newly_discovered_nodes_count = 0
            newly_discovered_creds: List[Tuple[int, model.CachedCredential]] = []
            for cached_credential in outcome.credentials:
                if cached_credential.node not in self.__discovered_nodes:
                    self.__discovered_nodes.append(cached_credential.node)
                    newly_discovered_nodes_count += 1

                if cached_credential not in self.__credential_cache:
                    self.__credential_cache.append(cached_credential)
                    added_credential_index = len(self.__credential_cache) - 1
                    newly_discovered_creds.append((added_credential_index, cached_credential))

            obs['newly_discovered_nodes_count'] = numpy.int32(newly_discovered_nodes_count)

            # Encode the returned new credentials in the format expected by the gym agent
            leaked_credentials = [numpy.array([USED_SLOT,
                                               cache_index,
                                               self.__find_external_index(cached_credential.node),
                                               self.__portname_to_index(cached_credential.port)], numpy.int32)
                                  for cache_index, cached_credential in newly_discovered_creds]

            obs['leaked_credentials'] = self.__pad_tuple_if_requested(leaked_credentials, 4, self.__bounds.maximum_discoverable_credentials_per_action)
        # [x] observations leaked credentials Typle() not maintained with same dimension?!
        # max number credentials per action. Find where Obs is processed for unified inpuut to model.

        if isinstance(outcome, model.LeakedProfiles):
            # update discovered nodes
            newly_discovered_profiles_count = 0
            for profile_str in outcome.discovered_profiles:
                profile_dict = model.profile_str_to_dict(profile_str)
                if "username" not in profile_dict.keys():
                    pass
                    # # TOCHECK maybe that works?
                    # self.__discovered_profiles.append(model.Profile(profile_dict))
                    # newly_discovered_profiles_count += len(profile_dict)
                else:
                    if profile_dict["username"] not in [prof.username for prof in self.__discovered_profiles]:
                        newly_discovered_profiles_count += len(profile_dict)
                        self.__discovered_profiles.append(model.Profile(**profile_dict))
                    else:
                        for profile in self.__discovered_profiles:
                            if profile_dict["username"] == profile.username:
                                newly_discovered_profiles_count += profile.update(profile_dict)

                if "ip.local" in profile_str and not self.__ip_local:
                    obs['ip_local_disclosure'] = numpy.int32(1)
                    self.__ip_local = True

            obs['newly_discovered_profiles_count'] = numpy.int32(newly_discovered_profiles_count)

        if isinstance(outcome, model.DetectionPoint):
            logger.info(f"or WARNING (hidden from agent): detection point {outcome.detection_point_name} triggered on step={self.__stepcount}!")
            if outcome.detection_point_name in self.__deception_tracker.keys():
                self.__deception_tracker[outcome.detection_point_name].trigger_times += [self.__stepcount]
            else:
                self.__deception_tracker[outcome.detection_point_name] = model.DeceptionTracker(outcome.detection_point_name, step=self.__stepcount)

        elif isinstance(outcome, model.LateralMove):
            obs['lateral_move'] = numpy.int32(1)
        elif isinstance(outcome, model.CustomerData):
            obs['ctf_flag'] = outcome.ctf_flag
            obs['customer_data_found'] = (numpy.int32(1),)
            logger.info(f"Customer Data leaked {outcome.ctf_flag*'with flag'} triggered on step={self.__stepcount}!")
        elif isinstance(outcome, model.ProbeSucceeded):
            obs['probe_result'] = numpy.int32(2)
        elif isinstance(outcome, model.ProbeFailed):
            obs['probe_result'] = numpy.int32(1)
        elif isinstance(outcome, model.ExploitFailed):
            obs['exploit_result'] = numpy.int32(1)
        # TODO include in obs ExploitFailed result to let agent_wrapper know failed actions using this outocme, instead of condition (reward < 0)
        elif isinstance(outcome, model.PrivilegeEscalation):
            obs['escalation'] = numpy.int32(outcome.level)

        cache = [numpy.array([self.__find_external_index(c.node), self.__portname_to_index(c.port)])
                 for c in self.__credential_cache]

        obs['credential_cache_matrix'] = self.__pad_tuple_if_requested(cache, 2, self.__bounds.maximum_total_credentials)
        cache = [numpy.array([self.__find_external_index(c.node), self.__portname_to_index(c.port)])
                 for c in self.__credential_cache]

        obs['credential_cache_matrix'] = self.__pad_tuple_if_requested(cache, 2, self.__bounds.maximum_total_credentials)

        # Dynamic statistics to be refreshed
        obs['credential_cache_length'] = len(self.__credential_cache)
        obs['discovered_node_count'] = len(self.__discovered_nodes)
        obs['discovered_profile_count'] = len(self.__discovered_profiles)
        obs['discovered_nodes_properties'] = self.__get_property_matrix()
        obs['nodes_privilegelevel'] = self.__get_privilegelevel_array()
        obs['_credential_cache'] = self.__credential_cache.copy()
        obs['_discovered_nodes'] = self.__discovered_nodes.copy()
        obs['_discovered_profiles'] = self.__discovered_profiles.copy()
        obs['_explored_network'] = self.__get_explored_network()
        obs['_deception_tracker'] = self.__deception_tracker.copy()

        self.__update_action_mask(obs['action_mask'])
        self.obs = obs
        return obs, result.reward

    def sample_connect_action_in_expected_range(self) -> Action:
        """Sample an action of type 'connect' where the parameters
        are in the the expected ranges but not necessarily verifying
        inter-component constraints.
        """
        np_random = self.action_space.np_random
        discovered_credential_count = len(self.__credential_cache)

        if discovered_credential_count <= 0:
            raise ValueError("Cannot sample a connect action until the agent discovers more potential target nodes.")

        return Action(connect=numpy.array([
            np_random.choice(self.__get__owned_nodes_indices()),
            np_random.randint(len(self.__discovered_nodes)),
            np_random.randint(self.__bounds.port_count),
            # credential space is sparse so we force sampling
            # from the set of credentials that were discovered so far
            np_random.randint(len(self.__credential_cache))], numpy.int32))

    def sample_action_in_range(self, kinds: Optional[List[int]] = None) -> Action:
        """Sample an action in the expected component ranges but
        not necessarily verifying inter-component constraints.
        (e.g., may return a local_vulnerability action that is not
        supported by the node)

        - kinds -- A list of elements in {0,1,2} indicating what kind of
        action to sample (0:local, 1:remote, 2:connect)
        """
        np_random = self.action_space.np_random

        discovered_credential_count = len(self.__credential_cache)

        if kinds is None:
            kinds = [0, 1, 2]

        if discovered_credential_count == 0:
            # cannot generate a connect action if no cred in the cache
            kinds = [t for t in kinds if t != 2]

        assert kinds, 'Kinds list cannot be empty'

        kind = np_random.choice(kinds)

        if kind == 2:
            action = self.sample_connect_action_in_expected_range()
        elif kind == 1:
            action = Action(local_vulnerability=numpy.array([
                np_random.choice(self.__get__owned_nodes_indices()),
                np_random.randint(self.__bounds.local_attacks_count)], numpy.int32))
        else:
            action = Action(remote_vulnerability=numpy.array([
                np_random.choice(self.__get__owned_nodes_indices()),
                np_random.randint(len(self.__discovered_nodes)),
                np_random.randint(self.__bounds.maximum_profiles_count),
                np_random.randint(self.__bounds.maximum_vulnerability_variables)], numpy.int32))

        return action

    def is_node_owned(self, node: int):
        """Return true if a discovered node (specified by its external node index)
        is owned by the attacker agent"""
        node_id = self.__internal_node_id_from_external_node_index(node)
        node_owned = self._actuator.get_node_privilegelevel(node_id) > PrivilegeLevel.NoAccess
        return node_owned

    def is_action_valid(self, action: Action, action_mask: Optional[ActionMask] = None) -> bool:
        """Determine if an action is valid (i.e. parameters are in expected ranges)"""
        assert 1 == len(action.keys())

        kind = DiscriminatedUnion.kind(action)
        in_range = False
        n_discovered_nodes = len(self.__discovered_nodes)
        if kind == "local_vulnerability":
            source_node, vulnerability_index = action['local_vulnerability']
            in_range = source_node < n_discovered_nodes \
                and self.is_node_owned(source_node) \
                and vulnerability_index < self.__bounds.local_attacks_count
        elif kind == "remote_vulnerability":
            source_node, target_node, profile_index, vulnerability_variable_index = action["remote_vulnerability"]
            in_range = source_node < n_discovered_nodes \
                and self.is_node_owned(source_node) \
                and target_node < n_discovered_nodes \
                and profile_index < self.__bounds.maximum_profiles_count \
                and vulnerability_variable_index < self.__bounds.maximum_vulnerability_variables
        elif kind == "connect":
            source_node, target_node, port_index, credential_cache_index = action["connect"]
            in_range = source_node < n_discovered_nodes and \
                self.is_node_owned(source_node) \
                and target_node < n_discovered_nodes \
                and port_index < self.__bounds.port_count \
                and credential_cache_index < len(self.__credential_cache)

        return in_range and self.apply_mask(action, action_mask)

    def sample_valid_action(self, kinds=None) -> Action:
        """Sample an action within the expected ranges until getting a valid one"""
        action_mask = self.compute_action_mask()
        action = self.sample_action_in_range(kinds)
        while not self.apply_mask(action, action_mask):
            action = self.sample_action_in_range(kinds)
        return action

    def sample_valid_action_with_luck(self) -> Action:
        """Sample an action until getting a valid one"""
        action_mask = self.compute_action_mask()
        action = cast(Action, self.action_space.sample())
        while not self.apply_mask(action, action_mask):
            action = cast(Action, self.action_space.sample())
        return action

    def __get_explored_network(self) -> networkx.DiGraph:
        """Returns the graph of nodes discovered so far
        with annotated edges representing interactions
        that took place during the simulation.
        """
        known_nodes = [node_id for node_id, _ in self._actuator.discovered_nodes()]
        network = self.__environment.network
        subgraph = network.subgraph(known_nodes).copy()

        # hide info for nodes that the agent does not own
        for node_id in subgraph.nodes:
            node_info: Optional[model.NodeInfo] = subgraph.nodes[node_id]['data']
            if node_info is not None:
                if not node_info.agent_installed:
                    subgraph.nodes[node_id]['data'] = None

                subgraph.nodes[node_id]['privilege_level'] = int(self._actuator.get_node_privilegelevel(node_id))
                subgraph.nodes[node_id]['flags'] = list(self._actuator.get_discovered_properties(node_id))
                subgraph.nodes[node_id]['flags_bits'] = self.__property_vector(node_id, node_info)

        return subgraph

    def __attacker_goal_reached(self) -> bool:
        goal = self.__attacker_goal

        if not goal:
            return False

        if numpy.sum(self.__episode_rewards) < goal.reward:
            return False

        if goal.ctf_flag and not self.obs['ctf_flag']:
            return False

        nodes_owned = self.__get__owned_nodes_indices()
        owned_count = len(nodes_owned)

        if owned_count < goal.own_atleast:
            return False

        if owned_count / self.__node_count < goal.own_atleast_percent:
            return False

        if self.__defender_agent is not None and \
                self._defender_actuator.network_availability >= goal.low_availability:
            return False

        return True

    def __defender_constraints_broken(self) -> bool:
        """Check if any of the defender's constraint is not met"""
        constraint = self.__defender_constraint

        if self.__defender_agent is not None and \
                self._defender_actuator.network_availability < constraint.maintain_sla:
            return True

        return False

    def __defender_goal_reached(self) -> bool:
        """Check if defender's goal is reached(e.g. full eviction of attacker)"""
        goal = self.__defender_goal

        return goal.eviction and not (self.__get__owned_nodes_indices())

    def get_explored_network_as_numpy(self, observation: Observation) -> numpy.ndarray:
        """Return the explored network graph adjacency matrix
        as an numpy array of shape (N,N) where
        N is the number of nodes discovered so far"""
        return convert_matrix.to_numpy_array(observation['_explored_network'], weight='kind_as_float')

    def get_explored_network_node_properties_bitmap_as_numpy(self, observation: Observation) -> numpy.ndarray:
        """Return a combined the matrix of adjacencies (left part) and
        node properties bitmap (right part).
        Suppose N is the number of discovered nodes and
                P is the total number of properties then
        Then the return matrix is of the form:

          ^  <---- N -----><------  P ------>
          |  (            |                 )
          N  ( Adjacency  | Node-Properties )
          |  (  Matrix    |     Bitmap      )
          V  (            |                 )

        """
        return numpy.block([convert_matrix.to_numpy_array(observation['_explored_network'], weight='kind_as_float'),
                            numpy.array(observation['discovered_nodes_properties'])])
        return numpy.block([convert_matrix.to_numpy_array(observation['_explored_network'], weight='kind_as_float'),
                            numpy.array(observation['discovered_nodes_properties'])])

    def step(self, action: Action) -> Tuple[Observation, float, bool, StepInfo]:
        if self.__done:
            raise RuntimeError("new episode must be started with env.reset()")

        self.__stepcount += 1
        duration = time.time() - self.__start_time
        try:
            result = self.__execute_action(action)
            observation, reward = self.__observation_reward_from_action_result(result)
            self.__episode_rewards.append(reward)

            # Execute the defender step if provided
            if self.__defender_agent:
                self._defender_actuator.on_attacker_step_taken()
                self.__defender_agent.step(self.__environment, self._defender_actuator, self.__stepcount)

            self.__owned_nodes_indices_cache = None

            if self.__attacker_goal_reached() or self.__defender_constraints_broken():
                self.__done = True
                reward = self.__WINNING_REWARD
            elif self.__defender_goal_reached():
                self.__done = True
                reward = self.__LOSING_REWARD
            # else:
            #     reward = max(0., reward)

        except OutOfBoundIndexError as error:
            logging.warning('Invalid entity index: ' + error.__str__())
            observation = self.__get_blank_observation()
            reward = 0.

        info = StepInfo(
            description='CyberBattle simulation',
            duration_in_ms=duration,
            step_count=self.__stepcount,
            network_availability=self._defender_actuator.network_availability,
            precondition_str=result.precondition if isinstance(result.precondition, str) else str(result.precondition.expression),
            profile_str=result.profile,
            reward_string=result.reward_string)

        return observation, reward, self.__done, info

    def reset(self) -> Observation:
        logger.warning("Resetting the CyberBattle environment")
        self.__reset_environment()
        observation = self.__get_blank_observation()
        observation['action_mask'] = self.compute_action_mask()
        observation['discovered_nodes_properties'] = self.__get_property_matrix()
        observation['nodes_privilegelevel'] = self.__get_privilegelevel_array()
        self.__owned_nodes_indices_cache = None
        self.obs = observation
        return observation

    def render_as_fig(self, csv_filename=None, mode=['with_rewards']):
        debug = commandcontrol.EnvironmentDebugging(self._actuator)
        self._actuator.print_all_attacks(filename=csv_filename if 'no_text' not in mode else None)

        # plot the cumulative reward and network side by side using plotly
        fig = make_subplots(rows=1, cols=1 + 1 * ('with_rewards' in mode))
        if 'with_rewards' in mode:
            fig.add_trace(go.Scatter(y=numpy.array(self.__episode_rewards).cumsum(),
                                     name='cumulative reward'), row=1, col=1)
        traces, layout = debug.network_as_plotly_traces(xref="x" + str(1 + 1 * ('with_rewards' in mode)),
                                                        yref="y" + str(1 + 1 * ('with_rewards' in mode)))
        for t in traces:
            fig.add_trace(t, row=1, col=1 + 1 * ('with_rewards' in mode))
            fig.update_layout(layout, template='plotly_white', xaxis_range=[0, None])
            fig.update_layout(**{
                'xaxis' + '2' * ('with_rewards' in mode): dict(
                    tickmode='linear',
                    showgrid=False, zeroline=False,
                    showticklabels=False
                ),
                'yaxis' + '2' * ('with_rewards' in mode): dict(
                    showgrid=False, zeroline=False,
                    showticklabels=False)}
            )
        return fig

    def render(self, mode: List[str] = ['human'], filename=None, image_hw=None) -> None:
        if isinstance(mode, str):
            mode = [mode]
        csv_filename = filename
        if csv_filename and '.csv' not in csv_filename:
            csv_filename = '.'.join(filename.split('.')[:-1] + ['csv'])
        fig = self.render_as_fig(csv_filename=csv_filename, mode=mode)
        # # requires,  pip install -U kaleido
        h, w = image_hw if image_hw else (None, None)
        fig.update_layout(
            xaxis=dict(
                tickmode='linear',
                # tick0 = 0.5,
                showgrid=False,
                dtick=1  # 0.75
            ),
            yaxis=dict(
                # tickmode='linear',
                # tick0 = 0.5,
                showgrid=False,
                # dtick=1  # 0.75
            ),
            font=dict(size=15),
            width=w,
            height=h
        )
        if filename:
            fig.write_image(filename)
        if 'human' in mode:
            fig.show(renderer=self.__renderer)

    def seed(self, seed: Optional[int] = None) -> None:
        if seed is None:
            self._seed = seed
            return

        self.np_random, seed = seeding.np_random(seed)

    def close(self) -> None:
        return None
