# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Data model for the simulation environment.

The simulation environment is given by the directed graph
formally defined by:

  Node := NodeID x ListeningService[] x Value x Vulnerability[] x FirewallConfig
  Edge := NodeID x NodeID x PortName

 where:
  - NodeID: string
  - ListeningService : Name x AllowedCredentials
  - AllowedCredentials : string[] # credential pair represented by just a
    string ID
  - Value : [0...100]     # Intrinsic value of reaching this node
  - Vulnerability : VulnerabilityID x Type x Precondition x Outcome x Rates
  - VulnerabilityID : string
  - Rates : ProbingDetectionRate x ExploitDetectionRate x SuccessRate
  - FirewallConfig: {
      outgoing :  FirwallRule[]
      incoming : FirwallRule [] }
  - FirewallRule: PortName x { ALLOW, BLOCK }
"""

from datetime import datetime, time
from typing import NamedTuple, List, Dict, OrderedDict, Optional, Union, Tuple, Iterator, Set, get_type_hints
import dataclasses
from dataclasses import dataclass, field
import matplotlib.pyplot as plt  # type:ignore
from enum import Enum, IntEnum
from boolean import boolean
import networkx as nx
import yaml
import random

VERSION_TAG = "0.1.0"

ALGEBRA = boolean.BooleanAlgebra()

# Type alias for identifiers
NodeID = str

# A unique identifier
ID = str

# a (login,password/token) credential pair is abstracted as just a unique
# string identifier
CredentialID = str

# Intrinsic value of a reaching a given node in [0,100]
NodeValue = int


PortName = str


@dataclass
class ListeningService:
    """A service port on a given node accepting connection initiated
    with the specified allowed credentials """
    # Name of the port the service is listening to
    name: PortName
    # credential allowed to authenticate with the service
    allowedCredentials: List[CredentialID] = dataclasses.field(default_factory=list)
    # whether the service is running or stopped
    running: bool = True
    # Weight used to evaluate the cost of not running the service
    sla_weight = 1.0


x = ListeningService(name='d')


class VulnerabilityID(NamedTuple):
    target_node: str
    vulnerability_id: str


# Probability rate
Probability = float

# The name of a node property indicating the presence of a
# service, component, feature or vulnerability on a given node.
PropertyName = str

RolesType = Set


# The name of a profile global property indicating the presence of a
# authentification credentials in form or profile, including username, cookie, roles,
@dataclass
class Profile:
    # username, after registering
    username: str = dataclasses.field(default=None, repr=lambda x: '')
    # set session cookies for username
    id: str = dataclasses.field(default=None, repr=lambda x: '')
    # roles
    roles: Optional[RolesType[str]] = dataclasses.field(default=None, repr=lambda: '')
    # IP from which vulnerability is feasible to maintain
    ip: Optional[str] = dataclasses.field(default=None, repr=lambda: '')

    @staticmethod
    def is_profile_symbol(symbol_str: str) -> bool:
        dot_separables = symbol_str.split('.')
        return len(dot_separables) == 2 and dot_separables[0] in [field.name for field in dataclasses.fields(Profile)] and dot_separables[-1] != ''

    @staticmethod
    def is_role_symbol(symbol_str: str) -> bool:
        return Profile.is_profile_symbol(symbol_str) and 'roles' in symbol_str

    @staticmethod
    def is_auth_symbol(symbol_str: str) -> bool:
        return Profile.is_profile_symbol(symbol_str) and ('username' in symbol_str or 'id' in symbol_str)

    def __str__(self) -> str:
        return "&".join(filter(None, ("&".join(key + '.' + str(value)
                                               for key, value in dataclasses.asdict(self).items()
                                               if value is not None and not isinstance(value, RolesType)),
                                      "&".join("&".join(key + '.' + str(value) for value in value_list)
                                               for key, value_list in dataclasses.asdict(self).items()
                                               if value_list is not None and isinstance(value_list, RolesType)))))

    def __le__(self, other) -> bool:
        for k, v in self.__dict__.items():
            if v is not None:
                if getattr(self, k) != getattr(other, k):  # if we have this property set, check if it is the same as in other
                    return False
        return True

    def update(self, new: Dict, diff_mode=True, propagate=True):
        diff_count = 0
        for key, value in new.items():
            if hasattr(self, key):
                if isinstance(getattr(self, key), RolesType):
                    if diff_mode:
                        diff_count += len(value - getattr(self, key)) if not getattr(self, key) else 0
                    if propagate:
                        setattr(self, key, getattr(self, key) | value)  # getattr(self, key).union(value) if RolesType is Set else
                else:
                    if diff_mode:
                        diff_count += int(not getattr(self, key))
                    if propagate:
                        setattr(self, key, value)
        return diff_count if diff_mode else self


class Rates(NamedTuple):
    """Probabilities associated with a given vulnerability"""
    probingDetectionRate: Probability = 0.0
    exploitDetectionRate: Probability = 0.0
    successRate: Probability = 1.0


class VulnerabilityType(Enum):
    """Is the vulnerability exploitable locally or remotely?"""
    LOCAL = 1
    REMOTE = 2


class PrivilegeLevel(IntEnum):
    """Access privilege level on a given node"""
    NoAccess = 0
    LocalUser = 1
    Admin = 2
    System = 3
    MAXIMUM = 3


def escalate(current_level, escalation_level: PrivilegeLevel) -> PrivilegeLevel:
    return PrivilegeLevel(max(int(current_level), int(escalation_level)))


class Memoize:
    def __init__(self, f):
        self.f = f
        self.memo = {}

    def __call__(self, *args):
        return self.memo.setdefault(args, self.f(*args))


@Memoize
def concatenate_outcomes(base):

    class DynamicalClass(*base):
        def __init__(self, **kwargs):
            super().__init__(**kwargs)

    return DynamicalClass


class VulnerabilityOutcome:
    """Outcome of exploiting a given vulnerability"""


class LateralMove(VulnerabilityOutcome):
    """Lateral movement to the target node"""
    success: bool

    def __init__(self, success: PrivilegeLevel = False, **kwargs):
        super().__init__(**kwargs)
        self.success = success


class CustomerData(VulnerabilityOutcome):
    """Access customer data on target node"""

    def __init__(self, reward: float = 0.0, ctf_flag: bool = False, **kwargs):
        super().__init__(**kwargs)
        self.reward = reward
        self.ctf_flag = ctf_flag


class PrivilegeEscalation(VulnerabilityOutcome):
    """Privilege escalation outcome"""

    def __init__(self, level: PrivilegeLevel, **kwargs):
        super().__init__(**kwargs)
        self.level = level

    @property
    def tag(self):
        """Escalation tag that gets added to node properties when
        the escalation level is reached for that node"""
        return f"privilege_{self.level}"


class SystemEscalation(PrivilegeEscalation):
    """Escalation to SYSTEM privileges"""

    def __init__(self, **kwargs):
        super().__init__(PrivilegeLevel.System, **kwargs)


class AdminEscalation(PrivilegeEscalation):
    """Escalation to local administrator privileges"""

    def __init__(self, **kwargs):
        super().__init__(PrivilegeLevel.Admin, **kwargs)


class ProbeSucceeded(VulnerabilityOutcome):
    """Probing succeeded"""

    def __init__(self, discovered_properties: List[PropertyName], **kwargs):
        super().__init__(**kwargs)
        self.discovered_properties = discovered_properties


class LeakedProfiles(VulnerabilityOutcome):
    """Leaked properties of profile"""

    def __init__(self, discovered_profiles: List[Profile], **kwargs):
        super().__init__(**kwargs)
        self.discovered_profiles = discovered_profiles


class ProbeFailed(VulnerabilityOutcome):
    """Probing failed"""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)


class ExploitFailed(VulnerabilityOutcome):
    """This is for situations where the exploit fails """

    def __init__(self, cost: Optional[float] = None, deception=False, **kwargs):
        super().__init__(**kwargs)
        self.cost = cost
        self.deception = deception


class CachedCredential(NamedTuple):
    """Encodes a machine-port-credential triplet"""
    node: NodeID
    port: PortName
    credential: CredentialID


class LeakedCredentials(VulnerabilityOutcome):
    """A set of credentials obtained by exploiting a vulnerability"""

    credentials: List[CachedCredential]

    def __init__(self, credentials: List[CachedCredential], **kwargs):
        super().__init__(**kwargs)
        self.credentials = credentials


class LeakedNodesId(VulnerabilityOutcome):
    """A set of node IDs obtained by exploiting a vulnerability"""

    def __init__(self, discovered_nodes: List[NodeID], **kwargs):
        super().__init__(**kwargs)
        self.discovered_nodes = discovered_nodes


class DetectionPoint(VulnerabilityOutcome):
    """Detection point to track deception tocken"""

    def __init__(self, detection_point_name: str, **kwargs):
        super().__init__(**kwargs)
        self.detection_point_name = detection_point_name


VulnerabilityOutcomes = Union[
    LeakedCredentials, LeakedNodesId, LeakedProfiles, PrivilegeEscalation, AdminEscalation,
    SystemEscalation, CustomerData, LateralMove, ExploitFailed]


class AttackResult():
    """The result of attempting a specific attack (either local or remote)"""
    success: bool
    expected_outcome: Union[VulnerabilityOutcomes, None]


class Precondition:
    """ A predicate logic expression defining the condition under which a given
    feature or vulnerability is present or not.
    The symbols used in the expression refer to properties associated with
    the corresponding node.
    E.g. 'Win7', 'Server', 'IISInstalled', 'SQLServerInstalled',
    'AntivirusInstalled' ...
    """

    expression: boolean.Expression

    def __init__(self, expression: Union[boolean.Expression, str]):
        if isinstance(expression, boolean.Expression):
            self.expression = expression
        else:
            self.expression = ALGEBRA.parse(expression)

    def get_properties(self) -> Set[PropertyName]:
        return {str(symbol) for symbol in self.expression.get_symbols() if not Profile.is_profile_symbol(str(symbol))}

    def need_roles(self):
        symbols = [str(symbol) for symbol in self.expression.get_symbols()]
        return 'roles.isDoctor' in symbols, 'roles.isChemist' in symbols  # logic: roles are always included WIHTOUT ~(NOT)


class DeceptionTracker:
    """Object with saving and updating tracking of deceptive elements"""

    def __init__(self, detection_point_name: str, step=None):
        self.detection_point_name = detection_point_name
        self.trigger_times = [step] if step is not None else []


class VulnerabilityInfo(NamedTuple):
    """Definition of a known vulnerability"""
    # an optional description of what the vulnerability is
    description: str
    # type of vulnerability
    type: VulnerabilityType
    # what happens when successfully exploiting the vulnerability
    outcome: VulnerabilityOutcome
    # a boolean expression over a node's properties determining if the
    # vulnerability is present or not
    precondition: Precondition = Precondition("true")
    # rates of success/failure associated with this vulnerability
    rates: Rates = Rates()
    # points to information about the vulnerability
    URL: str = ""
    # some cost associated with exploiting this vulnerability (e.g.
    # brute force more costly than dumping credentials)
    cost: float = 1.0
    # a string displayed when the vulnerability is successfully exploited
    reward_string: str = ""


# A dictionary storing information about all supported vulnerabilities
# or features supported by the simulation.
# This is to be used as a global dictionary pre-populated before
# starting the simulation and estimated from real-world data.
VulnerabilityLibrary = OrderedDict[VulnerabilityID, VulnerabilityInfo]


class RulePermission(Enum):
    """Determine if a rule is blocks or allows traffic"""
    ALLOW = 0
    BLOCK = 1


@dataclass(frozen=True)
class FirewallRule:
    """A firewall rule"""
    # A port name
    port: PortName
    # permission on this port
    permission: RulePermission
    # An optional reason for the block/allow rule
    reason: str = ""


@dataclass
class FirewallConfiguration:
    """Firewall configuration on a given node.
    Determine if traffic should be allowed or specifically blocked
    on a given port for outgoing and incoming traffic.
    The rules are process in order: the first rule matching a given
    port is applied and the rest are ignored.

    Port that are not listed in the configuration
    are assumed to be blocked. (Adding an explicit block rule
    can still be useful to give a reason for the block.)
    """
    outgoing: List[FirewallRule] = field(repr=True, default_factory=lambda: [
        FirewallRule("RDP", RulePermission.ALLOW),
        FirewallRule("SSH", RulePermission.ALLOW),
        FirewallRule("HTTPS", RulePermission.ALLOW),
        FirewallRule("HTTP", RulePermission.ALLOW)])
    incoming: List[FirewallRule] = field(repr=True, default_factory=lambda: [
        FirewallRule("RDP", RulePermission.ALLOW),
        FirewallRule("SSH", RulePermission.ALLOW),
        FirewallRule("HTTPS", RulePermission.ALLOW),
        FirewallRule("HTTP", RulePermission.ALLOW)])


class MachineStatus(Enum):
    """Machine running status"""
    Stopped = 0
    Running = 1
    Imaging = 2


@dataclass
class NodeInfo:
    """A computer node in the enterprise network"""
    # List of port/protocol the node is listening to
    services: List[ListeningService]
    # List of known vulnerabilities for the node
    vulnerabilities: VulnerabilityLibrary = dataclasses.field(default_factory=dict)
    # Intrinsic value of the node (translates into a reward if the node gets owned)
    value: NodeValue = 0
    # Properties of the nodes, some of which can imply further vulnerabilities
    properties: List[PropertyName] = dataclasses.field(default_factory=list)
    # Fireall configuration of the node
    firewall: FirewallConfiguration = FirewallConfiguration()
    # Attacker agent installed on the node? (aka the node is 'pwned')
    agent_installed: bool = False
    # Esclation level
    privilege_level: PrivilegeLevel = PrivilegeLevel.NoAccess
    # Can the node be re-imaged by a defender agent?
    reimagable: bool = True
    # Last time the node was reimaged
    last_reimaging: Optional[time] = None
    # String displayed when the node gets owned
    owned_string: str = ""
    # Machine status: running or stopped
    status = MachineStatus.Running
    # Relative node weight used to calculate the cost of stopping this machine
    # or its services
    sla_weight: float = 1.0


class Identifiers(NamedTuple):
    """Define the global set of identifiers used
    in the definition of a given environment.
    Such set defines a common vocabulary possibly
    shared across multiple environments, thus
    ensuring a consistent numbering convention
    that a machine learniong model can learn from."""
    # Array of all possible node property identifiers
    properties: List[PropertyName] = []
    # Array of all possible port names
    ports: List[PortName] = []
    # Array of all possible local vulnerabilities names
    local_vulnerabilities: List[VulnerabilityID] = []
    # Array of all possible remote vulnerabilities names
    remote_vulnerabilities: List[VulnerabilityID] = []
    # Array of all possible profile names
    profile_usernames: List[str] = []
    # Array of all possible detection point names
    detection_point_names: List[str] = []
    # Array of properties known initially
    initial_properties: List[PropertyName] = []
    # Array of just the globals
    global_properties: List[PropertyName] = []


def iterate_network_nodes(network: nx.graph.Graph) -> Iterator[Tuple[NodeID, NodeInfo]]:
    """Iterates over the nodes in the network"""
    for nodeid, nodevalue in network.nodes.items():
        node_data: NodeInfo = nodevalue['data']
        yield nodeid, node_data


class EdgeAnnotation(Enum):
    """Annotation added to the network edges created as the simulation is played"""
    KNOWS = 0
    REMOTE_EXPLOIT = 1
    LATERAL_MOVE = 2


# NOTE: Using `NameTuple` instead of `dataclass` breaks deserialization
# with PyYaml 2.8.1 due to a new recrusive references to the networkx graph in the field
#   edges: !!python/object:networkx.classes.reportviews.EdgeView
#     _adjdict: *id018
#     _graph: *id019
@dataclass
class Environment:
    """ The static graph defining the network of computers """
    network: nx.DiGraph
    vulnerability_library: VulnerabilityLibrary
    identifiers: Identifiers
    creationTime: datetime = datetime.utcnow()
    lastModified: datetime = datetime.utcnow()
    # a version tag indicating the environment schema version
    version: str = VERSION_TAG

    def nodes(self) -> Iterator[Tuple[NodeID, NodeInfo]]:
        """Iterates over the nodes in the network"""
        return iterate_network_nodes(self.network)

    def get_node(self, node_id: NodeID) -> NodeInfo:
        """Retrieve info for the node with the specified ID"""
        node_info: NodeInfo = self.network.nodes[node_id]['data']
        return node_info

    def plot_environment_graph(self) -> None:
        """Plot the full environment graph"""
        styles = dict(zip([e.value for e in EdgeAnnotation], ['-', '.', ':']))
        nx.draw(self.network,
                with_labels=True,
                node_color=[n['data'].value
                            for i, n in
                            self.network.nodes.items()],
                style=[styles[n.kind] for i, n in self.network.edges.items()],
                cmap=plt.cm.Oranges)  # type:ignore


def create_network(nodes: Dict[NodeID, NodeInfo]) -> nx.DiGraph:
    """Create a network with a set of nodes and no edges"""
    graph = nx.DiGraph()
    graph.add_nodes_from([(k, {'data': v}) for (k, v) in list(nodes.items())])
    return graph

# Helpers to infer constants from an environment


def collect_detection_point_name_from_vuln(vuln: VulnerabilityInfo) -> List[str]:
    """Returns all the port named referenced in a given vulnerability"""
    outcome_iter = vuln.outcome if isinstance(vuln.outcome, list) else [vuln.outcome]

    return [outcome.detection_point_name for outcome in outcome_iter if isinstance(outcome, DetectionPoint)]


def collect_detection_point_names(nodes: Iterator[Tuple[NodeID, NodeInfo]],
                                  vulnerability_library: VulnerabilityLibrary) -> List[PortName]:
    """Collect and return all detection point names used in a given set of nodes
    and global vulnerability library"""
    return sorted(list({
        detection_point_name
        for _, v in vulnerability_library.items()
        for detection_point_name in collect_detection_point_name_from_vuln(v)
    }.union({
        detection_point_name
        for _, node_info in nodes
        for _, v in node_info.vulnerabilities.items()
        for detection_point_name in collect_detection_point_name_from_vuln(v)
    })))


def vuln_name_from_vuln(node_id: NodeID, id: VulnerabilityID, vuln_info: VulnerabilityInfo) -> Set:
    if isinstance(vuln_info.precondition, list):
        return {":".join([str(node_id), str(precondition.expression), str(id)]) if node_id else
                ":".join([str(precondition.expression), str(id)])
                for precondition in vuln_info.precondition}  # (Optional) Omit TRUE in precondition name: if vuln_info.precondition.expression is not Precondition("true").expression else ""])}
    else:
        return {":".join([str(node_id), str(vuln_info.precondition.expression), str(id)]) if node_id else
                ":".join([str(vuln_info.precondition.expression), str(id)])}  # (Optional) Omit TRUE in precondition name


def collect_vulnerability_ids_from_nodes_bytype(
        nodes: Iterator[Tuple[NodeID, NodeInfo]],
        global_vulnerabilities: VulnerabilityLibrary,
        type: VulnerabilityType) -> List[VulnerabilityID]:
    """Collect and return all IDs of all vulnerability of the specified type
    that are referenced in a given set of nodes and vulnerability library
    """
    return sorted(list(set.union(*(
        vuln_name_from_vuln(node_id, id, v)
        for node_id, node_info in nodes
        for id, v in node_info.vulnerabilities.items()
        if v.type == type)).union(*(
            vuln_name_from_vuln(node_id, id, v)
            for node_id, _ in nodes
            for id, v in global_vulnerabilities.items()
            if v.type == type)
    )))


def collect_properties_from_vuln(vuln_info: VulnerabilityInfo):
    if isinstance(vuln_info.precondition, list):
        return set.union(*(
            precondition.get_properties()
            for precondition in vuln_info.precondition))
    else:
        return vuln_info.precondition.get_properties()


def collect_properties_from_nodes(nodes: Iterator[Tuple[NodeID, NodeInfo]],
                                  vulnerability_library: VulnerabilityLibrary) -> List[PropertyName]:
    """Collect and return sorted list of all property names used in a given set of nodes"""
    return sorted(list({
        str(property)
        for node_id, node_info in nodes
        for property in node_info.properties
    }.union(*(
        collect_properties_from_vuln(v)
        for node_id, node_info in nodes
        for id, v in node_info.vulnerabilities.items()
    )).union(*(
        collect_properties_from_vuln(v)
        for id, v in vulnerability_library.items()
    ))))


def collect_profile_usernames_from_vuln(vuln: VulnerabilityInfo) -> List[str]:
    """Returns all the port named referenced in a given vulnerability"""
    outcome_precond_iter = iter(zip(vuln.outcome, vuln.precondition)) if isinstance(vuln.outcome, list) else iter(zip([vuln.outcome], [vuln.precondition]))

    profile_usernames = []
    for outcome, precondition in outcome_precond_iter:
        # TODO change split('&') to more meaningfull because of precondition, can have other symbols like |
        if isinstance(outcome, LeakedProfiles):
            profile_usernames += [symbol_str.split('.')[1] for profile_str in outcome.discovered_profiles for symbol_str in profile_str.split('&') if 'username.' in symbol_str]
        profile_usernames += [str(symbol).split('.')[1] for symbol in precondition.expression.get_symbols() if 'username.' in str(symbol)]
    return profile_usernames


def collect_profile_usernames_from_nodes(
        nodes: Iterator[Tuple[NodeID, NodeInfo]],
        vulnerability_library: VulnerabilityLibrary) -> List[PortName]:
    """Collect and return all profile usernames used in a given set of nodes
    and global vulnerability library"""
    return sorted(list({
        profile_username
        for _, v in vulnerability_library.items()
        for profile_username in collect_profile_usernames_from_vuln(v)
    }.union({
        profile_username
        for _, node_info in nodes
        for _, v in node_info.vulnerabilities.items()
        for profile_username in collect_profile_usernames_from_vuln(v)
    })))


def collect_ports_from_vuln(vuln: VulnerabilityInfo) -> List[PortName]:
    """Returns all the port named referenced in a given vulnerability"""
    if isinstance(vuln.outcome, LeakedCredentials):
        return [c.port for c in vuln.outcome.credentials]
    else:
        return []


def collect_ports_from_nodes(
        nodes: Iterator[Tuple[NodeID, NodeInfo]],
        vulnerability_library: VulnerabilityLibrary) -> List[PortName]:
    """Collect and return all port names used in a given set of nodes
    and global vulnerability library"""
    return sorted(list({
        port
        for _, v in vulnerability_library.items()
        for port in collect_ports_from_vuln(v)
    }.union({
        port
        for _, node_info in nodes
        for _, v in node_info.vulnerabilities.items()
        for port in collect_ports_from_vuln(v)
    }.union(
        {service.name
         for _, node_info in nodes
         for service in node_info.services}))))


def collect_ports_from_environment(environment: Environment) -> List[PortName]:
    """Collect and return all port names used in a given environment"""
    return collect_ports_from_nodes(environment.nodes(), environment.vulnerability_library)


def infer_constants_from_nodes(
        nodes: Iterator[Tuple[NodeID, NodeInfo]],
        global_vulnerabilities: Dict[VulnerabilityID, VulnerabilityInfo],
        global_properties: List[PropertyName] = [],
        initial_properties: List[PropertyName] = []) -> Identifiers:
    """Infer global environment constants from a given network"""
    return Identifiers(
        properties=sorted(list(set(collect_properties_from_nodes(nodes, global_vulnerabilities)).union(global_properties))),
        ports=collect_ports_from_nodes(nodes, global_vulnerabilities),
        local_vulnerabilities=collect_vulnerability_ids_from_nodes_bytype(
            nodes, global_vulnerabilities, VulnerabilityType.LOCAL),
        remote_vulnerabilities=collect_vulnerability_ids_from_nodes_bytype(
            nodes, global_vulnerabilities, VulnerabilityType.REMOTE),
        profile_usernames=collect_profile_usernames_from_nodes(
            nodes, global_vulnerabilities),
        detection_point_names=collect_detection_point_names(nodes, global_vulnerabilities),
        initial_properties=initial_properties,
        global_properties=global_properties
    )


def infer_constants_from_network(
        network: nx.Graph,
        vulnerabilities: Dict[VulnerabilityID, VulnerabilityInfo],
        global_properties: List[PropertyName] = [],
        initial_properties: List[PropertyName] = []) -> Identifiers:
    """Infer global environment constants from a given network"""
    return infer_constants_from_nodes(iterate_network_nodes(network), vulnerabilities, global_properties, initial_properties)


# Network creation

# A sample set of envrionment constants
SAMPLE_IDENTIFIERS = Identifiers(
    ports=['RDP', 'SSH', 'SMB', 'HTTP', 'HTTPS', 'WMI', 'SQL'],
    properties=[
        'Windows', 'Linux', 'HyperV-VM', 'Azure-VM', 'Win7', 'Win10',
        'PortRDPOpen', 'GuestAccountEnabled']
)


def assign_random_labels(
        graph: nx.DiGraph,
        vulnerabilities: VulnerabilityLibrary = dict([]),
        identifiers: Identifiers = SAMPLE_IDENTIFIERS) -> nx.DiGraph:
    """Create an envrionment network by randomly assigning node information
    (properties, firewall configuration, vulnerabilities)
    to the nodes of a given graph structure"""

    # convert node IDs to string
    graph = nx.relabel_nodes(graph, {i: str(i) for i in graph.nodes})

    def create_random_firewall_configuration() -> FirewallConfiguration:
        return FirewallConfiguration(
            outgoing=[
                FirewallRule(port=p, permission=RulePermission.ALLOW)
                for p in
                random.sample(
                    identifiers.ports,
                    k=random.randint(0, len(identifiers.ports)))],
            incoming=[
                FirewallRule(port=p, permission=RulePermission.ALLOW)
                for p in random.sample(
                    identifiers.ports,
                    k=random.randint(0, len(identifiers.ports)))])

    def create_random_properties() -> List[PropertyName]:
        return list(random.sample(
            identifiers.properties,
            k=random.randint(0, len(identifiers.properties))))

    def pick_random_global_vulnerabilities() -> VulnerabilityLibrary:
        count = random.random()
        return {k: v for (k, v) in vulnerabilities.items() if random.random() > count}

    def add_leak_neighbors_vulnerability(library: VulnerabilityLibrary, node_id: NodeID) -> None:
        """Create a vulnerability for each node that reveals its immediate neighbors"""
        neighbors = {t for (s, t) in graph.edges() if s == node_id}
        if len(neighbors) > 0:
            library['RecentlyAccessedMachines'] = VulnerabilityInfo(
                description="AzureVM info, including public IP address",
                type=VulnerabilityType.LOCAL,
                outcome=LeakedNodesId(list(neighbors)))

    def create_random_vulnerabilities(node_id: NodeID) -> VulnerabilityLibrary:
        library = pick_random_global_vulnerabilities()
        add_leak_neighbors_vulnerability(library, node_id)
        return library

    # Pick a random node as the agent entry node
    entry_node_index = random.randrange(len(graph.nodes))
    entry_node_id, entry_node_data = list(graph.nodes(data=True))[entry_node_index]
    graph.nodes[entry_node_id].clear()
    node_data = NodeInfo(services=[],
                         value=0,
                         properties=create_random_properties(),
                         vulnerabilities=create_random_vulnerabilities(entry_node_id),
                         firewall=create_random_firewall_configuration(),
                         agent_installed=True,
                         reimagable=False,
                         privilege_level=PrivilegeLevel.Admin)
    graph.nodes[entry_node_id].update({'data': node_data})

    def create_random_node_data(node_id: NodeID) -> NodeInfo:
        return NodeInfo(
            services=[],
            value=random.randint(0, 100),
            properties=create_random_properties(),
            vulnerabilities=create_random_vulnerabilities(node_id),
            firewall=create_random_firewall_configuration(),
            agent_installed=False,
            privilege_level=PrivilegeLevel.NoAccess)

    for node in list(graph.nodes):
        if node != entry_node_id:
            graph.nodes[node].clear()
            graph.nodes[node].update({'data': create_random_node_data(node)})

    return graph


# Serialization

def setup_yaml_serializer() -> None:
    """Setup a clean YAML formatter for object of type Environment.
    """
    yaml.add_representer(Precondition,
                         lambda dumper, data: dumper.represent_scalar('!BooleanExpression',
                                                                      str(data.expression)))  # type: ignore
    yaml.SafeLoader.add_constructor('!BooleanExpression',
                                    lambda loader, expression: Precondition(
                                        loader.construct_scalar(expression)))  # type: ignore
    yaml.add_constructor('!BooleanExpression',
                         lambda loader, expression:
                         Precondition(loader.construct_scalar(expression)))  # type: ignore

    yaml.add_representer(VulnerabilityType,
                         lambda dumper, data: dumper.represent_scalar('!VulnerabilityType',
                                                                      str(data.name)))  # type: ignore

    yaml.SafeLoader.add_constructor('!VulnerabilityType',
                                    lambda loader, expression: VulnerabilityType[
                                        loader.construct_scalar(expression)])  # type: ignore
    yaml.add_constructor('!VulnerabilityType',
                         lambda loader, expression: VulnerabilityType[
                             loader.construct_scalar(expression)])  # type: ignore

# Utility function for dictionary of vulnerabilities


def strkey_to_tuplekey(first_tuple_key: str, source_dict: Dict) -> Dict:
    return {(first_tuple_key, key): val for key, val in source_dict.items()}


# Help funcitons for working with simulaiton model entities


def profile_str_to_dict(profile_str: str) -> dict:
    profile_dict = {}
    type_hints = get_type_hints(Profile)
    for symbol_str in profile_str.split('&'):
        key, val = symbol_str.split('.')
        if str(RolesType) in str(type_hints[key]):
            if key in profile_dict.keys() and val not in profile_dict[key]:
                profile_dict[key] = profile_dict[key].union({val})
            else:
                profile_dict[key] = {val}
        else:
            profile_dict[key] = val
    return profile_dict
