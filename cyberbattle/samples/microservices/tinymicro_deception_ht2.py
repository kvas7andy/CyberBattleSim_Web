# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""
A tiny microservice environment based on partial example from myMedicPortal, with the full list of deception strategy detection points
"""
from cyberbattle.simulation import model as m
from cyberbattle.simulation.model import NodeID, NodeInfo, VulnerabilityID, VulnerabilityInfo, VulnerabilityType, PropertyName
from typing import Iterator, cast, Tuple, List
from collections import OrderedDict
from cyberbattle.simulation.config import configuration


ht_on = configuration.honeytokens_on
ht_on = {"HT1_v2tov1": False, "HT2_phonebook": True, "HT3_state": False, "HT4_cloudactivedefense": False}

global_vulnerability_library: OrderedDict[VulnerabilityID, VulnerabilityInfo] = OrderedDict(
    [] +
    [("State=1", VulnerabilityInfo(  # HT3 state
        description="Deceptive honeytoken with detection point",
        precondition=m.Precondition("~username.NoAuth&state"),  # ~script_block,
        type=VulnerabilityType.REMOTE,
        outcome=m.concatenate_outcomes((m.ExploitFailed, m.DetectionPoint))(cost=10, detection_point_name="HT3_state"),
        reward_string="Honeytoken tamepring: changing state value in cookies leads to no change",
    ))] * ht_on["HT3_state"] +
    [("V2toV1", VulnerabilityInfo(  # HT1 v2tov1
        description="Version change triggers deceptive token",
        # precondition=m.Precondition("~script_block"),
        type=VulnerabilityType.REMOTE,
        outcome=m.concatenate_outcomes((m.ExploitFailed, m.DetectionPoint))(detection_point_name="HT1_v2tov1"),
        reward_string="Forced browsing attempt: changing version of platform value leads to no change",
    ))] * ht_on["HT1_v2tov1"]
)

global_properties: List[PropertyName] = ["username_password_restrictions"] + ht_on["HT3_state"] * ["state"] + ht_on["HT4_cloudactivedefense"] * ["property.cloudactivedefense"]  # HT3 state ## HT4 cloudactive defense
initial_properties: List[PropertyName] = ["property.git", "robots.txt", "thisdoesnotexist"]

# Network nodes involved in the myMedcialPortal CTF
nodes = {
    "client_browser": m.NodeInfo(
        services=[],
        value=0,
        properties=["script_block"],
        owned_string="Attacker owns his laptop",
        vulnerabilities=OrderedDict([
            ("ScanPageSource", VulnerabilityInfo(
                description="Website HTML contains information about multiple blocks leading to endpoints "
                            "AND scripts with other endpoints + variables (tags?)",
                type=VulnerabilityType.LOCAL,
                outcome=m.concatenate_outcomes((m.LeakedNodesId, m.ProbeSucceeded))(
                    discovered_nodes=["GET_/v2", "GET_/v2/login", "POST_/v2/register", "GET_/v2/messages",
                                      "GET_/v2/documents"] + ht_on["HT2_phonebook"] * ["GET_/v2/phonebook"],  # HT2 phonebook
                    discovered_properties=["script_block"]),
                reward_string="Inspect: Viewing the web page source reveals main endpoints",
                cost=1.0
            )),
            ("ScanBlockRegister", VulnerabilityInfo(
                description="Website HTML contains script with rules of username configuration",
                type=VulnerabilityType.LOCAL,
                precondition=m.Precondition("script_block"),
                outcome=m.concatenate_outcomes((m.LeakedNodesId, m.ProbeSucceeded))(
                    discovered_nodes=["GET_/v2/calendar", "GET_/v2/users"],
                    discovered_properties=["username_password_restrictions"]),
                reward_string="Found script with rules of username creation from POST_/v2/register => access to GET_/v2/users",
                cost=1.0
            )),
            ("BurpSuiteHeaderScan", VulnerabilityInfo(
                description="Scan HTTP requests payloads",
                type=VulnerabilityType.LOCAL,
                outcome=m.concatenate_outcomes((m.ProbeSucceeded,))(discovered_properties=["property.cloudactivedefense"]) \
                if ht_on["HT4_cloudactivedefense"] else m.concatenate_outcomes((m.ProbeFailed,))(),  # HT4 cloudactive defense
                reward_string="Found multiple properties (username, password, server?)" + ht_on["HT4_cloudactivedefense"] * "among them the most important: property.cloudactivedefense",  # HT4 cloudactive defense
                cost=1.0
            ))
        ]),
        agent_installed=True,
    ),

    "GET_/v2": m.NodeInfo(
        services=[],
        properties=["property.git", "robots.txt", "thisdoesnotexist",  # "property.cloudactivedefense"
                    ],
        value=0,
        vulnerabilities=OrderedDict([
            ("BrowsingTarget", VulnerabilityInfo(
                description="Finding through HTTP requests special properties",
                type=VulnerabilityType.REMOTE,
                precondition=[m.Precondition("true"), m.Precondition("thisdoesnotexist")] + ht_on["HT4_cloudactivedefense"] * [m.Precondition("property.cloudactivedefense")] +  # HT4 cloudactive defense
                [m.Precondition("property.git"), m.Precondition("robots.txt")],
                outcome=[m.ExploitFailed()] * 2 + ht_on["HT4_cloudactivedefense"] * [m.concatenate_outcomes((m.ExploitFailed, m.DetectionPoint))(detection_point_name="HT4_cloudactivedefense")] +  # HT4 cloudactive defense
                        [m.concatenate_outcomes((m.ExploitFailed, m.DetectionPoint))(detection_point_name="DP_git")] +
                        [m.concatenate_outcomes((m.ExploitFailed, m.DetectionPoint))(detection_point_name="DP_robots")],
                reward_string=["Forced browsing attempts"] * 4 +
                              ["Forced browsing attempts (honey HTTP header paremeter - detection point triggered)"],
                cost=1.0
            ))
        ])
    ),

    "GET_/v2/login": m.NodeInfo(  # Kindha discovers only POST /v2/login and POSSIBLY redundant rules for /v2/users
        services=[],
        value=0,
        vulnerabilities=OrderedDict([
            ("ScanLoginPage", VulnerabilityInfo(
                description="Login button endpoint leading to form, scan source file and find correct username/password restrictions",
                precondition=m.Precondition("username.NoAuth"),
                type=VulnerabilityType.REMOTE,
                outcome=m.concatenate_outcomes((m.LeakedNodesId, m.ProbeSucceeded))(
                    discovered_nodes=["POST_/v2/login"],
                    discovered_properties=["username_password_restrictions"]),
                reward_string="Discovered login form linked to endopoint POST /v2/login & rules for correct username/password, ex. pattern for username",
                cost=1.0
            )),
        ])),

    "POST_/v2/login": m.NodeInfo(
        services=[],
        value=0,
        properties=[],
        vulnerabilities=OrderedDict([
            ("AdminProbe", VulnerabilityInfo(
                description="Probe admin/admin",
                precondition=m.Precondition("username.NoAuth&username_password_restrictions"),
                type=VulnerabilityType.REMOTE,
                outcome=m.concatenate_outcomes((m.ProbeFailed, m.DetectionPoint))(detection_point_name="DP_admin"),
                reward_string="invliad credentials admin/admin",
                cost=1.0
            )),
            ("SqlInjectUsername", VulnerabilityInfo(
                description="SQL injeciton on login field",
                precondition=m.Precondition("username.NoAuth&username_password_restrictions"),
                type=VulnerabilityType.REMOTE,
                outcome=m.concatenate_outcomes((m.ExploitFailed, m.DetectionPoint))(detection_point_name="DP_sqlinjectusername"),
                reward_string="""Response: Invalid query: You have an error in your SQL syntax;
                    check the manual that corresponds to your MySQL server version for the right syntax to use near '' at line 1""",
                # "SQL injeciton attack on login field: Invalid Credentials"
            )),
        ])),

    "POST_/v2/register": m.NodeInfo(
        services=[],
        value=0,
        vulnerabilities=OrderedDict([
            ("", VulnerabilityInfo(
                description="egister patient and check cokies from authorisation",
                precondition=m.Precondition("username.NoAuth"),
                type=VulnerabilityType.REMOTE,
                outcome=m.concatenate_outcomes((m.LeakedProfiles, m.ProbeSucceeded, m.LeakedNodesId))(
                    discovered_profiles=["username.patient&id.UUIDfake"],
                    discovered_properties=[] + ht_on["HT3_state"] * ["state"],  # HT3 state
                    discovered_nodes=["GET_/v2/users"]),
                reward_string="Register AlicAnon patient to be able to access more info + discover cookie tokens (i.e. state)",
                cost=1.0
            ))
        ])),

    "GET_/v2/calendar": m.NodeInfo(
        services=[],
        value=0,
        vulnerabilities=OrderedDict([
            ("ValidWeekday", VulnerabilityInfo(
                description="Found usernames from calendar & property",
                precondition=m.Precondition("~username.NoAuth"),
                type=VulnerabilityType.REMOTE,
                outcome=m.LeakedProfiles(["username.LisaGWhite"]),
                reward_string="One of the weekdays shedule output gives (or not) any rpofile details",
                cost=1.0
            )),
            ("InvalidWeekday", VulnerabilityInfo(
                description="DECEPTION decoy: Trying other calendar nums, like GET_/v2/calendar/8 (9, 10, 11, ...)",
                precondition=m.Precondition("~username.NoAuth"),
                type=VulnerabilityType.REMOTE,
                outcome=m.concatenate_outcomes((m.ExploitFailed, m.DetectionPoint))(
                    detection_point_name="DP_calendar"),
                reward_string="No access to the endpoint (GET_/v2/calendar/outofbound_number)",
                cost=1.0
            )),
        ])),

    "GET_/v2/messages": m.NodeInfo(
        services=[],
        value=0,
        vulnerabilities=OrderedDict([
            # Recoinnassance
            ("", VulnerabilityInfo(
                description="Getting messages as different profiles, while changing SESSION token",
                type=VulnerabilityType.REMOTE,
                precondition=[m.Precondition("username.LisaGWhite&id.994D5244&roles.isDoctor"),
                              m.Precondition("username.MarioDFiles&id.F5BCFE9D&roles.isDoctor")],
                outcome=[m.LeakedProfiles(["username.MarioDFiles"]),
                         m.LeakedProfiles(["ip.local"])],
                reward_string=[
                    "Found message to MarioDFiles",
                    "Found another user MagdaleneJBreen + local access to сircumven VPN requirement"],
                cost=1.0
            )),
        ])),

    "GET_/v2/users": m.NodeInfo(
        services=[],
        value=0,
        properties=["username_password_restrictions"],
        vulnerabilities=OrderedDict([
            ("", VulnerabilityInfo(
                description="Returns full JSON snippet of credentials database IF use /v2/render as proxy for local access",
                type=VulnerabilityType.REMOTE,
                precondition=m.Precondition("~username.NoAuth&ip.local"),
                outcome=m.LeakedProfiles(["username.JamesMPaterson&id.68097B9D&roles.isChemist",
                                          "username.MarioDFiles&id.F5BCFE9D&roles.isDoctor",
                                          "username.LisaGWhite&id.994D5244&roles.isDoctor"]),
                reward_string="Lateral move (local access): all available profiles leaked",
                cost=1.0
            )),
            ("Username", VulnerabilityInfo(
                description="Geting profile ID, roles, i.e. credentials",
                type=VulnerabilityType.REMOTE,
                precondition=[m.Precondition("username.LisaGWhite&username_password_restrictions"),
                              m.Precondition("username.MarioDFiles&username_password_restrictions"), ],
                outcome=[m.LeakedProfiles(["username.LisaGWhite&id.994D5244&roles.isDoctor"]),
                         m.LeakedProfiles(["username.MarioDFiles&id.F5BCFE9D&roles.isDoctor"])],
                reward_string=["Obtain Session ID and roles for LisaGWhite",
                               "Obtain Session ID and roles for MarioDFiles"],
                cost=1.0
            )),
        ])),

    "GET_/v2/documents": m.NodeInfo(
        services=[],
        value=0,
        properties=[],
        vulnerabilities=OrderedDict([
            ("", VulnerabilityInfo(
                description="Getting all documents as Chemist",
                type=VulnerabilityType.REMOTE,
                precondition=m.Precondition("~username.NoAuth&roles.isChemist"),
                outcome=m.CustomerData(100, ctf_flag=True),
                reward_string="Gaining 2 HTML entries, second as CTF flag as the base-64 encoded image",
                cost=1.0
            )),

        ])),
}

if ht_on["HT2_phonebook"]:
    nodes["GET_/v2/phonebook"] = m.NodeInfo(  # HT2 phonebook
        services=[],
        value=0,
        vulnerabilities=OrderedDict([
            ("", VulnerabilityInfo(
                description="DECEPTION trap: honeypot - endpoint phonebook",
                type=VulnerabilityType.REMOTE,
                outcome=m.concatenate_outcomes((m.ExploitFailed, m.DetectionPoint))(detection_point_name="HT2_phonebook"),
                reward_string="Cannot GET_/v2/phonebook",
                cost=1.0
            ))
        ]))

# Environment constants
ENV_IDENTIFIERS = m.infer_constants_from_nodes(
    cast(Iterator[Tuple[NodeID, NodeInfo]], list(nodes.items())),
    global_vulnerability_library,
    global_properties,
    initial_properties)


def new_environment() -> m.Environment:
    return m.Environment(
        network=m.create_network(nodes),
        vulnerability_library=global_vulnerability_library,
        identifiers=ENV_IDENTIFIERS
    )
