# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""
A tiny microservice environment based on partial example from myMedicPortal, with the full list of deception strategy detection points
"""
from cyberbattle.simulation import model as m
from cyberbattle.simulation.model import NodeID, NodeInfo, VulnerabilityID, VulnerabilityInfo, VulnerabilityType, PropertyName
from typing import Iterator, cast, Tuple, List
from collections import OrderedDict
from cyberbattle.simulation.config import logger, configuration


global_vulnerability_library: OrderedDict[VulnerabilityID, VulnerabilityInfo] = OrderedDict([
    ("State=1", VulnerabilityInfo(
        description="Deceptive honeytoken with detection point",
        precondition=m.Precondition("~username.NoAuth&state"),  # ~script_block,
        type=VulnerabilityType.REMOTE,
        outcome=m.concatenate_outcomes((m.ExploitFailed, m.DetectionPoint))(cost=10, detection_point_name="HT3_state"),
        reward_string="Honeytoken tamepring: changing state value in cookies leads to no change",
    )),
    ("V2toV1", VulnerabilityInfo(
        description="Version change triggers deceptive token",
        # precondition=m.Precondition("~script_block"),
        type=VulnerabilityType.REMOTE,
        outcome=m.concatenate_outcomes((m.ExploitFailed, m.DetectionPoint))(detection_point_name="HT1_v2tov1"),  # Meeting 27.01, logic should be a bit different, should it lead to a different
        reward_string="Forced browsing attempt: changing version of platform value leads to no change",
    )),
])

# intial_profiles: List[Profile] = [] #TODO include username.NoAuth here, but not in the __init__ of CyberBattleEnv
global_properties: List[PropertyName] = ["state", "username_password_restrictions", "property.cloudactivedefense"]  # "document_a5db38da", "server",  # Meeting 27.01, shared properties (document, username_password) + global properties (server state)
initial_properties: List[PropertyName] = ["property.git", "robots.txt", "thisdoesnotexist"]

# Network nodes involved in the myMedcialPortal CTF
nodes = {
    "client_browser": m.NodeInfo(
        services=[],
        value=0,  # owning reward
        properties=["script_block"],
        owned_string="Attacker owns his laptop",
        vulnerabilities=OrderedDict([
            ("ScanPageSource", VulnerabilityInfo(
                description="Website HTML contains information about multiple blocks leading to endpoints "
                            "AND scripts with other endpoints + variables (tags?)",
                type=VulnerabilityType.LOCAL,
                outcome=m.concatenate_outcomes((m.LeakedNodesId, m.ProbeSucceeded))(
                    discovered_nodes=["GET_/v2", "GET_/v2/login", "POST_/v2/register", "GET_/v2/messages",
                                      "GET_/v2/documents", "GET_/v2/phonebook"],
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
                outcome=m.concatenate_outcomes((m.ProbeSucceeded,))(discovered_properties=["property.cloudactivedefense"]),
                reward_string="Found multiple properties (username, password, server?), among them the most important: property.cloudactivedefense",
                cost=1.0
            ))
        ]),
        agent_installed=True,
    ),

    "GET_/v2": m.NodeInfo(
        services=[],
        properties=["property.git", "property.cloudactivedefense", "robots.txt", "thisdoesnotexist"],
        value=0,  # owning reward
        vulnerabilities=OrderedDict([
            ("BrowsingTarget", VulnerabilityInfo(
                description="Finding through HTTP requests special properties",
                type=VulnerabilityType.REMOTE,
                precondition=[m.Precondition("true"), m.Precondition("thisdoesnotexist"),
                              m.Precondition("property.git"), m.Precondition("robots.txt"), m.Precondition("property.cloudactivedefense")],
                outcome=[m.ExploitFailed()] * 2 +
                        [m.concatenate_outcomes((m.ExploitFailed, m.DetectionPoint))(detection_point_name="DP_git")] +
                        [m.concatenate_outcomes((m.ExploitFailed, m.DetectionPoint))(detection_point_name="DP_robots")] +
                        [m.concatenate_outcomes((m.ExploitFailed, m.DetectionPoint))(detection_point_name="HT4_cloudactivedefense")],
                reward_string=["Forced browsing attempts"] * 4 +
                              ["Forced browsing attempts (honey HTTP header paremeter - detection point triggered)"],
                cost=1.0
            ))
        ])
    ),

    "GET_/v2/login": m.NodeInfo(  # Kindha discovers only POST /v2/login and POSSIBLE rules for /v2/users
        services=[],
        value=0,
        vulnerabilities=OrderedDict([
            ("ScanLoginPage", VulnerabilityInfo(
                description="Login button endpoint leading to form, scan source file and find correct username/password restrictions",
                precondition=m.Precondition("username.NoAuth"),  # MEETING 27.01
                type=VulnerabilityType.REMOTE,
                outcome=m.concatenate_outcomes((m.LeakedNodesId, m.ProbeSucceeded))(
                    discovered_nodes=["POST_/v2/login"],
                    discovered_properties=["username_password_restrictions"]),
                # MEETING 27.01, discuss that now we can start using USERS with just GET_/v2/login rather OR
                # maybe we need 2 actions, "username_password_restriction_1" + "username_password_restriction_2" in order to gather HOW to form username from Name, Surname
                reward_string="Discovered login form linked to endopoint POST /v2/login & rules for correct username/password, ex. pattern for username",
                cost=1.0
            )),
        ])),

    "POST_/v2/login": m.NodeInfo(
        services=[],
        value=0,
        properties=[],  # !!! "server",
        # TONEXTDO switch action of profiles? or If we include password protection, here could be a lot of vulenerabilities because of "weak" security
        vulnerabilities=OrderedDict([
            ("AdminProbe", VulnerabilityInfo(
                description="Probe admin/admin",
                precondition=m.Precondition("username.NoAuth&username_password_restrictions"),
                type=VulnerabilityType.REMOTE,
                outcome=m.concatenate_outcomes((m.ProbeFailed, m.DetectionPoint))(detection_point_name="DP_admin"),  # m.concatenate_outcomes(( m.ExploitFailed))(),
                reward_string="invliad credentials admin/admin",
                cost=1.0
            )),
            ("SqlInjectUsername", VulnerabilityInfo(
                description="SQL injeciton on login field",
                precondition=m.Precondition("username.NoAuth&username_password_restrictions"),
                type=VulnerabilityType.REMOTE,
                outcome=m.concatenate_outcomes((m.ExploitFailed, m.DetectionPoint))(detection_point_name="DP_sqlinjectusername"),
                reward_string="SQL injeciton attack on login field: Invalid Credentials",
                # rates=m.Rates(succesRate=0.9),  # TONEXTDO
            )),
            # ("SqlServer", VulnerabilityInfo(
            #     description="SQL injeciton on login field",
            #     precondition=m.Precondition("server&username.NoAuth"),
            #     type=VulnerabilityType.REMOTE,
            #     outcome=m.concatenate_outcomes((m.ExploitFailed, m.DetectionPoint))(detection_point_name="HT_SqlServer"),
            #     reward_string="SQL injeciton attack on login field",
            #     rates=m.Rates(succesRate=0.9),
            #     cost=1.0
            # ))
        ])),

    "POST_/v2/register": m.NodeInfo(
        services=[],
        value=0,  # owning reward
        vulnerabilities=OrderedDict([
            ("", VulnerabilityInfo(  # LocalUser == registered user with SESSION token, but without privilages!
                description="egister patient and check cokies from authorisation",
                precondition=m.Precondition("username.NoAuth"),
                type=VulnerabilityType.REMOTE,
                outcome=m.concatenate_outcomes((m.LeakedProfiles, m.ProbeSucceeded, m.LeakedNodesId))(
                    discovered_profiles=["username.patient&id.UUIDfake"],
                    discovered_properties=["state"],
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
                outcome=m.LeakedProfiles(["username.LisaGWhite"]),  # , "username.JanJCovington", "username.DorisHDunn"]),
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
                              # m.Precondition("username.DorisHDunn&id.4ADA8BB4"),
                              # m.Precondition("username.JanJCovington&id.CDCEDE1C"),
                              # m.Precondition("username.Magdalene&id.5C0D2C9A"),
                              m.Precondition("username.MarioDFiles&id.F5BCFE9D&roles.isDoctor")],
                outcome=[m.LeakedProfiles(["username.MarioDFiles"]),
                         # m.ProbeFailed(),
                         # m.ProbeFailed(),
                         # m.ProbeFailed(),
                         m.LeakedProfiles(["ip.local"])],  # OR m.concatenate_outcomes((m.ProbeSucceeded, m.LeakedProfiles))(discovered_properties=["document_a5db38da"],
                #                                                                                                            discovered_profiles=["ip.local", "username.MagdaleneJBreen"])
                #                                                                                                            PLUS m.LeakedNodesId = ["GET_/v2/render"]
                reward_string=[
                    "Found message to MarioDFiles",
                    # "No messages",
                    # "No messages",
                    # "No messages",
                    "Found another user MagdaleneJBreen + local access to сircumven VPN requirement"],
                cost=1.0
            )),
        ])),

    "GET_/v2/users": m.NodeInfo(
        services=[],
        value=0,  # owning reward
        properties=["username_password_restrictions"],  # SO WE NEED INCLUDE all usernames into properties
        vulnerabilities=OrderedDict([
            ("", VulnerabilityInfo(
                description="Returns full JSON snippet of credentials database IF use /v2/render as proxy for local access",
                type=VulnerabilityType.REMOTE,
                precondition=m.Precondition("~username.NoAuth&ip.local"),  # Meeting 27.01, cannpot be used without  authorisation with SESSION cookie?
                outcome=m.LeakedProfiles(["username.JamesMPaterson&id.68097B9D&roles.isChemist",
                                          # "username.AnotherGuyName&id.cookie233424&roles.isAssistant",
                                          # "username.JanJCovington&id.CDCEDE1C&roles.isDoctor",
                                          "username.MarioDFiles&id.F5BCFE9D&roles.isDoctor",
                                          # "username.MagdaleneJBreen&id.5C0D2C9A&roles.isDoctor",
                                          # "username.DorisHDunn&id.4ADA8BB4&roles.isDoctor",
                                          "username.LisaGWhite&id.994D5244&roles.isDoctor"]),
                reward_string="Lateral move (local access): all available profiles leaked",
                cost=1.0
            )),
            ("Username", VulnerabilityInfo(
                description="Geting profile ID, roles, i.e. credentials",
                type=VulnerabilityType.REMOTE,
                precondition=[m.Precondition("username.LisaGWhite&username_password_restrictions"),
                              # m.Precondition("username.DorisHDunn&username_password_restrictions"),
                              # m.Precondition("username.MagdaleneJBreen&username_password_restrictions")],
                              m.Precondition("username.MarioDFiles&username_password_restrictions"), ],
                outcome=[m.LeakedProfiles(["username.LisaGWhite&id.994D5244&roles.isDoctor"]),
                         # m.LeakedProfiles(["username.DorisHDunn&id.4ADA8BB4&roles.isDoctor"]),
                         # m.LeakedProfiles(["username.MagdaleneJBreen&id.5C0D2C9A&roles.isDoctor"]),
                         m.LeakedProfiles(["username.MarioDFiles&id.F5BCFE9D&roles.isDoctor"])],
                reward_string=["Obtain Session ID and roles for LisaGWhite",
                               # "Globally Available Session ID and roles for DorisHDunn",
                               # "Globally Available Session ID and roles for MagdaleneJBreen"],
                               "Obtain Session ID and roles for MarioDFiles"],
                cost=1.0
            )),
        ])),

    "GET_/v2/documents": m.NodeInfo(
        services=[],
        value=0,
        properties=[],  # "document_a5db38da"
        vulnerabilities=OrderedDict([
            ("", VulnerabilityInfo(
                description="Getting all documents as Chemist",
                type=VulnerabilityType.REMOTE,
                precondition=m.Precondition("~username.NoAuth&roles.isChemist"),
                outcome=m.CustomerData(100, ctf_flag=True),  # Meeting 27.01, because its a stack of data, but person need at least to do one more action. So maybe probe => property and then 2 vulns with 2 properties
                reward_string="Gaining 2 HTML entries, second as CTF flag as the base-64 encoded image",
                cost=1.0
            )),
            # ("id", VulnerabilityInfo(
            #     description="Medical image of patient of Dr. MarioDFiles",
            #     type=VulnerabilityType.REMOTE,
            #     precondition=m.Precondition("~username.NoAuth&ip.local&document_a5db38dar"),
            #     outcome=m.CustomerData(10),
            #     reward_string="Obtained low value medical image of doctor's MarioDFiles patient",
            #     cost=1.0
            # )),
        ])),


    "GET_/v2/phonebook": m.NodeInfo(
        services=[],
        value=0,
        vulnerabilities=OrderedDict([
            # Identify GET_usage for anyuser
            ("", VulnerabilityInfo(
                description="DECEPTION trap: honeypot - endpoint phonebook",
                type=VulnerabilityType.REMOTE,
                outcome=m.concatenate_outcomes((m.ExploitFailed, m.DetectionPoint))(detection_point_name="HT2_phonebook"),
                reward_string="Cannot GET_/v2/phonebook",
                cost=1.0
            ))
        ])),

    # "GET_/v2/render": m.NodeInfo(
    #     services=[],
    #     value=0,
    #     properties=["ip_local"],
    #     vulnerabilities=OrderedDict(
    #         # Identify GET_usage for anyuser
    #         (("", VulnerabilityInfo(
    #             description="Trying to GET_/v2/render",
    #             type=VulnerabilityType.REMOTE,
    #             precondition=m.Precondition("~username.NoAuth"),
    #             outcome=m.ExploitFailed(), # TODO code same outcome as from node "GET_/v2"
    #             reward_string="Cannot GET_/render",
    #             cost=1.0
    #         ))
    #     )),
    # ),
    #         ("id",VulnerabilityInfo(
    #             description="/render/http%3A%2F%2F127.0.0.1%3A8081%2Fdocuments%2Fa5db38da-156a-4d00-a041-9702db349ca5",
    #             type=VulnerabilityType.REMOTE,
    #             precondition=m.Precondition("~username.NoAuth&document_a5db38da"),
    #             outcome=m.CustomerData(),
    #             reward_string="GET_ting image (not sensitive info)",
    #             cost=1.0
    #         )),
    #         # TODOMeeting what is the point of being unauthenticated here?
    #         ("test",VulnerabilityInfo(
    #             description="Ping test",
    #             type=VulnerabilityType.REMOTE,
    #             outcome=m.ExploitFailed(),
    #             reward_string="Server unreachable",
    #             cost=1.0
    #         )),
    #         ("outer_address", VulnerabilityInfo(
    #             description="Ping www.google.com",
    #             type=VulnerabilityType.REMOTE,
    #             outcome=m.ExploitFailed(),
    #             reward_string="Server unreachable",
    #             cost=1.0
    #         )),
    #         ("local_address",VulnerabilityInfo(
    #             description="Ping 127.0.0.1",
    #             type=VulnerabilityType.REMOTE,
    #             outcome=m.ProbeSucceeded(["ip_local"]),  # TOTMeeting or here we give profile of IP.local
    #             reward_string="GET_/ in header",
    #             cost=1.0
    #         ))
    #     )),
}

# Environment constants
ENV_IDENTIFIERS = m.infer_constants_from_nodes(
    cast(Iterator[Tuple[NodeID, NodeInfo]], list(nodes.items())),
    global_vulnerability_library,
    global_properties,
    initial_properties)
# OR initial_properties add afterwards, like
# ENV_IDENTIFIERS.initial_properties = initial_properties


def new_environment() -> m.Environment:
    return m.Environment(
        network=m.create_network(nodes),
        vulnerability_library=global_vulnerability_library,
        identifiers=ENV_IDENTIFIERS
    )
