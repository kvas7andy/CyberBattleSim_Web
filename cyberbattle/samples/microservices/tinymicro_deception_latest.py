# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""A tiny microservice environment based on partial example from myMedicPortal

"""
from cyberbattle.simulation import model as m
from cyberbattle.simulation.model import NodeID, NodeInfo, VulnerabilityID, VulnerabilityInfo, VulnerabilityType, Profile, PropertyName
from typing import Dict, Iterator, cast, Tuple, List
from collections import OrderedDict

default_allow_rules = [
    m.FirewallRule("SSH", m.RulePermission.ALLOW),
]

ADMINTAG = m.AdminEscalation().tag
SYSTEMTAG = m.SystemEscalation().tag


global_vulnerability_library: OrderedDict[VulnerabilityID, VulnerabilityInfo] = OrderedDict([
    ("state=1", VulnerabilityInfo(
        description="Deceptive honeytoken with detection point",
        precondition=m.Precondition("~username.NoAuth&state"),
        type=VulnerabilityType.REMOTE,
        outcome=m.get_dynamical_class((m.ProbeFailed, m.DetectionPoint))(detection_point_name="state_point_1"),
        reward_string="Changing state value in cookies does not change situation",
    )),
    # ("v2tov1", VulnerabilityInfo(
    #     description="Deceptive honeytoken with detection point",
    #     precondition=m.Precondition("~username.NoAuth"),
    #     type=VulnerabilityType.REMOTE,
    #     outcome=m.get_dynamical_class((m.ProbeFailed, m.DetectionPoint))(detection_point_name="v2tov1_point_1"),  # Meeting 25.01, logic should be a bit different, should it lead to a different
    #     reward_string="Forced browsing attempt: Changing version of platform value does not change situation",
    # )),
])

# global_profiles_library: List[Profile] = []
global_properties: List[PropertyName] = ["state", "document_a5db38da", "username_password_restrictions"]  # "server",  # Meeting 25.01, shared properties (document, username_password) + global properties (server state)
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
                outcome=m.get_dynamical_class((m.LeakedNodesId, m.ProbeSucceeded))(
                    discovered_nodes=["GET_/v2", "GET_/v2/login", "POST_/v2/register", "GET_/v2/messages",
                                      "GET_/v2/calendar", "GET_/v2/documents", "GET_/v2/phonebook"],  # , "GET_/v2/users"],
                    discovered_properties=["script_block"]),
                reward_string="Inspect: Viewing the web page source reveals main endpoints",
                cost=1.0
            )),
            # TODO put into POST_/v2/register # Meeting 25.01.22
            ("ScanBlockRegister", VulnerabilityInfo(
                description="Website HTML contains script with rules of username configuration",
                type=VulnerabilityType.LOCAL,
                precondition=m.Precondition("script_block"),
                outcome=m.ProbeSucceeded(["username_password_restrictions"]),
                reward_string="Found script with rules of username creation from POST_/v2/register => access to GET_/v2/users",
                cost=1.0
            ))
        ]),
        agent_installed=True,
    ),

    "GET_/v2": m.NodeInfo(
        services=[],
        properties=["property.git", "property.cloudactivedefence", "robots.txt", "thisdoesnotexist"],
        value=10,  # owning reward
        vulnerabilities=OrderedDict([
            ("browsing_target", VulnerabilityInfo(
                description="Finding through HTTP requests special properties",
                type=VulnerabilityType.REMOTE,
                precondition=[m.Precondition("true"), m.Precondition("property.git"), m.Precondition("robots.txt"),
                              m.Precondition("thisdoesnotexist"), m.Precondition("property.cloudactivedefence")],
                outcome=[m.ExploitFailed()] * 4 + \
                        [m.get_dynamical_class((m.ExploitFailed, m.DetectionPoint))(detection_point_name="cloudactive_defense_point_1")],
                reward_string=["Forced browsing attempts"] * 4 + \
                              ["Forced browsing attempts (detection point triggered)"],
                cost=1.0
            ))
        ])
    ),

    "GET_/v2/login": m.NodeInfo(  # Kindha discovers only POST /v2/login and POSSIBLE rules for /v2/users
        services=[],
        value=10,
        vulnerabilities=dict(
            POST_AsAnyUser=VulnerabilityInfo(
                description="Login button endpoint leading to form for correct username/password",
                precondition=m.Precondition("username.NoAuth"),  # MEETING 27.10
                type=VulnerabilityType.REMOTE,
                outcome=m.get_dynamical_class((m.LeakedNodesId, m.ProbeSucceeded))(discovered_nodes=["POST_/v2/login"], discovered_properties=["username_password_restrictions"]),  # MEETING 25.01,
                # discuss that now we can start using USERS with just GET_/v2/login rather OR maybe we need 2 actions, "username_password_restriction_1" + "username_password_restriction_2" in order to gather HOW to form username from Name, Surname
                reward_string="Discovered login form linked to endopoint POST /v2/login & rules for correct username/password",
                cost=1.0
            )
        )),

    "POST_/v2/login": m.NodeInfo(
        services=[],
        value=10,
        properties=["username", "username_password_restrictions"],  # !!! "server",
        # Vulnerability name: LOGGIN bruteforcing?
        # TODO switch action of profiles? or If we include password protection, here could be a lot of vulenerabilities because of "weak" security
        vulnerabilities=OrderedDict([
            ("", VulnerabilityInfo(
                description="Probe admin/admin",
                precondition=m.Precondition("username.NoAuth"),
                type=VulnerabilityType.REMOTE,
                outcome=m.ProbeFailed(),  # m.get_dynamical_class(( m.ExploitFailed))(),
                reward_string="Probing admin/admin login",
                cost=1.0
            )),
            ("sql_inject_username", VulnerabilityInfo(
                description="SQL injeciton on login field",
                precondition=m.Precondition("username.NoAuth"),
                type=VulnerabilityType.REMOTE,
                outcome=m.get_dynamical_class((m.ExploitFailed, m.DetectionPoint))(detection_point_name="sql_inject_username_point_1"),
                reward_string="SQL injeciton attack on login field",
                # rates=m.Rates(succesRate=0.9),  # !!! TONEXTDO
            )),
            # !!!
            # ("sql_server", VulnerabilityInfo(
            #     description="SQL injeciton on login field",
            #     precondition=m.Precondition("server&username.NoAuth"),
            #     type=VulnerabilityType.REMOTE,
            #     outcome=m.get_dynamical_class((m.ExploitFailed, m.DetectionPoint))(detection_point_name="sql_server_point_1"),
            #     reward_string="SQL injeciton attack on login field",
            #     rates=m.Rates(succesRate=0.9),
            #     cost=1.0
            # ))
        ])),

    "POST_/v2/register": m.NodeInfo(
        services=[],
        value=10,  # owning reward
        vulnerabilities=OrderedDict([
            ("", VulnerabilityInfo(  # LocalUser == registered user with SESSION token, but without privilages!
                description="Trap Deceptive endpoint to check",
                precondition=m.Precondition("username.NoAuth"),
                type=VulnerabilityType.REMOTE,
                outcome=m.get_dynamical_class((m.LeakedProfiles, m.ProbeSucceeded, m.LeakedNodesId))(
                    discovered_profiles=["username.patient&id.UUIDfake"], discovered_properties=["state"], discovered_nodes=["GET_/v2/users"]),  #
                # discovered_properties=["state"], discovered_nodes=["GET_/v2/users"]),
                reward_string="Register AlicAnon patient to be able to access more info",
                cost=1.0
            ))
        ])),

    "GET_/v2/calendar": m.NodeInfo(
        services=[],
        value=0,
        vulnerabilities=OrderedDict([
            ("", VulnerabilityInfo(
                description="Found usernames from calendar & property",
                precondition=m.Precondition("username.patient"),
                type=VulnerabilityType.REMOTE,
                outcome=m.LeakedProfiles(["username.LisaGWhite"]),  # , "username.JanJCovington", "username.DorisHDunn"]),
                reward_string="One of the weekdays shedule output gives (or not) any rpofile details",
                cost=1.0
            )),
            ("invalid_weekday", VulnerabilityInfo(
                description="DECEPTION decoy: Trying other calendar nums, like GET_/v2/calendar/8 (9, 10, 11, ...)",
                precondition=m.Precondition("username.patient"),
                type=VulnerabilityType.REMOTE,
                outcome=m.get_dynamical_class((m.ExploitFailed, m.DetectionPoint))(
                    detection_point_name="calendar_point_1"),
                reward_string="No access to the endpoint (GET_/v2/calendar/outofbound_number)",
                cost=1.0
            )),
        ])),

    "GET_/v2/messages": m.NodeInfo(
        services=[],
        value=40,
        vulnerabilities=OrderedDict([
            # Identify GET_usage for anyuser
            ("", VulnerabilityInfo(
                description="GET_ting messages as different profiles",
                type=VulnerabilityType.REMOTE,
                precondition=[m.Precondition("username.LisaGWhite&id.994D5244&roles.isDoctor"),
                              m.Precondition("username.MarioDFiles&id.F5BCFE9D&roles.isDoctor")],
                outcome=[m.LeakedProfiles(["username.MarioDFiles"]),
                         m.LeakedProfiles(["ip.local"])],  # , "username.MagdaleneJBreen"])],
                reward_string=[  # "Authentification required OR Error: doctors and chemists only",
                    "Found message to another user via link with MarioDFiles",
                    "Found another username MagdaleneJBreen + render with local access to other studd"],
                cost=1.0
            )),
            # GET_AsDoris=VulnerabilityInfo(
            #     description="GET_ting messages as Doris",
            #     type=VulnerabilityType.REMOTE,
            #     precondition=m.Precondition("username.DorisHDunn&id.4ADA8BB4"),
            #     outcome=m.ExploitFailed(),
            #     reward_string="No messages",
            #     cost=1.0
            # ),
            # GET_AsJan=VulnerabilityInfo(
            #     description="GET_ting messages as Jan",
            #     type=VulnerabilityType.REMOTE,
            #     precondition=m.Precondition("username.JanJCovington&id.CDCEDE1C"),
            #     outcome=m.ExploitFailed(),
            #     reward_string="No messages",
            #     cost=1.0
            # ),
            # GET_AsMagdalene=VulnerabilityInfo(
            #     description="GET_ting messages as Magdalene",
            #     type=VulnerabilityType.REMOTE,
            #     precondition=m.Precondition("username.Magdalene&id.5C0D2C9A"),
            #     outcome=m.ExploitFailed(),
            #     reward_string="No messages",
            #     cost=1.0
            # ),
            # # TODO merge these 2 vulnerabilities through the NEW OUTCOME type as concatenation of 2
            # GET_AsMarioDFilesRender=VulnerabilityInfo(
            #     description="GET_ting messages as Mario",
            #     type=VulnerabilityType.REMOTE,
            #     precondition=m.Precondition("username.MarioDFiles&id.F5BCFE9D"),
            #     outcome=m.LeakedNodesId(["GET_/v2/render"]),
            #     reward_string="/v2/render is leaked",
            #     cost=1.0
            # ),
            # TODOMeeting either GET_ting this doc from messages, or as vulnerability of probing first & then searching for document in /v2/render  GET_properties as id of document
            # GET_AsMarioDFilesId=VulnerabilityInfo(
            #     description="GET_ting messages as Mario",
            #     type=VulnerabilityType.REMOTE,
            #     precondition=m.Precondition("username.MarioDFiles&id.F5BCFE9D"),
            #     outcome=m.ProbeSucceeded(["document_a5db38da"]),
            #     reward_string="/v2/render is leaked",
            #     cost=1.0
            # )
        ])),

    "GET_/v2/documents": m.NodeInfo(
        services=[],
        value=0,
        properties=["document_a5db38da"],
        # properties=["LisaGWhite", "MarioD"],  # SO WE NEED INCLUDE all usernames into properties
        vulnerabilities=OrderedDict([
            ("", VulnerabilityInfo(
                description="GET_ting documents as Chemist",
                type=VulnerabilityType.REMOTE,
                precondition=m.Precondition("~username.NoAuth&roles.isChemist"),
                outcome=m.CustomerData(2000, ctf_flag=True),  # Meeting 25.01, because its a stack of data, but person need at least to do one more action. So maybe probe=> property and then 2 vulns with 2 properties
                reward_string="Gaining 2 HTML entries, one of which has CTF flag in base-64 encoded as image",
                cost=1.0
            )),
            # ("document_a5db38da", VulnerabilityInfo(
            #     description="Medical image of patient of Dr. MarioDFiles",
            #     type=VulnerabilityType.REMOTE,
            #     precondition=m.Precondition("~username.NoAuth&ip.local&document_a5db38dar"),
            #     outcome=m.CustomerData(100),
            #     reward_string="Obtained low value medical image of doctor's MarioDFiles patient",
            #     cost=1.0
            # )),
        ])),

    # "GET_/v2/render": m.NodeInfo(
    #     services=[],
    #     value=0,
    #     properties=["ip_local"],
    #     vulnerabilities=m.strkey_to_tuplekey("GET_/v2/render", dict(
    #         # Identify GET_usage for anyuser
    #         GET_AsLocalUser=VulnerabilityInfo(
    #             description="Trying to GET_/v2/render",
    #             type=VulnerabilityType.REMOTE,
    #             precondition=m.Precondition("username.patient"),
    #             outcome=m.ExploitFailed(5),
    #             reward_string="Cannot GET_/render",
    #             cost=1.0
    #         )
    #     )),
    # ),
    #         GET_AsDocument=VulnerabilityInfo(
    #             description="/render/http%3A%2F%2F127.0.0.1%3A8081%2Fdocuments%2Fa5db38da-156a-4d00-a041-9702db349ca5",
    #             type=VulnerabilityType.REMOTE,
    #             precondition=m.Precondition("username.LisaGWhite&document_a5db38da"),
    #             outcome=m.CustomerData(5),
    #             reward_string="GET_ting image (not sensitive info)",
    #             cost=1.0
    #         ),
    #         # TODOMeeting what is the point of being unauthenticated here?
    #         GET_AsTest=VulnerabilityInfo(
    #             description="Ping test",
    #             type=VulnerabilityType.REMOTE,
    #             outcome=m.ExploitFailed(),
    #             reward_string="Error: Authentication required",
    #             cost=1.0
    #         ),
    #         GET_WithInternet=VulnerabilityInfo(
    #             description="Ping www.google.com",
    #             type=VulnerabilityType.REMOTE,
    #             outcome=m.ExploitFailed(),
    #             reward_string="Server unreachable",
    #             cost=1.0
    #         ),
    #         GET_WithLocalHost=VulnerabilityInfo(
    #             description="Ping 127.0.0.1",
    #             type=VulnerabilityType.REMOTE,
    #             outcome=m.ProbeSucceeded(["ip_local"]),  # TOTMeeting or here we give profile of IP.local
    #             reward_string="GET_/ in header",
    #             cost=1.0
    #         )
    #     )),

    "GET_/v2/phonebook": m.NodeInfo(
        services=[],
        value=0,
        # properties=["LisaGWhite", "MarioD"],  # SO WE NEED INCLUDE all usernames into properties
        vulnerabilities=OrderedDict([
            # Identify GET_usage for anyuser
            ("", VulnerabilityInfo(
                description="DECEPTION trap: honeypot as phonebook",
                type=VulnerabilityType.REMOTE,
                outcome=m.get_dynamical_class((m.ExploitFailed, m.DetectionPoint))(detection_point_name="phonebook_point_1"),  # ProbeFailed is not ExploitFailed
                reward_string="Cannot GET_/v2/phonebook",
                cost=1.0
            ))
        ])),

    "GET_/v2/users": m.NodeInfo(
        services=[],
        value=100,  # owning reward
        properties=["username_password_restrictions"],  # SO WE NEED INCLUDE all usernames into properties
        vulnerabilities=OrderedDict([
            ("", VulnerabilityInfo(
                description="GET_ting Credentials",
                type=VulnerabilityType.REMOTE,
                precondition=m.Precondition("~username.NoAuth&ip.local"),  #
                outcome=m.LeakedProfiles(["username.JamesMPaterson&id.68097B9D&roles.isChemist",
                                          # "username.AnotherGuyName&id.cookie233424&roles.isAssistant",
                                          # "username.JanJCovington&id.CDCEDE1C&roles.isDoctor",
                                          "username.MarioDFiles&id.F5BCFE9D&roles.isDoctor",
                                          # "username.DorisHDunn&id.4ADA8BB4&roles.isDoctor",
                                          "username.LisaGWhite&id.994D5244&roles.isDoctor",
                                          "username.MagdaleneJBreen&id.5C0D2C9A&roles.isDoctor"]),
                reward_string="All available profiles",
                cost=1.0
            )),
            ("username", VulnerabilityInfo(
                description="GET_ting Credentials",
                type=VulnerabilityType.REMOTE,
                precondition=[m.Precondition("username.LisaGWhite&username_password_restrictions"),
                              m.Precondition("username.MarioDFiles&username_password_restrictions"), ],
                # m.Precondition("username.DorisHDunn"),
                # m.Precondition("username.MagdaleneJBreen")],
                outcome=[m.LeakedProfiles(["username.LisaGWhite&id.994D5244&roles.isDoctor"]),
                         m.LeakedProfiles(["username.MarioDFiles&id.F5BCFE9D&roles.isDoctor"]), ],
                # m.LeakedProfiles(["username.DorisHDunn&id.4ADA8BB4&roles.isDoctor"]),
                # m.LeakedProfiles(["username.MagdaleneJBreen&id.5C0D2C9A&roles.isDoctor"]), ],
                reward_string=["Globally Available Session ID and username for LisaGWhite",
                               "Globally Available Session ID and username for MarioDFiles", ],
                # "Globally Available Session ID and username for DorisHDunn",
                # "Globally Available Session ID, username for MagdaleneJBreen, roles and IP of profile"],
                cost=1.0
            )),
        ]))
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
