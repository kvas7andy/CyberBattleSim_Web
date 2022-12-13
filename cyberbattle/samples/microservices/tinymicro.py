# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""A tiny microservice environment based on partial example from myMedicPortal

"""
from cyberbattle.simulation import model as m
from cyberbattle.simulation.model import NodeID, NodeInfo, VulnerabilityID, VulnerabilityInfo, Profile
from typing import Dict, Iterator, cast, Tuple, List
from collections import OrderedDict

default_allow_rules = [
    m.FirewallRule("SSH", m.RulePermission.ALLOW),
]

ADMINTAG = m.AdminEscalation().tag
SYSTEMTAG = m.SystemEscalation().tag

# Network nodes involved in the myMedcialPortal CTF
nodes = {
    "client_browser": m.NodeInfo(
        services=[],
        value=0,  # owning reward
        properties=["script_block"],
        owned_string="Attacker owns his laptop",
        vulnerabilities=OrderedDict([
            ("ScanPageSource", m.VulnerabilityInfo(
                description="Website HTML contains information about multiple blocks leading to endpoints "
                            "AND scripts with other endpoints + variables (tags?)",
                type=m.VulnerabilityType.LOCAL,
                outcome=m.LeakedNodesId(["POST_/v2/register", "GET_/v2/messages", "GET_/v2/calendar", "GET_/v2/documents"]),  # "GET_/v2/phonebook", "POST_ /v2/login", "GET_/v2/login", "GET_/v2"]),
                # Not OWNED, need to make connect_to_remote with any credentials to make them owned and include all their properties
                reward_string="Inspect: Viewing the web page source reveals main endpoints",
                cost=1.0
            )),
            # TODOAFTER put into POST_ /v2/register
            ("ScanBlockRegister", m.VulnerabilityInfo(
                description="Website HTML contains script with rules of username configuration",
                type=m.VulnerabilityType.LOCAL,
                precondition=m.Precondition("script_block"),
                outcome=m.LeakedNodesId(["GET_/v2/users"]),  # m.GET__dynamical_class((m.LeakedNodesId, m.CustomerData))(
                # nodes=["GET_/v2/users"], reward=20),  # m.LeakedNodesId(["GET_/v2/users"]), #
                # Not OWNED, need to make connect_to_remote with any credentials to make them owned and include all their properties
                reward_string="Found script with rules of username creation from POST_ /register => access to GET_/v2/users",
                cost=1.0
            ))
        ]),
        agent_installed=True,
    ),
    # TODOMeeting !!!!!!! .cloudactivedefence property should be hidden in check_prerequisuites
    # "GET_/v2": m.NodeInfo(
    #     services=[],
    #     properties=[".cloudactivedefence"],
    #     value=10,  # owning reward
    #     vulnerabilities=dict(
    #         ScanBurp=m.VulnerabilityInfo(
    #             description="Finding through HTTP requests special properties",
    #             type=m.VulnerabilityType.REMOTE,
    #             outcome=m.ProbeSucceeded([".cloudactivedefence"]),
    #             # Not OWNED, need to make connect_to_remote with any credentials to make them owned and include all their properties
    #             reward_string="Found token in HTTP reqest header '.cloudactivedefence', but is it deceptive?",
    #             cost=1.0
    #         ),
    #         GET_AsNoAuth=m.VulnerabilityInfo(
    #             description="Cannot GET_/v2",
    #             type=m.VulnerabilityType.REMOTE,
    #             outcome=m.ExploitFailed(),
    #             # Not OWNED, need to make connect_to_remote with any credentials to make them owned and include all their properties
    #             reward_string="Cannot GET_/v2",
    #             cost=1.0
    #         )
    #     )),

    # "GET_/v2/login": m.NodeInfo(
    #     services=[],
    #     value=10,  # owning reward
    #     vulnerabilities=dict(
    #         # TODO switch action of profiles? or If we include password protection, here could be a lot of vulenerabilities because of "weak" security
    #         # POST_AsAnyUser=m.VulnerabilityInfo(
    #         #     description="Login button endpoint asks for correct credentials",
    #         #     precondition=m.Precondition("patient"),  # MEETING 27.10
    #         #     type=m.VulnerabilityType.REMOTE,
    #         #     outcome=m.LeakedProfiles("patient"),
    #         #     reward_string="Discovered endpoints available ",
    #         #     cost=1.0
    #         # )
    #     )),

    # "POST_ /v2/login": m.NodeInfo(
    #     services=[],
    #     value=10,  # owning reward
    #     # Vulnerability name: LOGGIN bruteforcing?
    #     vulnerabilities=dict(
    #         POST_AsAdmin=m.VulnerabilityInfo(  # LocalUser == registered user with SESSION token, but without privilages!
    #             description="Admin credentials are wrong",
    #             type=m.VulnerabilityType.REMOTE,
    #             outcome=m.ExploitFailed(),
    #             reward_string="Login as admin: invalid credentials",
    #             cost=1.0
    #         )
    #     )),

    "POST_/v2/register": m.NodeInfo(
        services=[],  # should I leave like this?
        value=10,  # owning reward
        vulnerabilities=OrderedDict([
            ("", m.VulnerabilityInfo(  # LocalUser == registered user with SESSION token, but without privilages!
                description="Trap Deceptive endpoint to check",
                type=m.VulnerabilityType.REMOTE,
                outcome=m.LeakedProfiles(["username.patient&id.UUIDfake"]),
                reward_string="Register AlicAnon patient to be able to access more info",
                cost=1.0
            ))
        ])),

    "GET_/v2/calendar": m.NodeInfo(
        services=[],  # should I leave like this?
        value=0,
        vulnerabilities=OrderedDict([
            # Identify GET_usage for anyuser
            ("", m.VulnerabilityInfo(
                description="Found usernames from calendar & property",
                precondition=m.Precondition("username.patient"),
                type=m.VulnerabilityType.REMOTE,
                outcome=m.LeakedProfiles(["username.LisaGWhite"]),  # , "username.JanJCovington", "username.DorisHDunn"]),
                reward_string="One of the weekdays shedule output gives (or not) any rpofile details",
                cost=1.0
            )),
            # TODO like example of vulnerability having wrong outcome without precondition
            # GET_AsNoAuth=m.VulnerabilityInfo(
            #     description="Authentification required",
            #     type=m.VulnerabilityType.REMOTE,
            #     outcome=m.ExploitFailed(),
            #     reward_string="Authentification required",
            #     cost=1.0
            # ),
            # GET_WithOtherCalenderNum=m.VulnerabilityInfo(
            #     description="DECEPTION decoy: Trying other calendar nums, like GET_/v2/calendar/8 (9, 10, 11, ...)",
            #     precondition=m.Precondition("username.patient"),
            #     type=m.VulnerabilityType.REMOTE,
            #     outcome=m.ExploitFailed(deception=True),  # Even with deception, it should be just as always, BUT we trigger
            #     reward_string="Error: day should be set between 0 and 7",
            #     cost=1.0
            # ),
        ])),

    "GET_/v2/messages": m.NodeInfo(
        services=[],
        value=40,
        vulnerabilities=OrderedDict([
            # Identify GET_usage for anyuser
            ("", m.VulnerabilityInfo(
                description="GET_ting messages as different profiles",
                type=m.VulnerabilityType.REMOTE,
                precondition=[m.Precondition("username.patient"),
                              m.Precondition("username.LisaGWhite&id.994D5244"),
                              m.Precondition("username.MarioDFiles&id.F5BCFE9D")],
                outcome=[m.ExploitFailed(),
                         m.LeakedProfiles(["username.MarioDFiles"]),
                         m.LeakedProfiles(["ip.local", "username.MagdaleneJBreen"])],
                reward_string=["Authentification required OR Error: doctors and chemists only",
                               "Found message to another user via link with MarioDFiles",
                               "Found another username MagdaleneJBreen + render with local access to other studd"],
                cost=1.0
            )),
            # GET_AsDoris=m.VulnerabilityInfo(
            #     description="GET_ting messages as Doris",
            #     type=m.VulnerabilityType.REMOTE,
            #     precondition=m.Precondition("username.DorisHDunn&id.4ADA8BB4"),
            #     outcome=m.ExploitFailed(),
            #     reward_string="No messages",
            #     cost=1.0
            # ),
            # GET_AsJan=m.VulnerabilityInfo(
            #     description="GET_ting messages as Jan",
            #     type=m.VulnerabilityType.REMOTE,
            #     precondition=m.Precondition("username.JanJCovington&id.CDCEDE1C"),
            #     outcome=m.ExploitFailed(),
            #     reward_string="No messages",
            #     cost=1.0
            # ),
            # GET_AsMagdalene=m.VulnerabilityInfo(
            #     description="GET_ting messages as Magdalene",
            #     type=m.VulnerabilityType.REMOTE,
            #     precondition=m.Precondition("username.Magdalene&id.5C0D2C9A"),
            #     outcome=m.ExploitFailed(),
            #     reward_string="No messages",
            #     cost=1.0
            # ),
            # # TODO merge these 2 vulnerabilities through the NEW OUTCOME type as concatenation of 2
            # GET_AsMarioDFilesRender=m.VulnerabilityInfo(
            #     description="GET_ting messages as Mario",
            #     type=m.VulnerabilityType.REMOTE,
            #     precondition=m.Precondition("username.MarioDFiles&id.F5BCFE9D"),
            #     outcome=m.LeakedNodesId(["GET_/v2/render"]),
            #     reward_string="/v2/render is leaked",
            #     cost=1.0
            # ),
            # TODOMeeting either GET_ting this doc from messages, or as vulnerability of probing first & then searching for document in /v2/render  GET_properties as id of document
            # GET_AsMarioDFilesId=m.VulnerabilityInfo(
            #     description="GET_ting messages as Mario",
            #     type=m.VulnerabilityType.REMOTE,
            #     precondition=m.Precondition("username.MarioDFiles&id.F5BCFE9D"),
            #     outcome=m.ProbeSucceeded(["GET__v2_documents:a5db38da_156a_4d00_a041_9702db349ca5"]),
            #     reward_string="/v2/render is leaked",
            #     cost=1.0
            # )
        ])),

    "GET_/v2/documents": m.NodeInfo(
        services=[],
        value=0,
        properties=["GET__v2_documents:a5db38da_156a_4d00_a041_9702db349ca5"],
        # properties=["LisaGWhite", "MarioD"],  # SO WE NEED INCLUDE all usernames into properties
        vulnerabilities=OrderedDict([
            # Identify GET_usage for anyuser
            # GET_AsLocalUser=m.VulnerabilityInfo(
            #     description="GET_ting documents as Fake user",
            #     type=m.VulnerabilityType.REMOTE,
            #     precondition=m.Precondition("username.patient"),
            #     outcome=m.ExploitFailed(0, deception=True),  # ProbeFailed is not ExploitFailed
            #     reward_string="Error: chemists only",
            #     cost=1.0
            # ),
            ("", m.VulnerabilityInfo(
                description="GET_ting documents as Chemist",
                type=m.VulnerabilityType.REMOTE,
                precondition=m.Precondition("roles.isChemist"),
                outcome=m.CustomerData(2000, ctf_flag=True),
                # Probe=> property and then 2 vulns with 2 properties
                reward_string="Gaining 2 HTML entries, one of which has CTF flag in base-64 encoded as image",
                cost=1.0
            )),
        ])),

    # "GET_/v2/render": m.NodeInfo(
    #     services=[],
    #     value=0,
    #     properties=["ip_local"],
    #     vulnerabilities=m.strkey_to_tuplekey("GET_/v2/render", dict(
    #         # Identify GET_usage for anyuser
    #         GET_AsLocalUser=m.VulnerabilityInfo(
    #             description="Trying to GET_/v2/render",
    #             type=m.VulnerabilityType.REMOTE,
    #             precondition=m.Precondition("username.patient"),
    #             outcome=m.ExploitFailed(5),
    #             reward_string="Cannot GET_/render",
    #             cost=1.0
    #         )
    #     )),
    # ),
    #         GET_AsDocument=m.VulnerabilityInfo(
    #             description="/render/http%3A%2F%2F127.0.0.1%3A8081%2Fdocuments%2Fa5db38da-156a-4d00-a041-9702db349ca5",
    #             type=m.VulnerabilityType.REMOTE,
    #             precondition=m.Precondition("username.LisaGWhite&GET__v2_documents:a5db38da_156a_4d00_a041_9702db349ca5"),
    #             outcome=m.CustomerData(5),
    #             reward_string="GET_ting image (not sensitive info)",
    #             cost=1.0
    #         ),
    #         # TODOMeeting what is the point of being unauthenticated here?
    #         GET_AsTest=m.VulnerabilityInfo(
    #             description="Ping test",
    #             type=m.VulnerabilityType.REMOTE,
    #             outcome=m.ExploitFailed(),
    #             reward_string="Error: Authentication required",
    #             cost=1.0
    #         ),
    #         GET_WithInternet=m.VulnerabilityInfo(
    #             description="Ping www.google.com",
    #             type=m.VulnerabilityType.REMOTE,
    #             outcome=m.ExploitFailed(),
    #             reward_string="Server unreachable",
    #             cost=1.0
    #         ),
    #         GET_WithLocalHost=m.VulnerabilityInfo(
    #             description="Ping 127.0.0.1",
    #             type=m.VulnerabilityType.REMOTE,
    #             outcome=m.ProbeSucceeded(["ip_local"]),  # TOTMeeting or here we give profile of IP.local
    #             reward_string="GET_/ in header",
    #             cost=1.0
    #         )
    #     )),

    # "GET_/v2/phonebook": m.NodeInfo(
    #     services=[],
    #     value=0,
    #     # properties=["LisaGWhite", "MarioD"],  # SO WE NEED INCLUDE all usernames into properties
    #     vulnerabilities=dict(
    #         # Identify GET_usage for anyuser
    #         GET_AsLocalUser=m.VulnerabilityInfo(
    #             description="DECEPTION trap: honeypot as phonebook",
    #             type=m.VulnerabilityType.REMOTE,
    #             outcome=m.ExploitFailed(5, deception=True),  # ProbeFailed is not ExploitFailed
    #             reward_string="Cannot GET_/v2/phonebook",
    #             cost=1.0
    #         )
    #     )),

    "GET_/v2/users": m.NodeInfo(
        services=[],  # should I leave like this?
        value=100,  # owning reward
        # properties=["LisaGWhite", "MarioDFiles"],  # SO WE NEED INCLUDE all usernames into properties
        vulnerabilities=OrderedDict([
            ("", m.VulnerabilityInfo(
                description="GET_ting Credentials",
                type=m.VulnerabilityType.REMOTE,
                precondition=m.Precondition("ip.local"),
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
            ("username", m.VulnerabilityInfo(
                description="GET_ting Credentials",
                type=m.VulnerabilityType.REMOTE,
                precondition=[m.Precondition("username.LisaGWhite"),
                              m.Precondition("username.MarioDFiles"), ],
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

global_vulnerability_library: Dict[VulnerabilityID, VulnerabilityInfo] = dict([])
global_profiles_library: List[Profile] = []

# Environment constants
ENV_IDENTIFIERS = m.infer_constants_from_nodes(
    cast(Iterator[Tuple[NodeID, NodeInfo]], list(nodes.items())),
    global_vulnerability_library)


def new_environment() -> m.Environment:
    return m.Environment(
        network=m.create_network(nodes),
        vulnerability_library=global_vulnerability_library,
        identifiers=ENV_IDENTIFIERS
    )
