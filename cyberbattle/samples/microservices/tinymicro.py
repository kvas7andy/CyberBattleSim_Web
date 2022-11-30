# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""A tiny microservice environment based on partial example from myMedicPortal

"""
from cyberbattle.simulation import model as m
from cyberbattle.simulation.model import NodeID, NodeInfo, VulnerabilityID, VulnerabilityInfo, Profile
from typing import Dict, Iterator, cast, Tuple, List

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
        vulnerabilities=m.strkey_to_tuplekey("client_browser", dict(
            ScanPageSource=m.VulnerabilityInfo(
                description="Website HTML contains information about multiple blocks leading to endpoints "
                            "AND scripts with other endpoints + variables (tags?)",
                type=m.VulnerabilityType.LOCAL,
                outcome=m.LeakedNodesId(["POST /v2/register", "GET /v2/messages", "GET /v2/calendar", "GET /v2/documents"]),  # "GET /v2/phonebook", "POST /v2/login", "GET /v2/login", "GET /v2"]),
                # Not OWNED, need to make connect_to_remote with any credentials to make them owned and include all their properties
                reward_string="Inspect: Viewing the web page source reveals main endpoints",
                cost=1.0
            ),
            # TODOAFTER put into POST /ve/register
            ScanBlockRegister=m.VulnerabilityInfo(
                description="Website HTML contains script with rules of username configuration",
                type=m.VulnerabilityType.LOCAL,
                precondition=m.Precondition("script_block"),
                outcome=m.LeakedNodesId(["GET /v2/users"]),
                # Not OWNED, need to make connect_to_remote with any credentials to make them owned and include all their properties
                reward_string="Found script with rules of username creation from POST /register => access to GET /v2/users",
                cost=1.0
            )
        )),
        agent_installed=True,
    ),
    # TODOMeeting !!!!!!! .cloudactivedefence property should be hidden in check_prerequisuites
    # "GET /v2": m.NodeInfo(
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
    #         GETAsNoAuth=m.VulnerabilityInfo(
    #             description="Cannot get /v2",
    #             type=m.VulnerabilityType.REMOTE,
    #             outcome=m.ExploitFailed(),
    #             # Not OWNED, need to make connect_to_remote with any credentials to make them owned and include all their properties
    #             reward_string="Cannot get /v2",
    #             cost=1.0
    #         )
    #     )),

    # "GET /v2/login": m.NodeInfo(
    #     services=[],
    #     value=10,  # owning reward
    #     vulnerabilities=dict(
    #         # TODO switch action of profiles? or If we include password protection, here could be a lot of vulenerabilities because of "weak" security
    #         # POSTAsAnyUser=m.VulnerabilityInfo(
    #         #     description="Login button endpoint asks for correct credentials",
    #         #     precondition=m.Precondition("patient"),  # MEETING 27.10
    #         #     type=m.VulnerabilityType.REMOTE,
    #         #     outcome=m.LeakedProfiles("patient"),
    #         #     reward_string="Discovered endpoints available ",
    #         #     cost=1.0
    #         # )
    #     )),

    # "POST /v2/login": m.NodeInfo(
    #     services=[],
    #     value=10,  # owning reward
    #     # Vulnerability name: LOGGIN bruteforcing?
    #     vulnerabilities=dict(
    #         POSTAsAdmin=m.VulnerabilityInfo(  # LocalUser == registered user with SESSION token, but without privilages!
    #             description="Admin credentials are wrong",
    #             type=m.VulnerabilityType.REMOTE,
    #             outcome=m.ExploitFailed(),
    #             reward_string="Login as admin: invalid credentials",
    #             cost=1.0
    #         )
    #     )),

    "POST /v2/register": m.NodeInfo(
        services=[],  # should I leave like this?
        value=10,  # owning reward
        vulnerabilities=m.strkey_to_tuplekey("POST /v2/register", dict(
            POSTAsAlicAnon=m.VulnerabilityInfo(  # LocalUser == registered user with SESSION token, but without privilages!
                description="Trap Deceptive endpoint to check",
                type=m.VulnerabilityType.REMOTE,
                outcome=m.LeakedProfiles(["username.patient&id.UUIDfake"]),
                reward_string="Register AlicAnon patient to be able to access more info",
                cost=1.0
            )
        ))),

    "GET /v2/calendar": m.NodeInfo(
        services=[],  # should I leave like this?
        value=0,
        vulnerabilities=m.strkey_to_tuplekey("GET /v2/calendar", dict(
            # Identify GET usage for anyuser
            GETAsLocalUser=m.VulnerabilityInfo(
                description="Found usernames from calendar & property",
                precondition=m.Precondition("username.patient"),
                type=m.VulnerabilityType.REMOTE,
                outcome=m.LeakedProfiles(["username.LisaGWhite", "username.JanJCovington", "username.DorisHDunn"]),
                reward_string="One of the weekdays shedule output gives (or not) any rpofile details",
                cost=1.0
            ),
            # TODO like example of vulnerability having wrong outcome without precondition
            # GETAsNoAuth=m.VulnerabilityInfo(
            #     description="Authentification required",
            #     type=m.VulnerabilityType.REMOTE,
            #     outcome=m.ExploitFailed(),
            #     reward_string="Authentification required",
            #     cost=1.0
            # ),
            # GETWithOtherCalenderNum=m.VulnerabilityInfo(
            #     description="DECEPTION decoy: Trying other calendar nums, like GET /v2/calendar/8 (9, 10, 11, ...)",
            #     precondition=m.Precondition("username.patient"),
            #     type=m.VulnerabilityType.REMOTE,
            #     outcome=m.ExploitFailed(deception=True),  # Even with deception, it should be just as always, BUT we trigger
            #     reward_string="Error: day should be set between 0 and 7",
            #     cost=1.0
            # ),
        ))),

    "GET /v2/messages": m.NodeInfo(
        services=[],
        value=40,
        vulnerabilities=m.strkey_to_tuplekey("GET /v2/messages", dict(
            # Identify GET usage for anyuser
            GETAsLocalUser=m.VulnerabilityInfo(
                description="Try to get messages as fake user",
                type=m.VulnerabilityType.REMOTE,
                precondition=m.Precondition("username.patient"),
                outcome=m.ExploitFailed(),
                reward_string="Authentification required OR Error: doctors and chemists only",  # TODOMeeting is it correct?
                cost=1.0
            ),
            GETAsLiz=m.VulnerabilityInfo(
                description="Getting messages as Liz",
                type=m.VulnerabilityType.REMOTE,
                precondition=m.Precondition("username.LisaGWhite&id.994D5244"),
                outcome=m.LeakedProfiles(["username.MarioDFiles"]),
                reward_string="Found message to another user via link with MarioDFiles",
                cost=1.0
            ),
            # GETAsDoris=m.VulnerabilityInfo(
            #     description="Getting messages as Doris",
            #     type=m.VulnerabilityType.REMOTE,
            #     precondition=m.Precondition("username.DorisHDunn&id.4ADA8BB4"),
            #     outcome=m.ExploitFailed(),
            #     reward_string="No messages",
            #     cost=1.0
            # ),
            # GETAsJan=m.VulnerabilityInfo(
            #     description="Getting messages as Jan",
            #     type=m.VulnerabilityType.REMOTE,
            #     precondition=m.Precondition("username.JanJCovington&id.CDCEDE1C"),
            #     outcome=m.ExploitFailed(),
            #     reward_string="No messages",
            #     cost=1.0
            # ),
            # GETAsMagdalene=m.VulnerabilityInfo(
            #     description="Getting messages as Magdalene",
            #     type=m.VulnerabilityType.REMOTE,
            #     precondition=m.Precondition("username.Magdalene&id.5C0D2C9A"),
            #     outcome=m.ExploitFailed(),
            #     reward_string="No messages",
            #     cost=1.0
            # ),
            GETAsMarioDFiles=m.VulnerabilityInfo(
                description="Getting messages as Mario",
                type=m.VulnerabilityType.REMOTE,
                precondition=m.Precondition("username.MarioDFiles&id.F5BCFE9D"),
                outcome=m.LeakedProfiles(["ip.local", "username.MagdaleneJBreen"]),
                reward_string="Found another username MagdaleneJBreen + render with local access to other studd",
                cost=1.0
            ),
            # # TODO merge these 2 vulnerabilities through the NEW OUTCOME type as concatenation of 2
            # GETAsMarioDFilesRender=m.VulnerabilityInfo(
            #     description="Getting messages as Mario",
            #     type=m.VulnerabilityType.REMOTE,
            #     precondition=m.Precondition("username.MarioDFiles&id.F5BCFE9D"),
            #     outcome=m.LeakedNodesId(["GET /v2/render"]),
            #     reward_string="/v2/render is leaked",
            #     cost=1.0
            # ),
            # TODOMeeting either getting this doc from messages, or as vulnerability of probing first & then searching for document in /v2/render  get properties as id of document
            # GETAsMarioDFilesId=m.VulnerabilityInfo(
            #     description="Getting messages as Mario",
            #     type=m.VulnerabilityType.REMOTE,
            #     precondition=m.Precondition("username.MarioDFiles&id.F5BCFE9D"),
            #     outcome=m.ProbeSucceeded(["GET_v2_documents:a5db38da_156a_4d00_a041_9702db349ca5"]),
            #     reward_string="/v2/render is leaked",
            #     cost=1.0
            # )
        ))),

    "GET /v2/documents": m.NodeInfo(
        services=[],
        value=0,
        properties=["GET_v2_documents:a5db38da_156a_4d00_a041_9702db349ca5"],
        # properties=["LisaGWhite", "MarioD"],  # SO WE NEED INCLUDE all usernames into properties
        vulnerabilities=m.strkey_to_tuplekey("GET /v2/documents", dict(
            # Identify GET usage for anyuser
            # GETAsLocalUser=m.VulnerabilityInfo(
            #     description="Getting documents as Fake user",
            #     type=m.VulnerabilityType.REMOTE,
            #     precondition=m.Precondition("username.patient"),
            #     outcome=m.ExploitFailed(0, deception=True),  # ProbeFailed is not ExploitFailed
            #     reward_string="Error: chemists only",
            #     cost=1.0
            # ),
            # GETAsIPLocal=m.VulnerabilityInfo(
            #     description="Getting documents via render",
            #     type=m.VulnerabilityType.REMOTE,
            #     precondition=m.Precondition("username.patient"),
            #     outcome=m.ExploitFailed(),
            #     reward_string="Error: chemists only",
            #     cost=1.0
            # ),
            GETAsChemist=m.VulnerabilityInfo(
                description="Getting documents as Chemist",
                type=m.VulnerabilityType.REMOTE,
                precondition=m.Precondition("roles.isChemist"),
                outcome=m.CustomerData(2000, ctf_flag=True),  # TODOMeeting maybe have another outcome as FLAG? with reward? Or even separate those 2 HTML images?
                # Probe=> property and then 2 vulns with 2 properties
                reward_string="Gaining 2 HTML entries, one of which has CTF flag in base-64 encoded as image",
                cost=1.0
            ),
        ))),

    # "GET /v2/render": m.NodeInfo(
    #     services=[],
    #     value=0,
    #     properties=["ip_local"],
    #     vulnerabilities=dict(
    #         # Identify GET usage for anyuser
    #         GETAsLocalUser=m.VulnerabilityInfo(
    #             description="Trying to get /v2/render",
    #             type=m.VulnerabilityType.REMOTE,
    #             precondition=m.Precondition("username.patient"),
    #             outcome=m.ExploitFailed(5),
    #             reward_string="Cannot get /render",
    #             cost=1.0
    #         ),
    #         GETAsDocument=m.VulnerabilityInfo(
    #             description="/render/http%3A%2F%2F127.0.0.1%3A8081%2Fdocuments%2Fa5db38da-156a-4d00-a041-9702db349ca5",
    #             type=m.VulnerabilityType.REMOTE,
    #             precondition=m.Precondition("username.LisaGWhite&GET_v2_documents:a5db38da_156a_4d00_a041_9702db349ca5"),
    #             outcome=m.CustomerData(5),
    #             reward_string="Getting image (not sensitive info)",
    #             cost=1.0
    #         ),
    #         # TODOMeeting what is the point of being unauthenticated here?
    #         GETAsTest=m.VulnerabilityInfo(
    #             description="Ping test",
    #             type=m.VulnerabilityType.REMOTE,
    #             outcome=m.ExploitFailed(),
    #             reward_string="Error: Authentication required",
    #             cost=1.0
    #         ),
    #         GETWithInternet=m.VulnerabilityInfo(
    #             description="Ping www.google.com",
    #             type=m.VulnerabilityType.REMOTE,
    #             outcome=m.ExploitFailed(),
    #             reward_string="Server unreachable",
    #             cost=1.0
    #         ),
    #         GETWithLocalHost=m.VulnerabilityInfo(
    #             description="Ping 127.0.0.1",
    #             type=m.VulnerabilityType.REMOTE,
    #             outcome=m.ProbeSucceeded(["ip_local"]),  # TOTMeeting or here we give profile of IP.local
    #             reward_string="GET / in header",
    #             cost=1.0
    #         )
    #     )),

    # "GET /v2/phonebook": m.NodeInfo(
    #     services=[],
    #     value=0,
    #     # properties=["LisaGWhite", "MarioD"],  # SO WE NEED INCLUDE all usernames into properties
    #     vulnerabilities=dict(
    #         # Identify GET usage for anyuser
    #         GETAsLocalUser=m.VulnerabilityInfo(
    #             description="DECEPTION trap: honeypot as phonebook",
    #             type=m.VulnerabilityType.REMOTE,
    #             outcome=m.ExploitFailed(5, deception=True),  # ProbeFailed is not ExploitFailed
    #             reward_string="Cannot get /v2/phonebook",
    #             cost=1.0
    #         )
    #     )),

    "GET /v2/users": m.NodeInfo(
        services=[],  # should I leave like this?
        value=100,  # owning reward
        # properties=["LisaGWhite", "MarioDFiles"],  # SO WE NEED INCLUDE all usernames into properties
        vulnerabilities=m.strkey_to_tuplekey("GET /v2/users", dict(
            GETWithParametersLisaGWhite=m.VulnerabilityInfo(
                description="Getting Credentials",
                type=m.VulnerabilityType.REMOTE,
                precondition=m.Precondition("username.LisaGWhite"),
                outcome=m.LeakedProfiles(["username.LisaGWhite&id.994D5244&roles.isDoctor"]),
                reward_string="Globally Available Session ID and username for LisaGWhite",
                cost=1.0
            ),
            # GETWithParametersDorisHDunn=m.VulnerabilityInfo(
            #     description="Getting Credentials",
            #     type=m.VulnerabilityType.REMOTE,
            #     precondition=m.Precondition("username.DorisHDunn"),
            #     outcome=m.LeakedProfiles(["username.DorisHDunn&id.4ADA8BB4&roles.isDoctor"]),
            #     reward_string="Globally Available Session ID and username for DorisHDunn",
            #     cost=1.0
            # ),
            GETWithParametersMarioDfiles=m.VulnerabilityInfo(
                description="Getting Credentials",
                type=m.VulnerabilityType.REMOTE,
                precondition=m.Precondition("username.MarioDFiles"),
                outcome=m.LeakedProfiles(["username.MarioDFiles&id.F5BCFE9D&roles.isDoctor"]),
                reward_string="Globally Available Session ID and username for MarioDFiles",
                cost=1.0
            ),
            # GETWithParametersMagdaleneJBreen=m.VulnerabilityInfo(
            #     description="Getting Credentials",
            #     type=m.VulnerabilityType.REMOTE,
            #     precondition=m.Precondition("username.MagdaleneJBreen"),
            #     outcome=m.LeakedProfiles(["username.MagdaleneJBreen&id.5C0D2C9A&roles.isDoctor"]),
            #     reward_string="Globally Available Session ID, username for MagdaleneJBreen, roles and IP of profile",
            #     cost=1.0
            # ),
            # GETWithParametersJanJCovington=m.VulnerabilityInfo(
            #     description="Getting Credentials",
            #     type=m.VulnerabilityType.REMOTE,
            #     precondition=m.Precondition("username.JanJCovington"),
            #     outcome=m.LeakedProfiles(["username.JanJCovington&id.CDCEDE1C&roles.isDoctor"]),
            #     reward_string="Globally Available Session ID, username for JanJCovington, roles and IP of profile",
            #     cost=1.0
            # ),
            GETAsIPLocal=m.VulnerabilityInfo(
                description="Getting Credentials",
                type=m.VulnerabilityType.REMOTE,
                precondition=m.Precondition("ip.local"),
                outcome=m.LeakedProfiles(["username.JamesMPaterson&id.68097B9D&roles.isChemist",
                                          "username.AnotherGuyName&id.cookie233424&roles.isAssistant",
                                          "username.JanJCovington&id.CDCEDE1C&roles.isDoctor",
                                          "username.MarioDFiles&id.F5BCFE9D&roles.isDoctor",
                                          "username.DorisHDunn&id.4ADA8BB4&roles.isDoctor",
                                          "username.LisaGWhite&id.994D5244&roles.isDoctor"]),
                reward_string="All available profiles",
                cost=1.0
            ),
            # GETAsLocalUser=m.VulnerabilityInfo(
            #     description="Getting Credentials",
            #     type=m.VulnerabilityType.REMOTE,
            #     outcome=m.ExploitFailed(),  # special cost like antireward
            #     reward_string="Access denied, please use VPN",
            #     cost=1.0
            # )
        )))
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
