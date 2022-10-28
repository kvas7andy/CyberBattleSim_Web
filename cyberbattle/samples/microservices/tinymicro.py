# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""A tiny microservice environment based on partial example from myMedicPortal

Attack path:    !a! action of out interest          !o! outcome of our interest         !! flad and end
Penalty: cost=100 deception, cost=50 penalty for touching, cost=0.0 loop problem (so better not use), cost=1.0 usual shortening of path, value=50 uncertainty in value, value=100 value


BEFORE TinyToy exmaple attackpath:
"client"//Local//SearchEdgeHistory => discovered LeakedNodesId Website
"client" + "Website"//Remote//ScanPageSource => discovered LeakedNodesId Website.Directory
"client" + "Website.Derectory"//REMOTE//NavigateWebDirectoryFurther => LeakedCredentials for connecting and owning Website with MySQL l:103
Connect from "client" to  "Website" through SSH (Firewall allowed) using MySQL credentials (port MySQL) => Reward 1000 => FLAG taken


REMAPPING:
"client" xxx
"Website" == "/"
"Website.Directory" == "/v2/messages"


AFTER TinyMicro
1. Passive recon
- attacker visits '/'
!a! view source of page (html)
- discover endpoints:
    - GET /v2/login       [FROM <DIV> "onclick"]
    - POST /v2/register   [FROM <DIV>, <BLOCK>: JAVASCRIPT]
        - {username, fullname}
        - understand that username is full name minus spaces and dots
    - GET /v2/calendar/[0-7]     [FROM <SCRIPT>]
    - GET /users/:username        [FROM <SCRIPT>]
- returns JSON which contains isChemist and isDoctor values
- discover (hidden) DIV  [FROM SCRIPT]          Pena
- login
- register
- calendar
!o! messages (no URL)  => discover endpoint?
- documents (no URL)
- phonebook (no URL)
- discover interesting variables
- username (default: "anonymous")
- employee (true if doctor or chemist)
- assistant
- chemist
- discover cookies:
- SESSION
- inspect BURP response
- discover envoy header
- discover x-cloud-active-defense header
- notice .cloudactivedefense path


2.  GET /v2/messages
!a! GET /v2/messages
!! discover name: MarioDFiles

3. ??ADD? /v2/users/?

"""
from cyberbattle.simulation import model as m
from cyberbattle.simulation.model import NodeID, NodeInfo, VulnerabilityID, VulnerabilityInfo, ProfileName
from typing import Dict, Iterator, cast, Tuple, List

default_allow_rules = [
    m.FirewallRule("SSH", m.RulePermission.ALLOW),
]


# These two lists are lists of potential vulnerabilities. They are split into linux vulnerabilities
# and Windows vulnerabilities so i can

ADMINTAG = m.AdminEscalation().tag
SYSTEMTAG = m.SystemEscalation().tag

# Network nodes involved in the Capture the flag game
nodes = {
    "client_browser": m.NodeInfo(
        services=[],
        value=0,  # owning reward
        # properties=["cloud"],
        owned_string="Attacker owns his laptop",
        vulnerabilities=dict(
            ScanPageSource=m.VulnerabilityInfo(
                description="Website HTML contains information about multiple blocks leading to endpoints "
                            "AND scripts with other endpoints + variables (tags?)",
                type=m.VulnerabilityType.LOCAL,
                outcome=m.LeakedNodesId(["GET /v2/login", "POST /v2/register", "GET /v2/messages", "GET /v2/phonebook", "GET /v2/calendar"]),
                # Not OWNED, need to make connect_to_remote with any credentials to make them owned and include all their properties
                reward_string="Inspect: Viewing the web page source reveals main endpoints",
                cost=1.0
            )),
        agent_installed=True,
        # Any discovered endpoint afterwards could be owned IN ORDER TO use LOCAL vulnerabilities without random serach from ALL REMOTES, at each stage
    ),

    # TODO write the outcome as Privilage raising?
    "GET /v2/login": m.NodeInfo(
        services=[m.ListeningService("HTTPS")],
        value=10,  # owning reward
        vulnerabilities=dict(
            POSTAsAnyUser=m.VulnerabilityInfo(
                description="Login button endpoint asks for correct credentials",
                precondition=m.Precondition("fake_user"),  # MEETING 27.10
                type=m.VulnerabilityType.REMOTE,
                outcome=m.ProbeSucceededGlobal("fake_user"),
                reward_string="Discovered endpoints available ",
                cost=1.0
            )
        )),

    # TODO write the outcome as Privilage raising?
    "POST /v2/register": m.NodeInfo(
        services=[m.ListeningService("HTTPS")],  # should I leave like this?
        value=10,  # owning reward
        vulnerabilities=dict(
            POSTAsAlicAnon=m.VulnerabilityInfo(  # LocalUser == registered user with SESSION token, but without privilages!
                description="Trap Deceptive endpoint to check",
                type=m.VulnerabilityType.REMOTE,
                outcome=m.ProbeSucceededGlobal("fake_user"),
                reward_string="Register to fake_user to be able to access more info",
                cost=1.0
            )
        )),

    "GET /v2/users": m.NodeInfo(
        services=[m.ListeningService("HTTPS")],  # should I leave like this?
        value=100,  # owning reward
        properties=["LisaGWhite", "MarioDFiles"],  # SO WE NEED INCLUDE all usernames into properties

        # TODO we need to get credential details (cachecredential OR global.property??) but depending on paramter
        vulnerabilities=dict(
            # Make credentials usage case with Liz
            # GETWithParameters=m.VulnerabilityInfo(  # Liz == with localuser SESSION token, with special privilages!
            #     description="Getting Credentials",
            #     # TOCHECK maybe REMOTE do not see all properties at once, so precondition will not be set as True at first before with ProbeSucceed() we will include discovered property as Liz
            #     type=m.VulnerabilityType.LOCAL,
            #     precondition="LisaGWhite",
            #     outcome=m.LeakedCredentials(credentials=[
            #         m.CachedCredential(node="/v2", port="FakePortORSeccionTokenORID",  # TODO Credentials Usage
            #                            credential="MarioDFiles")]),
            #     # ALREADY credentials? Do I include /v2/users and use found property form /v2/messages?
            #     # Then I do not give credentials, but give ProbeSucceeded
            #     reward_string="Messages available to Local User  (registered by attacker) include username Mario D Files (then interpreted as possible)",
            #     cost=1.0
            # ),
            GETWithParametersLisaGWhite=m.VulnerabilityInfo(  # Liz == with localuser SESSION token, with special privilages!
                description="Getting Credentials",
                # TOCHECK maybe REMOTE do not see all properties at once, so precondition will not be set as True at first before with ProbeSucceed() we will include discovered property as Liz
                type=m.VulnerabilityType.REMOTE,
                # precondition="LisaGWhite",
                outcome=m.ProbeSucceededGlobal("MarioD"),
                # ALREADY credentials? Do I include /v2/users and use found property form /v2/messages?
                # Then I do not give credentials, but give ProbeSucceeded
                reward_string="Globally Available Session ID and username for LisaGWhite",
                cost=1.0
            ),
            GETWithParametersMarioDfiles=m.VulnerabilityInfo(  # Liz == with localuser SESSION token, with special privilages!
                description="Getting Credentials",
                # TOCHECK maybe REMOTE do not see all properties at once, so precondition will not be set as True at first before with ProbeSucceed() we will include discovered property as Liz
                type=m.VulnerabilityType.REMOTE,
                # precondition="MarioDFiles",
                outcome=m.ProbeSucceededGlobal("LisaGWhite"),
                # ALREADY credentials? Do I include /v2/users and use found property form /v2/messages?
                # Then I do not give credentials, but give ProbeSucceeded
                reward_string="Globally Available Session ID and username for LisaGWhite",
                cost=1.0
            )
        )),


    "GET /v2/calendar": m.NodeInfo(
        services=[m.ListeningService("HTTPS")],  # should I leave like this?
        value=0,
        # properties=["Ubuntu", "nginx/1.10.3",
        #             "CTFFLAG:Readme.txt-Discover secret data"
        #             ],
        # global_properties=["user"],  # SO WE NEED INCLUDE all usernames into properties
        vulnerabilities=dict(
            # Identify GET usage for anyuser
            GETAsLocalUser=m.VulnerabilityInfo(  # LocalUser == registered user with SESSION token, but without privilages!
                description="Found username as (global??) property",
                type=m.VulnerabilityType.REMOTE,
                outcome=m.ProbeSucceededGlobal(["LisaGWhite"]),  # global.MarioDFiles maybe useful if we share the property among endpoints => have global properties? (there is global vuln idea also!!!)
                reward_string="Messages available to Local User  (registered by attacker) include username Mario D Files (then interpreted as possible)",
                cost=1.0
            )
        )),

    "GET /v2/messages": m.NodeInfo(
        services=[m.ListeningService("HTTPS")],  # should I leave like this?
        value=40,
        # properties=["Ubuntu", "nginx/1.10.3",
        #             "CTFFLAG:Readme.txt-Discover secret data"
        #             ],
        properties=["LisaGWhite", "MarioD"],  # SO WE NEED INCLUDE all usernames into properties
        vulnerabilities=dict(
            # Identify GET usage for anyuser
            GETAsLocalUser=m.VulnerabilityInfo(  # LocalUser == registered user with SESSION token, but without privilages!
                description="Found username as (global??) property",
                type=m.VulnerabilityType.REMOTE,
                outcome=m.ProbeFailed(),  # global.MarioDFiles maybe useful if we share the property among endpoints => have global properties? (there is global vuln idea also!!!)
                reward_string="Messages available to Local User  (registered by attacker) include username Mario D Files (then interpreted as possible)",
                cost=1.0
            ),
            # Make credentials usage case with Liz
            GETAsLiz=m.VulnerabilityInfo(  # Liz == with localuser SESSION token, with special privilages!
                description="Getting Credentials",
                # TOCHECK maybe REMOTE do not see all properties at once, so precondition will not be set as True at first before with ProbeSucceed() we will include discovered property as Liz
                type=m.VulnerabilityType.REMOTE,
                precondition=m.Precondition("LisaGWhite"),
                outcome=m.ProbeSucceededGlobal(["MarioD"]),  # m.LeakedCredentials(credentials=[
                #     m.CachedCredential(node="/v2", port="FakePortORSeccionTokenORID",  # TODO Credentials Usage
                #                        credential="MarioDFiles")]),
                # ALREADY credentials? Do I include /v2/users and use found property form /v2/messages?
                # Then I do not give credentials, but give ProbeSucceeded
                reward_string="Messages available to Local User  (registered by attacker) include username Mario D Files (then interpreted as possible)",
                cost=1.0
            )
        )),

    "GET /v2/phonebook": m.NodeInfo(
        services=[m.ListeningService("HTTPS")],  # should I leave like this?
        value=0,
        # properties=["Ubuntu", "nginx/1.10.3",
        #             "CTFFLAG:Readme.txt-Discover secret data"
        #             ],
        vulnerabilities=dict(
            GETAsAnyUser=m.VulnerabilityInfo(  # LocalUser == registered user with SESSION token, but without privilages!
                description="Trap Deceptive endpoint to check",
                type=m.VulnerabilityType.REMOTE,
                outcome=m.ExploitFailed(),
                # ALREADY credentials? Do I include /v2/users and use found property form /v2/messages?
                # Then I do not give credentials, but give ProbeSucceeded
                reward_string="Messages available to Local User  (registered by attacker) include username Mario D Files (then interpreted as possible)",
                cost=100.0  # HIGH cost, no value
            ),
        ))
}

global_vulnerability_library: Dict[VulnerabilityID, VulnerabilityInfo] = dict([])
global_profiles_library: List[ProfileName] = []  # TODO use global property as separate entity for all usernames possible? maybe use as global credentials list, but include into properties of every node, or

# Environment constants
ENV_IDENTIFIERS = m.infer_constants_from_nodes(
    cast(Iterator[Tuple[NodeID, NodeInfo]], list(nodes.items())),
    global_vulnerability_library)


def new_environment() -> m.Environment:
    return m.Environment(
        network=m.create_network(nodes),
        vulnerability_library=global_vulnerability_library,
        profile_library=global_profiles_library,
        identifiers=ENV_IDENTIFIERS
    )
