# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""A tiny microservice environment based on partial example from myMedicPortal

Attack path:    !a! action of out interest          !o! outcome of our interest         !! flad and end
Penalty: cost=100 deception, cost=50 penalty for touching, cost=0.0 loop problem (so better not use), cost=1.0 usual shortening of path, value=50 uncertainty in value, value=100 value


HERE TinyToy exmaple attackpath:
"client"//Local//SearchEdgeHistory => discovered LeakedNodesId Website
"Website"//Remote//ScanPageSource => discovered LeakedNodesId
gdsfgdgfd

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


TODO include more realistic actions per endpoints
TODO remapping

"""
from cyberbattle.simulation import model as m
from cyberbattle.simulation.model import NodeID, NodeInfo, VulnerabilityID, VulnerabilityInfo
from typing import Dict, Iterator, cast, Tuple

default_allow_rules = [
    m.FirewallRule("SSH", m.RulePermission.ALLOW),
]

# Network nodes involved in the Capture the flag game
nodes = {
    "GET /": m.NodeInfo(
        services=[
            m.ListeningService("SSH", allowedCredentials=[
                "ReusedMySqlCred-web"])],
        firewall=m.FirewallConfiguration(incoming=default_allow_rules,
                                         outgoing=default_allow_rules + [
                                             m.FirewallRule("su", m.RulePermission.ALLOW),
                                             m.FirewallRule("sudo", m.RulePermission.ALLOW)]),
        value=1000,
        properties=["MySql", "Ubuntu", "nginx/1.10.3"],
        owned_string="FLAG: Login using insecure SSH user/password",
        vulnerabilities=dict(
            ScanPageSource=m.VulnerabilityInfo(
                description="Website page source contains refrence to browseable "
                            "relative web directory",
                type=m.VulnerabilityType.REMOTE,
                outcome=m.LeakedNodesId(["Website.Directory"]),
                reward_string="Viewing the web page source reveals a URL to a .txt file and directory on the website",
                cost=1.0
            ),
        )),

    "GET /v2/messages": m.NodeInfo(
        services=[m.ListeningService("HTTPS")],
        value=50,
        properties=["Ubuntu", "nginx/1.10.3",
                    "CTFFLAG:Readme.txt-Discover secret data"
                    ],
        vulnerabilities=dict(
            NavigateWebDirectoryFurther=m.VulnerabilityInfo(
                description="Discover MYSQL credentials MySql for user "
                            "'web' in (getting-started.txt)",
                type=m.VulnerabilityType.REMOTE,
                outcome=m.LeakedCredentials(credentials=[
                    m.CachedCredential(node="Website", port="MySQL",
                                       credential="ReusedMySqlCred-web")]),
                reward_string="Discover browseable web directory: Navigating to parent URL revealed file `readme.txt`"
                              "with secret data (aflag); and `getting-started.txt` with MYSQL credentials",
                cost=1.0
            ),
        )),


    'client': m.NodeInfo(
        services=[],
        properties=["CLIENT:Win10"],
        value=0,
        vulnerabilities=dict(
            SearchEdgeHistory=m.VulnerabilityInfo(
                description="Search web history for list of accessed websites",
                type=m.VulnerabilityType.LOCAL,
                outcome=m.LeakedNodesId(["Website"]),
                reward_string="Web browser history revealed website URL of interest",
                cost=1.0
            )),
        agent_installed=True,
        reimagable=False),
}

global_vulnerability_library: Dict[VulnerabilityID, VulnerabilityInfo] = dict([])

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
