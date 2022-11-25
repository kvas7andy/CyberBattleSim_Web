import cyberbattle.simulation.model as m
from typing import get_type_hints

profile_str = "username.LisaGWhite&roles.isDoctor&roles.isChemist&ip.local"


def profile_str_to_dict(profile_str: str) -> dict:
    profile_dict = {}
    type_hints = get_type_hints(m.Profile)
    for property in profile_str.split('&'):
        key, val = property.split('.')
        if str(m.RolesType) in str(type_hints[key]):
            if key in profile_dict.keys() and val not in profile_dict[key]:
                profile_dict[key] = profile_dict[key].union({val})
            else:
                profile_dict[key] = {val}
        else:
            profile_dict[key] = val
    return profile_dict


profile_dict = profile_str_to_dict(profile_str)


prof = m.Profile(**profile_dict)
print(str(prof), prof.__repr__())

prof.update({"username": "LisaGWhite", "roles": {"isDoctor", "isAssistant"}})
print(str(prof), prof.__repr__())
