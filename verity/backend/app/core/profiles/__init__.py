from app.core.profiles.base import ProfileScore
from app.core.profiles.ntia_profile import score_ntia_profile
from app.core.profiles.bsi_v21_profile import score_bsi_v21_profile
from app.core.profiles.fsct_profile import score_fsct_profile
from app.core.profiles.oct_profile import score_oct_profile

PROFILE_MAP = {
    "ntia": score_ntia_profile,
    "bsi": score_bsi_v21_profile,
    "bsi-v2.1": score_bsi_v21_profile,
    "fsct": score_fsct_profile,
    "oct": score_oct_profile,
}

__all__ = [
    "ProfileScore",
    "score_ntia_profile",
    "score_bsi_v21_profile",
    "score_fsct_profile",
    "score_oct_profile",
    "PROFILE_MAP",
]
