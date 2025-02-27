#  _  __
# | |/ /___ ___ _ __  ___ _ _ (R)
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Secrets Manager
# Copyright 2025 Keeper Security Inc.
# Contact: sm@keepersecurity.com

from oci.config import from_file
from typing import Optional

class OCISessionConfig:
    def __init__(self, oci_config_file_location: str, profile: Optional[str] = None, kms_endpoint: str = ""):
        self.oci_config_file_location = oci_config_file_location
        self.profile = profile if profile else "DEFAULT"
        self.kms_endpoint = kms_endpoint

    def get_provider(self):
        return from_file(self.oci_config_file_location, self.profile)

    def get_kms_endpoint(self) -> str:
        return self.kms_endpoint
