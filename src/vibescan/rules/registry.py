"""Rule registry - returns all available rule instances."""

from __future__ import annotations

from vibescan.rules.base import BaseRule
from vibescan.rules.dangerous_patterns import DangerousPatternRule
from vibescan.rules.git_hygiene import GitHygieneRule
from vibescan.rules.structure import StructureRule
from vibescan.rules.secret.env_exposure import EnvExposureRule
from vibescan.rules.secret.config_hardcode import ConfigHardcodeRule
from vibescan.rules.secret.cloud_credentials import CloudCredentialsRule
from vibescan.rules.secret.docker_infra import DockerInfraRule
from vibescan.rules.secret.cicd_pipeline import CICDPipelineRule
from vibescan.rules.secret.ide_settings import IDESettingsRule
from vibescan.rules.secret.private_keys import PrivateKeysRule
from vibescan.rules.secret.hardcoded_patterns import HardcodedPatternsRule
from vibescan.rules.secret.frontend_env import FrontendEnvRule
from vibescan.rules.secret.data_files import DataFilesRule
from vibescan.rules.secret.doc_secrets import DocSecretsRule
from vibescan.rules.secret.mobile_files import MobileFilesRule
from vibescan.rules.secret.system_configs import SystemConfigsRule
from vibescan.rules.secret.editor_remnants import EditorRemnantsRule


def get_all_rules() -> list[BaseRule]:
    return [
        EnvExposureRule(),
        ConfigHardcodeRule(),
        CloudCredentialsRule(),
        DockerInfraRule(),
        CICDPipelineRule(),
        IDESettingsRule(),
        PrivateKeysRule(),
        HardcodedPatternsRule(),
        FrontendEnvRule(),
        DataFilesRule(),
        DocSecretsRule(),
        MobileFilesRule(),
        SystemConfigsRule(),
        EditorRemnantsRule(),
        GitHygieneRule(),
        DangerousPatternRule(),
        StructureRule(),
    ]
