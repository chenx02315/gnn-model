"""Local composition of the E101 sampling fix, with new explicit run authority.

Import is inert. Reuses immutable E100 code in a new isolated process and root;
does not rewrite its on-disk source, authorization, root or failed results.
Record-shape and source-attribute assertions are not human-consent authentication;
a future reviewed controller must bind the actual reply and frozen source bytes.
"""
import json

from . import direct_tessent_acceptance_e100 as base
from . import direct_memory_sample_e101 as sampler

ROOT = '/temp/jiangchuanc/multimode_ate_direct_e101_20261025_r1'
BASE_SHA = '92f9915bc431483ba73cc38829356ca315a16ae39713b021b2025d0ce744fb58'
SAMPLER_SHA = '8a4e81fb3ef50cb3ad7fcd720d7f205ba7df6228b2af34dd87c0986968a22009'
FAILED_RESPONSE_SHA = 'c76e1db86563019eacb27e0b96f90a9375a252aba187369f5e97e3389f564953'
require = base.require
_ParentDescendants = base.Descendants
_ParentMaterializer = base.DirectMaterializer


def validate_authority(raw):
    value=json.loads(raw.decode('utf-8'))
    require(type(value) is dict and value.get('schema')=='direct-tessent-repair-authorization-e101-v1'
        and value.get('user_authorization_received') is True
        and value.get('approval_source')=='explicit_user_reply'
        and type(value.get('user_reply')) is str and 0<len(value['user_reply'])<=4096
        and value.get('root')==ROOT
        and value.get('predecessor_execution_response_sha256')==FAILED_RESPONSE_SHA,
        'E101_EXPLICIT_ADDITIONAL_RUN_AUTHORITY_REQUIRED')
    for key,expected in (
        ('additional_launch_attempts_max',4),('workers',1),('automatic_retries',0),
        ('sampled_rss_plus_swap_stop_bytes',536870912),('per_case_seconds_including_cleanup',600),
        ('session_seconds',2700),('combined_output_bytes',16777216),
        ('process_count_stop_threshold',64),('scratch_stop_threshold_bytes',134217728)):
        require(type(value.get(key)) is int and value[key]==expected,'E101_FIXED_BUDGET')
    for key in ('lsf_allowed','kernel_memory_cap_required','atpg_generation_allowed','training_allowed','blind_allowed'):
        require(value.get(key) is False,'E101_SCOPE_NOT_EXPANDED')
    return value


class RepairedDescendants(_ParentDescendants):
    def sample(self):
        return sampler.sample_descendants(self,base._identity,base._small)


class RepairMaterializer(_ParentMaterializer):
    def initialize_bundle(self):
        plan=super(RepairMaterializer,self).initialize_bundle()
        base.material._publish(self.root_fd,'repair_binding.json',base.recipe.canonical(dict(
            execution_version='E101',format_family='direct-tessent-acceptance-e100-v1',
            root=ROOT,base_source_sha256=BASE_SHA,sampler_source_sha256=SAMPLER_SHA,
            authorization=self.authorization,predecessor_execution_response_sha256=FAILED_RESPONSE_SHA,
            kernel_memory_cap_enforced=False,lsf_used=False))+b'\n')
        return plan


def execute(raw85,raw93,authority):
    validate_authority(authority)  # Reject old E100 authority and the unapproved proposal.
    require(getattr(base,'__source_sha256__',None)==BASE_SHA and
            getattr(sampler,'__source_sha256__',None)==SAMPLER_SHA,'E101_PARENT_SOURCE_BINDING')
    previous=(base.ROOT,base.Descendants,base.DirectMaterializer,base.validate_authority,
              base.recipe.ROOT,base.material.RECIPE_SHA256)
    try:
        base.ROOT=ROOT
        base.Descendants=RepairedDescendants
        base.DirectMaterializer=RepairMaterializer
        base.validate_authority=validate_authority
        # Summary format stays E100; new root plus repair_binding identifies E101.
        return base.execute(raw85,raw93,authority)
    finally:
        (base.ROOT,base.Descendants,base.DirectMaterializer,base.validate_authority,
         base.recipe.ROOT,base.material.RECIPE_SHA256)=previous
