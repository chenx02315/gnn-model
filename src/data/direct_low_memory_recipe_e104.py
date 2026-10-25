"""Pure three-case variant: one exact Tcl command removal, no input changes."""
from . import prospective_tessent_acceptance_v1 as original

ROSTER=(('aes_core','H_TO_F','F'),('spi','H_TO_M','M'),('spi','H_TO_F','F'))
REMOVED=b'add_processors localhost:1\n'


def transform(plan):
    original.require(type(plan) is dict,'E104_RECIPE_REQUIRED')
    body={k:v for k,v in plan.items() if k not in ('recipe_sha256','items')}
    body['items']=[{k:v for k,v in row.items() if k!='tcl_bytes'} for row in plan['items']]
    original.require(original.sha(original.canonical(body))==plan['recipe_sha256'],
                     'E104_BASE_RECIPE_CHANGED')
    original.require([(r['circuit'],r['transition'],r['target_mode']) for r in plan['items']]
                     ==list(original.ROSTER),'E104_BASE_ROSTER_CHANGED')
    selected=[]
    for circuit,transition,mode in ROSTER:
        row=dict(next(r for r in plan['items'] if (r['circuit'],r['transition'])==(circuit,transition)))
        raw=row['tcl_bytes']
        original.require(raw.count(REMOVED)==1 and original.sha(raw)==row['tcl_sha256'],
                         'E104_EXACT_COMMAND_REMOVAL_REQUIRED')
        row['tcl_bytes']=raw.replace(REMOVED,b'',1)
        original.require(b'add_processors' not in row['tcl_bytes'].lower(),
                         'E104_NO_EXPLICIT_PROCESSOR_REQUEST')
        row['tcl_sha256']=original.sha(row['tcl_bytes'])
        selected.append(row)
    body.update(schema='direct-low-memory-three-case-recipe-e104-v1',
                base_recipe_sha256=plan['recipe_sha256'],
                exact_roster=[list(r) for r in ROSTER],
                items=[{k:v for k,v in r.items() if k!='tcl_bytes'} for r in selected],
                skipped_previously_passed_case=['aes_core','H_TO_M'],
                explicit_add_processors_requested=False,
                future_execution_policy='ONE_THREE_ITEM_PACKAGE_STOP_ON_FIRST_FAILURE_ZERO_RETRIES',
                memory_reduction_proven=False)
    return dict(body,items=selected,recipe_sha256=original.sha(original.canonical(body)))
