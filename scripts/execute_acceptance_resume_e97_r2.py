"""New control-phase receipts after a pre-mutation metadata-pin correction.

The first controller never reached bresume. This does not grant a second job,
retry a scheduler mutation, or overwrite the original failed phase.
"""
from scripts import execute_acceptance_resume_e97 as controller


def main():
    previous = controller.OBS_PHASE, controller.RESUME_PHASE, controller.REVIEWS
    try:
        controller.OBS_PHASE = controller.STAGING / 'v6_e97_pre_resume_observation_20261024_r2'
        controller.RESUME_PHASE = controller.STAGING / 'v6_e97_resume_20261024_r2'
        controller.REVIEWS = {
            name: controller.ROOT / ('data/manifests/ranking_v6_e97_' + name + '_bound_review_20261024_r2.json')
            for name in ('registration', 'pre_resume')}
        controller.main()
    finally:
        controller.OBS_PHASE, controller.RESUME_PHASE, controller.REVIEWS = previous


if __name__ == '__main__':
    main()
