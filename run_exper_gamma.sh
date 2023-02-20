
#!/usr/bin/python3.9

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Run all jupytext notebook and save output under output directory
OUTPUT_DIR=notebooks  #../../../../
INPUT_DIR=cyberbattle/agents/baseline/notebooks
REWARD_CLIP=False

# cat $INPUT_DIR/notebook_debug_tinymicro.py | jupytext --to ipynb --set-kernel - | papermill $OUTPUT_DIR/notebook_dql_debug_tiny_ht_one_by_one.ipynb -p gymid 'CyberBattleTinyMicro-v1' -p training_episode_count  2000  -p reward_clip $REWARD_CLIP -p gamma  # --log-output --log-level INFO --progress-bar  -p iteration_count 20 -p eval_episode_count 10

cat $INPUT_DIR/notebook_dql_debug_with_tinymicro.py | jupytext --to ipynb --set-kernel - | papermill $OUTPUT_DIR/notebook_dql_debug_tiny_ht_one_by_one.ipynb -p gymid 'CyberBattleTinyMicro-v2' -p training_episode_count  2000  -p reward_clip $REWARD_CLIP -p gamma 0.8 # --log-output --log-level INFO --progress-bar  -p iteration_count 20 -p eval_episode_count 10

cat $INPUT_DIR/notebook_dql_debug_with_tinymicro.py | jupytext --to ipynb --set-kernel - | papermill $OUTPUT_DIR/notebook_dql_debug_tiny_ht_one_by_one.ipynb -p gymid 'CyberBattleTinyMicro-v2' -p training_episode_count  2000  -p reward_clip $REWARD_CLIP -p gamma 0.5 # --log-output --log-level INFO --progress-bar  -p iteration_count 20 -p eval_episode_count 10

cat $INPUT_DIR/notebook_dql_debug_with_tinymicro.py | jupytext --to ipynb --set-kernel - | papermill $OUTPUT_DIR/notebook_dql_debug_tiny_ht_one_by_one.ipynb -p gymid 'CyberBattleTinyMicro-v2' -p training_episode_count  2000  -p reward_clip $REWARD_CLIP -p gamma 0.25 # --log-output --log-level INFO --progress-bar  -p iteration_count 20 -p eval_episode_count 10

cat $INPUT_DIR/notebook_dql_debug_with_tinymicro.py | jupytext --to ipynb --set-kernel - | papermill $OUTPUT_DIR/notebook_dql_debug_tiny_ht_one_by_one.ipynb -p gymid 'CyberBattleTinyMicro-v2' -p training_episode_count  2000  -p reward_clip $REWARD_CLIP -p gamma 0.1 # --log-output --log-level INFO --progress-bar  -p iteration_count 20 -p eval_episode_count 10