
#!/usr/bin/python3.9

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Run all jupytext notebook and save output under output directory
OUTPUT_DIR=notebooks  #../../../../
INPUT_DIR=cyberbattle/agents/baseline/notebooks
REWARD_CLIP=True

# cat $INPUT_DIR/notebook_debug_tinymicro.py | jupytext --to ipynb --set-kernel - | papermill $OUTPUT_DIR/notebook_dql_debug_tiny_ht_one_by_one.ipynb -p gymid 'CyberBattleTinyMicro-v1' -p training_episode_count  2000  $arg # --log-output --log-level INFO --progress-bar  -p iteration_count 20 -p eval_episode_count 10


for i in {1..3}; do
  for reward in "-p reward_clip True" ""; do
    for gamma in "-p gamma 0.25" ""; do
        cat $INPUT_DIR/notebook_dql_debug_with_tinymicro.py | jupytext --to ipynb --set-kernel - | papermill $OUTPUT_DIR/notebook_dql_debug_tiny_ht_one_by_one.ipynb -p gymid 'CyberBattleTinyMicro-v1' -p training_episode_count 2000 $reward $gamma
        cat $INPUT_DIR/notebook_dql_debug_with_tinymicro.py | jupytext --to ipynb --set-kernel - | papermill $OUTPUT_DIR/notebook_dql_debug_tiny_ht_one_by_one.ipynb -p gymid 'CyberBattleTinyMicro-v2' -p training_episode_count 2000 $reward $gamma
        cat $INPUT_DIR/notebook_dql_debug_with_tinymicro.py | jupytext --to ipynb --set-kernel - | papermill $OUTPUT_DIR/notebook_dql_debug_tiny_ht_one_by_one.ipynb -p gymid 'CyberBattleTinyMicro-v3' -p training_episode_count 2000 $reward $gamma
        cat $INPUT_DIR/notebook_dql_debug_with_tinymicro.py | jupytext --to ipynb --set-kernel - | papermill $OUTPUT_DIR/notebook_dql_debug_tiny_ht_one_by_one.ipynb -p gymid 'CyberBattleTinyMicro-v4' -p training_episode_count 2000 $reward $gamma
    done
  done
done