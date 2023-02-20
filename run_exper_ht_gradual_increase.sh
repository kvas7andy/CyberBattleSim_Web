
#!/usr/bin/python3.9

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Run all jupytext notebook and save output under output directory
OUTPUT_DIR=notebooks  #../../../../
INPUT_DIR=cyberbattle/agents/baseline/notebooks
REWARD_CLIP=True

# cat $INPUT_DIR/notebook_debug_tinymicro.py | jupytext --to ipynb --set-kernel - | papermill $OUTPUT_DIR/notebook_dql_tiny.ipynb -p gymid 'CyberBattleTinyMicro-v1' -p training_episode_count  2000  -p reward_clip $REWARD_CLIP # -p iteration_count 20 -p eval_episode_count 10

cat $INPUT_DIR/notebook_dql_debug_with_tinymicro.py | jupytext --to ipynb --set-kernel - | papermill $OUTPUT_DIR/notebook_dql_debug_tiny_ht_gradual_increase.ipynb -p gymid 'CyberBattleTinyMicro-v12' -p training_episode_count  2000  -p reward_clip $REWARD_CLIP # -p iteration_count 20 -p eval_episode_count 10

cat $INPUT_DIR/notebook_dql_debug_with_tinymicro.py | jupytext --to ipynb --set-kernel - | papermill $OUTPUT_DIR/notebook_dql_debug_tiny_ht_gradual_increase.ipynb -p gymid 'CyberBattleTinyMicro-v123' -p training_episode_count  2000  -p reward_clip $REWARD_CLIP # -p iteration_count 20 -p eval_episode_count 100

cat $INPUT_DIR/notebook_dql_debug_with_tinymicro.py | jupytext --to ipynb --set-kernel - | papermill $OUTPUT_DIR/notebook_dql_debug_tiny_ht_gradual_increase.ipynb -p gymid 'CyberBattleTinyMicro-v1234' -p training_episode_count  2000  -p reward_clip $REWARD_CLIP # -p iteration_count 20 -p eval_episode_count 10

### Rinse and repeat

cat $INPUT_DIR/notebook_dql_debug_with_tinymicro.py | jupytext --to ipynb --set-kernel - | papermill $OUTPUT_DIR/notebook_dql_debug_tiny_ht_gradual_increase.ipynb -p gymid 'CyberBattleTinyMicro-v12' -p training_episode_count  2000  -p reward_clip $REWARD_CLIP # -p iteration_count 20 -p eval_episode_count 10

cat $INPUT_DIR/notebook_dql_debug_with_tinymicro.py | jupytext --to ipynb --set-kernel - | papermill $OUTPUT_DIR/notebook_dql_debug_tiny_ht_gradual_increase.ipynb -p gymid 'CyberBattleTinyMicro-v123' -p training_episode_count  2000  -p reward_clip $REWARD_CLIP # -p iteration_count 20 -p eval_episode_count 100

cat $INPUT_DIR/notebook_dql_debug_with_tinymicro.py | jupytext --to ipynb --set-kernel - | papermill $OUTPUT_DIR/notebook_dql_debug_tiny_ht_gradual_increase.ipynb -p gymid 'CyberBattleTinyMicro-v1234' -p training_episode_count  2000  -p reward_clip $REWARD_CLIP # -p iteration_count 20 -p eval_episode_count 10
