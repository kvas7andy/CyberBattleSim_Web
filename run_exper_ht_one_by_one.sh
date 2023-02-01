
#!/usr/bin/python3.9

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Run all jupytext notebook and save output under output directory
OUTPUT_DIR=notebooks  #../../../../
INPUT_DIR=cyberbattle/agents/baseline/notebooks

# cat $INPUT_DIR/notebook_debug_tinymicro.py | jupytext --to ipynb --set-kernel - | papermill $OUTPUT_DIR/notebook_dql_debug_tiny_ht_one_by_one.ipynb -p gymid 'CyberBattleTinyMicro-v1' -p training_episode_count  2000 # --log-output --log-level INFO --progress-bar  -p iteration_count 20 -p eval_episode_count 10

cat $INPUT_DIR/notebook_dql_debug_with_tinymicro.py | jupytext --to ipynb --set-kernel - | papermill $OUTPUT_DIR/notebook_dql_debug_tiny_ht_one_by_one.ipynb -p gymid 'CyberBattleTinyMicro-v1' -p training_episode_count  2000 # --log-output --log-level INFO --progress-bar  -p iteration_count 20 -p eval_episode_count 10

cat $INPUT_DIR/notebook_dql_debug_with_tinymicro.py | jupytext --to ipynb --set-kernel - | papermill $OUTPUT_DIR/notebook_dql_debug_tiny_ht_one_by_one.ipynb -p gymid 'CyberBattleTinyMicro-v2' -p training_episode_count  2000 # --log-output --log-level INFO --progress-bar  -p iteration_count 20 -p eval_episode_count 10

cat $INPUT_DIR/notebook_dql_debug_with_tinymicro.py | jupytext --to ipynb --set-kernel - | papermill $OUTPUT_DIR/notebook_dql_debug_tiny_ht_one_by_one.ipynb -p gymid 'CyberBattleTinyMicro-v3' -p training_episode_count  2000 # --log-output --log-level INFO --progress-bar  -p iteration_count 20 -p eval_episode_count 10

cat $INPUT_DIR/notebook_dql_debug_with_tinymicro.py | jupytext --to ipynb --set-kernel - | papermill $OUTPUT_DIR/notebook_dql_debug_tiny_ht_one_by_one.ipynb -p gymid 'CyberBattleTinyMicro-v4' -p training_episode_count  2000 # --log-output --log-level INFO --progress-bar  -p iteration_count 20 -p eval_episode_count 10

cat $INPUT_DIR/notebook_dql_debug_with_tinymicro.py | jupytext --to ipynb --set-kernel - | papermill $OUTPUT_DIR/notebook_dql_debug_tiny_ht_one_by_one.ipynb -p gymid 'CyberBattleTinyMicro-v1' -p training_episode_count  2000 # --log-output --log-level INFO --progress-bar  -p iteration_count 20 -p eval_episode_count 10

cat $INPUT_DIR/notebook_dql_debug_with_tinymicro.py | jupytext --to ipynb --set-kernel - | papermill $OUTPUT_DIR/notebook_dql_debug_tiny_ht_one_by_one.ipynb -p gymid 'CyberBattleTinyMicro-v2' -p training_episode_count  2000 # --log-output --log-level INFO --progress-bar  -p iteration_count 20 -p eval_episode_count 10

cat $INPUT_DIR/notebook_dql_debug_with_tinymicro.py | jupytext --to ipynb --set-kernel - | papermill $OUTPUT_DIR/notebook_dql_debug_tiny_ht_one_by_one.ipynb -p gymid 'CyberBattleTinyMicro-v3' -p training_episode_count  2000 # --log-output --log-level INFO --progress-bar  -p iteration_count 20 -p eval_episode_count 10

cat $INPUT_DIR/notebook_dql_debug_with_tinymicro.py | jupytext --to ipynb --set-kernel - | papermill $OUTPUT_DIR/notebook_dql_debug_tiny_ht_one_by_one.ipynb -p gymid 'CyberBattleTinyMicro-v4' -p training_episode_count  2000 # --log-output --log-level INFO --progress-bar  -p iteration_count 20 -p eval_episode_count 10


# cat $INPUT_DIR/notebook_benchmark.py | jupytext --to ipynb --set-kernel - | papermill $OUTPUT_DIR/notebook_benchmark-tiny.ipynb -p gymid 'CyberBattleTiny-v0' -p iteration_count 200 -p training_episode_count 10 -p eval_episode_count 10 -p maximum_node_count 5 -p maximum_total_credentials 3

# cat $INPUT_DIR/notebook_benchmark.py | jupytext --to ipynb --set-kernel - | papermill $OUTPUT_DIR/notebook_benchmark-toyctf.ipynb -p gymid 'CyberBattleToyCtf-v0' -p iteration_count 2000 --log-output-p training_episode_count 20 -p eval_episode_count 10 -p maximum_node_count 12 -p maximum_total_credentials 10

# cat $INPUT_DIR/notebook_benchmark.py | jupytext --to ipynb --set-kernel - | papermill $OUTPUT_DIR/notebook_benchmark-chain.ipynb -p gymid 'CyberBattleChain-v0' -p iteration_count 9000 -p training_episode_count 50 -p eval_episode_count 5 -p maximum_node_count 22 -p maximum_total_credentials 22 -p env_size 10

# cat $INPUT_DIR/notebook_dql_transfer.py | jupytext --to ipynb --set-kernel - | papermill $OUTPUT_DIR/notebook_dql_transfer.ipynb

# cat $INPUT_DIR/notebook_tabularq.py | jupytext --to ipynb --set-kernel - | papermill $OUTPUT_DIR/notebook_tabularq.ipynb

# cat $INPUT_DIR/notebook_randlookups.py | jupytext --to ipynb --set-kernel - | papermill $OUTPUT_DIR/notebook_randlookups.ipynb

# cat $INPUT_DIR/notebook_withdefender.py | jupytext --to ipynb --set-kernel - | papermill $OUTPUT_DIR/notebook_withdefender.ipynb
