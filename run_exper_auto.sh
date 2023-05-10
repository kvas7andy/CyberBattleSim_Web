# Run all jupytext notebook and save output under output directory
OUTPUT_DIR=notebooks  #../../../../
INPUT_DIR=cyberbattle/agents/baseline/notebooks
REWARD_CLIP=True

# cat $INPUT_DIR/notebook_debug_tinymicro.py|jupytext −−to ipynb −−set−kernel −| papermill $OUTPUT_DIR/notebook_dql_debug_tiny_ht_one_by_one.ipynb -p gymid 'CyberBattleTinyMicro-v1' -p training_episode_count  2000  # --log-output --log-level INFO --progress-bar  -p iteration_count 20 -p eval_episode_count 10
env_str='CyberBattleTinyMicro-v'
# Define the version string pairs
ver_pairs=('12' '13' '14' '23' '24' '34' '123' '124' '134' '234' '1234' '1' '2' '3' '4' ) #
# Create an empty array for the final string list
final_str_list=()

# Loop through each version pair and concatenate with the environment string
for ver_str in "${ver_pairs[@]}"; do
    final_str_list+=("$env_str$ver_str")
done

# # Loop through pairs of numbers from 1 to 4
# for i in {1..4}; do
#   for j in {1..4}; do
#     if [ "$i" -ne "$j" ] && [ "$i" -lt "$j" ]; then
#       # Concatenate the environment string with the pair of numbers
#       final_str_list+=("$env_str$i$j")

for i in 1 3 5; do
    for gymid in "${final_str_list[@]}"; do
        echo 
        # for reward in "-p reward_clip True" ""; do
        #     for gamma in "-p gamma 0.25" ""; do
        cat $INPUT_DIR/notebook_dql_debug_with_tinymicro.py | jupytext --to ipynb --set-kernel - |
        papermill $OUTPUT_DIR/notebook_dql_debug_tiny_auto.ipynb -p gymid "$gymid" -p seed $i -p training_episode_count 2000 $reward $gamma
        #     done
        # done
    done
done