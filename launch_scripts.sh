#!/bin/bash

echo " "
echo "-----------------------------------------------------------"
echo "DPI Analysis Tool version 2.0.1"
echo ""
echo "STEP 2: launching the scripts"
echo " "

DIR_HOME=.
PATH_MALWARE=./traces/malware_macrotrace
PATH_MEDIA_GAMES=./traces/media_games_macrotrace
PATH_USER=./traces/user_traffic_macrotrace
PATH_IOT=./traces/IoT_macrotrace

unique_date="$(date +%F_%H-%M-%S)"
dir_log="$DIR_HOME"/log_general_script/log_"$unique_date"
mkdir -p "$dir_log"
touch "$dir_log"/error
touch "$dir_log"/output

dir_name=${TRACES_DIR%*/}
dir_name=${dir_name##*/}


# MALWARE MACROTRACE

echo " preprocessing_script.sh malware_macrotrace started"
./preprocessing_script.sh "$PATH_MALWARE" malware_macrotrace_filtered 2>> "$dir_log"/error >> "$dir_log"/output
echo " preprocessing_script.sh malware_macrotrace done"
echo ""
echo " call_libraries.sh malware_macrotrace_filtered"
./call_libraries.sh malware_macrotrace_filtered 2>> "$dir_log"/error >> "$dir_log"/output
echo " call_libraries.sh malware_macrotrace_filtered done"
echo ""
# ------------------------------------------------------------------------------


# MEDIA & GAMES MACROTRACE

echo " preprocessing_script.sh media_games_macrotrace started"
./preprocessing_script.sh "$PATH_MEDIA_GAMES" media_games_macrotrace_filtered 2>> "$dir_log"/error >> "$dir_log"/output
echo " preprocessing_script.sh media_games_macrotrace done"
echo ""
echo " call_libraries.sh media_games_macrotrace_filtered"
./call_libraries.sh media_games_macrotrace_filtered 2>> "$dir_log"/error >> "$dir_log"/output
echo " call_libraries.sh media_games_macrotrace_filtered done"
echo ""
# ------------------------------------------------------------------------------


# USER MACROTRACE

echo " preprocessing_script.sh user_macrotrace started"
./preprocessing_script.sh "$PATH_USER" user_macrotrace_filtered 2>> "$dir_log"/error >> "$dir_log"/output
echo " preprocessing_script.sh user_macrotrace done"
echo ""
echo " call_libraries.sh user_macrotrace_filtered"
./call_libraries.sh user_macrotrace_filtered 2>> "$dir_log"/error >> "$dir_log"/output
echo " call_libraries.sh user_macrotrace_filtered done"
echo ""
# ------------------------------------------------------------------------------


# IoT MACROTRACE

echo " preprocessing_script.sh IoT_macrotrace started"
./preprocessing_script.sh "$PATH_IOT" IoT_macrotrace_filtered 2>> "$dir_log"/error >> "$dir_log"/output
echo " preprocessing_script.sh IoT_macrotrace done"
echo ""
echo " call_libraries.sh IoT_macrotrace_filtered"
./call_libraries.sh IoT_macrotrace_filtered 2>> "$dir_log"/error >> "$dir_log"/output
echo " call_libraries.sh IoT_macrotrace_filtered done"
echo ""
# ------------------------------------------------------------------------------

echo " "
echo "-----------------------------------------------------------"
echo "DPI Analysis Tool"
echo ""
echo "STEP 2: lunching the scripts done"
echo "-----------------------------------------------------------"
echo " "
