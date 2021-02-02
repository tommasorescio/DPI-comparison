#!/bin/bash

# This script is in charge of preprocessing the traces: it creates the so-called
# "filtered_traces": for each trace, it creates 25 traces with an increasing number of Packets
# per flow (from 1 to 25)

if [[ $# -le 1 ]] ; then # if number of arguments are less or equal than 1, error
    echo 'ERROR: please insert the path of the traces and the output folder'
    exit 0
fi

DIR_HOME=.
unique_date="$(date +%F_%H-%M-%S)"
dir_log="$DIR_HOME"/log_preprocessing/log_"$unique_date"
mkdir -p "$dir_log"

TRACES_DIR="$1" # absolute path where there are all the traces to be preprocessed
for i in {1..25} # iteration on all arguments
do
  (
  for trace in "$TRACES_DIR"/*
  do
    name_trace=${trace%*/}
    name_trace=${name_trace##*/}
    mkdir -p "$DIR_HOME"/traces/"$2"
    mkdir -p "$DIR_HOME"/traces/"$2"/"$name_trace"_filtered
    mkdir -p "$DIR_HOME"/tstat_tmp_"$name_trace"_"$i" # creating a temporary directory
    tstat -T "$DIR_HOME"/preprocessing_files/runtime_"$i".conf -P "$TRACES_DIR"/"$name_trace" -s "$DIR_HOME"/tstat_tmp_"$name_trace"_"$i" 2>> "$dir_log"/error_"$i" >> "$dir_log"/output_"$i"
    if test -f "$DIR_HOME"/tstat_tmp_"$name_trace"_"$i"/*/traces00/tcp_complete.pcap.gz; then # checking if the tcp output exists
      mv "$DIR_HOME"/tstat_tmp_"$name_trace"_"$i"/*/traces00/tcp_complete.pcap.gz "$DIR_HOME"/traces/"$2"/"$name_trace"_filtered/"$name_trace"_tcp_filtered_nPkts_"$i".pcap.gz
    fi
    if test -f "$DIR_HOME"/tstat_tmp_"$name_trace"_"$i"/*/traces00/udp_complete.pcap.gz; then   # checking if the udp output exists
      mv "$DIR_HOME"/tstat_tmp_"$name_trace"_"$i"/*/traces00/udp_complete.pcap.gz "$DIR_HOME"/traces/"$2"/"$name_trace"_filtered/"$name_trace"_udp_filtered_nPkts_"$i".pcap.gz
    fi
    rm -r "$DIR_HOME"/tstat_tmp_"$name_trace"_"$i" # removing the temporary directory
    echo "... pre-processing trace "$name_trace", thread "$i" done ..."
  done
  )& #in order to lunch different threads
done
wait

echo " "
echo "-----------------------------------------------------------"
echo "DPI Analysis Tool"
echo ""
echo "STEP 2: Pre-processing of the traces complete"
echo "-----------------------------------------------------------"
echo " "
