#!/bin/bash

# This script is in charge of calling nDpi, Libprotoident, Tstat and Zeek in parallel

if [[ $# -lt 1 ]] ; then # if number of arguments are less or equal than 1, error
   echo 'ERROR: please insert the name of the filtered traces'
   exit 0
fi

echo " "
echo "-----------------------------------------------------------"
echo "DPI Analysis Tool"
echo ""
echo "STEP 3: Processing of the traces"
echo " "
echo "... initialization ..."#

DIR_HOME=$(pwd)
FILTERED_TRACES="$DIR_HOME"/traces/"$1"

START_TIME=$(date +%s.%N)

# to print stats about processing
count=0
arr=( "$FILTERED_TRACES"/* )
num_of_traces="${#arr[@]}"

#unzipping all traces if they are in pcap.gz (this is not done in parallel)
for trace in "$FILTERED_TRACES"/*
do
  for filtered_trace_pkt in $trace/*
  do
    (
    # echo "$filtered_trace_pkt"
    if [[ "$filtered_trace_pkt" =~ \.gz$ ]]; then
      zcat "$filtered_trace_pkt" > "${filtered_trace_pkt::-8}".pcap
      rm "$filtered_trace_pkt"
    fi
    )
  done
done

unique_date="$(date +%F_%H-%M-%S)"
dir_log="$DIR_HOME"/log_libraries/log_"$unique_date"
mkdir -p "$dir_log"

for i in {1..25} # iteration on all arguments
do
  touch "$dir_log"/error_"$i"
  touch "$dir_log"/output_"$i"
done

# testing all the libraries in parallel): 25 threads, 1 for each #pkt
for trace in "$FILTERED_TRACES"/*
do
  name_trace=${trace%*/}
  name_trace=${name_trace##*/}

  for i in {1..25}  # iteration on all arguments
  do
    (
    name_trace=${trace%*/}
    name_trace=${name_trace##*/}

    for protocol in {1..2}
    do
      if [[ "$protocol" -eq 1 ]] ; then
          filtered_trace_pkt="$trace"/"${name_trace::-9}"_tcp_filtered_nPkts_"$i".pcap
      fi
      if [[ "$protocol" -eq 2 ]] ; then
        filtered_trace_pkt="$trace"/"${name_trace::-9}"_udp_filtered_nPkts_"$i".pcap
      fi

      if test -f "$filtered_trace_pkt"; then # checking if the tcp output exists
        dir_name=${trace%*/}
        dir_name=${dir_name##*/}

        # nDpi
        dir_name=${trace%*/}
        dir_name=${dir_name##*/}
        mkdir -p "$DIR_HOME"/output_libraries/nDpi_"$dir_name"
        name_file=${filtered_trace_pkt%*/}
        name_file=${name_file##*/}
        /home/fast_dpiclass/classifier -r "$filtered_trace_pkt" 2>> "$dir_log"/error_"$i" > "$DIR_HOME"/output_libraries/nDpi_"$dir_name"/nDpi_"$name_file".txt

        # libprotoident
        mkdir -p "$DIR_HOME"/output_libraries/libprotoident_"$dir_name"
        name_file=${filtered_trace_pkt%*/}
        name_file=${name_file##*/}
        lpi_protoident "$filtered_trace_pkt" 2>> "$dir_log"/error_"$i" > "$DIR_HOME"/output_libraries/libprotoident_"$dir_name"/libprotoident_"$name_file".txt

        # zeek
        mkdir -p "$DIR_HOME"/output_libraries/zeek_"$dir_name"
        name_file=${filtered_trace_pkt%*/}
        name_file=${name_file##*/}
        mkdir -p "$DIR_HOME"/output_libraries/zeek_tmp_"$name_file"
        export PATH=/usr/local/zeek/bin:$PATH && cd "$DIR_HOME"/output_libraries/zeek_tmp_"$name_file" && zeek -C -r "$filtered_trace_pkt" 2>> "$dir_log"/error_"$i" >> "$dir_log"/output_"$i"
        if test -f "$DIR_HOME"/output_libraries/zeek_tmp_"$name_file"/conn.log; then
          mv "$DIR_HOME"/output_libraries/zeek_tmp_"$name_file"/conn.log "$DIR_HOME"/output_libraries/zeek_"$dir_name"/zeek_"$name_file".txt
        fi
        rm -r "$DIR_HOME"/output_libraries/zeek_tmp_"$name_file"

        # tstat
        mkdir -p "$DIR_HOME"/output_libraries/tstat_"$dir_name"
        name_file=${filtered_trace_pkt%*/}
        name_file=${name_file##*/}
        mkdir -p "$DIR_HOME"/output_libraries/tstat_tmp_"$name_file"
        tstat -P "$filtered_trace_pkt" -s "$DIR_HOME"/output_libraries/tstat_tmp_"$name_file" 2>> "$dir_log"/error_"$i" >> "$dir_log"/output_"$i"
        if test -f "$DIR_HOME"/output_libraries/tstat_tmp_"$name_file"/*/log_tcp_complete; then
          mv "$DIR_HOME"/output_libraries/tstat_tmp_"$name_file"/*/log_tcp_complete "$DIR_HOME"/output_libraries/tstat_"$dir_name"/tstat_"$name_file"_tcp.txt
        fi
        if test -f "$DIR_HOME"/output_libraries/tstat_tmp_"$name_file"/*/log_tcp_nocomplete; then
          mv "$DIR_HOME"/output_libraries/tstat_tmp_"$name_file"/*/log_tcp_nocomplete "$DIR_HOME"/output_libraries/tstat_"$dir_name"/tstat_"$name_file"_tcp_nc.txt
        fi
        if test -f "$DIR_HOME"/output_libraries/tstat_tmp_"$name_file"/*/log_udp_complete; then
          mv "$DIR_HOME"/output_libraries/tstat_tmp_"$name_file"/*/log_udp_complete "$DIR_HOME"/output_libraries/tstat_"$dir_name"/tstat_"$name_file"_udp.txt
        fi
        rm -r "$DIR_HOME"/output_libraries/tstat_tmp_"$name_file"
      fi
    done
    )&
  done
  name_trace=${trace%*/}
  name_trace=${name_trace##*/}
  ((count=count+1))
  echo "... processing trace with nDpi, libprotoident, zeek, tstat "$name_trace", "$count"/"$num_of_traces" ..."
  wait
done

wait

echo " "
echo "... processing with nDpi, libprotoident, zeek, tstat done."
echo " "


END_TIME=$(date +%s.%N)
echo "total time "$(echo "$END_TIME - $START_TIME" | bc)"" > "$dir_log"/log.txt
echo "traces" >> "$dir_log"/log.txt
echo "${arr[@]}" >> "$dir_log"/log.txt

echo " "
echo "-----------------------------------------------------------"
echo "DPI Analysis Tool"
echo ""
echo "STEP 3: Processing of the traces complete"
echo "-----------------------------------------------------------"
echo " "
