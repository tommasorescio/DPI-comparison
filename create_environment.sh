#!/bin/bash

# this script is in charge of creating the environment: all the required folders
# and the preprocessing files needed by Tstat

echo " "
echo "-----------------------------------------------------------"
echo "DPI Analysis Tool"
echo ""
echo "STEP 1: Environment creation"
echo "-----------------------------------------------------------"
echo " "

# creation of the required folders
mkdir -p ./preprocessing_files # where there are the preprocessing files used by Tstat to create traces with different packets
mkdir -p ./log_preprocessing
mkdir -p ./stats
mkdir -p ./output_libraries # where there are all the outputs coming out from the libraries

# put in the following folder the original traces
mkdir -p ./traces/malware_macrotrace
mkdir -p ./traces/media_games_macrotrace
mkdir -p ./traces/user_traffic_macrotrace
mkdir -p ./traces/IoT_macrotrace

# creation of the required configuration files for tstat
for i in {1..25} # iteration on all arguments
do
  echo "
  ####################################
  # Tstat Runtime configuration file.
  # Use 0/1 to disable/enable features
  ####################################

  # print logs on disk
  [log]
  histo_engine = 0                # logs created by histogram engine
  rrd_engine = 0                  # logs created by rrd engine
  ###########
  log_tcp_complete = 1            # tcp connections correctly terminated
  log_tcp_nocomplete = 1          # tcp connections not properly terminated
  log_udp_complete = 1            # udp flows
  log_mm_complete = 0             # multimedia
  log_skype_complete = 0          # skype traffic
  log_chat_complete = 0           # MSN/Yahoo/Jabber chat flows
  log_chat_messages = 0           # MSN/Yahoo/Jabber chat messages
  log_video_complete = 0          # video (YouTube and others)
  log_http_complete = 0           # all the HTTP requests/responses

  # log options
  [options]
  tcplog_end_to_end = 0           # Enable the logging of the End_to_End set of measures (RTT, TTL)
  tcplog_layer7 = 0               # Enable the logging of the Layer7 set of measures (SSL cert., message counts)
  tcplog_p2p = 0                  # Enable the logging of the P2P set of measures (P2P subtype and ED2K data)
  tcplog_options = 0              # Enable the logging of the TCP Options set of measures
  tcplog_advanced = 0             # Enable the logging of the Advanced set of measures

  videolog_end_to_end = 0         # Enable the logging in log_video_complete of the TCP End_to_End set of measures (RTT, TTL)
  videolog_layer7 = 0                     # Enable the logging in log_video_complete of the Layer7 set of measures (SSL cert., message counts)
  videolog_videoinfo = 0          # Enable the logging in log_video_complete of the additional video info (resolution, bitrate)
  videolog_youtube = 0            # Enable the logging in log_video_complete of the YouTube specific information
  videolog_options = 0            # Enable the logging in log_video_complete of the TCP Options set of measures
  videolog_advanced = 0           # Enable the logging in log_video_complete of video-related Advanced mesurements (rate)

  httplog_full_url = 0            # Enable the logging of the partial (=1) or full (=2) URLs in log_http_complete

  # protocols to dump
  [dump]

  snap_len = 0        # max num of bytes to dump from ip hdr (included)
                    # 0 == all bytes
  slice_win = 0       # dimension (in secs) of the dumping window
                    # used to slice the input traffic in different traces
                    # 0 == no slice

  #### UDP traces ####
  udp_dns = 0
  udp_rtp = 0
  udp_rtcp = 0
  udp_edk = 0
  udp_kad = 0
  udp_kadu = 0
  udp_okad = 0
  udp_gnutella = 0
  udp_bittorrent = 0
  udp_utp = 0
  udp_dc = 0
  udp_kazaa = 0
  udp_pplive = 0
  udp_sopcast = 0
  udp_tvants = 0
  udp_ppstream = 0
  udp_teredo = 0
  udp_vod = 0
  udp_sip = 0
  udp_dtls = 0
  udp_quic = 0
  udp_unknown = 0     # all the udp traffic that the DPI doesn't recognize

  #### TCP traces ####
  # Note: Packets (with or without payload) from the time when the classification
  # is defined. It follows that, 3-ways handshake and (possibly) some initial
  # data packets of the flows are skipped
  tcp_videostreaming = 0

  ### Aggregated traces ####
  ip_complete = 0     # all the traffic that use ip as level 3 (including tcp, udp, icmp, ...)
  ###
  udp_complete = 1    # only udp traffic
  udp_maxpackets = "$i"
  udp_maxbytes = 0
  ###
  tcp_complete = 1    # only tcp traffic
  tcp_maxpackets = "$i"
  tcp_maxbytes = 0

  ###
  # This enables the filter based on DNS names requested by clients.
  # See the tstat-conf/DNS_filter_example.txt file for more details.
  # A filename must be provided with the -F command line optionprotocol
  dns_filter = 0 # enable the dns filtering

  ###
  # This is a bitmask that is used to stop dumping tcp packets of flows we are not interested into
  # It is a bitmask based on protocol.h types that the con_type can take.
  # Setting this to 0 will keep logging everything
  # Setting a bit to 1 will stop logging packets of those protocol as soon as the
  # classifier set those flags
  # e.g., setting it to 1025 (1+1024), all http and smtp traffic will be discarded.
  # Note that we cannot discard those packets of a flow that we have seen before
  # actually identifying the protocol. For example, three-way-handshake segments will be always there...
  # stop_dumping_mask = 262143  # => 11 1111 1111 1111 1111 discard everything we know except UNKNOWN
  # stop_dumping_mask = 262142  # => 11 1111 1111 1111 1110 log only UNKNOWN and HTTP
  # stop_dumping_mask = 0x3DFFF # => 11 1101 1111 1111 1111 log only UNKNOWN and SSL/TLS
  # stop_dumping_mask = 1       # => 00 0000 0000 0000 0001 log everything which is not HTTP
  # stop_dumping_mask = 0       # => log everything
  #
  #  11 1111 1111 1111 1111
  #  ^^ ^^^^ ^^^^ ^^^^ ^^^^
  #  || |||| |||| |||| ||||______ HTTP
  #  || |||| |||| |||| |||_______ RTSP
  #  || |||| |||| |||| ||________ RTP
  #  || |||| |||| |||| |_________ ICY
  #  || |||| |||| ||||___________ RTCP
  #  || |||| |||| |||____________ MSN
  #  || |||| |||| ||_____________ YMSG
  #  || |||| |||| |______________ XMPP
  #  || |||| ||||________________ P2P
  #  || |||| |||_________________ SKYPE
  #  || |||| ||__________________ SMTP
  #  || |||| |___________________ POP3
  #  || ||||_____________________ IMAP4
  #  || |||______________________ SSL/TLS
  #  || ||_______________________ ED2K Obfuscated
  #  || |________________________ SSH
  #  ||__________________________ RTMP
  #  |___________________________ Bittorren MSE/PE
  #
  stop_dumping_mask = 0
  " > ./preprocessing_files/runtime_"$i".conf
done

echo " "
echo "-----------------------------------------------------------"
echo "DPI Analysis Tool"
echo ""
echo "STEP 1: Environment succesfully created"
echo "-----------------------------------------------------------"
echo " "
