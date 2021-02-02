#!/usr/bin/env python
# coding: utf-8

# In[34]:


import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import sys
import os
import pathlib
import re
from collections import Counter
from copy import deepcopy
import fastplot
from cycler import cycler
import seaborn as sns
import random

dir_home = os.getcwd() + '/'
num_pkt_vector_mod = range(1,21) # number of packets


# In[8]:


def read_nDpi(protocol, allowed_pkts):
    # this function is in charge of reading the output of nDpi. The input is the transport protocol and the number of packets per flow

    library = 'nDpi'
    file_name = str('nDpi') + '_' + str(trace) + '_' + str(protocol) + '_filtered_nPkts_' + str(allowed_pkts) + '.pcap.txt'
    name = dir_home + 'output_libraries/' + str(library) + '_' + str(trace) + '_filtered/' + file_name
    if os.path.isfile(name) == False:
        data = pd.DataFrame()
        return data, False, name, 0
    data = pd.read_csv(name, sep = ' ',  usecols = np.arange(7), names = ['start_timestamp', 'trans_protocol',  'src_ip', 'src_port', 'dst_ip', 'dst_port', 'detected_protocol'],
                      error_bad_lines=True,
                       dtype = {'src_ip': str, 'dst_ip': str,  'trans_protocol': str,
                                       'src_port': str, 'dst_port': str, 'detected_protocol': str,
                                       'start_timestamp': str, 'last_seen': str},
                      engine='python')
    data = data.fillna(0)
    data = data[(data['trans_protocol'] == '6') | (data['trans_protocol'] == '17')]
    data[['src_ip']] = data[['src_ip']].astype(str)
    data[['dst_ip']] = data[['dst_ip']].astype(str)
    data[['trans_protocol']] = data[['trans_protocol']].astype(np.int64)
    data[['dst_port']] = data[['dst_port']].astype(np.int64)
    data[['src_port']] = data[['src_port']].astype(np.int64)
    data[['detected_protocol']] = data[['detected_protocol']].astype(str)
    data[['start_timestamp']] = data[['start_timestamp']].astype(np.float64)
    data = data[(~data['src_ip'].str.contains(':')) | (~data['dst_ip'].str.contains(':'))]
    data['start_timestamp'] = data['start_timestamp']/10
    data['start_timestamp'] = data['start_timestamp'].apply(np.trunc)
    data = data[['src_ip', 'dst_ip',  'trans_protocol', 'src_port', 'dst_port', 'detected_protocol', 'start_timestamp']]
    shape = data.shape[0]
    return data, True, None, shape


# In[9]:


def read_libprotoident(protocol, allowed_pkts):
    # this function is in charge of reading the output of libprotoident. The input is the transport protocol and the number of packets per flow

    library = 'libprotoident'
    file_name = str(library) + '_' + str(trace) + '_' + str(protocol) + '_filtered_nPkts_' + str(allowed_pkts) + '.pcap.txt'
    name = dir_home + 'output_libraries/' + str(library) + '_' + str(trace) + '_filtered/' + file_name
    if os.path.isfile(name) == False:
        data = pd.DataFrame()
        return data, False, name, 0
    data = pd.read_csv(name, sep = '\s+', engine = 'python', names = ['detected_protocol','dst_ip','src_ip','dst_port',
                                                                      'src_port','trans_protocol','start_timestamp',
                                                                      'end_timestamp','I','L','M','N','O','P','Q','R',],
                      dtype = {'src_ip': str, 'dst_ip': str,  'trans_protocol': np.int64,
                               'src_port': np.int64, 'dst_port': np.int64, 'detected_protocol': str,
                               'start_timestamp': np.float64})
    data = data[['src_ip', 'dst_ip', 'trans_protocol', 'src_port', 'dst_port', 'detected_protocol', 'start_timestamp']]
    data['start_timestamp'] = data['start_timestamp']*100
    data['start_timestamp'] = data['start_timestamp'].apply(np.trunc)
    data[['start_timestamp']] = data[['start_timestamp']].astype(np.float64)
    data = data[(data['trans_protocol'] == 6) | (data['trans_protocol'] == 17)]
    data = data[(~data['src_ip'].str.contains(':')) | (~data['dst_ip'].str.contains(':'))]
    data = data[['src_ip', 'dst_ip',  'trans_protocol', 'src_port', 'dst_port', 'detected_protocol', 'start_timestamp']]
    shape = data.shape[0]
    return data, True, None, shape


# In[10]:


def read_zeek(protocol, allowed_pkts):
    # this function is in charge of reading the output of zeek. The input is the transport protocol and the number of packets per flow

    library = 'zeek'
    file_name = str(library) + '_' + str(trace) + '_' + str(protocol) + '_filtered_nPkts_' + str(allowed_pkts) + '.pcap.txt'
    name = dir_home + 'output_libraries/' + str(library) + '_' + str(trace) + '_filtered/' + file_name
    if os.path.isfile(name) == False:
        data = pd.DataFrame()
        return data, False, name, 0
    data = pd.read_csv(name, sep = '\t', skiprows = 8, skipfooter = 1, engine = 'python',
                       names = ['start_timestamp', 'uid', 'src_ip', 'src_port', 'dst_ip',
                                'dst_port', 'trans_protocol', 'detected_protocol', 'duration',
                                'orig_bytes', 'resp_bytes', 'conn_state', 'local_orig', 'local_resp',
                                'missed_bytes', 'history', 'orig_pkts', 'orig_ip_bytes', 'resp_pkts',
                                'resp_ip_bytes', 'tunnel_parents'],
                        dtype = {'src_ip': str, 'dst_ip': str,  'trans_protocol': str,
                               'src_port': np.int64, 'dst_port': np.int64, 'detected_protocol': str,
                               'start_timestamp': np.float64})
    data = data[['src_ip', 'dst_ip',  'trans_protocol', 'src_port', 'dst_port', 'detected_protocol', 'start_timestamp']]
    data['start_timestamp'] = data['start_timestamp']*100
    data['start_timestamp'] = data['start_timestamp'].apply(np.trunc)
    data = data[(data['trans_protocol'] == 'tcp') | (data['trans_protocol'] == 'udp')]
    data = data[(~data['src_ip'].str.contains(':')) | (~data['dst_ip'].str.contains(':'))]
    data.loc[data['trans_protocol'] == 'tcp', 'trans_protocol'] = 6
    data.loc[data['trans_protocol'] == 'udp', 'trans_protocol'] = 17
    data.loc[data['detected_protocol'] == '-', 'detected_protocol'] = 'unknown'
    data[['trans_protocol']] = data[['trans_protocol']].astype(np.int64)
    data = data[(data['trans_protocol'] == 6) | (data['trans_protocol'] == 17)]
    data = data[['src_ip', 'dst_ip',  'trans_protocol', 'src_port', 'dst_port', 'detected_protocol', 'start_timestamp']]
    shape = data.shape[0]
    return data, True, None, shape


# In[11]:


def read_tstat(protocol, allowed_pkts):
    # this function is in charge of reading the output of tstat. The input is the transport protocol and the number of packets per flow

    shape_1 = 0
    shape_2 = 0
    shape_3 = 0
    not_valid_flows_1 = 0
    not_valid_flows_2 = 0
    not_valid_flows_3 = 0

    library = 'tstat'
    file_name = str(library) + '_' + str(trace) + '_' + str(protocol) + '_filtered_nPkts_' + str(allowed_pkts) + '.pcap'
    name = dir_home + 'output_libraries/' + str(library) + '_' + str(trace) + '_filtered/' + file_name
    if (os.path.isfile(name + '_tcp.txt') == True) & (('udp' in name) == False):
        name_tmp = name + '_' + str(protocol) + '.txt'
        data_1 = pd.read_csv(name_tmp, sep = ' ', usecols = ['#15#c_ip:1', 's_ip:15', 'c_port:2', 's_port:16', 'con_t:42', 'first:29', 'c_bytes_uniq:7', 's_bytes_uniq:21'],
                            dtype = {'#15#c_ip:1': str, 's_ip:15': str, 'c_port:2': np.int64, 's_port:16': np.int64, 'con_t:42': str,
                                   'first:29': np.float64})
        data_1['trans_protocol'] = 6 # tcp
        not_valid_flows_1 = data_1[(data_1['c_bytes_uniq:7'] == 0) & (data_1['s_bytes_uniq:21'] == 0)].shape[0]
        data_1 = data_1[(data_1['c_bytes_uniq:7'] > 0) | (data_1['s_bytes_uniq:21'] > 0)]
        data_1[['trans_protocol']] = data_1[['trans_protocol']].astype(np.int64)
        data_1 = data_1.rename(columns={'#15#c_ip:1':'src_ip', 's_ip:15':'dst_ip', 'c_port:2':'src_port',
                                        's_port:16':'dst_port','con_t:42':'detected_protocol', 'first:29':'start_timestamp',})
        data_1['detected_protocol'] = data_1['detected_protocol'].fillna(0)
        data_1['start_timestamp'] = (data_1['start_timestamp']/10)
        data_1['start_timestamp'] = data_1['start_timestamp'].apply(np.trunc)
        shape_1 = data_1.shape[0]
    else:
        data_1 = pd.DataFrame()

    if (os.path.isfile(name + '_udp.txt') == True) & (('udp' in name) == True):
        name_tmp = name + '_udp.txt'
        data_2 = pd.read_csv(name_tmp, sep = ' ', usecols = ['#c_ip:1', 's_ip:10', 'c_port:2', 's_port:11', 'c_type:9', 'c_first_abs:3', 'c_bytes_all:5', 's_bytes_all:14'],
                            dtype = {'#c_ip:1': str, 's_ip:10': str, 'c_port:2': np.int64, 's_port:11': np.int64, 'c_type:9': str,
                                   's_first_abs:12': np.float64, 'c_first_abs:3': np.float64})
        data_2['trans_protocol'] = 17 # udp
        data_2 = data_2.rename(columns={'#c_ip:1':'src_ip', 's_ip:10':'dst_ip', 'c_port:2':'src_port', 's_port:11':'dst_port',
                                        'c_type:9':'detected_protocol', 'c_first_abs:3':'start_timestamp'})
        not_valid_flows_2 = data_2[(data_2['c_bytes_all:5'] == 0) & (data_2['s_bytes_all:14'] == 0)].shape[0]
        data_2 = data_2[(data_2['c_bytes_all:5'] > 0) | (data_2['s_bytes_all:14'] > 0)]
        data_2['detected_protocol'] = data_2['detected_protocol'].fillna(0)
        data_2['start_timestamp'] = (data_2['start_timestamp']/10)
        data_2['start_timestamp'] = data_2['start_timestamp'].apply(np.trunc)
        shape_2 = data_2.shape[0]
    else:
        data_2 = pd.DataFrame()

    if (os.path.isfile(name + '_tcp_nc.txt') == True) & (('udp' in name) == False):
        name_tmp = name + '_tcp_nc.txt'
        data_3 = pd.read_csv(name_tmp, sep = ' ', usecols = ['#15#c_ip:1', 's_ip:15', 'c_port:2', 's_port:16', 'con_t:42', 'first:29', 'c_bytes_uniq:7', 's_bytes_uniq:21'],
                            dtype = {'#15#c_ip:1': str, 's_ip:15': str, 'c_port:2': np.int64, 's_port:16': np.int64, 'con_t:42': str,
                                   'first:29': np.float64})
        data_3['trans_protocol'] = 6 # tcp
        not_valid_flows_3 = data_3[(data_3['c_bytes_uniq:7'] == 0) & (data_3['s_bytes_uniq:21'] == 0)].shape[0]
        data_3 = data_3[(data_3['c_bytes_uniq:7'] > 0) | (data_3['s_bytes_uniq:21'] > 0)]
        data_3[['trans_protocol']] = data_3[['trans_protocol']].astype(np.int64)
        data_3 = data_3.rename(columns={'#15#c_ip:1':'src_ip', 's_ip:15':'dst_ip', 'c_port:2':'src_port',
                                        's_port:16':'dst_port','con_t:42':'detected_protocol', 'first:29':'start_timestamp'})
        data_3['detected_protocol'] = data_3['detected_protocol'].fillna(0)
        data_3['start_timestamp'] = (data_3['start_timestamp']/10)
        data_3['start_timestamp'] = data_3['start_timestamp'].apply(np.trunc)
        shape_3 = data_3.shape[0]
    else:
        data_3 = pd.DataFrame()

    data = pd.concat([data_1, data_2, data_3], ignore_index=True)
    shape = shape_1 + shape_2 + shape_3
    not_valid_flows_tcp = not_valid_flows_1 + not_valid_flows_3
    not_valid_flows_udp = not_valid_flows_2
    if data.empty == False:
        data = data[(data['trans_protocol'] == 6) | (data['trans_protocol'] == 17)]
        data = data[(~data['src_ip'].str.contains(':')) | (~data['dst_ip'].str.contains(':'))]
        data = data[['src_ip', 'dst_ip',  'trans_protocol', 'src_port', 'dst_port', 'detected_protocol', 'start_timestamp']]
    return data, True, not_valid_flows_tcp, not_valid_flows_udp, shape


# In[8]:


def process_protocols(row, src_ip, dst_ip, trans_protocol, src_port, dst_port, nDpi, libprotoident, tstat, zeek):
    # this function is in charge of extracting and parsing the protocol found by the libraries

    for library, protocol in zip(['nDpi', 'libprotoident', 'tstat', 'zeek'], [nDpi, libprotoident, tstat, zeek]):
        if (library == 'tstat'):
            if type(protocol) == str:
                if protocol == 'notRevealedFlow':
                    row[library] = protocol
                    return row
            if trans_protocol == 6:
                protocol = protocol_h_tcp(protocol)
            elif trans_protocol == 17:
                protocol = protocol_h_udp(protocol)
        if protocol == '0':
            protocol = 'unknown'
        if protocol == 0:
            protocol = 'unknown'
        if type(protocol) != str:
            protocol = str(protocol)
        protocol = protocol.lower()

        if ',' in protocol:
            protocol = 'unknown'
        protocol = re.split('_|/|-|"\"', protocol)[0]
        protocol = protocol.split('.')[0]

        if (protocol == 'tcp') | (protocol == 'udp') | (protocol == 'data') | (protocol == 'browser'):
            protocol = 'unknown'
        if protocol == 'kerberos':
            protocol = 'krb'
        if protocol == 'spnego-krb5':
            protocol = 'krb'
        if protocol == 'spnego':
            protocol = 'krb'
        if protocol == 'rpc':
            protocol = 'dce'
        if protocol == 'dcerpc':
            protocol = 'dce'
        if (protocol == 'netbios') | (protocol == 'smb') | (protocol == 'smb2') | (protocol == 'nbns'):
            protocol = 'netbiosSmb'
        if protocol == 'skypetcp':
            protocol = 'skype'
        if protocol == 'no':
            protocol = 'unknown'
        if protocol == 'mdns':
            protocol = 'dns'
        if protocol == 'cldap':
            protocol = 'ldap'
        if protocol == 'nats':
            protocol = 'pop3'
        if protocol == 'llmnr':
            protocol = 'dns'
        if protocol == 'bittorrent':
            protocol = 'p2p'
        if protocol == 'torrent':
            protocol = 'p2p'
        if protocol == 'bit':
            protocol = 'p2p'
        if protocol == 'ipv6':
            protocol = 'teredo'
        if protocol == 'spotifybroadcast':
            protocol = 'spotify'
        if protocol == 'spotifybroadcast':
            protocol = 'spotify'
        if protocol == 'soap':
            protocol = 'sslTls'
        if protocol == 'gquic':
            protocol = 'quic'
        if protocol == 'gquic':
            protocol = 'quic'
        if protocol == 'gssapi,ntlm,smb':
            protocol = 'netbiosSmb'
        if protocol == 'edonkey':
            protocol = 'p2p'
        if protocol == 'emule':
            protocol = 'p2p'
        if protocol == 'ed2k':
            protocol = 'p2p'
        if protocol == 'cacaowebudp':
            protocol = 'p2p'
        if protocol == 'first':
            protocol = 'p2p'
        if protocol == 'kademlia':
            protocol = 'p2p'

        if protocol == 'notrevealedflow':
            protocol = 'notRevealedFlow'
        if protocol == 'noPayload':
            protocol = 'unknown'

        # handling ssl/tls/https traffic
        if (protocol == 'ssl') | (protocol == 'tls') | (protocol == 'https'):
            protocol = 'sslTls'
        if (protocol == 'sslTls') & (src_port == 443 | dst_port == 443):
            protocol = 'https'

        row[library] = protocol
    return row


# In[12]:


# the following 2 functions are used for processing the labels found by Tstat

def protocol_h_tcp(protocol):

    protocol = int(protocol)
    if protocol in protocol_h_tcp_dict:
        return protocol_h_tcp_dict[protocol]
    prot = 0
    for i in protocol_h_tcp_dict.keys():
        if i != 0:
            if (protocol % i == 0):
                prot = i
    return protocol_h_tcp_dict[prot]

# global variable
protocol_h_tcp_dict = {0 : 'unknown', 1 : 'HTTP', 2 : 'RTSP', 4 : 'RTP', 8 : 'ICY', 16 : 'RTCP',
                       32 : 'MSN', 64 : 'YMSG', 128 : 'XMPP', 256 : 'P2P', 512 : 'SKYPE',
                       1024 : 'SMTP', 2048 : 'POP3', 4096 : 'IMAP4', 8192 : 'TLS/TLS', 16384 : 'ED2K',
                       32768 : 'SSH', 65536 : 'RTMP', 131072 : 'Bittorrent'}

def protocol_h_udp(protocol):
    protocol = int(protocol)
    if protocol in protocol_h_udp_dict:
        return protocol_h_udp_dict[protocol]
    prot = 0
    for i in protocol_h_udp_dict.keys():
        if i != 0:
            if (protocol % i == 0):
                prot = i
    return protocol_h_udp_dict[prot]

# global variable
protocol_h_udp_dict = {0 : 'unknown', 1 : 'FIRST_RTP', 2 : 'FIRST_RTCP', 3 : 'RTP', 4 : 'RTCP',
                        5 : 'SKYPE_E2E', 6 : 'SKYPE_E2O', 7 : 'SKYPE_SIG', 8 : 'P2P_ED2K', 9 : 'P2P_KAD',
                        10 : 'P2P_KADU', 11 : 'P2P_GNU', 12 : 'P2P_BT', 13 : 'P2P_DC', 14 : 'P2P_KAZAA',
                        15 : 'P2P_PPLIVE', 16 : 'P2P_SOPCAST', 17 : 'P2P_TVANTS', 18 : 'P2P_OKAD', 19 : 'DNS',
                        20 : 'P2P_UTP', 21 : 'P2P_UTPBT', 22 : 'UDP_VOD', 23 : 'P2P_PPSTREAM', 24 : 'TEREDO',
                        25 : 'UDP_SIP', 26 : 'UDP_DTLS', 27 : 'UDP_QUIC'}


# In[13]:


def merge_df(data_Flow_Table, data_nDpi, data_libprotoident, data_zeek, data_tstat):
    # this function is in charge of merging the labels from different libraries. We perform a left merge based on the flow table identified by Tstat

    result_tmp = pd.merge(data_Flow_Table, data_tstat, how = 'left', on = ['src_ip', 'dst_ip', 'src_port', 'dst_port', 'trans_protocol', 'start_timestamp'])
    result_tmp.rename(columns = {'detected_protocol_y' : 'tstat', }, inplace = True)
    result_tmp.drop(columns = 'detected_protocol_x', inplace = True)
    result_tmp = pd.merge(result_tmp, data_libprotoident, how = 'left', on = ['src_ip', 'dst_ip', 'src_port', 'dst_port', 'trans_protocol', 'start_timestamp'])
    result_tmp.rename(columns = {'detected_protocol' : 'libprotoident'}, inplace = True)
    result_tmp = pd.merge(result_tmp, data_zeek, how = 'left', on = ['src_ip', 'dst_ip', 'src_port', 'dst_port', 'trans_protocol', 'start_timestamp'])
    result_tmp.rename(columns = {'detected_protocol' : 'zeek'}, inplace = True)
    result_tmp = pd.merge(result_tmp, data_nDpi, how = 'left', on = ['src_ip', 'dst_ip', 'src_port', 'dst_port', 'trans_protocol', 'start_timestamp'])
    result_tmp.rename(columns = {'detected_protocol' : 'nDpi'}, inplace = True)
    result_tmp.fillna('notRevealedFlow', inplace=True)
    result_tmp = result_tmp[['src_ip','dst_ip','trans_protocol','src_port','dst_port','start_timestamp','nDpi','libprotoident','zeek','tstat']]
    result_tmp = result_tmp.apply(lambda row: process_protocols(row, row['src_ip'], row['dst_ip'], row['trans_protocol'], row['src_port'], row['dst_port'],
                                                               row['nDpi'], row['libprotoident'], row['tstat'], row['zeek']), axis=1)
    return result_tmp


# In[11]:


def read_merged_df(protocol, allowed_pkts, traces_list, library_columns = None):
    # this function is used to read the merged dataframes

    if isinstance(traces_list, list) == False:
        print('traces_list must be a list')
        return
    if len(traces_list) == 1:
        name = dir_home + 'merged_dataframes/merged_' + str(traces_list[0]) + '/' + str(traces_list[0]) + '_'+ protocol + '_n_Pkts_' + str(allowed_pkts)
        if (os.path.isfile(name) == False):
            return pd.DataFrame()
        data = pd.read_csv(name, usecols = ['src_ip', 'dst_ip', 'trans_protocol', 'src_port',
                                            'dst_port', 'start_timestamp', 'nDpi', 'libprotoident',
                                            'zeek', 'tstat'])
    else:
        data = pd.DataFrame()
        for trace in traces_list:
            name = dir_home + 'merged_dataframes/merged_' + str(trace) + '/' + str(trace) + '_'+ protocol + '_n_Pkts_' + str(allowed_pkts)
            if (os.path.isfile(name) == True):
                data_tmp = pd.read_csv(name, usecols = ['src_ip', 'dst_ip', 'trans_protocol', 'src_port',
                                                    'dst_port', 'start_timestamp', 'nDpi', 'libprotoident',
                                                    'zeek', 'tstat'])
            else:
                print(name, ' not found')
                data_tmp = pd.DataFrame()
            data = pd.concat([data, data_tmp], ignore_index=True)
    if library_columns == None:
        return data
    else:
        return data[[library_columns]]


# In[14]:


def save_merged_dataframes():
    # this function is in charge of calling the function that merge the dataframes, and saving them in files

    for protocol in ['tcp', 'udp']:
        print(trace, protocol, ' started')
        for allowed_pkts in range(1,26):
            pathlib.Path(dir_home + '/merged_dataframes').mkdir(exist_ok = True)
            pathlib.Path(dir_home + '/merged_dataframes/merged_' + str(trace)).mkdir(exist_ok = True)
            data_Flow_Table, flag_Flow_Table, _, _, _ = read_tstat(protocol, 25)
            data_nDpi, flag_nDpi, name_nDpi, num_flows_nDpi = read_nDpi(protocol, allowed_pkts)
            data_libprotoident, flag_libprotoident, name_libprotoident, num_flows_libprotoident = read_libprotoident(protocol, allowed_pkts)
            data_zeek, flag_zeek, name_zeek, num_flows_zeek = read_zeek(protocol, allowed_pkts)
            data_tstat, flag_tstat, not_valid_flows_tcp, not_valid_flows_udp, num_flows_tstat = read_tstat(protocol, allowed_pkts)

            if ((flag_nDpi == False) | (flag_libprotoident == False) | (flag_zeek == False) |
                (flag_tstat == False) ):
                if flag_nDpi == False:
                    print(name_nDpi, ' NOT FOUND')
                if flag_libprotoident == False:
                    print(name_libprotoident, ' NOT FOUND')
                if flag_zeek == False:
                    print(name_zeek, ' NOT FOUND')
                if flag_tstat == False:
                    print(name_tstat, ' NOT FOUND')
            elif ((data_nDpi.empty) | (data_libprotoident.empty) | (data_zeek.empty) |
                (data_tstat.empty)):
                print('empty ', allowed_pkts)
            else:
                data_merged = merge_df(data_Flow_Table, data_nDpi, data_libprotoident, data_zeek, data_tstat)
                data_merged.to_csv(dir_home + '/merged_dataframes/merged_' + str(trace) + '/' + str(trace) + '_'+ protocol + '_n_Pkts_' + str(allowed_pkts))
                num_flows[protocol]['nDpi'][allowed_pkts] += num_flows_nDpi
                num_flows[protocol]['libprotoident'][allowed_pkts] +=  num_flows_libprotoident
                num_flows[protocol]['tstat'][allowed_pkts] +=  num_flows_tstat
                num_flows[protocol]['zeek'][allowed_pkts] += num_flows_zeek
                num_flows[protocol]['not_valid_flows_tcp'][allowed_pkts] += not_valid_flows_tcp
                num_flows[protocol]['not_valid_flows_udp'][allowed_pkts] += not_valid_flows_udp
    print(trace, ' done')


# In[15]:


def update_label_stats(row):
    # to calculate stats based on common label

    if row['detected_protocol_pkt'] == row['detected_protocol_gt']:
        return row['detected_protocol_pkt']
    else:
        return 'error'


def do_stats_gt(traces_list, data_gt_agg):
    # to obtain the stats with respect to a common label

    results = {}
    libraries = ['nDpi', 'libprotoident', 'zeek', 'tstat']
    for idx, library in enumerate(libraries):
        stats_1 = pd.DataFrame(index = range(1,21), columns = ['accuracy', 'precision', 'recall', 'f1_score'])
        num_flows = data_gt_agg[['gt_label']].shape[0]
        unknown_flows = data_gt_agg[data_gt_agg['gt_label'] == 'unknown'].shape[0]

        for allowed_pkts in range(1,21):
            # creation of the confuson matrix
            confusion_matrix = pd.DataFrame()
            confusion_matrix[['detected_protocol_gt']] = data_gt_agg[['gt_label']]
            confusion_matrix[['detected_protocol_pkt']] = pd.concat([read_merged_df('tcp', allowed_pkts, traces_list, library),
                                                                     read_merged_df('udp', allowed_pkts, traces_list, library)],
                                                                    ignore_index=True)

            confusion_matrix['detected_protocol_pkt'] = confusion_matrix.apply(lambda row: update_label_stats(row), axis=1)

            list_notRevealedFlow = confusion_matrix[['detected_protocol_pkt']].groupby('detected_protocol_pkt').size()
            if 'notRevealedFlow' in list_notRevealedFlow.index.to_list():
                notRevealedFlow = list_notRevealedFlow['notRevealedFlow']

            assert(confusion_matrix[['detected_protocol_pkt']].shape[0] == data_gt_agg.shape[0])
            confusion_matrix['col_1'] = 0
            confusion_matrix = confusion_matrix.groupby(['detected_protocol_pkt', 'detected_protocol_gt']).count().reset_index()
            confusion_matrix = confusion_matrix.pivot(index = 'detected_protocol_pkt', columns = 'detected_protocol_gt', values = 'col_1')
            full_index = confusion_matrix.index.union(confusion_matrix.columns)
            confusion_matrix = confusion_matrix.reindex(labels = full_index, axis = 0).reindex(labels = full_index, axis = 1).fillna(0.0)

            if 'unknown' in confusion_matrix.index:
                stats_1.at[allowed_pkts, 'unknown'] = confusion_matrix.loc['unknown'].sum()
                stats_1.at[allowed_pkts, 'unknown'] += confusion_matrix[['unknown']].sum()
                stats_1.at[allowed_pkts, 'unknown'] -= confusion_matrix.at['unknown', 'unknown']
                stats_1.at[allowed_pkts, 'unknown'] = stats_1.at[allowed_pkts, 'unknown'] / num_flows
                confusion_matrix = confusion_matrix.drop(columns = ['unknown'], index = ['unknown'])

            if 'notRevealedFlow' in confusion_matrix.index:
                stats_1.at[allowed_pkts, 'notRevealedFlow'] = confusion_matrix.loc['notRevealedFlow'].sum()
                stats_1.at[allowed_pkts, 'notRevealedFlow'] += confusion_matrix[['notRevealedFlow']].sum()
                stats_1.at[allowed_pkts, 'notRevealedFlow'] -= confusion_matrix.at['notRevealedFlow', 'notRevealedFlow']
                stats_1.at[allowed_pkts, 'notRevealedFlow'] = stats_1.at[allowed_pkts, 'notRevealedFlow'] / num_flows
                confusion_matrix = confusion_matrix.drop(columns = ['notRevealedFlow'], index = ['notRevealedFlow'])

            if 'error' in confusion_matrix.index:
                stats_1.at[allowed_pkts, 'error'] = confusion_matrix.loc['error'].sum()
                stats_1.at[allowed_pkts, 'error'] += confusion_matrix[['error']].sum()
                stats_1.at[allowed_pkts, 'error'] -= confusion_matrix.at['error', 'error']
                stats_1.at[allowed_pkts, 'error'] = stats_1.at[allowed_pkts, 'error'] / num_flows
                confusion_matrix = confusion_matrix.drop(columns = ['error'], index = ['error'])

            names = confusion_matrix.columns.to_list()
            for n in names:
                if (confusion_matrix.loc[:, n].sum() == 0) & (confusion_matrix.loc[n, :].sum() == 0):
                    confusion_matrix = confusion_matrix.drop(columns = [n], index = [n])

            if not confusion_matrix.empty:
                # to calculate the metrics
                cf_matrix_dropped = confusion_matrix
                cf_matrix_num = cf_matrix_dropped.to_numpy()
                cf_matrix_num_upper = np.triu(cf_matrix_num, 1)
                cf_matrix_num_lower = cf_matrix_num - np.triu(cf_matrix_num, -1)
                cf_matrix_diag = np.diagonal(cf_matrix_num)

                # accuracy
                accuracy = np.sum(cf_matrix_diag) / (num_flows)
                stats_1.at[allowed_pkts, 'accuracy'] = accuracy

                # to calculate the precision
                row = 0
                precision = np.array([])
                for i in cf_matrix_diag:
                    if np.sum(cf_matrix_num[row]) != 0:
                        precision = np.append(precision, np.divide(i, np.sum(cf_matrix_num[row])))
                    elif (i == 0) & (np.sum(cf_matrix_num[row]) == 0):
                        precision = np.append(precision, 1)
                    else:
                        precision = np.append(precision, 0)
                    row += 1
                precision_mean = np.mean(precision)
                stats_1.at[allowed_pkts, 'precision'] = precision_mean

                # to calculate the recall
                column = 0
                recall = np.array([])
                for i in cf_matrix_diag:
                    if i != 0:
                        recall = np.append(recall, np.divide(i, np.sum(cf_matrix_num[:, column])))
                    elif (i == 0) & (np.sum(cf_matrix_num[:, column]) == 0):
                        recall = np.append(recall, 1)
                    else:
                        recall = np.append(recall, 0)
                    column += 1
                recall_mean = np.mean(recall)
                stats_1.at[allowed_pkts, 'recall'] = recall_mean

                # to calculate the F1_score
                f1_score = np.array([])
                for i in range(0, len(cf_matrix_diag)):
                        if (precision[i] != 0) | (recall[i] != 0):
                            f1_score = np.append(f1_score, 2*(precision[i]*recall[i])/(precision[i]+recall[i]))
                        else:
                            f1_score = np.append(f1_score, 0)
                f1_score_mean = np.mean(f1_score)
                stats_1.at[allowed_pkts, 'f1_score'] = f1_score_mean

                stats_1.at[allowed_pkts, 'new_metric'] = np.sum(cf_matrix_diag) / (num_flows - unknown_flows)

                #print('\naccuracy ', accuracy)
                #print('precision ', precision)
                #print('recall ', recall)
                #print('f1_score ', f1_score)
            else:
                stats_1.at[allowed_pkts, 'accuracy'] = 0
                stats_1.at[allowed_pkts, 'precision'] = 0
                stats_1.at[allowed_pkts, 'recall'] = 0
                stats_1.at[allowed_pkts, 'f1_score'] = 0

        stats_1.index.name = 'pkts_sent'
        stats_1 = stats_1.fillna(0)
        results[idx] = stats_1
    return results


# In[16]:


def do_final_stats_gt():
    # to obtain the stats only considering the most popular classes

    libraries = ['nDpi', 'libprotoident', 'zeek', 'tstat']
    macrotraces = ['malware_macrotrace', 'media_games_macrotrace', 'user_traffic_macrotrace', 'IoT_macrotrace',]
    results = pd.DataFrame(index = macrotraces)

    for macrotrace in macrotraces:
        data_gt_agg = pd.read_csv(dir_home + 'final_results/' + macrotrace + '/' + macrotrace)
        data_gt_agg.drop(columns = 'Unnamed: 0', inplace = True)

        for idx, library in enumerate(libraries):
            num_flows = data_gt_agg[['gt_label']].shape[0]
            unknown_flows = data_gt_agg[data_gt_agg['gt_label'] == 'unknown'].shape[0]

            # creation of the confuson matrix
            confusion_matrix = pd.DataFrame()
            confusion_matrix[['detected_protocol_gt']] = data_gt_agg[['label']]
            confusion_matrix[['detected_protocol_pkt']] = data_gt_agg[[library + '_label']]

            assert(confusion_matrix[['detected_protocol_pkt']].shape[0] == data_gt_agg.shape[0])
            confusion_matrix['col_1'] = 0
            confusion_matrix = confusion_matrix.groupby(['detected_protocol_pkt', 'detected_protocol_gt']).count().reset_index()
            confusion_matrix = confusion_matrix.pivot(index = 'detected_protocol_pkt', columns = 'detected_protocol_gt', values = 'col_1')
            full_index = confusion_matrix.index.union(confusion_matrix.columns)
            confusion_matrix = confusion_matrix.reindex(labels = full_index, axis = 0).reindex(labels = full_index, axis = 1).fillna(0.0)

            if 'unknown' in confusion_matrix.index:
                results.at[macrotrace, 'unknown_' + library] = confusion_matrix.loc['unknown'].sum()
                results.at[macrotrace, 'unknown_' + library] += confusion_matrix[['unknown']].sum()
                results.at[macrotrace, 'unknown_' + library] -= confusion_matrix.at['unknown', 'unknown']
                results.at[macrotrace, 'unknown_' + library] = results.at[macrotrace, 'unknown_' + library] / num_flows
                confusion_matrix = confusion_matrix.drop(columns = ['unknown'], index = ['unknown'])

            if 'notRevealedFlow' in confusion_matrix.index:
                results.at[macrotrace, 'notRevealedFlow_' + library] = confusion_matrix.loc['notRevealedFlow'].sum()
                results.at[macrotrace, 'notRevealedFlow_' + library] += confusion_matrix[['notRevealedFlow']].sum()
                results.at[macrotrace, 'notRevealedFlow_' + library] -= confusion_matrix.at['notRevealedFlow', 'notRevealedFlow']
                results.at[macrotrace, 'notRevealedFlow_' + library] = results.at[macrotrace, 'notRevealedFlow_' + library] / num_flows
                confusion_matrix = confusion_matrix.drop(columns = ['notRevealedFlow'], index = ['notRevealedFlow'])

            if 'error' in confusion_matrix.index:
                results.at[macrotrace, 'error_' + library] = confusion_matrix.loc['error'].sum()
                results.at[macrotrace, 'error_' + library] += confusion_matrix[['error']].sum()
                results.at[macrotrace, 'error_' + library] -= confusion_matrix.at['error', 'error']
                results.at[macrotrace, 'error_' + library] = results.at[macrotrace, 'error_' + library] / num_flows
                confusion_matrix = confusion_matrix.drop(columns = ['error'], index = ['error'])

            names = confusion_matrix.columns.to_list()
            for n in names:
                if (confusion_matrix.loc[:, n].sum() == 0) & (confusion_matrix.loc[n, :].sum() == 0):
                    confusion_matrix = confusion_matrix.drop(columns = [n], index = [n])

            if not confusion_matrix.empty:
                # to calculate the metrics
                cf_matrix_dropped = confusion_matrix
                cf_matrix_num = cf_matrix_dropped.to_numpy()
                cf_matrix_num_upper = np.triu(cf_matrix_num, 1)
                cf_matrix_num_lower = cf_matrix_num - np.triu(cf_matrix_num, -1)
                cf_matrix_diag = np.diagonal(cf_matrix_num)

                # accuracy
                accuracy = np.sum(cf_matrix_diag) / (num_flows)
                results.at[macrotrace, 'accuracy_' + library] = np.round(accuracy, 2)

                # to calculate the precision
                row = 0
                precision = np.array([])
                for i in cf_matrix_diag:
                    if np.sum(cf_matrix_num[row]) != 0:
                        precision = np.append(precision, np.divide(i, np.sum(cf_matrix_num[row])))
                    elif (i == 0) & (np.sum(cf_matrix_num[row]) == 0):
                        precision = np.append(precision, 1)
                    else:
                        precision = np.append(precision, 0)
                    row += 1
                precision_mean = np.mean(precision)
                results.at[macrotrace, 'precision_' + library] = np.round(precision_mean, 2)

                # to calculate the recall
                column = 0
                recall = np.array([])
                for i in cf_matrix_diag:
                    if i != 0:
                        recall = np.append(recall, np.divide(i, np.sum(cf_matrix_num[:, column])))
                    elif (i == 0) & (np.sum(cf_matrix_num[:, column]) == 0):
                        recall = np.append(recall, 1)
                    else:
                        recall = np.append(recall, 0)
                    column += 1
                recall_mean = np.mean(recall)
                results.at[macrotrace, 'recall_' + library] = np.round(recall_mean, 2)

                # to calculate the F1_score
                f1_score = np.array([])
                for i in range(0, len(cf_matrix_diag)):
                        if (precision[i] != 0) | (recall[i] != 0):
                            f1_score = np.append(f1_score, 2*(precision[i]*recall[i])/(precision[i]+recall[i]))
                        else:
                            f1_score = np.append(f1_score, 0)
                f1_score_mean = np.mean(f1_score)
                results.at[macrotrace, 'f1_score_' + library] = np.round(f1_score_mean, 2)

                results.at[macrotrace, 'new_metric_' + library] = np.sum(cf_matrix_diag) / (num_flows - unknown_flows)

    results = results.reindex(sorted(results.columns), axis = 1)
    results = results.transpose()
    results = results.round(2)
    return results


# In[17]:


def estimate_score_label(data_gt_agg):
    # this function is in charge of calculating the score

    data_gt_agg['nDpi_label'] = 0
    data_gt_agg['libprotoident_label'] = 0
    data_gt_agg['zeek_label'] = 0
    data_gt_agg['tstat_label'] = 0
    data_gt_agg['gt_label'] = 0
    data_gt_agg['gt_score'] = 0
    data_gt_agg = data_gt_agg.apply(lambda row: estimate_label(row), axis=1)
    popular_protocol = data_gt_agg[['gt_label']].groupby(['gt_label']).size().to_frame(name = 'occurences').sort_values('occurences', ascending = False)
    popular_protocol = popular_protocol/data_gt_agg.shape[0] * 100
    popular_protocol = popular_protocol[popular_protocol['occurences'] > 1]
    list_popular_protocols = popular_protocol.index.to_list()
    if 'unknown' not in list_popular_protocols:
        list_popular_protocols.append('unknown')
    data_gt_agg = data_gt_agg.apply(lambda row: update_label(row, list_popular_protocols), axis=1)
    return data_gt_agg


def estimate_label(row):
    # it estimates the common label through a majority voting approach

    nDpi = row['nDpi']
    libprotoident = row['libprotoident']
    zeek = row['zeek']
    tstat = row['tstat']
    gt_label = row['gt_label']
    score = row['gt_score']

    if nDpi == 'notRevealedFlow':
        nDpi = 'unknown'
    if libprotoident == 'notRevealedFlow':
        libprotoident = 'unknown'
    if zeek == 'notRevealedFlow':
        zeek = 'unknown'
    if tstat == 'notRevealedFlow':
        tstat = 'unknown'

    protocols = nDpi, libprotoident, zeek, tstat
    res = Counter(protocols)
    if 'unknown' in res:
        num_unknow = res.pop('unknown')
    label = 'unknown'

    previous_index = 0
    while(len(res) != 0):
        label = max(res, key=res.get)
        index_max = res[label]
        res.pop(label)
        if ((index_max in res.values()) | (index_max == previous_index)):
            # there are the same label
            previous_index = index_max
            label = 'conflict'
        else:
            break
    row['gt_label'] = label

    protocols = row['nDpi'], row['libprotoident'], row['zeek'], row['tstat']
    res = Counter(protocols)
    row['gt_score'] = res[label]/4 # if label is not in res, it returns correctly zero
    return row


def update_label(row, list_popular_protocols):
    # to add 'others' label for not common flows in graphs

    if row['gt_label'] in list_popular_protocols:
        row['label'] = row['gt_label']
    else:
        row['label'] = 'others'

    if row['nDpi'] in list_popular_protocols:
        row['nDpi_label'] = row['nDpi']
    else:
        row['nDpi_label'] = 'others'

    if row['libprotoident'] in list_popular_protocols:
        row['libprotoident_label'] = row['libprotoident']
    else:
        row['libprotoident_label'] = 'others'

    if row['zeek'] in list_popular_protocols:
        row['zeek_label'] = row['zeek']
    else:
        row['zeek_label'] = 'others'

    if row['tstat'] in list_popular_protocols:
        row['tstat_label'] = row['tstat']
    else:
        row['tstat_label'] = 'others'

    if row['gt_label'] == 'notRevealedFlow':
        row['label'] = 'unknown'

    if row['nDpi'] == 'notRevealedFlow':
        row['nDpi_label'] = 'unknown'

    if row['libprotoident'] == 'notRevealedFlow':
        row['libprotoident_label'] = 'unknown'

    if row['zeek'] == 'notRevealedFlow':
        row['zeek_label'] = 'unknown'

    if row['tstat'] == 'notRevealedFlow':
        row['tstat_label'] = 'unknown'
    return row


# In[18]:


def plot_average_accuracy():
    # to plot the average accuracy

    pathlib.Path(dir_home + 'final_results/' + 'accuracy').mkdir(exist_ok = True)
    result = pd.DataFrame()

    for library in ['_result_nDpi', '_result_libprotoident', '_result_zeek', '_result_tstat']:
        results = {}
        for traces_list_name in['malware_macrotrace', 'media_games_macrotrace', 'user_traffic_macrotrace', 'IoT_macrotrace',]:

            results[traces_list_name] = (pd.read_csv(dir_home + 'final_results/'+ traces_list_name + '/' + traces_list_name + library))
        df = pd.DataFrame([results['malware_macrotrace']['accuracy'],results['media_games_macrotrace']['accuracy'],results['user_traffic_macrotrace']['accuracy'],results['IoT_macrotrace']['accuracy']]).transpose()
        df.columns = ['a', 'b', 'c', 'd']
        df = df.round(2)
        df[library] = df.mean(axis = 1)
        result = pd.concat([result, df[[library]]], axis = 1)
    result.columns = ['nDpi', 'libprotoident', 'zeek', 'tstat']
    result['zeek'] = result['zeek'].round(1)

    x = range(1,11)
    cc = (cycler('color', ['r', 'b', 'g', 'orange', 'y']) +
                   cycler('linestyle', ['-',  '-', '-', '-', '-',]) +
                   cycler('marker', ['o', 's', 'v', 'd', '*']))

    y_1 = result[['nDpi']][0:10]
    y_2 = result[['libprotoident']][0:10]
    y_3 = result[['zeek']][0:10]
    y_4 = result[['tstat']][0:10]

    fastplot.plot([('nDpi', (x, y_1) ),
                   ('Libprotoident', (x, y_2)),
                   ('Zeek', (x, y_3)),
                   ('Tstat', (x, y_4)),],
                    # style = 'latex',
                    path = dir_home + '/final_results/' + '/accuracy' + '/average_accuracy.pdf',
                    mode = 'line_multi',
                    xlabel = 'Packets per flow',
                    ylabel = 'Average Accuracy',
                    xticks = (x, None),
                    ylim = (0.5,1),
                    xlim = (1,10),
                    cycler = cc,
                    legend = True,
                    legend_loc = 'lower right',
                    legend_fontsize = 'small',
                    figsize = (10,5),
                    plot_args = {"clip_on" : False},
                    grid = True,
                    fontsize = 28,
                    legend_ncol = 2,
                    )
    plt.close()


# In[19]:


def plot_complete_stacked_bar():
    # to plot the complete stacked bar

    pathlib.Path(dir_home + 'final_results/' + 'stacked_bars').mkdir(exist_ok = True)

    data_gt_agg_complete = {}
    labels = []
    for traces_list_name in['malware_macrotrace', 'media_games_macrotrace', 'user_traffic_macrotrace', 'IoT_macrotrace',]:

        data_gt_agg_complete[traces_list_name] = pd.read_csv(dir_home + 'final_results/' + traces_list_name + '/' + traces_list_name)
        data_gt_agg_complete[traces_list_name].drop(columns = 'Unnamed: 0', inplace = True)
        for library in ['nDpi_label', 'libprotoident_label', 'zeek_label', 'tstat_label', 'label']:
            labels += data_gt_agg_complete[traces_list_name][library].values.tolist()
    unique_labels = np.unique(labels)
    array_col = np.array(sns.color_palette("tab20c", len(unique_labels)))
    np.random.seed(seed=2494)
    np.random.shuffle(array_col)
    dict_color = dict(zip(unique_labels, array_col.tolist()))
    dict_color['unknown'] = [0.8,0.8,0.8]

    for traces_list_name in['malware_macrotrace', 'media_games_macrotrace', 'user_traffic_macrotrace', 'IoT_macrotrace',]:
        data_gt_agg_complete[traces_list_name].loc[data_gt_agg_complete[traces_list_name]['label']=='conflict'] = 'unknown'
        out_res = data_gt_agg_complete[traces_list_name][['nDpi_label', 'libprotoident_label', 'zeek_label', 'tstat_label']]
        color = pd.DataFrame()
        color = pd.concat([color, out_res.groupby('nDpi_label').size().to_frame('nDpi_label')], axis=1, sort=True)
        color = pd.concat([color, out_res.groupby('libprotoident_label').size().to_frame('libprotoident_label')], axis=1, sort=True)
        color = pd.concat([color, out_res.groupby('zeek_label').size().to_frame('zeek_label')], axis=1, sort=True)
        color = pd.concat([color, out_res.groupby('tstat_label').size().to_frame('tstat_label')], axis=1, sort=True)
        color = pd.concat([color, data_gt_agg_complete[traces_list_name].groupby('label').size().to_frame('Reference Label')], axis=1, sort=True)
        color = color.fillna(0)
        color.sort_values(by = ['Reference Label'], inplace = True, ascending = False)
        color = color[['nDpi_label', 'libprotoident_label', 'zeek_label', 'tstat_label', 'Reference Label']].transpose()
        color['sum'] = color.apply(np.sum, axis=1)
        color = color.apply(lambda row: np.divide(row, row['sum'])*100, axis=1)
        color = color.drop(columns = ['sum'])
        color.rename(index = {'nDpi_label' : 'nDPI', 'libprotoident_label' : 'Libprotoident', 'zeek_label' : 'Zeek', 'tstat_label' : 'Tstat'}, inplace = True)
        color[['Unknown']] = color[['unknown']]
        color.drop(columns = ['unknown'], inplace = True)
        color.rename(columns = {'Unknown':'unknown'}, inplace = True)

        cc = [dict_color.get(key) for key in color.columns.tolist()]
        cc = (cycler('color', cc))

        if traces_list_name == 'malware_macrotrace':
            legend_args_1 = 0.75
            legend_args_2 = -0.06
            legend_ncol=2
        if traces_list_name == 'media_games_macrotrace':
            legend_args_1 = 1.05
            legend_args_2 = -0.06
            legend_ncol=4
        if traces_list_name == 'user_traffic_macrotrace':#
            legend_args_1 = 0.88
            legend_args_2 = -0.06
            legend_ncol=3
        if traces_list_name == 'IoT_macrotrace':#
            legend_args_1 = 1.09
            legend_args_2 = -0.06
            legend_ncol=4

        fastplot.plot(color,
                      path = dir_home + '/final_results/' + 'stacked_bars' + '/stacked_bar_' + traces_list_name + '.pdf',
                      mode = 'bars_stacked',
                      cycler = cc,
                      # style = 'latex',
                      ylabel = 'Percentage',
                      legend = True,
                      legend_ncol=legend_ncol,
                      figsize=(10,6),
                      grid_axis="y",
                      grid=True,
                      #legend_loc = 'lower left',
                      legend_fontsize = 'small',
                      legend_args={'bbox_to_anchor':(legend_args_1,legend_args_2)},
                      fontsize=24,
                      #legend_border=True,
                     )
        plt.close()


# In[20]:


def plot_score_common_labels():
    # to plot the score of the common label

    pathlib.Path(dir_home + 'final_results/' + 'common_labels').mkdir(exist_ok = True)

    data_gt_agg_complete = pd.DataFrame()
    labels = []

    for traces_list_name in['malware_macrotrace', 'media_games_macrotrace', 'user_traffic_macrotrace', 'IoT_macrotrace',]:
        data = pd.read_csv(dir_home + 'final_results/' + traces_list_name + '/' + traces_list_name)
        data.drop(columns = 'Unnamed: 0', inplace = True)
        data_gt_agg_complete = pd.concat([data_gt_agg_complete, data])

    result = data_gt_agg_complete[(data_gt_agg_complete['label'] != 'unknown') & (data_gt_agg_complete['label'] != 'conflict')].groupby(['label']).mean()['gt_score'].to_frame()
    result = result.sort_values(by = 'gt_score', ascending = False)[1:15]
    ordered_list = result.index.to_list()
    if 'others' in ordered_list:
        ordered_list.remove('others')
        ordered_list.append('others') # to put others at the end of the graph
    result = result.reindex(ordered_list)
    result = np.round(result*100,2)
    result = list(zip(result.index.tolist(),result.squeeze().tolist()))

    fastplot.plot(result,
                path = dir_home + '/final_results/' + '/common_labels' + '/score_common_labels' + '.pdf',
                mode = 'bars',
                # style = 'latex',
                ylabel = 'Score (\%)',
                xlabel = 'Protocol',
                grid_axis="y",
                yticks = ([25, 50, 75, 100], None),
                xticks_rotate = 45,
                grid=True,
                ylim = (0,100),
                figsize=(11,6),
                fontsize=28,
                )
    plt.close()


# ## Main

# In[242]:


## MAIN
file_list = os.listdir('./traces/IoT_macrotrace/')
malware_macrotrace = file_list

file_list = os.listdir('./traces/media_games_macrotrace/')
media_games_macrotrace = file_list

file_list = os.listdir('./traces/user_traffic_macrotrace/')
user_traffic_macrotrace = file_list

file_list = os.listdir('./traces/IoT_macrotrace/')
IoT_macrotrace = file_list
macrotrace_list_name = ['malware_macrotrace', 'media_games_macrotrace', 'user_traffic_macrotrace', 'IoT_macrotrace']

for m in macrotrace_list_name:
    if (m == 'malware_macrotrace'):
        traces_list = malware_macrotrace
    elif (m == 'media_games_macrotrace'):
        traces_list = media_games_macrotrace
    elif (m == 'user_traffic_macrotrace'):
        traces_list = media_games_macrotrace
    elif (m == 'IoT_macrotrace'):
        traces_list = media_games_macrotrace

    traces_list_name = m

    # structure to count the number of flows
    num_flows = {}
    for protocol in ['tcp', 'udp']:
        num_flows[protocol] = {}
        for library in ['nDpi', 'libprotoident', 'tstat', 'zeek', 'not_valid_flows_tcp', 'not_valid_flows_udp']:
            num_flows[protocol][library] = {}
            for allowed_pkts in range(1,26):
                num_flows[protocol][library][allowed_pkts] = 0

    # with this function we save the merged dataframes in txt files
    print('Starting to merge dataframes ...')
    for trace in traces_list:
        save_merged_dataframes()
    num_flows_df = pd.DataFrame(num_flows)
    num_flows_df.to_csv(dir_home + 'stats/' + traces_list_name + '_num_flows_filtered')
    print('')

    # reading the merged dataframes
    print('Estimating the score ...')
    data_gt_agg = pd.concat([read_merged_df('tcp', 25, traces_list),read_merged_df('udp', 25, traces_list)], ignore_index=True)
    data_gt_agg = estimate_score_label(data_gt_agg)
    print('')

    # calculating the accuracy, precision, recall at the increasing number of packets per flow
    print('Doing the stats ...')
    results = do_stats_gt(traces_list, data_gt_agg)

    # saving the partial results
    pathlib.Path(dir_home + 'final_results').mkdir(exist_ok = True)
    pathlib.Path(dir_home + 'final_results/' + traces_list_name).mkdir(exist_ok = True)
    data_gt_agg.to_csv(dir_home + 'final_results/' + traces_list_name + '/' + traces_list_name)

    result_nDpi = pd.DataFrame.from_dict(results[0])
    result_libprotoident = pd.DataFrame.from_dict(results[1])
    result_zeek = pd.DataFrame.from_dict(results[2])
    result_tstat = pd.DataFrame.from_dict(results[3])

    result_nDpi.to_csv(dir_home + 'final_results/'+ traces_list_name + '/' + traces_list_name + '_result_nDpi')
    result_libprotoident.to_csv(dir_home + 'final_results/' + traces_list_name + '/' + traces_list_name + '_result_libprotoident')
    result_zeek.to_csv(dir_home + 'final_results/' + traces_list_name + '/' + traces_list_name + '_result_zeek')
    result_tstat.to_csv(dir_home + 'final_results/' + traces_list_name + '/' + traces_list_name + '_result_tstat')


# plotting graphs
print('Plotting the graphs ...')
plot_score_common_labels()
plot_complete_stacked_bar()
plot_average_accuracy()

# to calculate the accuracy, precision, recall
results_final = do_final_stats_gt()
results_final.to_csv(dir_home + 'stats/table_results_confusion_matrix.csv')
print('Done!')
