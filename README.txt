A Python script for Abnormal Flows Detection.

This script needs two inputs: (i) Either the PCAP FILE of NETWORK INTERFACE 
and (ii) The ML Model being used (provided PKL file)


>> CASE 1: OFFLINE MODE

Run the following command for ensuring that we can process the content 
of a PCAP File using this script

COMMAND:
python Python-Script.py ./dos.pcap ./AI4HS-ML-Model.pkl

The following ones should appear in your screen (command line output). 
The File "ML-output.txt" will be also generated. 

OUTPUT:

Loading ML Model from File: './AI4HS-ML-Model.pkl' ...
Loading ML Model successfully completed !

OFFLINE MODE: Process the content of PCAP File: './dos.pcap'

There are 80 flow(s) in the given PCAP File.

Abnormal Flows Detected: [53]


>> CASE 2: ONLINE MODE (you need to knwo a)

Run the following command for real time network traffic monitor 
You need to know a valid NETWORK INTERFACE (please replace eth0 with your network interface)

python Python-Script.py eth0 ./AI4HS-ML-Model.pkl

OUTPUT:

The output should be something like the following one.

NFlow(id=0, expiration_id=0, src_ip=10.60.100.25, src_mac=d4:76:a0:e6:9d:5b, src_oui=d4:76:a0, src_port=1028, dst_ip=192.168.15.2, dst_mac=b6:93:92:e3:b6:09, dst_oui=b6:93:92, dst_port=22, protocol=6, ip_version=4, vlan_id=0, tunnel_id=0, bidirectional_first_seen_ms=1655285339615, bidirectional_last_seen_ms=1655285339615, bidirectional_duration_ms=0, bidirectional_packets=4, bidirectional_bytes=490, src2dst_first_seen_ms=1655285339615, src2dst_last_seen_ms=1655285339615, src2dst_duration_ms=0, src2dst_packets=2, src2dst_bytes=174, dst2src_first_seen_ms=1655285339615, dst2src_last_seen_ms=1655285339615, dst2src_duration_ms=0, dst2src_packets=2, dst2src_bytes=316, bidirectional_min_ps=56, bidirectional_mean_ps=122.5, bidirectional_stddev_ps=58.20366540576862, bidirectional_max_ps=198, src2dst_min_ps=56, src2dst_mean_ps=87.0, src2dst_stddev_ps=43.840620433565945, src2dst_max_ps=118, dst2src_min_ps=118, dst2src_mean_ps=158.0, dst2src_stddev_ps=56.568542494923804, dst2src_max_ps=198, bidirectional_min_piat_ms=0, bidirectional_mean_piat_ms=0.0, bidirectional_stddev_piat_ms=0.0, bidirectional_max_piat_ms=0, src2dst_min_piat_ms=0, src2dst_mean_piat_ms=0.0, src2dst_stddev_piat_ms=0.0, src2dst_max_piat_ms=0, dst2src_min_piat_ms=0, dst2src_mean_piat_ms=0.0, dst2src_stddev_piat_ms=0.0, dst2src_max_piat_ms=0, bidirectional_syn_packets=0, bidirectional_cwr_packets=0, bidirectional_ece_packets=0, bidirectional_urg_packets=0, bidirectional_ack_packets=4, bidirectional_psh_packets=3, bidirectional_rst_packets=0, bidirectional_fin_packets=0, src2dst_syn_packets=0, src2dst_cwr_packets=0, src2dst_ece_packets=0, src2dst_urg_packets=0, src2dst_ack_packets=2, src2dst_psh_packets=1, src2dst_rst_packets=0, src2dst_fin_packets=0, dst2src_syn_packets=0, dst2src_cwr_packets=0, dst2src_ece_packets=0, dst2src_urg_packets=0, dst2src_ack_packets=2, dst2src_psh_packets=2, dst2src_rst_packets=0, dst2src_fin_packets=0, application_name=SSH, application_category_name=RemoteAccess, application_is_guessed=1, application_confidence=1, requested_server_name=, client_fingerprint=, server_fingerprint=, user_agent=, content_type=)

IN THE CURRENT VERSION, IN THE ONLINE MODE, WE ONLY PRINT THE FLOW DATA (i.e., ML MODEL IS NOT CURRENTLY BEING USED)




