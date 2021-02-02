# DPI-comparison

The goal of this tool is automatically perform a comparison among the following DPI tools: nDPI, Libprotoident, Tstat and Zeek.


## Required Libraries

- libprotoident (availabale at https://github.com/wanduow/libprotoident)
- nDPI (availabale at https://github.com/ntop/nDPI)
- Tstat (availabale at http://tstat.tlc.polito.it)
- Zeek (availabale at https://zeek.org)

##  How to use?
The code has been tested on Ubuntu 18.04.5 LTS. This project has been developed with Bash and Python 3.8.
Lunch all the scripts inside the folder.

1. Lunch `'create_environment.sh'`. This script is in charge of creating all the required directories and the pre-processing files.
2. Put the original traces you want to test in `'./traces/malware_macrotrace'`, `'./traces/media_games_macrotrace'`, `'./traces/IoT_macrotrace'`and `'./traces/user_traffic_macrotrace'`. You can download the original traces at this link https://smartdata.polito.it/dpi-in-practice/.
3. Lunch `'lunch_scripts.sh'`. This script is in charge of pre-processing the traces (creating for each trace, 25 filtered traces with an increasing number of packets per flow) and then it calls the four libraries.
4. Lunch the Python script`'script_evaluation.sh'`. This script is in charge of doing all the statistics and printing the graphs.


 
## Folders

- `final_results`: in this folder you can find the graphs related to the accuracy, the percentage of recognized protocols and the score of the reference label;
- `log_general_script`: here you can find the logs of `'lunch_scripts.sh'`;
- `log_libraries`: here you can find the logs of `'call_libraries.sh'`(the function that is in charge of calling the different libraries);
- `log_preprocessing`:  here you can find the logs of `'preprocessing_script.sh'`;
- `merged_dataframes`:  here you can find the merged Dataframes (it is an intermediate step);
- `output_libraries`:  here you can find the outputs of all the libraries for each trace;
- `preprocessing_files`: here you can find the pre-processing files needed by Tstat;
- `stats`:  here you can find general statistics about the macrotraces;
- `traces`:  here you can find the original traces and the filtered ones.
