# ScheduledBlocks
Scheduled Block Checker for Cardano Stakepool Operators

Lightweight and Portable Scheduled Blocks Checker for Current Epoch.
No cardano-node Required, data is taken from blockfrost.io

Note: This is a reworking of old python script leaderLogs.py 
available on https://github.com/papacarp/pooltool.io.git
            
Instructions:

- copy your vrf.skey file into a path of your choice, keep it as read only (chmod 400 vrf.skey)

- get a project id on blockfrost.io

- edit python script ScheduledBlocks.py

set your time zone in line 22
set variables in lines 25-28

BlockFrostId = ""
PoolId = ""
PoolTicker = ""
VrfKeyFile = ('/path_to_file/vrf.skey')


Usage:

python3 ScheduledBlocks.py
