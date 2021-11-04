# ScheduledBlocks
Scheduled Block Checker for Cardano Stakepool Operators

Lightweight and Portable Scheduled Blocks Checker for Current Epoch.
No cardano-node Required, data is taken from blockfrost.io

Note: This is a reworking of old python script leaderLogs.py 
available on https://github.com/papacarp/pooltool.io.git
            

## Prerequisites:
- Python 3.8
- pip (Python package installer)
- libsodium library

## Setup:
- clone this repository using git: ``` git clone https://github.com/adasnakepool/ScheduledBlocks.git ```
- execute inside the newly cloned directory: ```pip install -r requirements.txt   ```  to install all needed python package requirements
- get a project id on blockfrost.io
- make sure you can access your vrf.skey file (you can copy in it a path of your choice) and remember to keep it as read only ``` chmod 400 vrf.skey ```
- copy the config.yaml.default into a new file and call it **config.yaml** (do not remove the default if you want to update the script via git pull in future)
- open the newly created config.yaml and configure the settings accordingly:
  - **timezone**: your timezone (default: "Europe/Berlin")
  - **blockfrost_id**: project id from blockfrost
  - **pool_id**: your pool id. You can get it from adapools (it's the last part of the url)
  - **pool_ticker**: your pool ticker
  - **vrf_key**: "the path (relative or absolute) to the vrf.skey file

## Usage:
``` python3 ScheduledBlocks.py ```

## Output: 
- a *console output* with all the slots assigned for the latest available epoch
- a SQLite database called: *slotschedule.db* which contains the slots assigned for every epoch the tool has been run.
