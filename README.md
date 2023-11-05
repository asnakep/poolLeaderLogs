# poolLeaderLogs
<br/>
Leader Logs Checker for Cardano SPOs
<br/>
Leader Logs Checker for Next, Current and Previous Epochs. \
<br/>
All Needed Data is get from Koios APIs.
<br/>
Note: This is a reworking of old python script leaderLogs.py 
available on https://github.com/papacarp/pooltool.io.git
<br/>
## Prerequisites:
- Python 3.8
- pip (Python package installer)
- libsodium library
<br/>

## Setup:
- clone this repository using git: ``` git clone https://github.com/asnakep/poolLeaderLogs.git ```
- execute inside the newly cloned directory: ```pip install -r pip_requirements.txt   ```  to install all needed python package requirements
- make sure you can access your vrf.skey file (you can copy in it a path of your choice) and remember to keep it as read only ``` chmod 400 vrf.skey ```

- Set Variables on lines 37-40 of poolLeaderLogs_koios.py:

### Set your own timezone -----------------------------------------###
local_tz = pytz.timezone('')

### Set These Variables ###
PoolId = ""
PoolIdBech = ""
PoolTicker = ""
VrfKeyFile = ('')
### -------------------------------------------------------------- ###


## Usage:
``` python3 poolLeaderLogs_koios.py ```

## Output: 
- a *console output* with all the slots assigned for next, current and previous Epochs
