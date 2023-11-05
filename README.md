# poolLeaderLogs
<br/>
SPO Leader Logs Checker for Next, Current and Previous Epochs.
<br/><br/>
All Needed Data is get from Koios APIs.
<br/><br/>
Note: This is a reworking of old python script leaderLogs.py 
available on https://github.com/papacarp/pooltool.io.git
<br/><br/>
## Prerequisites:
- Python 3.8
- pip (Python package installer)
- libsodium library
<br/><br/>

## Setup:
<br/>
- clone this repository using git: ``` git clone https://github.com/asnakep/poolLeaderLogs.git ```
<br/><br/>
- execute inside the newly cloned directory: ```pip install -r pip_requirements.txt   ```  to install all needed python package requirements
<br/><br/>
- make sure you can access your vrf.skey file (you can copy in it a path of your choice) and remember to keep it as read only ``` chmod 400 vrf.skey ```
<br/><br/>
- Set Variables on lines 41-47 of poolLeaderLogs_koios.py:
<br/><br/>
### Set your own timezone ###
<br/><br/>
local_tz = pytz.timezone('')
<br/><br/>
### Set These Variables ###
<br/><br/>
PoolId     = ""
<br/>
PoolIdBech = ""
<br/>
PoolTicker = ""
<br/>
VrfKeyFile = ('')
<br/><br/>
## Usage:
<br/><br/>
``` python3 poolLeaderLogs.py ```
<br/><br/>
## Output:
<br/><br/>
- a *console output* with all the slots assigned for next, current and previous Epochs
<br/><br/>
