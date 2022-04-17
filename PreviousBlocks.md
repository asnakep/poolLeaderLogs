Depending on how long is your pool history you may need to add query parameter "?page=n" at the end of pool history url

Example: I'm searching for previous schedules which are not in first returned page, so I need to add query parameter ?page=2

script line 152:  
poolHistStake = requests.get("https://cardano-mainnet.blockfrost.io/api/v0/pools/"+PoolId+"/history?page=2", headers=headers)
