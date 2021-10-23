#!/bin/env python3

import requests
import urllib.request
import math
import binascii
import json
import pytz
import hashlib
import re
from ctypes import *
from os import path
from datetime import datetime, timezone
from sys import exit, platform

class col:
    green = '\033[92m'
    endcl = '\033[0m'
    bold = '\033[1m'

### Set your own timezone, default is Europe/Berlin ---------------###
local_tz = pytz.timezone('Europe/Berlin')

### Set These Variables ###
BlockFrostId = ""
PoolId = ""
PoolTicker = ""
VrfKeyFile = ('/path_to_file/vrf.skey')
### -------------------------------------------------------------- ###

### ADA Unicode symbol and Lovelaces removal ###
ada = " \u20B3"
lovelaces = 1000000

### Get data from blockfrost.io APIs ###
headers = {'content-type': 'application/json', 'project_id': BlockFrostId}

epochParam = requests.get("https://cardano-mainnet.blockfrost.io/api/v0/epochs/latest/parameters", headers=headers)
json_data = epochParam.json()
epoch = epochParam.json().get("epoch") 
eta0 = epochParam.json().get("nonce")

poolSigma = requests.get("https://cardano-mainnet.blockfrost.io/api/v0/pools/"+PoolId, headers=headers)
json_data = poolSigma.json()
sigma = poolSigma.json().get("active_size")

netStakeParam = requests.get("https://cardano-mainnet.blockfrost.io/api/v0/epochs/latest", headers=headers)
json_data = netStakeParam.json()
nStake = int(netStakeParam.json().get("active_stake")) / lovelaces
nStake = "{:,}".format(nStake)

poolStakeParam = requests.get("https://cardano-mainnet.blockfrost.io/api/v0/pools/"+PoolId, headers=headers)
json_data = poolStakeParam.json()
pStake = int(poolStakeParam.json().get("active_stake")) / lovelaces
pStake = "{:,}".format(pStake)

print()
print(col.bold + f'Checking SlotLeader Schedules for Stakepool: ' + (col.green + PoolTicker + col.endcl))
print()
print(col.bold + f'Pool Id: ' + (col.green + PoolId + col.endcl))
print()
print(col.bold + f'Current Epoch: ' + col.green + str(epoch) + col.endcl)
print()
print(col.bold + f'Nonce: ' + col.green + str(eta0) + col.endcl)
print()
print(col.bold + f'Network Active Stake: ' + col.green + str(nStake) + col.endcl + col.bold + ada + col.endcl)
print()
print(col.bold + f'Pool Active Stake: ' + col.green + str(pStake) + col.endcl + col.bold + ada + col.endcl)
print()


### Slots Leader Computation ###

### Opening vrf.skey file ###
with open(VrfKeyFile) as f:
        skey = json.load(f)
        poolVrfSkey = skey['cborHex'][4:]

### Determine libsodium path based on platform ###
libsodium = None
if platform == "linux" or platform == "linux2":
    # Bindings are not avaliable so using ctypes to just force it in for now.
    libsodium = cdll.LoadLibrary("/usr/local/lib/libsodium.so")
elif platform == "darwin":
    # Try both Daedalus' bundled libsodium and a system-wide libsodium path.
    daedalusLibsodiumPath = path.join("/Applications", "Daedalus Mainnet.app", "Contents", "MacOS", "libsodium.23.dylib")
    systemLibsodiumPath = path.join("/usr", "local", "lib", "libsodium.23.dylib")

    if path.exists(daedalusLibsodiumPath):
        libsodium = cdll.LoadLibrary(daedalusLibsodiumPath)
    elif path.exists(systemLibsodiumPath):
        libsodium = cdll.LoadLibrary(systemLibsodiumPath)
    else:
        exit(f'Unable to find libsodium, checked the following paths: {", ".join([daedalusLibsodiumPath, systemLibsodiumPath])}')
libsodium.sodium_init()
################################################## ###

### Get Blockchain Genesis Parameters from blockfrost.io ###
GenesisParam = requests.get("https://cardano-mainnet.blockfrost.io/api/v0/genesis", headers=headers)
json_data = GenesisParam.json()

epochLength = GenesisParam.json().get("epoch_length")
activeSlotCoeff = GenesisParam.json().get("active_slots_coefficient")
slotLength = GenesisParam.json().get("slot_length")

### Epoch211FirstSlot ###
firstShelleySlot = requests.get("https://cardano-mainnet.blockfrost.io/api/v0/blocks/4555184", headers=headers)
json_data = firstShelleySlot.json()
firstSlot = firstShelleySlot.json().get("slot")

### calculate first slot of target epoch ###
firstSlotOfEpoch = (firstSlot) + (epoch - 211)*epochLength

from decimal import *
getcontext().prec = 9
getcontext().rounding = ROUND_HALF_UP

def mkSeed(slot,eta0):

    h = hashlib.blake2b(digest_size=32)
    h.update(bytearray([0,0,0,0,0,0,0,1])) #neutral nonce
    seedLbytes=h.digest()

    h = hashlib.blake2b(digest_size=32)
    h.update(slot.to_bytes(8,byteorder='big') + binascii.unhexlify(eta0))
    slotToSeedBytes = h.digest()

    seed = [x ^ slotToSeedBytes[i] for i,x in enumerate(seedLbytes)]

    return bytes(seed)

def vrfEvalCertified(seed, tpraosCanBeLeaderSignKeyVRF):
    if isinstance(seed, bytes) and isinstance(tpraosCanBeLeaderSignKeyVRF, bytes):
        proof = create_string_buffer(libsodium.crypto_vrf_ietfdraft03_proofbytes())

        libsodium.crypto_vrf_prove(proof, tpraosCanBeLeaderSignKeyVRF,seed, len(seed))

        proofHash = create_string_buffer(libsodium.crypto_vrf_outputbytes())

        libsodium.crypto_vrf_proof_to_hash(proofHash,proof)

        return proofHash.raw

    else:
        print("error.  Feed me bytes")
        exit()

# Determine if our pool is a slot leader for this given slot
# @param slot The slot to check
# @param activeSlotCoeff The activeSlotsCoeff value from protocol params
# @param sigma The controlled stake proportion for the pool
# @param eta0 The epoch nonce value
# @param poolVrfSkey The vrf signing key for the pool

def isSlotLeader(slot,activeSlotCoeff,sigma,eta0,poolVrfSkey):
    seed = mkSeed(slot, eta0)
    tpraosCanBeLeaderSignKeyVRFb = binascii.unhexlify(poolVrfSkey)
    cert=vrfEvalCertified(seed,tpraosCanBeLeaderSignKeyVRFb)
    certNat  = int.from_bytes(cert, byteorder="big", signed=False)
    certNatMax = math.pow(2,512)
    denominator = certNatMax - certNat
    q = certNatMax / denominator
    c = math.log(1.0 - activeSlotCoeff)
    sigmaOfF = math.exp(-sigma * c)
    return q <= sigmaOfF


slotcount=0

for slot in range(firstSlotOfEpoch,epochLength+firstSlotOfEpoch):

    slotLeader = isSlotLeader(slot, activeSlotCoeff, sigma, eta0, poolVrfSkey)

    if slotLeader:
        timestamp = datetime.fromtimestamp(slot + 1591566291, tz=local_tz)

        slotcount+=1
        print(col.bold + "Leader At Slot: "  + str(slot-firstSlotOfEpoch) + " - Local Time " + str(timestamp.strftime('%Y-%m-%d %H:%M:%S') + " - Scheduled Epoch Blocks: " + str(slotcount)))

if slotcount == 0:
    print(col.bold + "No SlotLeader Schedules Found for Current Epoch " +str(epoch))
    quit()

