#!/bin/env python3

import requests
import urllib.request
import math
import binascii
import json
import pytz
import hashlib
import re
import readchar
import subprocess as sp
from ctypes import *
from os import system, path
from datetime import datetime, timezone
from sys import exit, platform

class col:
    red = '\033[31m'
    green = '\033[92m'
    endcl = '\033[0m'

def ClearScreen():
    command ='clear'
    system(command)

### Set your own timezone -----------------------------------------###
### Eg: local_tz = pytz.timezone('Europe/Berlin')                  ###

local_tz = pytz.timezone('')

### Set These Variables ###
BlockFrostId = ""
PoolId       = "Pool Hash, not bech32"
PoolTicker   = ""
VrfKeyFile   = ('<your-path-to>/vrf.skey')
### -------------------------------------------------------------- ###


### ADA Unicode symbol and Lovelaces removal ###
ada       = " \u20B3"
lovelaces = 1000000

### Get Current Epoch from BlockFrost ###
headers    = {'content-type': 'application/json', 'project_id': BlockFrostId}
epochParam = requests.get("https://cardano-mainnet.blockfrost.io/api/v0/epochs/latest/parameters", headers=headers)
json_data  = epochParam.json()
epoch      = epochParam.json().get("epoch")


### User Prompt ###
ClearScreen()
print()
print(col.green + f'Welcome to YaLL (Yet Another Leader Logs) for Cardano SPOs. ')
print()
print(col.green + f'Check Leader Logs in Next, Current and Previous Cardano Epochs.')
print(col.endcl)
print(col.green + f'Current Epoch: ' + col.endcl +str(epoch))
print(col.endcl)

### newEpochNonce Availability ###
latestBlocks = requests.get("https://cardano-mainnet.blockfrost.io/api/v0/blocks/latest", headers=headers)
json_data    = latestBlocks.json()
epochSlot    = latestBlocks.json().get("epoch_slot")

if epochSlot >= 302400:
   epochNonce = print(col.green + f'New epochNonce Available' + col.endcl)
   print()
if epochSlot <  302400:
   epochNonce = print(col.red + f'New epochNonce Not Available' + col.endcl)
   print()

print(f'(n) to Check Next Epoch Leader Logs')
print(col.endcl)
print(f'(c) to Check Current Epoch Leader Logs')
print(col.endcl)
print(f'(p) to Check Previous Epochs Leader Logs')
print(col.endcl)
print(f'(any other key) to Exit')


### Read Keyboard keys ###
key = readchar.readkey()

if(key == 'n'):

### Extract newEpochNonce from cardano-node ###
### Get Current Epoch and Current epoch_slot from BlockFrost ###

  ClearScreen()

  headers      = {'content-type': 'application/json', 'project_id': BlockFrostId}

  epochParam   = requests.get("https://cardano-mainnet.blockfrost.io/api/v0/epochs/latest", headers=headers)
  json_data    = epochParam.json()
  epoch        = epochParam.json().get("epoch")
  epoch        = int(epoch + 1)

  latestBlocks = requests.get("https://cardano-mainnet.blockfrost.io/api/v0/blocks/latest", headers=headers)
  json_data    = latestBlocks.json()
  epochSlot    = latestBlocks.json().get("epoch_slot")


  ### Check Next Epoch Leader Logs ###

  if epochSlot >= 302400:

    ### Take "candidateNonce" from protocol-state ###
    candidateNonce      = sp.getoutput('cardano-cli query protocol-state --mainnet | jq -r .candidateNonce.contents')

    ### Take "lastEpochBlockNonce" from protocol-state ###
    lastEpochBlockNonce = sp.getoutput("cardano-cli query protocol-state --mainnet | jq -r .lastEpochBlockNonce.contents")

    ### Extract newEpochNonce ###
    print()
    eta0 = hashlib.blake2b(bytes.fromhex(candidateNonce + lastEpochBlockNonce),digest_size=32).hexdigest()
    print(f'New epochNonce: ' + col.green + str(eta0) + col.endcl)

    ### Network and Pool Data from BlockFrost ###
    netStakeParam  = requests.get("https://cardano-mainnet.blockfrost.io/api/v0/epochs/latest", headers=headers)
    json_data      = netStakeParam.json()
    nStake         = int(netStakeParam.json().get("active_stake")) / lovelaces
    nStake         = "{:,}".format(nStake)

    poolStakeParam = requests.get("https://cardano-mainnet.blockfrost.io/api/v0/pools/"+PoolId, headers=headers)
    json_data      = poolStakeParam.json()
    pStake         = int(poolStakeParam.json().get("active_stake")) / lovelaces
    pStake         = "{:,}".format(pStake)

    poolSigma      = requests.get("https://cardano-mainnet.blockfrost.io/api/v0/pools/"+PoolId, headers=headers)
    json_data      = poolSigma.json()
    sigma          = poolSigma.json().get("active_size")

    ### Message ###
    print()
    print(f'Checking Leader Logs for Stakepool: ' + (col.green + PoolTicker + col.endcl))
    print()
    print(f'Pool Id: '    + (col.green + PoolId + col.endcl))
    print()
    print(f'Next Epoch: ' + col.green + str(epoch) + col.endcl)
    print()
    print(f'Network Active Stake in Epoch ' + str(epoch-1) + ": " + col.green + str(nStake) + col.endcl + ada + col.endcl)
    print()
    print(f'Pool Active Stake in Epoch '    + str(epoch-1) + ": " + col.green + str(pStake) + col.endcl + ada + col.endcl)
    print()


  if epochSlot < 302400:
    print()
    print(f'New epochNonce Not Yet Computable for Epoch: ' + str(epoch))
    print()
    print(f'Come back at epochSlot 302400.')
    print()
    print(f'Current epochSlot '+ str(epochSlot) + '.')
    print()
    exit()


### Check Current Epoch Leader Logs ###

if(key == 'c'):

  ClearScreen()

  headers        = {'content-type': 'application/json', 'project_id': BlockFrostId}

  epochParam     = requests.get("https://cardano-mainnet.blockfrost.io/api/v0/epochs/latest/parameters", headers=headers)
  json_data      = epochParam.json()
  epoch          = epochParam.json().get("epoch")
  eta0           = epochParam.json().get("nonce")

  netStakeParam  = requests.get("https://cardano-mainnet.blockfrost.io/api/v0/epochs/latest", headers=headers)
  json_data      = netStakeParam.json()
  nStake         = int(netStakeParam.json().get("active_stake")) / lovelaces
  nStake         = "{:,}".format(nStake)

  poolStakeParam = requests.get("https://cardano-mainnet.blockfrost.io/api/v0/pools/"+PoolId, headers=headers)
  json_data      = poolStakeParam.json()
  pStake         = int(poolStakeParam.json().get("active_stake")) / lovelaces
  pStake         = "{:,}".format(pStake)

  poolSigma      = requests.get("https://cardano-mainnet.blockfrost.io/api/v0/pools/"+PoolId, headers=headers)
  json_data      = poolSigma.json()
  sigma          = poolSigma.json().get("active_size")


  ### Message ###
  print()
  print(f'Checking Leader Logs for Stakepool: ' + (col.green + PoolTicker + col.endcl))
  print()
  print(f'Pool Id: ' + (col.green + PoolId + col.endcl))
  print()
  print(f'Epoch: '   + col.green + str(epoch) + col.endcl)
  print()
  print(f'Nonce: '   + col.green + str(eta0) + col.endcl)
  print()
  print(f'Network Active Stake in Epoch ' + str(epoch) + ": " + col.green + str(nStake) + col.endcl + ada + col.endcl)
  print()
  print(f'Pool Active Stake in Epoch '    + str(epoch) + ": " + col.green + str(pStake) + col.endcl + ada + col.endcl)
  print()


### Check Previous Epochs Leader Logs ###

if(key == 'p'):

  ClearScreen()
  print()
  Epoch = input("Enter Previous Epoch Number: " + col.green)
  print(col.endcl)


  ### Historical Network and Pool Data from BlockFrost ###

  headers       = {'content-type': 'application/json', 'project_id': BlockFrostId}

  epochParam    = requests.get("https://cardano-mainnet.blockfrost.io/api/v0/epochs/"+Epoch+"/parameters", headers=headers)
  json_data     = epochParam.json()
  epoch         = epochParam.json().get("epoch")
  eta0          = epochParam.json().get("nonce")

  netStakeParam = requests.get("https://cardano-mainnet.blockfrost.io/api/v0/epochs/"+Epoch, headers=headers)
  json_data     = netStakeParam.json()
  nStake        = int(netStakeParam.json().get("active_stake")) / lovelaces
  nStake        = "{:,}".format(nStake)

  poolHistStake = requests.get("https://cardano-mainnet.blockfrost.io/api/v0/pools/"+PoolId+"/history?page=2", headers=headers)
  json_data     = poolHistStake.json()

  for i in json_data :
      if i['epoch'] == int(Epoch) :
          sigma  = (i["active_size"])
          pStake = (i["active_stake"])
          pStake = int(pStake) / lovelaces
          pStake = "{:,}".format(pStake)

  ### Message ###
  print(f'Checking Leader Logs for Stakepool: ' + (col.green + PoolTicker + col.endcl))
  print()
  print(f'Pool Id: ' + (col.green + PoolId + col.endcl))
  print()
  print(f'Epoch: '   + col.green + Epoch + col.endcl)
  print()
  print(f'Nonce: '   + col.green + str(eta0) + col.endcl)
  print()
  print(f'Network Active Stake in Epoch ' + Epoch + ": " + col.green + str(nStake) + col.endcl + ada + col.endcl)
  print()
  print(f'Pool Active Stake in Epoch '    + Epoch + ": " + col.green + str(pStake) + col.endcl + ada + col.endcl)
  print()


### ######################################### ###
if(key != 'n') and (key != 'c') and (key != 'p'):
   ClearScreen()
   exit(0)


### Leader Logs Computation ###

### Opening vrf.skey file ####
with open(VrfKeyFile) as f:
        skey = json.load(f)
        pool_vrf_skey = skey['cborHex'][4:]

### Load libsodium library from /usr/local/lib/  ###
libsodium = cdll.LoadLibrary("/usr/local/lib/libsodium.so")
libsodium.sodium_init()

### Blockchain Genesis Parameters ###
headers          = {'content-type': 'application/json', 'project_id': BlockFrostId}
GenesisParam     = requests.get("https://cardano-mainnet.blockfrost.io/api/v0/genesis", headers=headers)
json_data        = GenesisParam.json()

epochLength      = GenesisParam.json().get("epoch_length")
activeSlotCoeff  = GenesisParam.json().get("active_slots_coefficient")
slotLength       = GenesisParam.json().get("slot_length")

### Epoch211FirstSlot ###
firstShelleySlot = requests.get("https://cardano-mainnet.blockfrost.io/api/v0/blocks/4555184", headers=headers)
json_data        = firstShelleySlot.json()
firstSlot        = firstShelleySlot.json().get("slot")

### calculate first slot of target epoch ###
firstSlotOfEpoch = (firstSlot) + (epoch - 211)*epochLength



# Determine if our pool is a slot leader for this given slot
# @param slot The slot to check
# @param activeSlotCoeff The activeSlotsCoeff value from protocol params
# @param sigma The controlled stake proportion for the pool
# @param eta0 The epoch nonce value
# @param pool_vrf_skey The vrf signing key for the pool



# Credits for new Praos Math to https://github.com/QuixoteSystems
# From https://github.com/QuixoteSystems/cardano-leader-slot.git

from decimal import *
getcontext().prec = 9
getcontext().rounding = ROUND_HALF_UP


def mk_seed(slot, eta0):
    h = hashlib.blake2b(digest_size=32)
    h.update(slot.to_bytes(8, byteorder='big') + binascii.unhexlify(eta0))
    slotToSeedBytes = h.digest()

    return slotToSeedBytes


def vrf_eval_certified(seed, praosCanBeLeaderSignKeyVRF):
    if isinstance(seed, bytes) and isinstance(praosCanBeLeaderSignKeyVRF, bytes):
        proof = create_string_buffer(libsodium.crypto_vrf_ietfdraft03_proofbytes())
        libsodium.crypto_vrf_prove(proof, praosCanBeLeaderSignKeyVRF, seed, len(seed))
        proof_hash = create_string_buffer(libsodium.crypto_vrf_outputbytes())
        libsodium.crypto_vrf_proof_to_hash(proof_hash, proof)

        return proof_hash.raw
    else:
        print("Error.  Feed me bytes")
        exit()


def vrf_leader_value(vrfCert):
    h = hashlib.blake2b(digest_size=32)
    h.update(str.encode("L"))
    h.update(vrfCert)
    vrfLeaderValueBytes = h.digest()

    return int.from_bytes(vrfLeaderValueBytes, byteorder="big", signed=False)


def isOverlaySlot(firstSlotOfEpoch, currentSlot, decentralizationParam):
    diff_slot = float(currentSlot - firstSlotOfEpoch)
    left = Decimal(diff_slot) * Decimal(decentralizationParam)
    right = Decimal(diff_slot + 1) * Decimal(decentralizationParam)
    if math.ceil(left) < math.ceil(right):
        return True
    return False


### Epoch Assigned Performance or Luck ###
def get_performance(nStake, pStake):
    blocksEpoch = 21600

    nStake = nStake.replace(',','')
    pStake = pStake.replace(',','')

    nStake = float(nStake)
    pStake = float(pStake)

    nStake = math.trunc(nStake)
    pStake = math.trunc(pStake)

    epoch_luck = int(100 * slotcount) / (blocksEpoch * pStake / nStake)

    print()
    print(f'Assigned Epoch Performance: ' + str(format(epoch_luck, ".2f")) + ' %' )
    print()

    if slotcount == 0:
        print()
        print("No SlotLeader Schedules Found for Epoch: " +str(epoch))
        print()
        exit


### For Epochs inside Praos Time ###
if float(epoch) >= 364:
    def is_slot_leader(slot, activeSlotsCoeff, sigma, eta0, pool_vrf_skey):
        seed = mk_seed(slot, eta0)
        praosCanBeLeaderSignKeyVRFb = binascii.unhexlify(pool_vrf_skey)
        cert = vrf_eval_certified(seed, praosCanBeLeaderSignKeyVRFb)
        certLeaderVrf = vrf_leader_value(cert)
        certNatMax = math.pow(2, 256)
        denominator = certNatMax - certLeaderVrf
        q = certNatMax / denominator
        c = math.log(1.0 - activeSlotsCoeff)
        sigmaOfF = math.exp(-sigma * c)

        return q <= sigmaOfF

    slotcount=0

    for slot in range(firstSlotOfEpoch,epochLength+firstSlotOfEpoch):

        slotLeader = is_slot_leader(slot, activeSlotCoeff, sigma, eta0, pool_vrf_skey)

        seed = mk_seed(slot, eta0)
        praosCanBeLeaderSignKeyVRFb = binascii.unhexlify(pool_vrf_skey)
        cert = vrf_eval_certified(seed,praosCanBeLeaderSignKeyVRFb)
        certLeaderVrf = vrf_leader_value(cert)
        certNatMax = math.pow(2,256)
        denominator = certNatMax - certLeaderVrf
        q = certNatMax / denominator
        c = math.log(1.0 - activeSlotCoeff)
        sigmaOfF = math.exp(-sigma * c)

        if slotLeader:
            pass
            timestamp = datetime.fromtimestamp(slot + 1591566291, tz=local_tz)
            slotcount+=1

            print("Epoch: " + str(epoch) + " - Local Time: " + str(timestamp.strftime('%Y-%m-%d %H:%M:%S') + " - Slot: " + str(slot-firstSlotOfEpoch) + "  - Block: " + str(slotcount)))
    print()
    print("Total Scheduled Blocks: " + str(slotcount))

    get_performance(nStake, pStake)


### For old Epochs inside TPraos Time (before Current Ouroboros Praos) ###
else:
    def mkSeed(slot, eta0):
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


    def isSlotLeader(slot,activeSlotCoeff,sigma,eta0,pool_vrf_skey):
        seed = mkSeed(slot, eta0)
        tpraosCanBeLeaderSignKeyVRFb = binascii.unhexlify(pool_vrf_skey)
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
        slotLeader = isSlotLeader(slot, activeSlotCoeff, sigma, eta0, pool_vrf_skey)
        if slotLeader:
            pass
            timestamp = datetime.fromtimestamp(slot + 1591566291, tz=local_tz)
            slotcount+=1
            print("Epoch: " + str(epoch) + " - Local Time: " + str(timestamp.strftime('%Y-%m-%d %H:%M:%S') + " - Slot: " + str(slot-firstSlotOfEpoch) + "  - Block: " + str(slotcount)))
    print()
    print("Total Scheduled Blocks: " + str(slotcount))

    get_performance(nStake, pStake)
