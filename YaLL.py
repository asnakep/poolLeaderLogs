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
from ctypes import *
from os import system, path
from datetime import datetime, timezone
from sys import exit, platform

### ADA Unicode symbol, Percent and Lovelaces  ###
ada       = " \u20B3"
lovelaces = 1000000
percent   = " %"

### Def Colors
class col:
    red = '\033[31m'
    green = '\033[92m'
    endcl = '\033[0m'

### Clear Screen
def ClearScreen():
    command ='clear'
    system(command)

### Set your own timezone -----------------------------------------###
local_tz = pytz.timezone('Europe/Berlin')

### Set These Variables ###
PoolId        = ""
PoolIdBech    = ""
PoolTicker    = ""
VrfKeyFile    = '<PATH_TO>/vrf.skey'

### Example
# PoolId        = "342350284fd76ba9dbd7fd4ed579b2a2058d5ee558f8872b37817b28"
# PoolIdBech    = "pool1xs34q2z06a46nk7hl48d27dj5gzc6hh9trugw2ehs9ajsevqffx"
# PoolTicker    = "SNAKE"
# VrfKeyFile    = '/home/user/cardano/vrf.skey'
### -------------------------------------------------------------- ###

### Koios Headers and BaseURL ###
koiosHeaders = {'content-type': 'application/json'}
koiosBaseUrl = "https://api.koios.rest/api/v0/"

### Get Current Current Epoch, Epoch Slot and Total Epoch Slots ###
koiosTipUrl        = koiosBaseUrl+"tip"
request            = urllib.request.Request(koiosTipUrl, headers=koiosHeaders)
response           = urllib.request.urlopen(request).read()
tipData            = json.loads(response.decode('utf-8'))
epoch              = int(tipData[0]['epoch_no'])
epochSlot          = int(tipData[0]['epoch_slot'])
epochSlotFormat    = "{:,}".format(epochSlot)

### Genesis Info ###
koiosGenesisUrl    = koiosBaseUrl+"genesis"
request            = urllib.request.Request(koiosGenesisUrl, headers=koiosHeaders)
response           = urllib.request.urlopen(request).read()
genesisData        = json.loads(response.decode('utf-8'))
epochLength        = int(genesisData[0]['epochlength'])
slotLength         = int(genesisData[0]['slotlength'])
remainingSlots     = epochLength - epochSlot
remainingSlots     = "{:,}".format(remainingSlots)

### Network Active Stake ###
koiosEpochInfoUrl  = koiosBaseUrl+"epoch_info?_epoch_no="+str(epoch)
request            = urllib.request.Request(koiosEpochInfoUrl, headers=koiosHeaders)
response           = urllib.request.urlopen(request).read()
epochInfoData      = json.loads(response.decode('utf-8'))
nStake             = int(epochInfoData[0]['active_stake'])
nStakeToFormat     = math.trunc(int(nStake) / lovelaces)
nStakeFormat       = "{:,}".format(nStakeToFormat)
nStakePerf         = nStakeFormat

### Current Epoch Nonce from Koios ###
koiosEpochParamUrl = koiosBaseUrl+"epoch_params?_epoch_no="+str(epoch)
request            = urllib.request.Request(koiosEpochParamUrl, headers=koiosHeaders)
response           = urllib.request.urlopen(request).read()
epochParamData     = json.loads(response.decode('utf-8'))
eta0               = epochParamData[0]['nonce']

### Get Pool Stats from Koios ###
poolInfoUrl        = koiosBaseUrl+"pool_info"
poolPostData       = {"_pool_bech32_ids":[PoolIdBech]}

poolinfo           = requests.post(poolInfoUrl, data=json.dumps(poolPostData))
poolinfo           = poolinfo.text
poolinfo           = json.loads(poolinfo)

poolPledge         = int(poolinfo[0]['pledge']) / lovelaces
poolPledge         = math.trunc(poolPledge)
poolPledge         = "{:,}".format(poolPledge)

poolMargin         = poolinfo[0]['margin']

poolFixedCost      = int(poolinfo[0]['fixed_cost']) / lovelaces
poolFixedCost      = math.trunc(poolFixedCost)

poolDelegators     = poolinfo[0]['live_delegators']

blocksLifetime     = poolinfo[0]['block_count']

poolSaturation     = poolinfo[0]['live_saturation']

poolLiveStake      = int(poolinfo[0]['live_stake']) / lovelaces
poolLiveStake      = math.trunc(poolLiveStake)
poolLiveStake      = "{:,}".format(poolLiveStake)

pStake             = int(poolinfo[0]['active_stake']) / lovelaces
poolActiveStake    = math.trunc(pStake)
poolActiveStake    = "{:,}".format(poolActiveStake)

pStakePerf         = poolActiveStake

sigma              = poolinfo[0]['sigma']

### Get Other Pool Stats from cexplorer.io ###
PoolIdBechStr      =  PoolIdBech+".json"
cexplorer_headers  = {'content-type': 'application/json'}
poolUrl            = "https://js.cexplorer.io/api-static/pool/"+PoolIdBechStr
request            = urllib.request.Request(poolUrl, headers=cexplorer_headers)
response           = urllib.request.urlopen(request).read()
poolDat            = json.loads(response.decode('utf-8'))

luckLifetime       = float(poolDat['data']['luck_lifetime']) * 100
luckLifetime       = round(luckLifetime,2)
roaShort           = float(poolDat['data']['roa_short'])
roaShort           = round(roaShort, 1)
roaLifetime        = (poolDat['data']['roa_lifetime'])
poolRanking        = (poolDat['data']['position'])

### Get Global Cardano Stats from cexplorer.io ###
statsUrl           = "https://js.cexplorer.io/api-static/basic/global.json"
request            = urllib.request.Request(statsUrl, headers=cexplorer_headers)
response           = urllib.request.urlopen(request).read()
statsDat           = json.loads(response.decode('utf-8'))

circSupply         = int(statsDat['data']['supply']['now'] / lovelaces)
circSupplyFormat   = "{:,}".format(circSupply)

stakePools         = int(statsDat['data']['stats']['pools'])
stakePools         = "{:,}".format(stakePools)

delegators         = int(statsDat['data']['stats']['delegators'])
delegators         = "{:,}".format(delegators)

stakedPercent      = (nStakeToFormat * 100 / circSupply)
stakedPercent      = str(round(stakedPercent, 2))

### Next Epoch Nonce, Next Pool Sigma and Next Pool Active Stake from Koios ###
koiosPoolSnapshotUrl      = koiosBaseUrl+"pool_stake_snapshot?_pool_bech32="+PoolIdBech
request                   = urllib.request.Request(koiosPoolSnapshotUrl, headers=koiosHeaders)
response                  = urllib.request.urlopen(request).read()
poolStakeSnapData         = json.loads(response.decode('utf-8'))
nextEpochNonce            = str(poolStakeSnapData[2]['nonce'])
nextPoolActiveStake       = (poolStakeSnapData[2]['pool_stake'])
nextPoolActiveStakeFormat = int(nextPoolActiveStake) / lovelaces
nextPoolActiveStakeFormat = math.trunc(nextPoolActiveStakeFormat)
nextPoolActiveStakeFormat = "{:,}".format(nextPoolActiveStakeFormat)
pStakePerf                = nextPoolActiveStakeFormat

nextNetActiveStake        = (poolStakeSnapData[2]['active_stake'])
nextNetActiveStakeFormat  = int(nextNetActiveStake) / lovelaces
nextNetActiveStakeFormat  = math.trunc(nextNetActiveStakeFormat)
nextNetActiveStakeFormat  = "{:,}".format(nextNetActiveStakeFormat)
nStakePerf                = nextNetActiveStakeFormat
nextPoolSigma             = int(nextPoolActiveStake) / int(nextNetActiveStake)

### Pool Estimated Blocks from Koios ###
koiosGenesisUrl           = koiosBaseUrl+"genesis"
request                   = urllib.request.Request(koiosGenesisUrl, headers=koiosHeaders)
response                  = urllib.request.urlopen(request).read()
networkGenesisData        = json.loads(response.decode('utf-8'))
epochlength               = int(networkGenesisData[0]['epochlength'])
activeSlotCoeff           = float(networkGenesisData[0]['activeslotcoeff'])
blocksInEpoch             = math.trunc(epochlength * activeSlotCoeff)

nextPoolActiveInt         = int(nextPoolActiveStake) / lovelaces
nextNetActiveInt          = int(nextNetActiveStake) / lovelaces
blocksEstimated           = int(blocksInEpoch * nextPoolActiveInt) / (nextNetActiveInt)
blocksEstimated           = round(blocksEstimated,2)

### User Prompt ###
ClearScreen()
print()
print(col.green + f'Yet Another Leader Logs for Cardano SPOs. ')
print()
print(col.green + f'Check Scheduled Blocks in Next, Current and Previous Epochs.')
print(col.endcl)
print(col.endcl)
print(col.green + f'Current Cardano Epoch ' + col.endcl +str(epoch))
print(col.green + f'Epoch Slot            ' + col.endcl +str(epochSlotFormat))
print(col.green + f'Remaining Slots       ' + col.endcl +str(remainingSlots))
print(col.endcl)
print(col.green + f'Circulating Supply    ' + col.endcl +str(circSupplyFormat) +str(ada))
print(col.green + f'Total Staked          ' + col.endcl +str(nStakeFormat)     +str(ada))
print(col.green + f'Staked percent        ' + col.endcl +str(stakedPercent)    +str(percent))
print(col.endcl)
print(col.green + f'Stakepools            ' + col.endcl +str(stakePools))
print(col.green + f'Delegators            ' + col.endcl +str(delegators))
print(col.endcl)
print(col.endcl)

### newEpochNonce Availability ###
if epochSlot >= 302400:
   epochNonce = print(col.green + f'New epochNonce Available'     + col.endcl)
   print()
if epochSlot <  302400:
   epochNonce = print(col.red   + f'New epochNonce Not Available' + col.endcl)
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

  ClearScreen()
  epoch         = int(epoch + 1)

  ### Check Next Epoch Leader Logs ###

  if epochSlot >= 302400:

    eta0   = nextEpochNonce
    sigma  = nextPoolSigma

    ### Message ###
    print()
    print(f'Checking Leader Logs for Stakepool: ' + (col.green + PoolTicker                 + col.endcl))
    print()
    print(f'Pool Id: '                            + (col.green + PoolId                     + col.endcl))
    print()
    print(f' Live Stake:       '                  + (col.green + poolLiveStake              + col.endcl) + ada)
    print(f' Active Stake:     '                  + (col.green + nextPoolActiveStakeFormat  + col.endcl) + ada)
    print(f' Pledge:           '                  + (col.green + poolPledge                 + col.endcl) + ada)
    print(f' Pool Margin:      '                  + (col.green + str(poolMargin)            + col.endcl) + percent)
    print(f' Pool FixedCost:   '                  + (col.green + str(poolFixedCost)         + col.endcl) + ada)
    print(f' Delegators:       '                  + (col.green + str(poolDelegators)        + col.endcl))
    print(f' Estimated Blocks: '                  + (col.green + str(blocksEstimated)       + col.endcl))
    print(f' Lifetime Blocks:  '                  + (col.green + str(blocksLifetime)        + col.endcl))
    print(f' Lifetime Luck:    '                  + (col.green + str(luckLifetime)          + col.endcl) + percent)
    print(f' Last Roa:         '                  + (col.green + str(roaShort) + col.endcl) + percent)
    print(f' Lifetime Roa:     '                  + (col.green + roaLifetime + col.endcl)   + percent)
    print(f' Saturation:       '                  + (col.green + str(poolSaturation)        + col.endcl) + percent)
    print(f' Rank:             '                  + (col.green + poolRanking                + col.endcl))
    print()
    print(f'Next Epoch: '                         + col.green + str(epoch)                  + col.endcl)
    print()
    print(f'Nonce: '                              + col.green + str(eta0)                   + col.endcl)
    print()
    print(f'Network Active Stake in Epoch '       + str(epoch) + ": " + col.green + str(nextNetActiveStakeFormat)  + col.endcl + ada + col.endcl)
    print()
    print(f'Pool Active Stake in Epoch '          + str(epoch) + ": " + col.green + str(nextPoolActiveStakeFormat) + col.endcl + ada + col.endcl)
    print()


  if epochSlot < 302400:
    print()
    print(f'New epochNonce Not Yet Available for Epoch: ' + str(epoch))
    print()
    print(f'Please come back at epochSlot 302400.')
    print()
    print(f'Current epochSlot '+ str(epochSlot) + '.')
    print()
    exit()

### Check Current Epoch Leader Logs ###

if(key == 'c'):

  ClearScreen()

  ### Message ###
  print()
  print(f'Checking Leader Logs for Stakepool: ' + (col.green + PoolTicker + col.endcl))
  print()
  print(f'Pool Id: '                            + (col.green + PoolId + col.endcl))
  print()
  print(f' Live Stake:       '                  + (col.green + poolLiveStake              + col.endcl) + ada)
  print(f' Active Stake:     '                  + (col.green + poolActiveStake            + col.endcl) + ada)
  print(f' Pledge:           '                  + (col.green + poolPledge                 + col.endcl) + ada)
  print(f' Pool Margin:      '                  + (col.green + str(poolMargin)            + col.endcl) + percent)
  print(f' Pool FixedCost:   '                  + (col.green + str(poolFixedCost)         + col.endcl) + ada)
  print(f' Estimated Blocks: '                  + (col.green + str(blocksEstimated)       + col.endcl))
  print(f' Delegators:       '                  + (col.green + str(poolDelegators)        + col.endcl))
  print(f' Lifetime Blocks:  '                  + (col.green + str(blocksLifetime)        + col.endcl))
  print(f' Lifetime Luck:    '                  + (col.green + str(luckLifetime)          + col.endcl) + percent)
  print(f' Last Roa:         '                  + (col.green + str(roaShort) + col.endcl) + percent)
  print(f' Lifetime Roa:     '                  + (col.green + roaLifetime + col.endcl)   + percent)
  print(f' Saturation:       '                  + (col.green + str(poolSaturation)        + col.endcl) + percent)
  print(f' Rank:             '                  + (col.green + poolRanking                + col.endcl))
  print()
  print(f'Epoch: '                              + col.green + str(epoch)                  + col.endcl)
  print()
  print(f'Nonce: '                              + col.green + str(eta0)                   + col.endcl)
  print()
  print(f'Network Active Stake in Epoch '       + str(epoch) + ": " + col.green + str(nStakeFormat)    + col.endcl + ada + col.endcl)
  print()
  print(f'Pool Active Stake in Epoch '          + str(epoch) + ": " + col.green + str(poolActiveStake) + col.endcl + ada + col.endcl)
  print()

### Check Previous Epochs Leader Logs ###

if(key == 'p'):

  ClearScreen()
  print()
  Epoch = input("Enter Previous Epoch Number: " + col.green)
  print(col.endcl)


  ### Historical Network and Pool Data from Koios ###
  histEpochParamsUrl    = koiosBaseUrl+"epoch_params?_epoch_no="+Epoch
  request               = urllib.request.Request(histEpochParamsUrl, headers=koiosHeaders)
  response              = urllib.request.urlopen(request).read()
  histEpochParamsData   = json.loads(response.decode('utf-8'))
  epoch                 = histEpochParamsData[0]['epoch_no']
  eta0                  = histEpochParamsData[0]['nonce']

  histNetEpochInfoUrl   = koiosBaseUrl+"epoch_info?_epoch_no="+Epoch
  request               = urllib.request.Request(histNetEpochInfoUrl, headers=koiosHeaders)
  response              = urllib.request.urlopen(request).read()
  histNetEpochInfoData  = json.loads(response.decode('utf-8'))
  nStake                = int(histNetEpochInfoData[0]['active_stake']) / lovelaces
  nStakeFormat          = math.trunc(nStake)
  nStakeFormat          = "{:,}".format(nStakeFormat)
  nStakePerf            = nStakeFormat

  histPoolEpochInfoUrl  = koiosBaseUrl+"pool_history?_pool_bech32="+PoolIdBech+"&_epoch_no="+Epoch
  request               = urllib.request.Request(histPoolEpochInfoUrl, headers=koiosHeaders)
  response              = urllib.request.urlopen(request).read()
  histPoolEpochInfoData = json.loads(response.decode('utf-8'))
  pStake                = int(histPoolEpochInfoData[0]['active_stake']) / lovelaces
  poolActiveStake       = math.trunc(pStake)
  poolActiveStake       = "{:,}".format(poolActiveStake)
  pStakePerf            = poolActiveStake
  sigma                 = pStake / nStake


  ### Message ###
  print(f'Checking Leader Logs for Stakepool: ' + (col.green + PoolTicker + col.endcl))
  print()
  print(f'Pool Id: '                            + (col.green + PoolId      + col.endcl))
  print()
  print(f'Epoch: '                              + col.green  + Epoch       + col.endcl)
  print()
  print(f'Nonce: '                              + col.green  + str(eta0)   + col.endcl)
  print()
  print(f'Network Active Stake in Epoch '       + Epoch + ": " + col.green + str(nStakeFormat)    + col.endcl + ada + col.endcl)
  print()
  print(f'Pool Active Stake in Epoch '          + Epoch + ": " + col.green + str(poolActiveStake) + col.endcl + ada + col.endcl)
  print()

### ######################################### ###
if(key != 'n') and (key != 'c') and (key != 'p'):
   ClearScreen()
   exit(0)

### Leader Logs Computation: ###
### Opening vrf.skey file   ####
with open(VrfKeyFile) as f:
        skey = json.load(f)
        pool_vrf_skey = skey['cborHex'][4:]

### Load libsodium library from /usr/local/lib/  ###
libsodium = cdll.LoadLibrary("/usr/local/lib/libsodium.so")
libsodium.sodium_init()

### Epoch211FirstSlot ###
firstShelleyBlockHash = "33a28456a44277cbfb3457082467e56f16554932eb2a9eb7ceca97740bd4f4db"
blockInfoUrl          = koiosBaseUrl+"block_info"
postData              = {"_block_hashes":[firstShelleyBlockHash]}
blockInfo             = requests.post(blockInfoUrl, data=json.dumps(postData))
blockInfo             = blockInfo.text
blockInfo             = json.loads(blockInfo)
firstSlot             = blockInfo[0]['abs_slot']

### calculate first slot of target epoch ###
firstSlotOfEpoch = (firstSlot) + (epoch - 211)*epochLength


# Determine if our pool is a slot leader for this given slot
# @param slot The slot to check
# @param activeSlotCoeff The activeSlotsCoeff value from protocol params
# @param sigma The controlled stake proportion for the pool
# @param eta0 The epoch nonce value
# @param pool_vrf_skey The vrf signing key for the pool

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
def get_performance(nStakePerf, pStakePerf):

    blocksEpoch = 21600

    nStakePerf = nStakePerf.replace(',','')
    pStakePerf = pStakePerf.replace(',','')

    nStakePerf = float(nStakePerf)
    pStakePerf = float(pStakePerf)

    nStakePerf = math.trunc(nStakePerf)
    pStakePerf = math.trunc(pStakePerf)

    epoch_luck = int(100 * slotcount) / (blocksEpoch * pStakePerf / nStakePerf)

    print()
    print(f'Assigned Performance: ' + str(format(epoch_luck, ".0f")) + ' %' )
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

            print("Epoch: " + str(epoch) + " - Local Time: " + str(timestamp.strftime('%Y-%m-%d %H:%M:%S') + " - Absolute Slot: " + str(slot) + " - Epoch Slot: " + str(slot-firstSlotOfEpoch)))
    print()
    print("Total Scheduled Blocks: " + str(slotcount))

    get_performance(nStakePerf, pStakePerf)

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
            print("Epoch: " + str(epoch) + " - Local Time: " + str(timestamp.strftime('%Y-%m-%d %H:%M:%S') + " - Absolute Slot: " + str(slot) + " - Epoch Slot: " + str(slot-firstSlotOfEpoch)))
    print()
    print("Total Scheduled Blocks: " + str(slotcount))

    get_performance(nStakePerf, pStakePerf)
