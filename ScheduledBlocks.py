#!/bin/env python3
import requests
import math
import binascii
import json
import pytz
from sqlalchemy.sql.sqltypes import BigInteger
import yaml
import hashlib
from ctypes import *
from decimal import *
from os import path
from datetime import datetime
from sys import exit, platform
from sqlalchemy import Column
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.engine.create import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker

#################################
######### configuration #########
#################################
BASE_DIR = path.dirname(path.abspath(__file__))
CONFIGPATH = path.join(BASE_DIR, "config.yaml")
with open(CONFIGPATH) as f:
    CONFIG = yaml.load(f, Loader=yaml.FullLoader)

##################################
######### setup slots db #########
##################################
Base = declarative_base()
engine = create_engine("sqlite:///slotschedule.db")
session = scoped_session(sessionmaker(autocommit=False,bind=engine))

class Slots(Base):
    __tablename__ = "slots"
    epoch = Column(BigInteger, primary_key=True)
    slot_qty = Column(BigInteger)
    slots = Column(BigInteger)

Base.metadata.create_all(engine)

### --------------------- Settings ------------------------------- ###
local_tz = pytz.timezone(CONFIG["timezone"])
BlockFrostId = CONFIG["blockfrost_id"]
PoolId = CONFIG["pool_id"]
PoolTicker = CONFIG["pool_ticker"]
VrfKeyFile = CONFIG["vrf_key"]
### -------------------------------------------------------------- ###
### ADA Unicode symbol and Lovelaces removal ###
ada = " \u20B3"
lovelaces = 1000000


##################################
######### main routines ##########
##################################
class col:
    green = '\033[92m'
    endcl = '\033[0m'
    bold = '\033[1m'


class SlotLeaderCheck:
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

    ### Slots Leader Computation ###

    ### Opening vrf.skey file ###
    with open(VrfKeyFile) as f:
            skey = json.load(f)
            poolVrfSkey = skey['cborHex'][4:]

    ### Determine libsodium path based on platform ###
    Libsodium = None
    if platform == "linux" or platform == "linux2":
        # Bindings are not avaliable so using ctypes to just force it in for now.
        Libsodium = cdll.LoadLibrary("/usr/local/lib/libsodium.so")
    elif platform == "darwin":
        # Try both Daedalus' bundled libsodium and a system-wide libsodium path.
        daedalusLibsodiumPath = path.join("/Applications", "Daedalus Mainnet.app", "Contents", "MacOS", "libsodium.23.dylib")
        systemLibsodiumPath = path.join("/usr", "local", "lib", "libsodium.23.dylib")

        if path.exists(daedalusLibsodiumPath):
            Libsodium = cdll.LoadLibrary(daedalusLibsodiumPath)
        elif path.exists(systemLibsodiumPath):
            Libsodium = cdll.LoadLibrary(systemLibsodiumPath)
        else:
            exit(f'Unable to find libsodium, checked the following paths: {", ".join([daedalusLibsodiumPath, systemLibsodiumPath])}')
    
    Libsodium.sodium_init()
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

    getcontext().prec = 9
    getcontext().rounding = ROUND_HALF_UP

    # mkseed
    def mkSeed(self,slot,eta0):

        h = hashlib.blake2b(digest_size=32)
        h.update(bytearray([0,0,0,0,0,0,0,1])) #neutral nonce
        seedLbytes=h.digest()

        h = hashlib.blake2b(digest_size=32)
        h.update(slot.to_bytes(8,byteorder='big') + binascii.unhexlify(eta0))
        slotToSeedBytes = h.digest()

        seed = [x ^ slotToSeedBytes[i] for i,x in enumerate(seedLbytes)]
        return bytes(seed)

    # eval certified
    def vrfEvalCertified(self, seed, tpraosCanBeLeaderSignKeyVRF):
        if isinstance(seed, bytes) and isinstance(tpraosCanBeLeaderSignKeyVRF, bytes):
            proof = create_string_buffer(self.Libsodium.crypto_vrf_ietfdraft03_proofbytes())

            self.Libsodium.crypto_vrf_prove(proof, tpraosCanBeLeaderSignKeyVRF,seed, len(seed))

            proofHash = create_string_buffer(self.Libsodium.crypto_vrf_outputbytes())

            self.Libsodium.crypto_vrf_proof_to_hash(proofHash,proof)

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

    def isSlotLeader(self, slot,activeSlotCoeff,sigma,eta0,poolVrfSkey):
        seed = self.mkSeed(slot, eta0)
        tpraosCanBeLeaderSignKeyVRFb = binascii.unhexlify(poolVrfSkey)
        cert=self.vrfEvalCertified(seed,tpraosCanBeLeaderSignKeyVRFb)
        certNat  = int.from_bytes(cert, byteorder="big", signed=False)
        certNatMax = math.pow(2,512)
        denominator = certNatMax - certNat
        q = certNatMax / denominator
        c = math.log(1.0 - activeSlotCoeff)
        sigmaOfF = math.exp(-sigma * c)
        return q <= sigmaOfF

    def checkLeaderSlots(self,verbose):

        if verbose == True:
            print()
            print(col.bold + f'Checking SlotLeader Schedules for Stakepool: ' + (col.green + PoolTicker + col.endcl))
            print()
            print(col.bold + f'Pool Id: ' + (col.green + PoolId + col.endcl))
            print()
            print(col.bold + f'Current Epoch: ' + col.green + str(self.epoch) + col.endcl)
            print()
            print(col.bold + f'Nonce: ' + col.green + str(self.eta0) + col.endcl)
            print()
            print(col.bold + f'Network Active Stake: ' + col.green + str(self.nStake) + col.endcl + col.bold + ada + col.endcl)
            print()
            print(col.bold + f'Pool Active Stake: ' + col.green + str(self.pStake) + col.endcl + col.bold + ada + col.endcl)
            print()

        slotcount=0
        slots = []

        for slot in range(self.firstSlotOfEpoch,self.epochLength+self.firstSlotOfEpoch):

            slotLeader = self.isSlotLeader(slot, self.activeSlotCoeff, self.sigma, self.eta0, self.poolVrfSkey)

            if slotLeader:
                timestamp = datetime.fromtimestamp(slot + 1591566291, tz=local_tz)
                slots.append(slot)
                slotcount+=1
                if verbose == True:
                    print(col.bold + "Leader At Slot: "  + str(slot-self.firstSlotOfEpoch) + " - Local Time " + str(timestamp.strftime('%Y-%m-%d %H:%M:%S') + " - Scheduled Epoch Blocks: " + str(slotcount)))

        if slotcount == 0:
            if verbose == True:
                print(col.bold + "No SlotLeader Schedules Found for Current Epoch " +str(self.epoch))

        # save to SQLite database
        try: 
            newSlots = Slots(
                        epoch = self.epoch,
                        slot_qty = slotcount,
                        slots = str(slots)
                    )
            session.merge(newSlots)
            session.commit()
        except Exception as ex:
            print(ex)

        # default constructor
    def __init__(self,verbose=True):
        self.checkLeaderSlots(verbose)

####################################
######### main shell exec ##########
####################################
if __name__ == "__main__":
    # run the leaderslot check function
    SlotLeaderCheck()