#!/usr/bin/python
# Author: Heini Bergsson Debes

import logging
import sys
import subprocess
from pathlib import Path, PurePath
import csv

def process(param):
    p = subprocess.run(['%s' %param['miningSoftware'], '-t%s' %param['targetType'], '-m%s' %param['minLen'], '-n%s' %param['maxLen'], '-s%s' %param['AESimplementation']['minSup'], '-v|%i,%a,%S', '%s/preprocessed_%s' %(param['reducedSequenceDir'], param['reducedSequenceFileName']), '%s/processed_%s' %(param['reducedSequenceDir'], param['reducedSequenceFileName'])], check=True, capture_output=True)
    log('> %s' %' '.join(p.args), param)

    seqs     = []
    seqStats = []
    with open('%s/processed_%s' %(param['reducedSequenceDir'], param['reducedSequenceFileName'])) as reducedSeqFile:
        for seq in reducedSeqFile.read().split('\n'):
            if seq != '':
                stats = seq.split('|')[1].split(',')
                seqs.append(seq.split('|')[0])
                seqStats.append({'len': stats[0], 'absSupport': stats[1], 'relSupport': stats[2]})
    return seqs, seqStats

def preprocess(param, packetAddress=''):
    if packetAddress == '': 
        param['reducedSequenceFileName'] = param['sequenceFileName']
    else: 
        param['reducedSequenceFileName'] = param['sequenceFileName'] + '_exploitedPacketAddress'
    seqs     = []
    seqStats = []
    with open('%s/preprocessed_%s' %(param['reducedSequenceDir'], param['reducedSequenceFileName']), 'w') as out:
        with open('%s/%s' %(param['sequenceDir'], param['sequenceFileName'])) as seqFile:
            for seq in seqFile.read().split('\n'):
                if seq != '':
                    if packetAddress != '':
                        seq = seq.split(packetAddress)[0]
                    words = seq.split(' ')
                    for idx, word in reversed(list(enumerate(words))): # remove words read past the stack boundary (values of 'ff3f')
                        if word != 'ff3f': break
                        words.pop(idx)
                    seqStats.append({'len': len(words)})
                    seqs.append(' '.join(words))
                    out.write(' '.join(words) + '\n')
    return param, seqs, seqStats

def getKeyStats(seqs, param):
    keys     = []
    keyStats = []
    for keyIdx, roundKey in enumerate(param['AESimplementation']['roundKeys']): keys.append({'roundKey': roundKey, 'roundKeyNumber': keyIdx+1, 'occurrences': 0})
    for seqIdx, seq in enumerate(seqs):
        for keyIdx, key in enumerate(keys):
            if key['roundKey'] in seq:
                count = seq.count(key['roundKey'])
                keys[keyIdx]['occurrences'] += count
                for idx in range(0, count):
                    seqSplits    = seq.split(key['roundKey'])
                    predecessors = len(seqSplits[idx].split(' '))-1
                    end          = predecessors + len(key['roundKey'].split(' '))
                    keyStats.append({'roundKey': key['roundKey'], 'roundKeyNumber': key['roundKeyNumber'], 'seqId': seqIdx+1, 'firstWordIdx': predecessors+1, 'lastWordIdx': end})
    return keys, keyStats

def log(msg, param, override=False):
    if param['verbose'] == True or override == True:
        logging.info(msg)
        print(msg)

def main(param):
    seqStats = []
    keyStats = []
    for seqFile in Path(param['sequenceDir']).iterdir():
        param['sequenceFileName'] = PurePath(seqFile).name
        if not param['sequenceFileName'].startswith('seqs-'): continue

        seqFileNameSplits = param['sequenceFileName'].split('-')
        if len(seqFileNameSplits) != 5:
            log('Path error: %s' %seqFile, param, True)
            continue
        
        aesImplementationName = seqFileNameSplits[1]
        optimizationLevel     = seqFileNameSplits[2]
        freq = seqFileNameSplits[3]
        rid  = seqFileNameSplits[4].replace('rid', '') # run ID
    
        param['AESimplementation'] = param['AESimplementations'][aesImplementationName]
        log("Parameters: %s" %param, param)

        # pre
        param, seqs, stats = preprocess(param)
        for stat in stats:
            seqStats.append({
                'rid': rid, 'aes_implementation': aesImplementationName, 'optimization_level': optimizationLevel, 'freq': freq, 'stage': 'pre', 'exploitedPacketAddress': False, 'len': stat['len'], 'abs_support': 'NaN', 'rel_support': 'NaN'
            })
        occurrences, stats = getKeyStats(seqs, param)
        for stat in stats:
            keyStats.append({
                'rid': rid, 'aes_implementation': aesImplementationName, 'optimization_level': optimizationLevel, 'freq': freq, 'stage': 'pre', 'exploitedPacketAddress': False, 'round_key_number': stat['roundKeyNumber'], 'seq_id': stat['seqId'], 'key_start_word_idx': stat['firstWordIdx'], 'key_end_word_idx': stat['lastWordIdx']
            })
        # processed
        seqs, stats = process(param)
        if len(stats) == 0:
            seqStats.append({
                'rid': rid, 'aes_implementation': aesImplementationName, 'optimization_level': optimizationLevel, 'freq': freq, 'stage': 'processed', 'exploitedPacketAddress': False, 'len': 'NaN', 'abs_support': 'NaN', 'rel_support': 'NaN'
            })
        for stat in stats:
            seqStats.append({
                'rid': rid, 'aes_implementation': aesImplementationName, 'optimization_level': optimizationLevel, 'freq': freq, 'stage': 'processed', 'exploitedPacketAddress': False, 'len': stat['len'], 'abs_support': stat['absSupport'], 'rel_support': stat['relSupport']
            })
        occurrences, stats = getKeyStats(seqs, param)
        for stat in stats:
            keyStats.append({
                'rid': rid, 'aes_implementation': aesImplementationName, 'optimization_level': optimizationLevel, 'freq': freq, 'stage': 'processed', 'exploitedPacketAddress': False, 'round_key_number': stat['roundKeyNumber'], 'seq_id': stat['seqId'], 'key_start_word_idx': stat['firstWordIdx'], 'key_end_word_idx': stat['lastWordIdx']
            })

        ###################################################
        ##### remove all words past the packet address ####
        ###################################################
        packetAddress = param['AESimplementation']['packetAddresses'][optimizationLevel]
        # pre
        param, seqs, stats = preprocess(param, packetAddress)
        for stat in stats:
            seqStats.append({
                'rid': rid, 'aes_implementation': aesImplementationName, 'optimization_level': optimizationLevel, 'freq': freq, 'stage': 'pre', 'exploitedPacketAddress': True, 'len': stat['len'], 'abs_support': 'NaN', 'rel_support': 'NaN'
            })
        occurrences, stats = getKeyStats(seqs, param)
        for stat in stats:
            keyStats.append({
                'rid': rid, 'aes_implementation': aesImplementationName, 'optimization_level': optimizationLevel, 'freq': freq, 'stage': 'pre', 'exploitedPacketAddress': True, 'round_key_number': stat['roundKeyNumber'], 'seq_id': stat['seqId'], 'key_start_word_idx': stat['firstWordIdx'], 'key_end_word_idx': stat['lastWordIdx']
            })
        # processed
        seqs, stats = process(param)
        if len(stats) == 0:
            seqStats.append({
                'rid': rid, 'aes_implementation': aesImplementationName, 'optimization_level': optimizationLevel, 'freq': freq, 'stage': 'processed', 'exploitedPacketAddress': True, 'len': 'NaN', 'abs_support': 'NaN', 'rel_support': 'NaN'
            })
        for stat in stats:
            seqStats.append({
                'rid': rid, 'aes_implementation': aesImplementationName, 'optimization_level': optimizationLevel, 'freq': freq, 'stage': 'processed', 'exploitedPacketAddress': True, 'len': stat['len'], 'abs_support': stat['absSupport'], 'rel_support': stat['relSupport']
            })
        occurrences, stats = getKeyStats(seqs, param)
        for stat in stats:
            keyStats.append({
                'rid': rid, 'aes_implementation': aesImplementationName, 'optimization_level': optimizationLevel, 'freq': freq, 'stage': 'processed', 'exploitedPacketAddress': True, 'round_key_number': stat['roundKeyNumber'], 'seq_id': stat['seqId'], 'key_start_word_idx': stat['firstWordIdx'], 'key_end_word_idx': stat['lastWordIdx']
            })

    with open('%s/seqStats.csv' %param['summaryDir'], 'w', newline='') as csvfile: 
        fieldnames = ['rid', 'aes_implementation', 'optimization_level', 'freq', 'stage', 'exploitedPacketAddress', 'len', 'abs_support', 'rel_support']
        writer = csv.DictWriter(csvfile, dialect='excel', fieldnames=fieldnames)
        writer.writeheader()
        for seqStat in seqStats: writer.writerow(seqStat)
    with open('%s/keyStats.csv' %param['summaryDir'], 'w', newline='') as csvfile: 
        fieldnames = ['rid', 'aes_implementation', 'optimization_level', 'freq', 'stage', 'exploitedPacketAddress', 'round_key_number', 'seq_id', 'key_start_word_idx', 'key_end_word_idx']
        writer = csv.DictWriter(csvfile, dialect='excel', fieldnames=fieldnames)
        writer.writeheader()
        for keyStat in keyStats: writer.writerow(keyStat)

if __name__ == '__main__':
    param            = {}
    param['verbose'] = False
    param['AESimplementations'] = {
        'TIAES': {
            'minSup': '6.25', # positive for relative, negative for absolute
            'roundKeys': [
                '4e46 5e56 6e66 7e76 0e06 1e16 2e26 3e36',
                'b8f4 5b67 d692 2511 d894 3b07 f6b2 0531',
                '8d9f 9c25 5b0d b934 8399 8233 752b 8702',
                '7888 ebb8 2385 528c a01c d0bf d537 57bd',
                'ead3 91bb c956 c337 694a 1388 bc7d 4435',
                '05c8 07de cc9e c4e9 a5d4 d761 19a9 9354',
                'f614 270a 3a8a e3e3 9f5e 3482 86f7 a7d6',
                'de48 d14e e4c2 32ad 7b9c 062f fd6b a1f9',
                '217a 481a c5b8 7ab7 be24 7c98 434f dd61',
                'bebb a700 7b03 ddb7 c527 a12f 8668 7c4e',
                'cdab 8844 b6a8 55f3 738f f4dc f5e7 8892'
            ],
            'packetAddresses': {
                'O0': 'd811',
                'O1': 'd811',
                'O2': 'd811',
                'O3': 'dc11',
                'Os': 'd811',
            }
            }, 
        'TinyAES': {
            'minSup': '25', # positive for relative, negative for absolute
            'roundKeys': [
                '4e46 5e56 6e66 7e76 0e06 1e16 2e26 3e36',
            ],
            'packetAddresses': {
                'O0': '9812',
                'O1': '9812',
                'O2': '9812',
                'O3': '9c12',
                'Os': '9812',
            }
            }
        }
    param['outputDir']          = 'Results/spaceReductor'
    param['reducedSequenceDir'] = param['outputDir'] + '/ReducedDatasets'
    param['summaryDir']         = param['reducedSequenceDir'] + '/Summary'
    param['sequenceDir']        = 'Results/getStacks/Datasets'
    param['miningSoftware']     = './seqwog.exe'
    param['minLen']             = 2
    param['maxLen']             = 800
    param['targetType']         = 'm' # m for maximal, c for closed

    if len(sys.argv) > 1:
        for arg in sys.argv:
            if arg == '--verbose' or arg == '-v': param['verbose'] = True
    Path('%s' %param['summaryDir']).mkdir(parents=True, exist_ok=True)
    with open('%s/inputParams.log' %param['outputDir'], 'w') as paramFile:
        for p, v in param.items(): paramFile.write('%s: %s\n' %(p, v))
    logging.root.handlers = []
    logging.basicConfig(filename='%s/spaceReductor.log' %param['outputDir'], level=logging.DEBUG, format='%(asctime)s:%(levelname)s:%(name)s:%(message)s')
    main(param)
