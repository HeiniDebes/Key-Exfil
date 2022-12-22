#!/usr/bin/python
# Author: Heini Bergsson Debes

import subprocess
import logging
import sys
from pathlib import Path
import math

def getStack(p, start, numBytes, param, force=False):
    p.stdin.write('md %s %s\n' %(start, numBytes))
    while True:
        line = p.stdout.readline().rstrip('\n')
        if line != '':
            if force: print(line)
            log(line, param)
            if '(mspdebug) md' in line: break

    stack = ''
    while True:
        line = p.stdout.readline().rstrip('\n')
        if line != '':
            if force: print(line)
            log(line, param)
            if line.count('|') >= 2 and line.count(': ') >= 1:
                stack += line.split(': ')[1].split('|')[0]
            if (len(stack.strip().split(' ')) == int(numBytes)) or (line.count('?') >= 8): break
    return stack.strip()

def log(msg, param):
    if param['verbose'] == True:
        logging.info(msg)
        print(msg)

def getMalcode(param, name):
    malcode = {'verb': '', 'hex': '', 'asm': ''}
    p = subprocess.run(['msp430-objdump -d %s/build/telosb/main.exe | awk -F"\n" -v RS="\n\n" \'$1 ~ /%s/\' | awk -F\';\' \'{print $1}\' | tail -n+2' %(param['malcodeDir'], name)], 
        check=True, capture_output=True, shell=True, text=True)
    log('> %s' %' '.join(p.args), param)

    for idx, line in enumerate(p.stdout.split('\n')):
        if idx+2 == len(p.stdout.split('\n')) and 'ret' in line: break # skip last RET instruction (it is for the C function, not the malcode)        
        if line != '':
            malcode['verb'] += line.strip() + '\n'
            malcode['hex']  += line.split(':')[1].strip().split('\t')[0].strip() + ' '
            tmp = ' '.join(line.split(':')[1].strip().split('\t')[1:])
            if tmp != '': malcode['asm'] += tmp + '\n'
    malcode['verb'] = malcode['verb'].strip()
    malcode['hex']  = malcode['hex'].strip()
    malcode['asm']  = malcode['asm'].strip()
    return malcode

def concat(malcode1, malcode2):
    malcode1['verb'] += '\n' + malcode2['verb']
    malcode1['hex']  += ' '  + malcode2['hex']
    malcode1['asm']  += '\n' + malcode2['asm']
    return malcode1

def compile(address, param):
    # compile reception handler
    p = subprocess.run(['make', '-C', '%s' %param['recvcodeDir'], 'telosb', 'optimizationLevel="-O%s"' %param['optimizationLevel'], 'AESimplementation=%s' %param['AESimplementation']['id'], 'ADDRse="%s"' %address['se']], check=True, capture_output=True)
    log('> %s' %' '.join(p.args), param)

    # retrieve address of the next instruction after the "BR #ADDRse" instruction
    p = subprocess.run(['msp430-objdump -d %s/build/telosb/main.exe | grep -A 1 "br[[:blank:]]*#%s"' %(param['recvcodeDir'], address['se'])], check=True, capture_output=True, shell=True, text=True)
    log('> %s' %' '.join(p.args), param)
    address['restore'] = p.stdout.split('\n')[1].strip().split(':')[0] # fills address['restore'] (which the Setup Engine, SE, branches to after executing)

    # compile malcode
    p = subprocess.run(['make', '-C', '%s' %param['malcodeDir'], 'telosb', 'PARAMruns="%s"' %param['runs'], 'PARAMcaptures="%s"' %param['captures'], 'PARAMperiod="%s"' %param['periodTicks'], 'PARAMrg="%s"' %param['rg'], 'ADDRtmp="%s"' %address['tmp'], 'ADDRrestore="0x%s"' %address['restore'], 'ADDRse="%s"' %address['se'], 'ADDRisri="%s"' %address['isri'], 'ADDRst="%s"' %address['st'], 'ADDRfe="%s"' %address['fe']], check=True, capture_output=True)
    log('> %s' %' '.join(p.args), param)
    return address, param

def run(p, param, address, malcode):
    filename = ''
    rid      = 1 # run ID (increments automatically when repeating the experiment)
    while True:
        filename = '%s/seqs-%s-O%s-%s-rid%s' %(param['sequenceDir'], param['AESimplementationName'], param['optimizationLevel'], param['freq'], rid)
        if Path(filename).exists():
            rid += 1
        else: break
    sequenceFile = open(filename, 'a')
    log('Writing sequences to: "%s"' %filename, param)

    try:
        # write the reception handler onto the sensor mote
        p.stdin.write('prog %s/build/telosb/main.exe\n' %param['recvcodeDir'])
        p.stdin.flush()
        while True:
            line = p.stdout.readline().rstrip('\n')
            if line != '':
                print(line)
                log(line, param)
                if 'Done,' in line: break # finished writing the program

        # mem = getStack(p, '0x2200', '1024', param)
        # print(mem)

        p.stdin.write('fill 0x2000 0x200 0\n')
        p.stdin.write('fill 0x2200 0x400 0\n')
        p.stdin.write('fill 0x3600 0x900 0\n')
        p.stdin.write('mw %s %s\n' %(address['se'], malcode['se']['hex']))
        p.stdin.write('mw %s %s\n' %(address['st'], malcode['st']['hex']))
        p.stdin.write('mw %s %s\n' %(address['fe'], malcode['fe']['hex']))
        p.stdin.write('mw %s %s\n' %(address['isri'], malcode['isri']['hex']))
        p.stdin.write('setbreak %s 0\n' %param['captureBreakpoint'])
        p.stdin.flush()

        # mem = getStack(p, '0x2200', '1024', param, True)
        # print(mem)

        # printedRun = False

        for run in range(0, int(param['runs'], 16)):
            log('Run: %s/%s' %(run+1, int(param['runs'], 16)), param)

            while True:
                line = p.stdout.readline().rstrip('\n')
                
                # if '(mspdebug) mw' in line or 'run' in line:
                #     if 'run' in line:
                #         if not printedRun:
                #             print(line)
                #             printedRun = True
                #     else: print(line)
                
                if line != '':
                    if 'setbreak' in line:
                        print('(mspdebug) setbreak 0x214c 0')
                    else: print(line)
                    if 'setbreak' in line: break



            print('(mspdebug) run')

            for capture in range(0, int(param['captures'], 16)):
                log('Capture: %s/%s' %(capture+1, int(param['captures'], 16)), param)
                p.stdin.write('run\n')
                while True:
                    line = p.stdout.readline().rstrip('\n')
                    
                    if line != '':
                        log(line, param)
                        if 'Breakpoint 0 triggered' in line: break

                # get stack contents and marshal bytes as words
                stack = getStack(p, '%s' %param['simulatedRgStart'], '%s' %param['simulatedRg'], param)
                stack = list(stack.strip().split())
                formattedStack = ''
                for byte in range(0, len(stack)):
                    formattedStack += stack[byte]
                    if (byte+1) % 2 == 0: formattedStack += ' '
                sequenceFile.write('%s\n' %formattedStack.strip()) # write captured sequence to file

        mem = getStack(p, '0x2200', '1024', param, True)
        # mem = list(mem.strip().split())
        # formattedStack = ''
        # for byte in range(0, len(mem)):
        #     formattedStack += mem[byte]
        #     if (byte+1) % 2 == 0: formattedStack += ' '
        # # print('%s\n' %formattedStack.strip())
        # bla = list(formattedStack.strip().split())
        # a = 1
        # for byte in range(0, len(bla)):
        #     if (a == 32):
        #         print("%s"%bla[byte])
        #         a = 0
        #     else:
        #         print("%s "%bla[byte], end='')
        #     a = a + 1
        # print('')

    except KeyboardInterrupt:
        sequenceFile.close()
        p.stdin.write('exit\n')
        p.kill()
        exit(1)
    sequenceFile.close()

def main(address, malcode, param):
    try:
        # open debugger
        p = subprocess.Popen(['mspdebug', 'tilib', '-d', '/dev/ttyACM0'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE, text=True, bufsize=1, universal_newlines=True)
        log('> %s' %' '.join(p.args), param)
        while True:
            line = p.stdout.readline().rstrip('\n')
            if line != '':
                # print(line)
                log(line, param)
                if line == 'Press Ctrl+D to quit.': break
                if 'device initialization failed' in line:
                    p.kill()
                    exit(1)

        for repetitionNr in range(0, param['repeatExperiment']):
            param['repetitionNr'] = repetitionNr + 1
            log('Repetition number: %s/%s' %(param['repetitionNr'], param['repeatExperiment']), param)
            for aesImplementationName, aesImplementation in param['AESimplementations'].items():
                param['AESimplementationName'] = aesImplementationName
                param['AESimplementation']     = aesImplementation
                for optimizationLevel, settings in aesImplementation['optimizationLevels'].items():
                    param['optimizationLevel'] = optimizationLevel

                    # hardcoded addresses of sub-exploits (could also be calculated programmatically)
                    address['tmp']     = '0x2200'
                    address['restore'] = ''
                    address['se']      = '0x2004'
                    address['isri']    = '0x202C'
                    address['st']      = '0x20C4'
                    address['fe']      = '0x20FC' # address['fe'] = hex(int(address['st'], 16) + len(malcode['st']['hex'].split(' ')))

                    for freq in param['freqs']:
                        param['freq']        = freq # the frequency is defined as the number of captures per unit time (CW), i.e., freq = CW / period
                        param['CW']          = settings['ET'] # the capture window (in ms)
                        param['CW']         += param['receptionDelay']
                        param['periodMS']    = param['CW'] / freq # period (ms) = CW / freq
                        param['periodTicks'] = '{0:#0{1}x}'.format(math.ceil(param['periodMS']*param['tpms']), 6) # period (in clock ticks)
                        param['captures']    = '{0:#0{1}x}'.format(int(freq), 4)

                        address, param = compile(address, param) # compile reception handler and malcode

                        # retrieve malcode
                        malcode['se']   = getMalcode(param, 'MalcodeC__setupEngine')
                        malcode['st']   = concat(getMalcode(param, 'MalcodeC__stackTracer'),    getMalcode(param, 'endST'))
                        malcode['fe']   = concat(getMalcode(param, 'MalcodeC__frameExtractor'), getMalcode(param, 'endFE'))
                        malcode['isri'] = getMalcode(param, 'MalcodeC__isrInjector')

                        # find location where FE performs one capture (used as a breakpoint to simulate captures, where we are not bound to the capture range that is hardcoded into the malcode)
                        for line in malcode['fe']['verb'].split('\n'):
                            if 'add' in line and '&0x2002,' in line and 'r13' in line:
                                diff = int(line.split(':')[0], 16) - int(malcode['fe']['verb'].split('\n')[0].split(':')[0], 16)
                                param['captureBreakpoint'] = hex(int(address['fe'], 16) + diff)
                                break

                        # print simulation configuration
                        log('Addresses: %s' %address, param)
                        log('Parameters: %s' %param, param)

                        run(p, param, address, malcode) # run the simulation

    except KeyboardInterrupt:
        p.stdin.write('exit\n')
        p.kill()
        exit(1)
    p.stdin.write('exit\n')
    p.kill()

if __name__ == '__main__':
    address                     = {}
    malcode                     = {}
    param                       = {}
    param['verbose']            = False
    param['malcodeDir']         = 'malcode'
    param['recvcodeDir']        = 'recv'
    param['outputDir']          = 'tmp/getStacks'
    param['sequenceDir']        = param['outputDir'] + '/Datasets'
    param['receptionDelay']     = 0  # time (in ms) until the reception handler is assumed to be invoked (OPTIONAL)
    param['tpms']               = 32 # ticks per ms (for the 32 kHz watch crystal 32 ticks = 1 ms)
    param['freqs']              = [17] # all frequencies (captures in a run/CW)
    param['runs']               = '0x01'   # the malcode runs only once (in which it captures the stack a number of times depending on the frequency)
    param['rg']                 = '0x0040' # the malcode captures only 4 bytes (the value is small to prevent needing a lot of memory if the number of captures becomes to high)
    param['simulatedRg']        = '64'     # capture 64 bytes using the debugger when the malcode would have done so
    param['simulatedRgStart']   = '@SP+10' # capture memory area starting at SP+10 byte
    param['repeatExperiment']   = 1 # how often to repeat the experiment (each repetition is dynamically assigned a unique run ID in the beginning of the run function, which is appended at the end of each of its datasets)
    param['AESimplementations'] = {
        # 'TIAES': {
        #     'id': 1,
        #     'optimizationLevels': {
        #         '0': { 'ET': 13.064 }, 
        #         '1': { 'ET': 4.16   }, 
        #         '2': { 'ET': 3.353  }, 
        #         '3': { 'ET': 2.126  }, 
        #         's': { 'ET': 3.937  }
        #     }
        # },
        'TinyAES': {
            'id': 2,
            'optimizationLevels': {
                # '0': { 'ET': 97.57 }, 
                # '1': { 'ET': 8.602 }, 
                # '2': { 'ET': 7.247 }, 
                # '3': { 'ET': 5.903 }, 
                's': { 'ET': 8.309 }
            }
        }
    }

    if len(sys.argv) > 1:
        for arg in sys.argv:
            if arg == '--verbose' or arg == '-v': param['verbose'] = True
    Path('%s' %param['sequenceDir']).mkdir(parents=True, exist_ok=True)
    with open('%s/inputParams.log' %param['outputDir'], 'w') as paramFile:
        for p, v in param.items(): paramFile.write('%s: %s\n' %(p, v))
    logging.root.handlers = []
    logging.basicConfig(filename='%s/getStacks.log' %param['outputDir'], level=logging.DEBUG, format='%(asctime)s:%(levelname)s:%(name)s:%(message)s')
    main(address, malcode, param)
