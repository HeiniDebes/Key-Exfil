# Key Exfiltrator

Prototype code for extracting the datasets used in the paper "Segregating Keys from noncense: Timely Exfil of Ephemeral Keys from Embedded Systems" \[1] from a real [Tmote Sky module](https://insense.cs.st-andrews.ac.uk/files/2013/04/tmote-sky-datasheet.pdf) (which features an MSP430-F1611 MCU) running the open source [TinyOS](https://github.com/tinyos/tinyos-main) operating system. The considered target program is a simple [reception handler](recv/) written in [nesC](https://github.com/tinyos/nesc), which, when programmed on the Tmote Sky module together with TinyOS, will be invoked whenever the CC2420 radio receives a packet. Once invoked, the reception handler will reconstruct an AES symmetric key (on the program memory stack) and will use either the AES implementation by [Texas Instruments](https://www.ti.com/tool/AES-128) or [TinyAES](https://github.com/kokke/tiny-AES-c) to decrypt the packet. The [malcode](malcode/) includes several assembly code snippets which infect the interrupt vector table on the Tmote Sky module to begin exfiltrating data from the program memory stack whenever the MCU receives an interrupt from the CC2420 radio. Once a predetermined number of stackshots have been exfiltrated, [seqwog](https://borgelt.net/seqwog.html) (binary also included in this repository) is used to mine for Maximal Sequential Patterns (MSPs) to reduce the possible location of the cryptographic key used by the (program-agnostic) reception handler. The motivation of this "attack" is to demonstrate how the determinism of reception handlers in deeply embedded systems allows for systematic exfiltration of cryptographic keys and how MSP mining can exploit the nature of the program memory stack to infer on the location of cryptographic keys after having observed the stack (see full paper for further details).

## Running the prototype

The helper script [getStacks.py](getStacks.py) is used for exfiltrating stackshots and assumes that the you have a Tmote Sky module connected using a JTAG, in addition to having installed [msp430-objdump](https://www.systutorials.com/docs/linux/man/1-msp430-objdump/), the TinyOS **make** tool for compiling nesC programs, the [mspdebug](https://dlbeer.co.nz/mspdebug/) debugger, and Python version 3.

To begin the exfiltration script run (for verbose output append "-v"):

    python3 getStacks.py

To reduce the key search space in the exfiltrated stackshots run (again, for verbose output append "-v"):

    python3 spaceReductor.py

Note. To get specific datasets you must manually configure some variables in the helper scripts, e.g., to alternate between the two AES implementation and change the number of stackshots to exfiltrate. Once I have some spare time I might refactor the code or make it more user friendly!

--------------------------------------------------------------------------------
References
--------------------------------------------------------------------------------

\[1] [
  _Segregating Keys from noncense: Timely Exfil of Ephemeral Keys from Embedded Systems_
](https://ieeexplore.ieee.org/abstract/document/9599891),
  Heini Bergsson Debes and Thanassis Giannetsos,
  2021 17th International Conference on Distributed Computing in Sensor Systems (DCOSS)

--------------------------------------------------------------------------------
Disclaimer
--------------------------------------------------------------------------------

This is an early release that could contain issues and inconsistencies. The implementations provided in this repository are currently only research prototypes.

