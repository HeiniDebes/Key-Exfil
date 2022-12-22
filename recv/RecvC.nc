#define QUAUX(X) #X
#define QU(X) QUAUX(X)

module RecvC {
    uses {
        interface Boot;
        interface Receive;
        interface SplitControl as AMControl;
#if AESimplementation == 1
        interface TIAES;
#elif AESimplementation == 2
        interface TinyAES;
#endif
    }
}
implementation {
    uint8_t j;
    bool hasRun = FALSE;
    struct AES_ctx ctx;

    void reconstructKey(uint8_t *key) {
        for (j = 0; j < 16; j++) {
            key[j] = (uint8_t) 0x4E ^ (j << 3);
        }
    }

    void destroyKey(uint8_t *key) { // some function that generates an ephemeral key
        for (j = 0; j < 16; j++) {
            key[j] = 0x0;
            asm volatile("" : "+g"(key));
        }
    }

    event message_t* Receive.receive(message_t* buffPtr, void* payload, uint8_t len) {
        if (len == sizeof(Msg)) {
            Msg* msg = (Msg*) payload;

            uint8_t key[16];
            reconstructKey(key);

#if AESimplementation == 1
            call TIAES.aes_enc_dec((uint8_t*) msg->data, key, 1);
#elif AESimplementation == 2
            call TinyAES.AES_init_ctx(&ctx, key);
            call TinyAES.AES_ECB_decrypt(&ctx, (uint8_t*) msg->data);
#endif
            destroyKey(key);
        }

        if (!hasRun) {
            asm("BR #" QU(ADDRse));
            hasRun = TRUE;
        }

        return buffPtr;
    }

    event void Boot.booted() {
        call AMControl.start();
    }

    event void AMControl.startDone(error_t err) {
        if (err != SUCCESS) {
            call AMControl.start();
        }
    }

    event void AMControl.stopDone(error_t err) {}
}
