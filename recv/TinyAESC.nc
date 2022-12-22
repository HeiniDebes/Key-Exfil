configuration TinyAESC {
    provides interface TinyAES;
}
implementation {
    components TinyAESM;
    TinyAES = TinyAESM;
}
