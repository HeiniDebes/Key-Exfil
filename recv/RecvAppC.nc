#include "Recv.h"

configuration RecvAppC {}
implementation {
    components MainC, RecvC as App;
    components ActiveMessageC;
    components new AMReceiverC(AM_BLINKTORADIO);
#if AESimplementation == 1
    components TIAESM;
#elif AESimplementation == 2
    components TinyAESC;
#endif

    App.Boot      -> MainC.Boot;
    App.AMControl -> ActiveMessageC;
    App.Receive   -> AMReceiverC;
#if AESimplementation == 1
    App.TIAES   -> TIAESM.TIAES;
#elif AESimplementation == 2
    App.TinyAES -> TinyAESC.TinyAES;
#endif
}
