
configuration MalcodeAppC {}
implementation {
    components MainC, MalcodeC as App;

    App.Boot -> MainC.Boot;
}
