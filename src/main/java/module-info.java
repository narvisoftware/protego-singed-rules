module app.narvi.protego.basic {
    requires transitive app.narvi.protego.core;
    requires static org.slf4j;
//    requires com.example.utils;
    exports app.narvi.authz.rules;
    uses app.narvi.authz.AuditProvider;
}