// Enums of the access services. The token policy's tunnel types reuse the
// live tables' TUNNEL_TYPE (TunLive loads first).
(function() {
    'use strict';

    window.TunAccess = window.TunAccess || {};
    TunAccess.enums = {
        TUNNEL_TYPE: TunLive.enums.TUNNEL_TYPE
    };
    TunAccess.render = {
        revoked: (v) => Layer8DRenderers.renderBoolean(v, { trueText: 'Revoked', falseText: 'Valid',
            trueClass: 'layer8d-status-terminated', falseClass: 'layer8d-status-active' })
    };
})();
