// Enums of the alert rules. Values match proto/tun.proto.
(function() {
    'use strict';

    window.TunAlerts = window.TunAlerts || {};
    const CONDITION = Layer8EnumFactory.withValues([
        ['Unspecified', null], ['Relay lost', 'relaylost'], ['No ready relay', 'noready'],
        ['Edge pool down', 'pooldown'], ['Certificate expiring', 'certexpiring'],
        ['Edge listener failed', 'listenerfailed'], ['Token offline', 'tokenoffline'], ['Agent offline', 'agentoffline']
    ]);
    TunAlerts.enums = { CONDITION: CONDITION.enum, CONDITION_VALUES: CONDITION.values };
    TunAlerts.render = {
        condition: (v) => Layer8DRenderers.renderEnum(v, CONDITION.enum),
        enabled: (v) => Layer8DRenderers.renderBoolean(v, { trueText: 'Enabled', falseText: 'Disabled' })
    };
})();
