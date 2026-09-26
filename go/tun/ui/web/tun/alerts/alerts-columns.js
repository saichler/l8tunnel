// Table columns of the alert rules; the delivery log and integrations use
// l8notify's own column definitions.
(function() {
    'use strict';

    const col = Layer8ColumnFactory;
    const esc = Layer8DUtils.escapeHtml;

    TunAlerts.columns = {
        TunAlertRule: [
            ...col.col('name', 'Name'),
            ...col.enum('condition', 'Condition', TunAlerts.enums.CONDITION_VALUES, TunAlerts.render.condition),
            ...col.number('threshold', 'Threshold'),
            ...col.custom('targets', 'Targets', (item) => esc((item.targets || []).map(t => t.endpoint).join(', ') || '-'), { sortKey: false }),
            ...col.number('cooldownMinutes', 'Cooldown (min)'),
            ...col.custom('enabled', 'Enabled', (item) => TunAlerts.render.enabled(item.enabled)),
            ...col.custom('lastFired', 'Last fired', (item) => TunLive.render.when(item.lastFired))
        ],
        NotifyRecord: L8NotifyDeliveryLog.getColumns(),
        IntegrationConfig: L8NotifyIntegrationMgmt.getColumns()
    };

    TunAlerts.primaryKeys = { TunAlertRule: 'ruleId', NotifyRecord: 'notifyId', IntegrationConfig: 'integrationId' };
})();
