// The alert rule form; the delivery log and integrations use l8notify's
// own form definitions.
(function() {
    'use strict';

    const f = Layer8FormFactory;
    const ro = TunForms.readOnly;
    const targets = L8NotifyTargetEditor.getInlineTableDef();

    TunAlerts.forms = {
        TunAlertRule: f.form('Alert rule', [
            f.section('Rule', [
                ...f.text('name', 'Name', true),
                ...f.select('condition', 'Condition', TunAlerts.enums.CONDITION, true),
                ...f.number('threshold', 'Threshold (days for certificates, minutes for offline)'),
                ...f.reference('tokenId', 'Token (token offline)', 'TunToken'),
                ...f.text('agentId', 'Agent ID (agent offline)'),
                ...f.number('cooldownMinutes', 'Cooldown (minutes, 0 = 60)'),
                ...f.checkbox('enabled', 'Enabled'),
                ...ro([...f.datetime('lastFired', 'Last fired')])
            ]),
            f.section('Targets', [...f.inlineTable(targets.key, targets.label, targets.columns)])
        ]),
        NotifyRecord: L8NotifyDeliveryLog.getFormDefinition(),
        IntegrationConfig: L8NotifyIntegrationMgmt.getFormDefinition()
    };
})();
