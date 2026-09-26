// Reference pickers for the l8tunnel Prime Objects.
(function() {
    'use strict';

    const ref = Layer8RefFactory;
    Layer8DReferenceRegistry.register({
        ...ref.simple('TunToken', 'tokenId', 'name', 'Token'),
        ...ref.simple('TunRelay', 'relayId', 'relayId', 'Relay'),
        ...ref.simple('EdgeDomain', 'domainId', 'domain', 'Domain'),
        ...ref.simple('TunAgent', 'agentId', 'agentId', 'Agent')
    });
})();
