// Mobile reference pickers for the l8tunnel Prime Objects (the desktop
// ones are in js/reference-registry-tun.js).
(function() {
    'use strict';

    const ref = Layer8RefFactory;
    Layer8MReferenceRegistry.register({
        ...ref.simple('TunToken', 'tokenId', 'name', 'Token'),
        ...ref.simple('TunRelay', 'relayId', 'relayId', 'Relay'),
        ...ref.simple('EdgeDomain', 'domainId', 'domain', 'Domain'),
        ...ref.simple('TunAgent', 'agentId', 'agentId', 'Agent')
    });
})();
