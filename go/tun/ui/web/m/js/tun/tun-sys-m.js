// Mobile System: service health (card columns over L8Health, as the other
// Layer 8 projects do -- l8ui has no mobile health module) and the shared
// l8security users, roles, credentials and security events.
(function() {
    'use strict';

    const col = Layer8ColumnFactory;

    function formatBytes(bytes) {
        if (!bytes) return '0 B';
        const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(1024));
        return i === 0 ? bytes + ' B' : (bytes / Math.pow(1024, i)).toFixed(2) + ' ' + sizes[i];
    }

    // since formats the time from a millisecond timestamp to now.
    function since(ms) {
        const start = Number(ms || 0);
        if (!start) return '00:00:00';
        const s = Math.max(0, Math.floor((Date.now() - start) / 1000));
        return String(Math.floor(s / 3600)).padStart(2, '0') + ':' +
            String(Math.floor((s % 3600) / 60)).padStart(2, '0') + ':' + String(s % 60).padStart(2, '0');
    }

    const health = {
        transformData: function(item) {
            if (!item.stats) return null;
            return {
                service: item.alias || 'Unknown',
                rx: (item.stats.rxMsgCount || 0).toLocaleString(),
                tx: (item.stats.txMsgCount || 0).toLocaleString(),
                memory: formatBytes(item.stats.memoryUsage || 0),
                cpuPercent: (item.stats.cpuUsage || 0).toFixed(2) + '%',
                upTime: since(item.startTime),
                lastPulse: since(item.stats.lastMsgTime)
            };
        },
        columns: {
            L8Health: [
                Object.assign({}, col.custom('service', 'Service', null, { sortKey: 'alias', filterKey: 'alias' })[0], { primary: true }),
                ...col.custom('cpuPercent', 'CPU %', null, { sortKey: 'stats.cpuUsage' }),
                ...col.custom('memory', 'Memory', null, { sortKey: 'stats.memoryUsage' }),
                ...col.custom('rx', 'RX', null, { sortKey: 'stats.rxMsgCount' }),
                ...col.custom('tx', 'TX', null, { sortKey: 'stats.txMsgCount' }),
                ...col.custom('upTime', 'Up time', null, { sortKey: 'startTime' }),
                ...col.custom('lastPulse', 'Last pulse', null, { sortKey: 'stats.lastMsgTime' })
            ]
        },
        getTransformData: (model) => model === 'L8Health' ? health.transformData : null
    };

    Layer8MModuleRegistry.create('MobileTunSys', { 'Health': health, 'Security': L8Security });
})();
