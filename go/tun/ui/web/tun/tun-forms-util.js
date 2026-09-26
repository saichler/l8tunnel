// Helpers shared by the l8tunnel form definitions.
(function() {
    'use strict';

    window.TunForms = {
        // readOnly marks form fields display-only: fields the backend sets
        // or protects (ImmutabilityUiAlignment).
        readOnly: function(fields) {
            return fields.map(f => Object.assign({}, f, { readOnly: true }));
        }
    };
})();
