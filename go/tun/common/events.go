package common

import (
	"github.com/saichler/l8types/go/ifs"
	"github.com/saichler/l8types/go/types/l8events"
)

// SourceType marks every event l8tunnel posts.
const SourceType = "l8tunnel"

// PostEvent records an event through the required l8events service (fire
// and forget).
func PostEvent(vnic ifs.IVNic, category l8events.EventCategory, eventType string, severity l8events.Severity,
	sourceID, sourceName, message string, attributes map[string]string) {
	events := vnic.Resources().Events()
	if events == nil {
		vnic.Resources().Logger().Warning("no events service; dropped event ", eventType, ": ", message)
		return
	}
	events.PostEvent(category, eventType, severity, sourceID, sourceName, SourceType, message, attributes)
}

// PostSecurityEvent records a security event (tokens, certificates, keys).
func PostSecurityEvent(vnic ifs.IVNic, eventType, sourceID, sourceName, message string) {
	PostEvent(vnic, l8events.EventCategory_EVENT_CATEGORY_SECURITY, eventType, l8events.Severity_SEVERITY_INFO,
		sourceID, sourceName, message, nil)
}
