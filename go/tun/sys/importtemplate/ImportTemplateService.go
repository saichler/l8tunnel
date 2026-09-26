// Package importtemplate is the ImprtTmpl service: the saved column
// mappings of the System ▸ Data Import tool. l8services' data import
// executes the imports, but leaves the template store to the application
// because it needs the database; only the backend activates it.
package importtemplate

import (
	l8common "github.com/saichler/l8common/go/common"
	"github.com/saichler/l8types/go/ifs"
	"github.com/saichler/l8types/go/types/l8api"
)

const (
	ServiceName = "ImprtTmpl"
	ServiceArea = byte(0)
)

// Activate activates the ORM-backed service.
func Activate(creds, dbname string, vnic ifs.IVNic) {
	sla := l8common.NewOrmSLA(ServiceName, ServiceArea, "TemplateId", newImportTemplateServiceCallback(),
		&l8api.L8ImportTemplate{}, &l8api.L8ImportTemplateList{})
	l8common.ActivateService(sla, creds, dbname, vnic)
}
