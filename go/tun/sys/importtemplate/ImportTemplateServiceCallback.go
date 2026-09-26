package importtemplate

import (
	l8common "github.com/saichler/l8common/go/common"
	"github.com/saichler/l8tunnel/go/tun/common"
	"github.com/saichler/l8types/go/ifs"
	"github.com/saichler/l8types/go/types/l8api"
)

func newImportTemplateServiceCallback() ifs.IServiceCallback {
	return common.NewCallback(common.Hooks{
		TypeName: "L8ImportTemplate",
		Check:    func(e interface{}) bool { _, ok := e.(*l8api.L8ImportTemplate); return ok },
		SetID: func(e interface{}) {
			l8common.GenerateID(&e.(*l8api.L8ImportTemplate).TemplateId)
		},
		Validate: func(e interface{}, action ifs.Action, _ ifs.IVNic) (interface{}, error) {
			if action == ifs.PATCH {
				return nil, nil
			}
			t := e.(*l8api.L8ImportTemplate)
			for _, f := range []struct{ value, name string }{
				{t.Name, "Name"}, {t.TargetModelType, "TargetModelType"}, {t.TargetServiceName, "TargetServiceName"},
			} {
				if err := l8common.ValidateRequired(f.value, f.name); err != nil {
					return nil, err
				}
			}
			return nil, nil
		},
	})
}
