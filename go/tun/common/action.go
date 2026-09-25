package common

import (
	"github.com/saichler/l8srlz/go/serialize/object"
	"github.com/saichler/l8types/go/ifs"
)

// ActionStubs completes an IServiceHandler for a POST-only action service
// (TunIssue, TunClaim, TunCtl): embed it and implement Post.
//
// The framework builds handler instances itself (by type name), so a
// handler can't carry state in its own fields: pass it with sla.SetArgs
// and read it back with Arg.
type ActionStubs struct {
	SLA *ifs.ServiceLevelAgreement
}

func (a *ActionStubs) Activate(sla *ifs.ServiceLevelAgreement, _ ifs.IVNic) error {
	a.SLA = sla
	return nil
}

func (a *ActionStubs) DeActivate() error { return nil }

// Arg returns the i-th value given to sla.SetArgs.
func (a *ActionStubs) Arg(i int) interface{} {
	if a.SLA == nil || len(a.SLA.Args()) <= i {
		return nil
	}
	return a.SLA.Args()[i]
}

func (a *ActionStubs) Put(ifs.IElements, ifs.IVNic) ifs.IElements {
	return object.NewError("this service only accepts POST")
}

func (a *ActionStubs) Patch(ifs.IElements, ifs.IVNic) ifs.IElements {
	return object.NewError("this service only accepts POST")
}

func (a *ActionStubs) Delete(ifs.IElements, ifs.IVNic) ifs.IElements {
	return object.NewError("this service only accepts POST")
}

func (a *ActionStubs) Get(ifs.IElements, ifs.IVNic) ifs.IElements {
	return object.NewError("this service only accepts POST")
}

func (a *ActionStubs) Failed(ifs.IElements, ifs.IVNic, *ifs.Message) ifs.IElements { return nil }

func (a *ActionStubs) TransactionConfig() ifs.ITransactionConfig { return nil }

func (a *ActionStubs) WebService() ifs.IWebService { return a.SLA.WebService() }
