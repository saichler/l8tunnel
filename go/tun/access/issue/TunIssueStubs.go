package issue

import (
	"github.com/saichler/l8srlz/go/serialize/object"
	"github.com/saichler/l8types/go/ifs"
)

func (h *IssueHandler) Put(ifs.IElements, ifs.IVNic) ifs.IElements {
	return object.NewError("TunIssue only accepts POST")
}

func (h *IssueHandler) Patch(ifs.IElements, ifs.IVNic) ifs.IElements {
	return object.NewError("TunIssue only accepts POST")
}

func (h *IssueHandler) Delete(ifs.IElements, ifs.IVNic) ifs.IElements {
	return object.NewError("TunIssue only accepts POST")
}

func (h *IssueHandler) Get(ifs.IElements, ifs.IVNic) ifs.IElements {
	return object.NewError("TunIssue only accepts POST")
}

func (h *IssueHandler) Failed(ifs.IElements, ifs.IVNic, *ifs.Message) ifs.IElements {
	return nil
}
