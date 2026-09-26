package common

import (
	"fmt"
	"path"
	"strings"

	"github.com/saichler/l8srlz/go/serialize/object"
	"github.com/saichler/l8types/go/ifs"
	"github.com/saichler/l8types/go/types/l8api"
)

// CheckCertPath accepts only FileStore paths under CertStoragePrefix, with
// no "..", so an EdgeDomain can't point at another file (the FileStore
// itself doesn't guard against it; plan §16.4).
func CheckCertPath(p string) error {
	clean := path.Clean(p)
	if clean != p || !strings.HasPrefix(clean, CertStoragePrefix) || strings.Contains(p, "..") {
		return fmt.Errorf("storage path %q isn't an uploaded certificate file", p)
	}
	return nil
}

// FetchFile downloads a file from FileStore (in the web process) over the
// vnet.
func FetchFile(storagePath string, vnic ifs.IVNic) ([]byte, error) {
	if err := CheckCertPath(storagePath); err != nil {
		return nil, err
	}
	resp := vnic.Request("", FileStoreService, FileStoreArea, ifs.PUT,
		&l8api.L8FileDownloadRequest{StoragePath: storagePath}, RequestTimeout)
	if resp.Error() != nil {
		return nil, fmt.Errorf("download %s: %w", storagePath, resp.Error())
	}
	file, ok := resp.Element().(*l8api.L8FileDownloadResponse)
	if !ok || len(file.FileData) == 0 {
		return nil, fmt.Errorf("download %s: empty or unexpected response", storagePath)
	}
	return file.FileData, nil
}

// DeleteEntity deletes the object matching filter (by primary key), through
// the local handler when this process owns the service. l8common has no
// delete helper; this mirrors its PutEntity.
func DeleteEntity(serviceName string, serviceArea byte, filter interface{}, vnic ifs.IVNic) error {
	if h, ok := vnic.Resources().Services().ServiceHandler(serviceName, serviceArea); ok {
		return h.Delete(object.New(nil, filter), vnic).Error()
	}
	return vnic.Request("", serviceName, serviceArea, ifs.DELETE, filter, RequestTimeout).Error()
}

// PatchEntity patches the object (by primary key), through the local
// handler when this process owns the service.
func PatchEntity(serviceName string, serviceArea byte, entity interface{}, vnic ifs.IVNic) error {
	if h, ok := vnic.Resources().Services().ServiceHandler(serviceName, serviceArea); ok {
		return h.Patch(object.New(nil, entity), vnic).Error()
	}
	return vnic.Request("", serviceName, serviceArea, ifs.PATCH, entity, RequestTimeout).Error()
}
