# Fail on errors and don't open cover file
set -e
# clean up
rm -rf go.sum
rm -rf go.mod
rm -rf vendor

# fetch dependencies
#cp go.mod.main go.mod
go mod init
GOPROXY=direct GOPRIVATE=github.com go mod tidy
go mod vendor
