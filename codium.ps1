# Fix 1: Remove ErrInvalidSignature redeclaration in signature.go
$sig = Get-Content pkg\crypto\signature.go
$sig = $sig -replace '^\s*ErrInvalidSignature\s*=.*$', '' | Where-Object { $_ -ne '' }
$sig | Set-Content pkg\crypto\signature.go

# Fix 2: Change badger.Snappy to badger.ZSTD in secure_storage.go  
(Get-Content internal\storage\secure_storage.go) -replace 'badger\.Snappy', 'badger.ZSTD' | Set-Content internal\storage\secure_storage.go

# Fix 3: Check mempool_enhanced.go for redeclarations
Get-Content internal\mempool\mempool_enhanced.go -Head 40