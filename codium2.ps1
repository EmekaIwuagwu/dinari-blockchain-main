# STEP 1: Remove the conflicting enhanced files
Remove-Item internal\mempool\mempool_enhanced.go -ErrorAction SilentlyContinue
Remove-Item internal\consensus\enhanced_pow.go -ErrorAction SilentlyContinue

# STEP 2: Fix remaining issues
# Fix crypto.S256 in hsm_interface.go - should be just S256()
(Get-Content pkg\crypto\hsm_interface.go) -replace 'crypto\.S256\(\)', 'S256()' | Set-Content pkg\crypto\hsm_interface.go

# Fix unused import in crypto_hardened.go
(Get-Content pkg\crypto\crypto_hardened.go) -replace '^\s*"encoding/hex"\s*$', '' | Set-Content pkg\crypto\crypto_hardened.go

# STEP 3: Fix storage compression - Badger v4 doesn't use compression enum
# Just remove the compression line
(Get-Content internal\storage\secure_storage.go) -replace '\s*opts = opts\.WithCompression\(.*\)', '' | Set-Content internal\storage\secure_storage.go

# STEP 4: Build
go build -o bin/dinari-node.exe ./cmd/dinari-node

# Check result
if ($LASTEXITCODE -eq 0) {
    Write-Host "`n=== BUILD SUCCESSFUL! ===" -ForegroundColor Green
    dir bin\dinari-node.exe
} else {
    Write-Host "`nBuild failed. Errors above." -ForegroundColor Red
}