# Fix FeePerByte access - it's a method on Transaction, not a field on MempoolTx
$validator = Get-Content internal\mempool\validator.go
$validator = $validator -replace 'entries\[i\]\.FeePerByte', 'entries[i].Tx.FeePerByte()'
$validator = $validator -replace 'entries\[j\]\.FeePerByte', 'entries[j].Tx.FeePerByte()'
$validator | Set-Content internal\mempool\validator.go
# There's a space in "rateLimit er" - should be "rateLimiter"
(Get-Content internal\core\circuit_breaker.go) -replace 'rateLimit er\s+\*', 'rateLimiter         *' | Set-Content internal\core\circuit_breaker.go
# See what's in the api package
dir pkg\api\*.go | Select-Object Name
Get-Content pkg\api\server.go -Head 30