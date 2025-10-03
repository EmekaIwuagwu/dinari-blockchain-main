Get-ChildItem -Recurse -Filter *.go | ForEach-Object {
    (Get-Content $_.FullName) -replace 'github.com/yourusername/dinari-blockchain', 'github.com/EmekaIwuagwu/dinari-blockchain' | Set-Content $_.FullName
}

# Also update go.mod
(Get-Content go.mod) -replace 'github.com/yourusername/dinari-blockchain', 'github.com/EmekaIwuagwu/dinari-blockchain' | Set-Content go.mod