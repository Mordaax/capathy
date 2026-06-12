# Synthetic extraction fixture; never execute.
function Fetch-Example {
    $url = 'https://example.invalid/payload'
    Invoke-WebRequest -Uri $url | Write-Output
}
Write-Output 'ready'
