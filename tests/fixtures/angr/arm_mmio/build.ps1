$ErrorActionPreference = "Stop"

$repositoryRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..\..\..")
$venvPython = Join-Path $repositoryRoot ".venv\Scripts\python.exe"
if (Test-Path -LiteralPath $venvPython) {
    $python = $venvPython
} else {
    $python = (Get-Command python -ErrorAction Stop).Source
}

& $python (Join-Path $PSScriptRoot "generate_fixture.py")
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}
