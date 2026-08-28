
function cu { & "c:\Users\jar71\blue\linux\extra\cursor\id_modifier_v5.ps1" }

# Obsidian — matches Windows Terminal scheme (see Tech/Hardware/Windows/Windows Terminal.md)
# ASCII only: Windows PowerShell 5.1 reads this file as the system ANSI code page,
# so a UTF-8 chevron became mojibake (a-circumflex euro).
if (Get-Command Set-PSReadLineOption -ErrorAction SilentlyContinue) {
    try {
        Set-PSReadLineOption -Colors @{
            Command            = '#4F8A5B'
            Comment            = '#8A8A8A'
            ContinuationPrompt = '#8A8A8A'
            Default            = '#222222'
            Emphasis           = '#7C6AE6'
            Error              = '#C4554D'
            Keyword            = '#C4554D'
            Member             = '#3D7A76'
            Number             = '#C4554D'
            Operator           = '#8A8A8A'
            Parameter          = '#3D6A9A'
            Selection          = '#D8D2F0'
            String             = '#9A7B2F'
            Type               = '#3D6A9A'
            Variable           = '#7C6AE6'
        }
    } catch {}
}

function prompt {
    $here = $PWD.Path
    if ($here.StartsWith($HOME, [System.StringComparison]::OrdinalIgnoreCase)) {
        $here = '~' + $here.Substring($HOME.Length)
    }
    Write-Host ('{0}  {1}' -f $env:USERNAME, $here) -ForegroundColor DarkGray -NoNewline
    try { $Host.UI.RawUI.WindowTitle = 'PS' } catch {}
    ' > '
}
