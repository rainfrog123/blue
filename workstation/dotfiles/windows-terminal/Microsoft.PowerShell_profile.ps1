
function cu { & "c:\Users\jar71\blue\linux\extra\cursor\id_modifier_v5.ps1" }

# Linen — matches Windows Terminal scheme (see Tech/Hardware/Windows/Windows Terminal.md)
# ASCII only: Windows PowerShell 5.1 reads this file as the system ANSI code page,
# so a UTF-8 chevron became mojibake (a-circumflex euro).
if (Get-Command Set-PSReadLineOption -ErrorAction SilentlyContinue) {
    try {
        Set-PSReadLineOption -Colors @{
            Command            = '#5F7D58'
            Comment            = '#9A9288'
            ContinuationPrompt = '#9A9288'
            Default            = '#3F3A36'
            Emphasis           = '#C17B5A'
            Error              = '#B85E4E'
            Keyword            = '#B85E4E'
            Member             = '#4F7874'
            Number             = '#B85E4E'
            Operator           = '#8B847A'
            Parameter          = '#4F6F8C'
            Selection          = '#DDD2C2'
            String             = '#A98442'
            Type               = '#4F6F8C'
            Variable           = '#7A5F7C'
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
