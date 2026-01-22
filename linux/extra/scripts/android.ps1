function adb_command($command) {
    $result = Start-Process -FilePath "C:\Users\jar71\Downloads\scrcpy-win64-v2.3.1\scrcpy-win64-v2.3.1\adb" -ArgumentList $command -NoNewWindow -PassThru -Wait
    if ($result.ExitCode -ne 0) {
        Write-Error "Error executing command: $command"
    } else {
        $output = & "C:\Users\jar71\Downloads\scrcpy-win64-v2.3.1\adb" $command
        Write-Output $output
    }
}

function click($x, $y) {
    adb_command "shell input tap $x $y"
}

function main {
    # Example usage: clicking on (500, 1000) coordinates
    $coordinates = @(
        @{x=500; y=1000},
        @{x=600; y=1100},
        @{x=700; y=1200}
    )

    foreach ($coord in $coordinates) {
        click $coord.x $coord.y
        Start-Sleep -Seconds 1  # Wait for 1 second before the next click (adjust as needed)
    }
}

main
