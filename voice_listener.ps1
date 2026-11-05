# Offline voice commands for the DORE Afloat demo, using the Windows speech recognizer.
# The server starts this script. "DORE" is listed as "door" because that is how it sounds.
param([int]$Port = 8765, [double]$MinConfidence = 0.5, [double]$RecordConfidence = 0.6, [string]$Wav = "")

Add-Type -AssemblyName System.Speech
[System.Net.WebRequest]::DefaultWebProxy = $null  # Local calls only; skips slow proxy lookup.

$commands = @{
    "door shipboard fire"                          = "fire"
    "door shipboard collision"                     = "collision"
    "door shipboard man overboard"                 = "overboard"
    "door shipboard man overboard port side"       = "overboard_port"
    "door shipboard man overboard starboard side"  = "overboard_starboard"
    "door step complete"                           = "done"
    "door repeat the steps"                        = "repeat"
    "door watch brief"                             = "brief"
    "door response summary"                        = "summary"
    "door casualty is secured"                     = "end"
    "door log boundaries set"                      = "status_boundaries"
    "door log fuel secured"                        = "status_fuel"
    "door log ventilation secured"                 = "status_ventilation"
    "door log firemain pressurized"                = "status_firemain"
    "door log lookouts posted"                     = "status_lookouts"
}

$recognizer = [System.Speech.Recognition.SpeechRecognitionEngine]::InstalledRecognizers() |
    Where-Object { $_.Culture.Name -eq "en-US" } | Select-Object -First 1
if (-not $recognizer) { Write-Output "No en-US speech recognizer found."; exit 1 }

$engine = New-Object System.Speech.Recognition.SpeechRecognitionEngine($recognizer)
$choices = New-Object System.Speech.Recognition.Choices
$choices.Add([string[]]$commands.Keys)
# Exact phrases only. Wildcards made any sound match with high confidence.
$builder = New-Object System.Speech.Recognition.GrammarBuilder($choices)
$builder.Culture = $recognizer.Culture
$grammar = New-Object System.Speech.Recognition.Grammar($builder)
$grammar.Name = "commands"
$engine.LoadGrammar($grammar)
$engine.BabbleTimeout = [TimeSpan]::FromSeconds(4)
$engine.EndSilenceTimeout = [TimeSpan]::FromSeconds(0.4)

function Find-Command($result) {
    # Push-to-talk gates the mic, so the bar can sit low. Commands that change the record need more.
    if (-not $result -or -not $commands.ContainsKey($result.Text)) { return $null }
    $changesRecord = $commands[$result.Text] -eq "done" -or $commands[$result.Text] -eq "end" -or $commands[$result.Text] -like "status_*"
    $needed = if ($changesRecord) { $RecordConfidence } else { $MinConfidence }
    if ($result.Confidence -ge $needed) { return $result.Text }
    return $null
}

function Send-Voice($command, $phrase, $confidence, $audio = $null) {
    $started = 0.0
    $seconds = 0.0
    if ($audio) {
        $started = ([DateTimeOffset]$audio.StartTime).ToUnixTimeMilliseconds() / 1000
        $seconds = $audio.Duration.TotalSeconds
    }
    $body = @{ command = $command; phrase = $phrase; confidence = $confidence; started = $started; seconds = $seconds; token = $env:DORE_VOICE_TOKEN } | ConvertTo-Json
    Invoke-RestMethod -Uri "http://127.0.0.1:$Port/api/voice" -Method Post -Body $body -ContentType "application/json" -TimeoutSec 3
}

if ($Wav) {
    # Test path: runs a recorded file through the same recognizer and rules.
    $engine.SetInputToWaveFile($Wav)
    $result = $engine.Recognize()
    $found = Find-Command $result
    if ($found) { Write-Output "COMMAND $($commands[$found]) ($($result.Confidence))" }
    elseif ($result) { Write-Output "ignored: $($result.Text) ($($result.Confidence))" }
    else { Write-Output "ignored: nothing" }
    exit 0
}

$engine.SetInputToDefaultAudioDevice()
Register-ObjectEvent -InputObject $engine -EventName SpeechRecognized -SourceIdentifier heard | Out-Null
Register-ObjectEvent -InputObject $engine -EventName SpeechRecognitionRejected -SourceIdentifier rejected | Out-Null

# The recognizer runs only while the talk key is held, so each command starts clean.
$failures = 0
$running = $false
while ($failures -lt 30) {  # Stop once the server has gone away.
    $event = Wait-Event -Timeout 0.1 | Select-Object -First 1
    try {
        if ($event) {
            $result = $event.SourceEventArgs.Result
            $kind = $event.SourceIdentifier
            Remove-Event -EventIdentifier $event.EventIdentifier
            $found = if ($kind -eq "heard") { Find-Command $result } else { $null }
            if ($found) {
                Send-Voice $commands[$found] $found $result.Confidence $result.Audio | Out-Null
            } elseif ($result -and $result.Text) {
                Send-Voice "heard" "$($result.Text)" $result.Confidence | Out-Null
            }
        }
        $state = Send-Voice "level" $(if ($running) { "running" } else { "idle" }) $engine.AudioLevel
        if ($state.talk -and -not $running) {
            $engine.RecognizeAsync([System.Speech.Recognition.RecognizeMode]::Multiple)
            $running = $true
        } elseif (-not $state.talk -and $running) {
            $engine.RecognizeAsyncCancel()
            $running = $false
        }
        $failures = 0
    } catch {
        $failures += 1
    }
}
$engine.Dispose()
