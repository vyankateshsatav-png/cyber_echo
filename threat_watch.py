"""Microsoft Defender threat notifications.

Reads detections with Get-MpThreatDetection. This is read-only: nothing is
removed, quarantined or changed. New detections are emailed to the owner once.
"""

import base64
import hashlib
import json
import subprocess

import notifier
import security_store as store

PS_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
try { $null = Get-MpComputerStatus } catch {
    Write-Error ('Microsoft Defender is not available: ' + $_.Exception.Message)
    exit 2
}
$ErrorActionPreference = 'SilentlyContinue'
$names = @{}
foreach ($t in @(Get-MpThreat)) { $names[[string]$t.ThreatID] = [string]$t.ThreatName }
$items = @()
foreach ($d in @(Get-MpThreatDetection)) {
    $when = ''
    if ($d.InitialDetectionTime) { $when = $d.InitialDetectionTime.ToString('yyyy-MM-dd HH:mm:ss') }
    $items += [PSCustomObject]@{
        DetectionId   = [string]$d.DetectionID
        ThreatName    = [string]$names[[string]$d.ThreatID]
        Time          = $when
        Process       = [string]$d.ProcessName
        Resources     = (@($d.Resources) -join '; ')
        ActionSuccess = [string]$d.ActionSuccess
    }
}
ConvertTo-Json -InputObject @($items) -Compress -Depth 3
"""


def read_detections():
    """Return (list_of_detections, error_text). Never raises."""
    encoded = base64.b64encode(PS_SCRIPT.encode("utf-16-le")).decode("ascii")
    try:
        result = subprocess.run(
            [
                "powershell", "-NoProfile", "-NonInteractive",
                "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded,
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return None, f"Could not run PowerShell: {error}"

    if result.returncode != 0:
        return None, (result.stderr or "Defender query failed").strip()

    output = result.stdout.strip()
    if not output:
        return [], None
    try:
        data = json.loads(output)
    except json.JSONDecodeError as error:
        return None, f"Could not read the Defender output: {error}"
    if isinstance(data, dict):
        data = [data]
    return data, None


def detection_key(item):
    if item.get("DetectionId"):
        return str(item["DetectionId"])
    return hashlib.sha256(json.dumps(item, sort_keys=True).encode("utf-8")).hexdigest()


def new_detections(detections, is_seen=store.threat_seen):
    """Return (key, item) pairs for detections not reported yet."""
    fresh = []
    for item in detections:
        key = detection_key(item)
        if not is_seen(key):
            fresh.append((key, item))
    return fresh


def threat_email(fresh):
    device = notifier.device_name()
    lines = [
        "CYBER ECHO THREAT REPORT",
        "",
        f"Device: {device}",
        "Source: Microsoft Defender (read-only check)",
        "",
    ]
    for _, item in fresh[:20]:
        succeeded = str(item.get("ActionSuccess", "")).lower() == "true"
        action = "succeeded" if succeeded else "not confirmed"
        lines.append(f"Threat : {item.get('ThreatName') or 'unknown name'}")
        lines.append(f"Time   : {item.get('Time') or 'unknown'}")
        lines.append(f"Process: {item.get('Process') or 'unknown'}")
        lines.append(f"Files  : {item.get('Resources') or 'unknown'}")
        lines.append(f"Action : Defender action {action}")
        lines.append("")
    if len(fresh) > 20:
        lines.append(f"... and {len(fresh) - 20} more. See Windows Security > Protection history.")
    lines.append("CYBER ECHO did not delete or quarantine anything.")
    lines.append("Review Windows Security > Protection history.")
    subject = f"[CYBER ECHO] {len(fresh)} new threat detection(s) on {device}"
    return subject, "\n".join(lines)


def check_and_notify():
    """Email about new detections. Returns the number of new detections found."""
    detections, error = read_detections()
    if error:
        print(f"[THREAT WATCH] {error}")
        return 0
    fresh = new_detections(detections)
    if not fresh:
        return 0

    subject, body = threat_email(fresh)
    ok, info = notifier.send_email(subject, body)
    if ok:
        for key, item in fresh:
            store.mark_threat_seen(key, item.get("ThreatName"))
        print(f"[THREAT WATCH] Emailed {len(fresh)} new detection(s).")
    else:
        print(f"[THREAT WATCH] {len(fresh)} new detection(s) not emailed yet: {info}")
    return len(fresh)
