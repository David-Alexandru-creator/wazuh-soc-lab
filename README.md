# wazuh-soc-lab
Wazuh SIEM SOC Lab: Telemetry, FIM &amp; MITRE ATT&amp;CK Persistence Detection
Executive Summary

Dieses Repository dokumentiert den Aufbau und die praktische Evaluierung eines zentralen Security Operations Center Labs auf Basis von Wazuh SIEM. Ziel des Projekts war die Erfassung, Überwachung und Korrelation von Endpunkt-Telemetrie einer Windows-Zielumgebung sowie die forensische Identifikation realer Angriffsmuster (insbesondere Persistenz via Windows Task Scheduler, MITRE ATT&CK T1053.005).

Architecture Overview

Die Systemlandschaft unterteilt sich in einen containerisierten Wazuh SIEM-Stack und ein überwachtes Windows-Zielsystem.

+-------------------------------------------------+       +---------------------------------------------------+
|               Wazuh SIEM Server                 |       |                 Windows Target VM                 |
|            (Docker Single-Node Stack)           |       |                    (win-target)                   |
|                                                 |       |                                                   |
|  +------------------+   +--------------------+  | Sysmon|  +-------------------+     +-------------------+  |
|  |  Wazuh Manager   |   |  Wazuh Dashboard   |  |<------|  |   Wazuh Agent     |     |  Microsoft Sysmon |  |
|  | (192.168.0.160)  |   |    & Indexer       |  | Logs  |  |  (Agent ID: 001)  |---- |   & Audit Policy  |  |
|  +------------------+   +--------------------+  |       |  +-------------------+     +-------------------+  |
+-------------------------------------------------+       +---------------------------------------------------+

Key Findings & Detection Engineering

1. Endpoint Telemetry & Process Monitoring

Microsoft Sysmon: Integration als primäre Telemetrie-Quelle zur lückenlosen Protokollierung von Prozessstarts und Systemaktivitäten (nachgewiesen anhand einer initialen Serie von 28 korrelierten Events).

File Integrity Monitoring (FIM / Syscheck): Echtzeit-Überwachung kritischer Dateipfade. Testweise Erstellung und Löschung der Datei C:\Users\vboxuser\Desktop\test.txt im Benutzerverzeichnis:

File Added: Rule ID 554 (Level 5)

File Deleted: Rule ID 553 (Level 7)

2. False Positive Triage & Forensic Analysis

Im Rahmen der Security Analysis wurden wiederholte Schreibzugriffe im Windows-Stammverzeichnis getriggert (Executable dropped in Windows root folder, Rule ID 92217, MITRE T1570).

Analyst Evaluation: Die forensische Überprüfung klassifizierte das Verhalten als harmloses Grundrauschen (False Positive), welches durch Hintergrunddienste der VirtualBox Guest Additions verursacht wurde.

Threat Emulation: MITRE ATT&CK T1053.005 (Persistence)

Ein Kernfokus des Labors lag auf der Erkennung von Persistenz-Mechanismen via Windows Task Scheduler.

Endpoint Hardening

Da Windows das Erstellen geplanter Aufgaben standardmäßig nicht auditierte, wurde die lokale Audit-Policy gezielt erweitert: auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable

Result: Generierung der Windows Security Event ID 4698 (A scheduled task was created) bei jeder Task-Erstellung.

Adversary Emulation (Obfuscated Task Creation)

Simulation einer verdeckten Persistenz-Etablierung durch Erstellen des Tasks UpdaterCheck:

schtasks /create /tn "UpdaterCheck" /tr "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -NoProfile -File C:\path\to\script.ps1" /sc daily /st 09:00


SIEM Correlation & JSON Payload Analysis

Das Wazuh-SIEM erfasste die Manipulation zuverlässig. Die JSON-Payload-Analyse lieferte folgendes:

{
  "agent": {
    "id": "001",
    "name": "win-target",
    "ip": "10.0.2.15"
  },
  "data": {
    "win": {
      "system": {
        "eventID": "4698",
        "channel": "Security"
      },
      "eventdata": {
        "subjectUserName": "vboxuser",
        "subjectDomainName": "WIN-TARGET",
        "taskName": "\\UpdaterCheck",
        "taskContent": "<?xml version=\"1.0\"...><Command>powershell.exe</Command><Arguments>-ExecutionPolicy Bypass -WindowStyle Hidden -NoProfile...</Arguments>..."
      }
    }
  }
}

MITRE ATT&CK Mapping Overview
+-------------------+-----------------------------------------+--------------------+-------------------------+
| Taktik            | Technisches Event / Auslöser            | MITRE ID           | Wazuh Rule ID / Level   |
+-------------------+-----------------------------------------+--------------------+-------------------------+
| Persistence       | Scheduled Task Created (UpdaterCheck)   | T1053.005          | Event ID 4698           |
| Discovery         | Account Discovery via net.exe           | T1087              | Rule ID 92039 / Level 3 |
| Execution         | PowerShell Scripting & Command Exec     | T1059.001          | Rule ID 92201 / Level 9 |
| Command & Control | Ingress Tool Transfer                   | T1105              | Rule ID 92201 / Level 9 |
| Initial Access    | Windows User Logon Success              | T1078              | Rule ID 60106 / Level 3 |
+-------------------+-----------------------------------------+--------------------+-------------------------+


Das Labor belegt erfolgreich:

End-to-End Visibility: Erfassung aller System-, Prozess- und Dateiänderungen auf dem Windows-Target.

Proactive Hardening: Die Notwendigkeit angepasster Audit-Policies zur Aufdeckung verdeckter Persistenz-Vektoren.

Automated Framework Correlation: Automatische Einordnung von Security Events in das MITRE ATT&CK Framework zur Beschleunigung von Analysten-Reaktionen.
