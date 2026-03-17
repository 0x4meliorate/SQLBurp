# 🗡️ SQLBurp

![Java](https://img.shields.io/badge/java-17+-blue?logo=java&logoColor=white)
![Burp Suite](https://img.shields.io/badge/Burp_Suite-Extension-orange)
![sqlmap](https://img.shields.io/badge/sqlmap-REST%20API-red)

A Burp Suite extension that integrates the sqlmap REST API into your testing workflow. Send requests from anywhere in Burp, track multiple scans concurrently, and review persisted results.

## ⚙️ Requirements

- Burp Suite
- [Java JDK](https://www.oracle.com/java/technologies/downloads/) (JDK 17 or later)
- [sqlmap](https://github.com/sqlmapproject/sqlmap) installed and accessible

## 🚀 Setup

**1. Get the jar**

Download the latest `SQLBurp.jar` from the [Releases](../../releases) page, or build it yourself:

Install the JDK from `https://www.oracle.com/java/technologies/downloads/`, then install Gradle via [Scoop](https://scoop.sh):

```powershell
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
irm get.scoop.sh | iex
scoop install gradle
```

Then in the project folder:

```powershell
gradle wrapper
.\gradlew.bat jar
```

The jar is output to `build\libs\SQLBurp.jar`.

**2. Start the sqlmap REST API**

```bash
python sqlmapapi.py -s -H 127.0.0.1 -p 8775
```

No `--database` flag needed.

**3. Load the extension**

`Extensions` -> `Add` -> `Extension Type: Java` -> select `SQLBurp.jar`.

The **SQLBurp** tab will appear. Use the **Ping** button to verify the API is reachable.

## 📖 Usage

### Sending a request

Right-click any request in Proxy, Repeater, Target, or anywhere else in Burp and select **Send to SQLMap API**. The scan is submitted immediately using the current configuration panel settings.

### ⚡ Configuration panel

| Setting | Description |
| --- | --- |
| API URL | Address of the running sqlmapapi server |
| Level | Detection level (1-5) |
| Risk | Risk level (1-3) |
| Threads | Concurrent HTTP requests (1-10) |
| Technique | SQLi techniques to test (e.g. `BEUSTQ`) |
| DBMS | Force a specific backend, or leave as `(auto)` |
| Tamper | Comma-separated tamper scripts (e.g. `space2comment,randomcase`) |
| Batch | Non-interactive mode (always use defaults) |
| Random Agent | Randomise the User-Agent header |
| Parse Forms | Discover and test forms on the target page |
| Enum DBs | Enumerate databases on injection confirmation |
| Current User | Retrieve the current database user |
| Banner | Retrieve the DBMS banner |
| Is DBA | Check whether the current user has DBA privileges |
| Poll (s) | How often to poll for status updates |

Settings are snapshotted at submission time, so each scan row remembers the exact options it was run with. Changing the panel after submission does not affect running scans.

### 📊 Scan table

Each submitted request appears as a row. Columns are sortable. Click any row to view its live log and option snapshot in the detail panel below.

| Status | Meaning |
| --- | --- |
| Queued | Submitted, not yet started |
| Running | Actively scanning |
| Finished | Completed, no injections found |
| Vulnerable | Injection confirmed |
| Stopped | Manually stopped |
| Error | Scan failed |

### 🖱️ Right-click menu

| Action | Description |
| --- | --- |
| Stop Task | Sends a stop signal to sqlmapapi and marks the scan as Stopped |
| Delete Task | Stops the scan, deletes it from the API, and removes all persisted data |
| Remove Row | Removes the row and purges persisted data without touching the API |

### 🧰 Toolbar

| Button | Description |
| --- | --- |
| Stop All | Stops all currently running scans |
| Remove Finished | Removes all Finished, Stopped, and Error rows and purges their data |

## 💾 Persistence

All scan data is stored in the Burp project file via the Montoya API's `persistence().extensionData()`. This is natively project-scoped, so opening a different Burp project shows only that project's scans with no cross-contamination between engagements.

- **No external database** - sqlmapapi can be restarted freely without losing any scan history.
- **Incremental saving** - the scan record is written on start and updated on every log line, so data is preserved even if Burp is closed mid-scan.
- **Automatic restore** - all scans for the current project are loaded back into the table when the extension initialises.

Deleting a scan via right-click or Remove Finished purges it from both the API and the project permanently.

## 📝 Notes

- The extension deduplicates requests, so sending the same request multiple times in a single action will only create one scan.
- HTTPS targets are detected automatically from the HTTP service; `forceSSL` is set accordingly.
- For scans that were still running when the extension was last closed, the extension will attempt to reconnect to the live API on load. If the API has been restarted in the interim, those scans will show their last known status.
