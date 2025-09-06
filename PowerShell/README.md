# PowerShell Monitoring Scripts – SOC Lab

This folder contains two **PowerShell scripts** for monitoring files and checking their security using the VirusTotal API. These scripts are part of the SOC Lab repository.

---

## 1. `Api-Request.ps1` – VirusTotal File Check

**Purpose:**  
Checks the security of individual files using the VirusTotal API.

**Functionality:**

- Computes the SHA256 hash of a specified file.  
- Sends the hash to VirusTotal for analysis.  
- Interprets the API response and reports whether the file is safe or potentially malicious.  

**Parameters:**

| Parameter | Description |
|-----------|-------------|
| `FilePath` | Full path to the file to scan. |
| `ApiKey`  | VirusTotal API key. |

**Example Usage:**

```powershell
.\Api-Request.ps1 -FilePath "C:\Test\eicar.com" -ApiKey "YOUR_API_KEY"
```

---

## MonitoringFolders.ps1 – Folder Monitoring & Auto-Processing

**Purpose:**  
Monitors a folder for `.txt` files and moves them to a destination folder automatically.

**Functionality:**

- Checks the source folder every 2 seconds for `.txt` files.  
- Moves detected files to the destination folder.  
- Creates the destination folder if it does not exist.  
- Logs moved files and errors in the console.

**Parameters:**

| Parameter       | Description                           |
|-----------------|---------------------------------------|
| `SourcePath`      | Folder to monitor for `.txt` files.   |
| `DestinationPath` | Folder to move `.txt` files into.    |

**Example Usage:**

```powershell
.\MonitoringFolders.ps1 -SourcePath "C:\In" -DestinationPath "C:\Out"
```

**Notes:**

- Run PowerShell with sufficient permissions to read/write files in the monitored directories.  
- Use `Ctrl+C` to stop the folder monitoring script.  
- A valid VirusTotal API key is required for `Api-Request.ps1`.  

