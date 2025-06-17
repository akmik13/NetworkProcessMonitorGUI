# Network Process Monitor GUI (Python)

## Requirements
- Windows 10/11
- Python 3.11+
- pip

## Quick Start

1. Open a terminal (cmd or PowerShell) in this folder.
2. Create and activate a virtual environment:
   ```
   python -m venv venv
   venv\Scripts\activate
   ```
3. Install dependencies:
   ```
   pip install -r requirements.txt
   ```
4. Run the program:
   ```
   python main.py
   ```

## Features
- View and filter running processes
- Multi-select or auto-select by process name
- Monitor network activity for selected processes
- Save new remote IPs to `<process_name>.log`
- Resizable and dark-themed GUI
- Window and splitter positions are remembered

## Usage
- Use the filter to search for processes
- Select one or more processes (Ctrl/Shift or auto-select)
- Click "Start Scan" to monitor network activity
- Check the log area for connections and new IPs
- Stop monitoring with "Stop Scan"
- Terminate processes if needed

---

If you have issues, check your Python version and permissions. For questions, see the main README or contact the author.