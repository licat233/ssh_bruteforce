# SSH Brute Force Tool - GUI Usage Guide

## Starting GUI Mode

```bash
./ssh_bruteforce --gui
```

## GUI Interface Features

### Configuration Area
- **Target IP**: SSH server IP address to attack
- **SSH Port**: SSH service port (default 22)
- **Username**: Username to brute force
- **Threads**: Number of concurrent threads (recommended 10-50)
- **Timeout(s)**: SSH connection timeout in seconds
- **Max Attempts**: Maximum password attempts (0=unlimited)
- **Max Time**: Maximum runtime in seconds (0=unlimited)

### Control Buttons
- **Load Config**: Load configuration from config.yaml file
- **Save Config**: Save current configuration to config.yaml file
- **Start Attack**: Begin SSH brute force process
- **Stop Attack**: Stop current attack process

### Status Display
- **Status**: Shows current running status
- **Progress Bar**: Shows attack progress
- **Log Area**: Real-time display of attack logs and results

## Usage Steps

1. Launch GUI application
2. Fill in target server information
3. Set attack parameters
4. Click "Start Attack" button
5. Monitor log output and progress
6. If password is found, it will be displayed in logs and saved to password.txt file

## Important Notes

- Ensure you use this tool only in legally authorized environments
- Recommend testing connectivity before starting large-scale attacks
- You can click "Stop Attack" at any time to interrupt the process
- Attack results are automatically saved to password.txt file
- Closing the window during an active attack will show a confirmation prompt

## Command Line Mode

If you don't use the --gui parameter, the program runs in traditional command line mode:

```bash
./ssh_bruteforce
```

In this mode, the program reads the config.yaml configuration file and starts attacking directly.

## Interface Language

The GUI interface uses English to ensure proper display across different systems and avoid character encoding issues that might cause garbled text.