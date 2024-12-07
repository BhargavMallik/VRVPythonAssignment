# Log Analysis Security Tool

## Overview

This Python script is a powerful log analysis tool designed to help security professionals and system administrators analyze web server logs for potential security threats and traffic patterns. The script performs a comprehensive analysis of log files, providing insights into:

- IP address request frequencies
- Most accessed endpoints
- Potential suspicious activities based on failed login attempts

## Features

- **IP Request Tracking**: Counts and ranks requests from different IP addresses
- **Endpoint Analysis**: Identifies the most frequently accessed endpoint
- **Suspicious Activity Detection**: Flags IP addresses with multiple failed login attempts
- **CSV Export**: Saves detailed analysis results in a structured CSV file
- **Configurable Threshold**: Easily adjust the failed login attempt threshold

## Prerequisites

- Python 3.7+
- Standard Python libraries (csv, collections, re)

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/log-analysis-tool.git
   cd log-analysis-tool
   ```

2. Ensure you have Python installed on your system

## Configuration

Before running the script, modify the following variables in the script:

- `FAILED_LOGIN_THRESHOLD`: Set the number of failed login attempts that trigger a suspicious activity flag (default: 5)
- `LOG_FILE`: Path to your log file (default: "sample.log")
- `OUTPUT_FILE`: Path for the CSV output file (default: "log_analysis_results.csv")

## Usage

1. Prepare your log file:
   - Ensure the log file follows a standard format with IP addresses, HTTP methods, and endpoints
   - Place the log file in the same directory or specify the full path

2. Run the script:
   ```
   python log_analysis.py
   ```

3. Review the console output and check the generated CSV file

## Output

The script generates two types of output:

### Console Output
- Requests per IP Address
- Most Frequently Accessed Endpoint
- Suspicious Activity Details

### CSV File (`log_analysis_results.csv`)
The CSV file contains three sections:
1. IP Address and Request Count
2. Most Accessed Endpoint
3. Suspicious Activity (IP addresses with multiple failed login attempts)

## Example Log Format

The script supports log lines similar to this format:
```
192.168.1.100 - - [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326
```

## Customization

You can easily modify the script to:
- Change the suspicious activity detection criteria
- Add more detailed log parsing
- Implement additional security checks

## Security Notes

- Always ensure log files do not contain sensitive information
- Use appropriate file permissions when handling log files
- Consider using this tool as part of a broader security monitoring strategy

## Limitations

- Designed for standard web server logs
- Assumes a specific log format
- Does not perform real-time monitoring

## Contributing

Contributions are welcome! Please submit pull requests or open issues on the GitHub repository.

## License

[Specify your license here, e.g., MIT License]

## Disclaimer

This tool is for educational and security assessment purposes. Always use it responsibly and in compliance with your organization's policies.