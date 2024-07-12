# PortSeeker: Network Vulnerability Scanner

PortSeeker is a powerful network scanning tool that helps you identify open ports and potential vulnerabilities on target systems. It combines two key components:

- **Efficient Port Scanning (C++):** A fast and reliable port scanner implemented in C++, leveraging the `nmap` library for accurate port discovery and service detection.
- **Vulnerability Assessment (Python):** A Python module that integrates with the National Vulnerability Database (NVD) API to assess the severity of vulnerabilities found on open ports.

## Table of Contents

- [Installation](#installation)
- [Usage](#usage)
  - [Basic Port Scanning (C++)](#basic-port-scanning-c)
  - [Vulnerability Assessment with NVD API (Python)](#vulnerability-assessment-with-nvd-api-python)
- [Contributing](#contributing)
- [License](#license)
- [Troubleshooting](#troubleshooting)
- [Authors](#authors)

## Installation

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/yourusername/portseeker.git
   cd portseeker
   ```

2. **Install Dependencies:**

   - **For Python (NVD API Integration):**
     ```bash
     python3 -m venv venv      # Create a virtual environment
     source venv/bin/activate  # Activate the environment
     pip install -r requirements.txt
     ```

   - **For C++ (Core Scanner):**
     - **Arch-based Distros:**
       ```bash
       sudo pacman -S curl g++
       g++ compile.cpp -o prtker -std=c++11 -lcurl
       ```
     - **Debian-based Distros:**
       ```bash
       sudo bash start.sh
       ```

3. **Set up your NVD API Key:**
   - Obtain an API key from the [NVD website](https://nvd.nist.gov/developers/request-an-api-key).
   - Create a `.env` file in the root directory of the project.
   - Add the following line to your `.env` file, replacing `your_api_key_here` with your actual NVD API key:
     ```plaintext
     NVD_API_KEY=your_api_key_here
     ```

## Usage

### Basic Port Scanning (C++)

Run as root:
```bash
./prtker 192.168.0.1        # Basic Scan
./prtker 192.168.0.1 -sV  # Port Version Scan
./prtker 192.168.0.1 -p 80 # Scan a specific port (e.g., port 80)
```

### Vulnerability Assessment with NVD API (Python)

Activate your Python virtual environment:
```bash
source venv/bin/activate
```

Run the Python script:
```bash
python API/portseeker.py <target_IP_or_hostname>
```

**Example:**
```bash
python API/portseeker.py 192.168.1.100
```

**Output:**
The script will print a list of open ports and any associated vulnerabilities found in the NVD database.

**Example Output:**
```plaintext
Port: 22
CVE ID: CVE-2023-1234 
Description: A vulnerability in the SSH server...
CVSS Score: 7.5
---
Port: 80
CVE ID: CVE-2023-5678
Description: A vulnerability in the web server...
CVSS Score: 9.0
---
```

## Contributing

Contributions are welcome! If you'd like to contribute to the project, please follow these steps:

1. Fork the repository.
2. Create a new branch for your feature or bug fix.
3. Make your changes and commit them.
4. Push your changes to your fork.
5. Submit a pull request to the main repository.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Troubleshooting

- **Issue: `ModuleNotFoundError` when running the Python script.**
  - **Solution:** Ensure all Python dependencies are installed by running `pip install -r requirements.txt` within your activated virtual environment.

- **Issue: API key not working.**
  - **Solution:**
    - Verify that your API key is correct and has not expired.
    - You can obtain a new API key from the [NVD website](https://nvd.nist.gov/developers/request-an-api-key) if necessary.
    - Make sure the `.env` file is in the correct location (the project root directory) and has the correct format.

## Authors

- **Original C++ Port Scanner:**
  - @DigitalNinja00
  - @jsposu
  - @Cr0w-ui

- **Python NVD API Integration:**
  - @elliotsecops
