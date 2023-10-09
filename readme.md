# YARA and ClamAV Scanning
This Docker container and Python script is a malware scanning tool that utilizes YARA and ClamAV to scan files for potential malware. It is designed to be easy to use and extendable for various use cases.

## Features
* YARA Scanning: Utilizes YARA rules to scan files for patterns that indicate potential malware.
* ClamAV Scanning: Uses ClamAV to scan files for known malware signatures.
* Extensible: Easily add more YARA rules or integrate additional scanning tools.
* TBD add ML model
* TBD summary of results

## How to build and run
``` 
docker build -t malware-scanner .
docker run -it -v <local-path>:/app/files --entrypoint /bin/bash malware-scanner
```
Next we need to update ClamAV and start several services
``` 
freshclam
service clamav-daemon start
service clamav-freshclam start
```

## Adding More YARA Rules

The container leverages [YARA Rules](https://github.com/Yara-Rules/rules), however you can add more YARA rules by placing your .yar or .yara files in the /app/rules directory, and the script will automatically include them in the scanning process.

## Usage 
```
python app.py <file_path>
```


## Resources
* [YARA](https://virustotal.github.io/yara/)
* [Yextend](https://github.com/BayshoreNetworks/yextend)
* [Awesome YARA](https://github.com/InQuest/awesome-yara)
* [Writing better Yara rules in 2023…](https://www.hexacorn.com/blog/2023/08/26/writing-better-yara-rules-in-2023/)
* [Yara Scan Service](https://github.com/cocaman/yara-scan-service)
* [Florian Roth Neo23x0 ](https://github.com/Neo23x0)
    * [Neo23x0 signature-base](https://github.com/Neo23x0/signature-base)
    * [yarGen](https://github.com/Neo23x0/yarGen)
        * [Nextron Systems](https://www.nextron-systems.com/)
        * Comparison table [here](https://www.nextron-systems.com/compare-our-scanners/)
        * [Forensic Scanner Decision Tree](https://twitter.com/cyb3rops/status/1361980419223207936)
