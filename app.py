import subprocess
import sys
import glob
import re

def extract_rules(yara_output):
    # Adjusted the regular expression to match the rule names from the YARA output
    pattern = re.compile(r'^([a-zA-Z0-9_]+) ', re.MULTILINE)
    rules = pattern.findall(yara_output)
    return rules

def scan_with_yara(file_path):
    try:
        yara_files = glob.glob('/app/rules/*yar')

        if not yara_files:
            print("No YARA rule files found.")
            return None, None

        results = []
        rules = set()

        for yara_file in yara_files:
            result = subprocess.run(['yara', yara_file, file_path], capture_output=True, text=True)
            print("Yara Output:", result.stdout.strip(), "Yara Error:", result.stderr.strip())
            
            if result.stdout.strip():
                results.append(result.stdout.strip())
                rules.update(extract_rules(result.stdout.strip()))

        if results:
            return results, rules
        else:
            return None, None
    except Exception as e:
        print("Error executing Yara:", e)
        return None, None

def scan_with_clamav(file_path):
    try:
        result = subprocess.run(['clamdscan', file_path], capture_output=True, text=True)
        
        if 'FOUND' in result.stdout:
            print("\n\033[31mClamAV Output:", result.stdout.strip(), "ClamAV Error:", result.stderr.strip(), "\033[0m")
        else:
            print("\nClamAV Output:", result.stdout.strip(), "ClamAV Error:", result.stderr.strip())

        return 'FOUND' in result.stdout
    except Exception as e:
        print("Error executing ClamAV:", e)
        return False

def main(file_path):
    print(f"Scanning file: {file_path}\n")

    yara_detected = scan_with_yara(file_path)

    if yara_detected and yara_detected[1]:  # Check if rules are not None
        yara_results, rules = yara_detected
        print("\n\033[31mYara Hits (Rules: {})\033[0m".format(', '.join(rules)))
    else:
        print("\nNo Yara Hits")

    clamav_detected = scan_with_clamav(file_path)

    if clamav_detected:
        print("\nMalware detected by ClamAV")
    else:
        print("\nNo malware detected by ClamAV")

    # Add ML model scanning here if needed

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python app.py <file_path>")
        sys.exit(1)

    file_path = sys.argv[1]
    main(file_path)
