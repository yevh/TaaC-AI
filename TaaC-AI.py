import os
import sys
import yaml
import json
from openai import OpenAI
import argparse
from datetime import datetime, date
from jinja2 import Environment, FileSystemLoader

class Config:
    OPENAI_KEY = "OPENAI_KEY"
    HTML_OUTPUT_FILE = 'report.html'
    TEMPLATE_FILE = 'template.html'
    MODEL = 'gpt-3.5-turbo'

    @staticmethod
    def set_output_file(service_name):
        current_date = date.today().strftime("%Y-%m-%d")
        Config.HTML_OUTPUT_FILE = f"{service_name.replace(' ', '_')}_{current_date}_ThreatModelingReport.html"

class YAMLDataHandler:
    @staticmethod
    def load_and_validate_yaml_file(file_path):
        try:
            with open(file_path, 'r') as file:
                data = yaml.safe_load(file)
        except FileNotFoundError:
            return False, None, f"Error: File '{file_path}' not found."
        except yaml.YAMLError as e:
            return False, None, f"YAML syntax error in '{file_path}': {e}"
        valid, message = YAMLDataHandler.validate_yaml_data(data)
        if not valid:
            return False, None, message
        return True, data, "YAML file is valid."

    @staticmethod
    def validate_yaml_data(data):
        required_keys = {
            'Version': str,
            'Date': '%d.%m.%Y',
            'Description': {'Name', 'Type', 'Criticality'},
            'DataProcessed': {'Type', 'DataCategory', 'EncryptionAtRest'},
            'Components': {'Internal', 'External'},
            'Pipeline': {'Type', 'CODEOWNERS', 'BranchProtection', 'SignCommits', 'PinActions'},
            'Network': {'Access'},
            'dataFlow': list
        }
        for key, expected in required_keys.items():
            if key not in data:
                return False, f"Missing key: '{key}' in YAML data."
            if isinstance(expected, set) and not expected.issubset(data[key].keys()):
                return False, f"Missing keys in '{key}': {expected - data[key].keys()}"
            if isinstance(expected, type) and not isinstance(data[key], expected):
                return False, f"'{key}' should be of type {expected.__name__}."
            if key == 'Date':
                try:
                    datetime.strptime(data[key], required_keys[key])
                except ValueError:
                    return False, f"'Date' is not in the correct format (DD.MM.YYYY)."
        return True, "YAML data is valid."

class ThreatModeling:
    def __init__(self, service_description, model):
        self.service_description = service_description
        self.model = model
        self.client = OpenAI(api_key=os.getenv(Config.OPENAI_KEY))

    @staticmethod
    def convert_data_flow_to_json(data_flows):
        nodes = set()
        links = []
        for flow in data_flows:
            for interaction in flow['interactions']:
                nodes.add(interaction['from'])
                nodes.add(interaction['to'])
                links.append({
                    "source": interaction['from'],
                    "target": interaction['to'],
                    "type": interaction['method']
                })
        return json.dumps({"nodes": list(map(lambda x: {"id": x}, nodes)), "links": links})

    def generate_threat_modeling(self):
        if not self.client.api_key:
            return "<p>OpenAI key was not provided or is incorrect. AI Threat Modeling was not performed.</p>"

        prompt = f"""Perform a thorough threat modeling analysis for the provided service, utilizing the STRIDE framework, OWASP Top 10 2021, and OWASP Top 10 CI/CD Security Risks guidelines. The analysis should be formatted as HTML code suitable for inclusion in a web page section. Follow this structured approach:

        - Name for the table: AI-driven Threat Modeling Analysis
        - Begin with an HTML 'div' element, assigning it a class 'card' to encapsulate the threat analysis.
        - Inside this 'div', include a header to introduce the threat modeling section.
        - The body of this 'div' should contain a detailed table. This table is the core of your analysis, where each row represents a specific identified threat. 
        - Columns in the table should include:
            1. 'Title' for the name of the threat.
            2. 'Description' for a detailed explanation, including how the threat affects the authentication service.
            3. 'Categories', distinguishing whether the threat falls under STRIDE, OWASP Top 10 2021, and OWASP Top 10 CI/CD Security Risks categories. Clarify the specific category from these frameworks that each threat pertains to.
            4. 'Remediation', outlining recommended steps or strategies to mitigate or resolve the threat.
            5. 'Status': This column should feature an HTML checkbox element. When this checkbox is checked, the text in the corresponding row should be struck through to visually indicate the threat's mitigation status. The functionality is implemented using a JavaScript function named toggleStrikeThrough. This function is triggered whenever the state of a checkbox changes (captured by the onchange event). The script finds the parent row of the checkbox and applies a 'line-through' text decoration to the text in each cell of that row, except for the last cell containing the checkbox itself. 

        - Each threat identified should be analyzed considering the various aspects of STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) as follows: 

            STRIDE: Spoofing Identity
            * OWASP Web A07:2021 - Identification and Authentication Failures: Weaknesses in identity management.
            * CI/CD-SEC-3: Insecure Integrations: Use of insecure, spoofable integrations in the CI/CD pipeline.

            STRIDE: Tampering with Data
            * OWASP Web A03:2021 - Injection: Injection flaws like SQL, NoSQL, OS command injections.
            * OWASP Web A05:2021 - Security Misconfiguration: Can lead to unauthorized data access and tampering.
            * CI/CD-SEC-7: Insufficient Pipeline Monitoring: Lack of monitoring can allow unnoticed tampering.

            STRIDE: Repudiation
            * OWASP Web A10:2021 - Server-Side Request Forgery (SSRF): Can be used to falsify requests.
            * CI/CD-SEC-10: Insufficient Logging and Monitoring: Insufficient logging can lead to untraceable actions.

            STRIDE: Information Disclosure
            * OWASP Web A02:2021 - Cryptographic Failures: Often lead to sensitive data exposure.
            * OWASP Web A06:2021 - Vulnerable and Outdated Components: Can expose information if exploited.
            * CI/CD-SEC-2: Insecure Storage of Secrets: Could lead to sensitive information disclosure.

            STRIDE: Denial of Service
            * OWASP Web A08:2021 - Software and Data Integrity Failures: Can result in DoS if data or software is compromised.
            * CI/CD-SEC-9: Inadequate Infrastructure Protection: Can lead to service interruptions.

            STRIDE: Elevation of Privilege
            * OWASP Web A01:2021 - Broken Access Control: Directly relates to unauthorized elevation of privileges.
            * OWASP Web A04:2021 - Insecure Design: Can include design flaws that lead to privilege escalation.
            * CI/CD-SEC-1: Insufficient Flow Control Mechanisms: Can lead to unauthorized access or escalation of privileges in CI/CD workflows.
            * CI/CD-SEC-5: Inadequate Identity and Access Management in CI/CD: Can allow unauthorized elevation of privilege.
            * CI/CD-SEC-6: Weak Artifact Management: Improper management may lead to unauthorized elevation of privileges through manipulation of artifacts.

        - Ensure that each category above is covered in the review. Each risk per OWASP described separately.
        - Validate each risk based on data flow and service_description.
        - Ensure that the HTML structure is clean, well-organized, and can be seamlessly integrated into a web page layout.
        -Do not add any additional CSS and unnecessary parts like ```html

        The analysis should be thorough, reflecting a deep understanding of potential security vulnerabilities in the service and how they align with recognized security frameworks like STRIDE and OWASP. The goal is to provide a clear, actionable, and comprehensive security assessment in a visually structured HTML format. 

        Service data:
        {self.service_description}
    """

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a security expert. Provide a threat analysis."},
                    {"role": "user", "content": prompt}
                ]
            )
            return response.choices[0].message.content.strip()
        except Exception as e:
            return f"<p>Error generating threat modeling: {str(e)}</p>"

class HTMLReportRenderer:
    def __init__(self, service_info, data_flow_json, threat_analysis_html):
        self.service_info = service_info
        self.data_flow_json = data_flow_json
        self.threat_analysis_html = threat_analysis_html
        self.service_name = service_info.get('Description', {}).get('Name', 'Report')
        self.current_date = date.today().strftime("%Y-%m-%d")

    def render(self):
        env = Environment(loader=FileSystemLoader('.'))
        template = env.get_template(Config.TEMPLATE_FILE)
        return template.render(
            service=self.service_info,
            data_flow_json=self.data_flow_json,
            threat_analysis_html=self.threat_analysis_html,
            service_name=self.service_name,
            current_date=self.current_date
        )

class PrintManager:
    TITLE_STYLE = '\033[1;34m'
    NORMAL_STYLE = '\033[0m'
    NAME_STYLE = '\033[1;32m'
    HIGHLIGHT_STYLE = '\033[1;33m'
    FILE_STYLE = '\033[1;33m'
    ERROR_STYLE = '\033[1;31m'

    @staticmethod
    def print_usage():
        print(f"{PrintManager.TITLE_STYLE}AI-driven Threat modeling-as-a-Code (TaaC) v1.0{PrintManager.NORMAL_STYLE}")
        print(f"Created by YevhSec1\n")
        print(f"{PrintManager.HIGHLIGHT_STYLE}Usage:{PrintManager.NORMAL_STYLE} python3 TaaC.py [options] <yaml_file>\n")
        print(f"{PrintManager.HIGHLIGHT_STYLE}Options:{PrintManager.NORMAL_STYLE}")
        print("  -h, --help            show this help message and exit")
        print("  --model               Select the model version: gpt-3.5-turbo or gpt-4\n")
        print(f"{PrintManager.HIGHLIGHT_STYLE}Arguments:{PrintManager.NORMAL_STYLE}")
        print("  yaml_file             Path to the YAML file containing the service information.\n")
        print(f"{PrintManager.HIGHLIGHT_STYLE}Example:{PrintManager.NORMAL_STYLE}")
        print("  python3 TaaC.py auth_service.yaml --model gpt-3.5-turbo")

    @staticmethod
    def print_progress(file_name):
        print(f"{PrintManager.TITLE_STYLE}Processing: {file_name}{PrintManager.NORMAL_STYLE}")
        print("Generating report... Please wait.")

    @staticmethod
    def print_completion():
        print(f"\n{PrintManager.NAME_STYLE}Done! The report has been successfully generated.{PrintManager.NORMAL_STYLE}\n")

    @staticmethod
    def print_error(message):
        print(f"{PrintManager.ERROR_STYLE}Error:{PrintManager.NORMAL_STYLE} {message}")

def parse_arguments():
    parser = argparse.ArgumentParser(description='Generate a threat modeling report from a YAML file.')
    parser.add_argument('yaml_file', help='Path to the YAML file containing the service information.')
    parser.add_argument('--model', choices=['gpt-3.5-turbo', 'gpt-4'], default='gpt-3.5-turbo', help='Choice of GPT model for generating the report.')
    return parser.parse_args()

def main():
    args = parse_arguments()

    Config.MODEL = args.model

    valid, service_info, message = YAMLDataHandler.load_and_validate_yaml_file(args.yaml_file)
    if not valid:
        PrintManager.print_error(message)
        return

    service_name = service_info.get('Description', {}).get('Name', 'Report')
    Config.set_output_file(service_name)

    PrintManager.print_progress(args.yaml_file)
    
    data_flows = service_info.get('dataFlow', [])
    data_flow_json = ThreatModeling.convert_data_flow_to_json(data_flows)
    
    threat_modeling = ThreatModeling(json.dumps(service_info, indent=2), args.model)
    threat_analysis_html = threat_modeling.generate_threat_modeling()
    
    renderer = HTMLReportRenderer(service_info, data_flow_json, threat_analysis_html)
    html_report = renderer.render()
    
    with open(Config.HTML_OUTPUT_FILE, 'w') as file:
        file.write(html_report)
    PrintManager.print_completion()

if __name__ == "__main__":
    main()
