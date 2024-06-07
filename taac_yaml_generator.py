import yaml
from datetime import datetime
from termcolor import colored

class ServiceDescriptionGenerator:
    def __init__(self):
        self.service_description = {}

    def get_user_input(self, prompt, required=True, validation=None):
        while True:
            value = input(colored(prompt, 'blue', attrs=['bold'])).strip()
            if not value and required:
                print(colored("This field is required. Please provide a value.", 'red'))
            elif validation and not validation(value):
                print(colored("Invalid input. Please try again.", 'red'))
            else:
                return value

    def create_service_description(self):
        print(colored("\n# Version and Date", 'green', attrs=['bold']))
        self.service_description['Version'] = self.get_user_input("Enter the service version (e.g., 1.0): ")
        self.service_description['Date'] = datetime.now().strftime("%d.%m.%Y")

        print(colored("\n# Service Description", 'green', attrs=['bold']))
        self.service_description['Description'] = {
            'Name': self.get_user_input("Enter the service name (e.g., AuthService): "),
            'Type': self.get_user_input("Enter the service type (e.g., Authentication): "),
            'Criticality': self.get_user_input("Enter the service criticality (Tier1/Tier2/Tier3): ",
                                               validation=lambda x: x in ['Tier1', 'Tier2', 'Tier3'])
        }

        print(colored("\n# Service Functionality", 'green', attrs=['bold']))
        self.service_description['Functionality'] = self.get_user_input("Enter a brief description of the service functionality (e.g., Handles user authentication and authorization.): ")

        print(colored("\n# Data Processing Details", 'green', attrs=['bold']))
        self.service_description['DataProcessed'] = {
            'Type': self.get_user_input("Enter the type of data processed (Secret/Confidential/Internal/Public): ",
                                        validation=lambda x: x in ['Secret', 'Confidential', 'Internal', 'Public']),
            'DataCategory': self.get_user_input("Enter the data category (Auth/PCI/PII/etc): "),
            'EncryptionAtRest': self.get_user_input("Is data encrypted at rest? (Yes/No): ",
                                                    validation=lambda x: x.lower() in ['yes', 'no']).capitalize()
        }

        print(colored("\n# Components Used by the Service", 'green', attrs=['bold']))
        self.service_description['Components'] = {
            'Internal': {
                'Exist': self.get_user_input("Do internal components exist? (Yes/No): ",
                                             validation=lambda x: x.lower() in ['yes', 'no']).capitalize()
            },
            'External': {
                'Exist': self.get_user_input("Do external components exist? (Yes/No): ",
                                             validation=lambda x: x.lower() in ['yes', 'no']).capitalize()
            }
        }
        if self.service_description['Components']['Internal']['Exist'] == 'Yes':
            self.service_description['Components']['Internal']['Source'] = self.get_user_input("Enter the source of internal components (Private/Public): ")
            self.service_description['Components']['Internal']['Note'] = self.get_user_input("Enter any notes about internal components (e.g., Namespacing/Scoped Package Access): ", required=False)
        if self.service_description['Components']['External']['Exist'] == 'Yes':
            self.service_description['Components']['External']['PackageManager'] = self.get_user_input("Enter the package manager for external components (NPM/Maven/NuGet/RubyGems/etc): ")

        print(colored("\n# Pipeline Configuration", 'green', attrs=['bold']))
        self.service_description['Pipeline'] = {
            'Type': self.get_user_input("Enter the CI/CD pipeline type (GithubActions/Jenkins/etc): "),
            'CODEOWNERS': self.get_user_input("Are CODEOWNERS used? (Yes/No): ",
                                              validation=lambda x: x.lower() in ['yes', 'no']).capitalize(),
            'BranchProtection': self.get_user_input("Is branch protection enabled? (Yes/No): ",
                                                    validation=lambda x: x.lower() in ['yes', 'no']).capitalize(),
            'SignCommits': self.get_user_input("Are commits signed? (Yes/No): ",
                                               validation=lambda x: x.lower() in ['yes', 'no']).capitalize(),
            'PinActions': self.get_user_input("Are actions pinned? (Yes/No): ",
                                              validation=lambda x: x.lower() in ['yes', 'no']).capitalize()
        }

        print(colored("\n# Network Information", 'green', attrs=['bold']))
        self.service_description['Network'] = {
            'Access': self.get_user_input("Enter the network access level (Public/Private): ",
                                          validation=lambda x: x.lower() in ['public', 'private']).capitalize()
        }

        print(colored("\n# Data Flow", 'green', attrs=['bold']))
        self.service_description['dataFlow'] = []

        print(colored("Illustrate the flow of data within the service, including sources, targets, and methods.", 'yellow'))
        print(colored("Example:", 'yellow'))
        print(colored("  - name: UserAuthenticationFlow", 'yellow'))
        print(colored("    description: Handles user login and authentication.", 'yellow'))
        print(colored("    source: UserLoginInterface", 'yellow'))
        print(colored("    EncryptionTransit: Yes", 'yellow'))
        print(colored("    Authentication:", 'yellow'))
        print(colored("      Exist: Yes", 'yellow'))
        print(colored("      Type: JWT", 'yellow'))
        print(colored("    Authorization: read-write", 'yellow'))
        print(colored("    Protocol: HTTPS", 'yellow'))
        print(colored("    Communication:", 'yellow'))
        print(colored("      Type: RESTful API", 'yellow'))
        print(colored("    interactions:", 'yellow'))
        print(colored("      - from: UserLoginInterface", 'yellow'))
        print(colored("        to: AuthService", 'yellow'))
        print(colored("        method: RESTful API", 'yellow'))
        print(colored("        protocol: HTTPS", 'yellow'))
        print(colored("      - from: AuthService", 'yellow'))
        print(colored("        to: UserDatabase", 'yellow'))
        print(colored("        method: Query", 'yellow'))
        print(colored("        protocol: JDBC", 'yellow'))
        print(colored("    servicesInvolved: [UserLoginInterface, AuthService, UserDatabase]", 'yellow'))

        while True:
            add_flow = self.get_user_input("\nDo you want to add a data flow? (Yes/No): ",
                                           validation=lambda x: x.lower() in ['yes', 'no'])
            if add_flow.lower() != 'yes':
                break

            data_flow = {
                'name': self.get_user_input("Enter the name of the data flow: "),
                'description': self.get_user_input("Enter a brief description of the data flow: "),
                'source': self.get_user_input("Enter the source of the data flow: "),
                'EncryptionTransit': self.get_user_input("Is data encrypted in transit? (Yes/No): ",
                                                         validation=lambda x: x.lower() in ['yes', 'no']).capitalize(),
                'Authentication': {
                    'Exist': self.get_user_input("Does authentication exist for this data flow? (Yes/No): ",
                                                 validation=lambda x: x.lower() in ['yes', 'no']).capitalize(),
                    'Type': self.get_user_input("Enter the authentication type (JWT/API Keys/etc): ", required=False)
                },
                'Authorization': self.get_user_input("Enter the authorization level (read/write/admin/etc): "),
                'Protocol': self.get_user_input("Enter the communication protocol (HTTPS/AMQP/etc): "),
                'Communication': {
                    'Type': self.get_user_input("Enter the communication type (RESTful API/Message Queues/etc): ")
                },
                'interactions': [],
                'servicesInvolved': []
            }

            while True:
                add_interaction = self.get_user_input("Do you want to add an interaction? (Yes/No): ",
                                                      validation=lambda x: x.lower() in ['yes', 'no'])
                if add_interaction.lower() != 'yes':
                    break

                interaction = {
                    'from': self.get_user_input("Enter the source of the interaction (e.g., UserLoginInterface): "),
                    'to': self.get_user_input("Enter the target of the interaction (e.g., AuthService): "),
                    'method': self.get_user_input("Enter the method of the interaction (e.g., RESTful API): "),
                    'protocol': self.get_user_input("Enter the protocol of the interaction (e.g., HTTPS): ")
                }
                data_flow['interactions'].append(interaction)
                data_flow['servicesInvolved'].extend([interaction['from'], interaction['to']])

            data_flow['servicesInvolved'] = list(set(data_flow['servicesInvolved']))
            self.service_description['dataFlow'].append(data_flow)

        return self.service_description

    def save_yaml_file(self, file_name):
        with open(file_name, 'w') as file:
            yaml.dump(self.service_description, file, default_flow_style=False)
        print(colored(f"\nService description saved to {file_name}", 'green'))

def main():
    print(colored("**Welcome to the Service Description Generator!**", 'cyan', attrs=['bold']))
    print(colored("- This tool is designed to generate a valid service description for AI-driven Threat modeling-as-a-Code (TaaC-AI).", 'cyan'))
    print(colored("- TaaC-AI is available at https://github.com/yevh/TaaC-AI/", 'cyan'))
    print(colored("- This tool will guide you through creating a service description in YAML format.", 'cyan'))
    print(colored("- Please provide the requested information as prompted.", 'cyan'))

    generator = ServiceDescriptionGenerator()
    generator.create_service_description()

    file_name = generator.get_user_input("\nEnter the name of the YAML file to save the service description: ")
    if not file_name.endswith('.yaml'):
        file_name += '.yaml'

    generator.save_yaml_file(file_name)

if __name__ == "__main__":
    main()
