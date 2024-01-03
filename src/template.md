## Creating a Valid Service Description in YAML Format

### Introduction
To ensure successful threat modeling with TaaC, it's crucial to follow a specific structure for your service description in the YAML file. Below is a step-by-step guide on how to structure your YAML file.

### Tips:

- Indentation is crucial in YAML. Use spaces (not tabs) for indentation
- Ensure that keys and nested items are properly aligned
- Use quotes if values contain special characters or spaces
- Validate your YAML file with online tools to catch syntax errors

### YAML File Structure
Your YAML file should consist of several key sections:

- **Version:** Specify the version of the service or the document.
- **Date:** The date when the document was created or last updated, in DD.MM.YYYY format.
- **Description:** Basic details of the service, including its name, type, and criticality.
- **Functionality:** A brief description of what the service does.
- **Data Processed:** Details about the type and category of data processed by the service, and its encryption status at rest.
- **Components:** Information about internal and external components used by the service.
- **Pipeline:** Details of the CI/CD pipeline configuration.
- **Network:** Information about the network access level.
- **Data Flow:** A detailed representation of how data moves within the service, including interactions between different components.

### Instructions
#### Version and Date

```yaml
Version: '1.0'
Date: 15.01.2024
```

#### Description: Provide the name, type, and criticality of the service

```yaml
Description:
  Name: ExampleService
  Type: Web Application
  Criticality: High
```
#### Functionality: A brief summary of what the service does

```yaml
Functionality: Manages user data and authentication.
```

#### Data Processed: Specify the type of data, its category, and encryption status

```yaml
DataProcessed:
  Type: User Data
  DataCategory: PII
  EncryptionAtRest: Yes
```

#### Components: Detail any internal and external components

```yaml
Components:
  Internal:
    Exist: Yes
    Source: Internal Repository
  External:
    Exist: Yes
    PackageManager: npm
```

####  Pipeline: Configuration of your CI/CD pipeline

```yaml
Pipeline:
  Type: Jenkins
  CODEOWNERS: Yes
  BranchProtection: Yes
  SignCommits: Yes
  PinActions: No
```

####  Network: Define the network accessibility

```yaml
Network:
  Access: Restricted
```

####  Data Flow: Illustrate the flow of data within the service, including sources, targets, and methods

```yaml
DataFlow:
  - name: UserAuthenticationFlow
    description: Handles user login and authentication.
    interactions:
      - from: UserInterface
        to: AuthenticationServer
        method: HTTPS POST
      - from: AuthenticationServer
        to: Database
        method: SQL Query
```

### Examples 

1. **Template.yaml**
```yaml
Version: '1.0'
Date: 14.11.2023

# Service Description
Description:
  Name: Name1
  Type: Service
  Criticality: Tier1/Tier2/Tier3

# Service Functionality
Functionality: # Add a short description of what the service does

# Data Processing Details
DataProcessed: 
  Type: Secret/Confidential/Internal/Public
  DataCategory: Auth/PCI/PII/etc
  EncryptionAtRest: Yes/No

# Components Used by the Service
Components:
  Internal: 
    Exist: Yes/No
    Source: Private/Public
    Note: Namespacing/Scoped Package Access/etc
  External: 
    Exist: Yes/No
    PackageManager: NPM/Maven/NuGet/RubyGems/etc

# Pipeline Configuration
Pipeline:
  Type: GithubActions/Jenkins/etc
  CODEOWNERS: Yes/No
  BranchProtection: Yes/No
  SignCommits: Yes/No
  PinActions: Yes/No
  
# Network Information
Network:
  Access: Public/Private

# Data Flow Examples
dataFlow:
  - name: UserAuthenticationFlow
    description: Handles user login and authentication.
    source: UserLoginInterface
    EncryptionTransit: Yes
    Authentication:
      Exist: Yes
      Type: JWT
    Authorization: read-write
    Protocol: HTTPS
    Communication:
      Type: RESTful API
    interactions:
      - from: UserLoginInterface
        to: AuthenticationService
        method: RESTful API
        protocol: HTTPS
      - from: AuthenticationService
        to: Database
        method: CredentialVerification
        protocol: JDBC/ODBC/DatabaseAPI
    servicesInvolved: [UserLoginInterface, AuthenticationService, Database]

  - name: OrderProcessingNotificationFlow
    description: Processes orders and sends notifications to users.
    source: OrderSubmissionInterface
    EncryptionTransit: Yes
    Authentication:
      Exist: Yes
      Type: API Keys
    Authorization: admin
    Protocol: HTTPS/AMQP/SMTP
    Communication:
      Type: REST APIs/Message Queues/WebSockets
    interactions:
      - from: OrderSubmissionInterface
        to: OrderProcessingService
        method: RESTful API
        protocol: HTTPS
      - from: OrderProcessingService
        to: NotificationService
        method: MessageQueue
        protocol: AMQP
      - from: NotificationService
        to: EmailService
        method: SMTP
        protocol: SMTP
    servicesInvolved: [OrderSubmissionInterface, OrderProcessingService, NotificationService, EmailService]

  - name: DataReportingAnalyticsFlow
    description: Aggregates data and generates analytics reports.
    source: DataCollectionService
    EncryptionTransit: Yes
    Authentication:
      Exist: Yes
      Type: OAuth
    Authorization: read-write
    Protocol: HTTPS/SQL
    Communication:
      Type: REST APIs/Batch Processing
    interactions:
      - from: DataCollectionService
        to: DataWarehouse
        method: BatchUpload
        protocol: HTTPS
      - from: DataWarehouse
        to: AnalyticsService
        method: DataQuery
        protocol: SQL
      - from: AnalyticsService
        to: ReportingTool
        method: RESTful API
        protocol: HTTPS
    servicesInvolved: [DataCollectionService, DataWarehouse, AnalyticsService, ReportingTool]

  - name: InventoryManagementFlow
    description: Manages inventory levels based on orders and supply chain updates.
    source: InventoryUpdateInterface
    EncryptionTransit: Yes
    Authentication:
      Exist: Yes
      Type: Client Certificates
    Authorization: admin
    Protocol: HTTPS
    Communication:
      Type: REST APIs/Direct Database Access
    interactions:
      - from: InventoryUpdateInterface
        to: InventoryService
        method: RESTful API
        protocol: HTTPS
      - from: InventoryService
        to: SupplierService
        method: RESTful API
        protocol: HTTPS
      - from: InventoryService
        to: Database
        method: UpdateQuery
        protocol: JDBC/ODBC/DatabaseAPI
    servicesInvolved: [InventoryUpdateInterface, InventoryService, SupplierService, Database]
```

2. **Auth_service.yaml**
```yaml
Version: '1.0'
Date: 14.11.2023

# Authentication Service Description
Description:
  Name:  AuthService
  Type: Service
  Criticality: Tier1

# Service Functionality
Functionality: Handles user authentication, including login and token generation.

# Data Processing Details
DataProcessed: 
  Type: Confidential
  DataCategory: Auth
  EncryptionAtRest: Yes

# Components Used by the Service
Components:
  Internal: 
    Exist: Yes
    Source: Private
    Note: Scoped Package Access
  External: 
    Exist: Yes
    PackageManager: NPM

# Pipeline Configuration
Pipeline:
  Type: GithubActions
  CODEOWNERS: Yes
  BranchProtection: Yes
  SignCommits: Yes
  PinActions: Yes
  
# Network Information
Network:
  Access: Private

# Authentication Service Data Flow
dataFlow:  # Removed the dash here
  - name: UserAuthenticationFlow
    description: Authenticates users and issues tokens.
    source: UserLoginInterface
    EncryptionTransit: Yes
    Authentication:
      Exist: Yes
      Type: JWT
    Authorization: read-write
    Protocol: HTTPS
    Communication:
      Type: RESTful API
    interactions:
      - from: UserLoginInterface
        to: AuthService
        method: RESTful API
        protocol: HTTPS
      - from: AuthService
        to: UserDatabase
        method: Query
        protocol: JDBC
    servicesInvolved: [UserLoginInterface, AuthService, UserDatabase]
```
3.  **Order_service.yaml**
```yaml
Version: '1.0'
Date: 14.11.2023

# Order Processing Service Description
Description:
  Name: OrderProcessingService
  Type: Service
  Criticality: Tier2

# Service Functionality
Functionality: Processes customer orders and manages the order database.

# Data Processing Details
DataProcessed:
  Type: Internal
  DataCategory: PCI
  EncryptionAtRest: Yes

# Components Used by the Service
Components:
  Internal:
    Exist: Yes
    Source: Private
    Note: Namespacing
  External:
    Exist: Yes
    PackageManager: Maven

# Pipeline Configuration
Pipeline:
  Type: Jenkins
  CODEOWNERS: No
  BranchProtection: Yes
  SignCommits: No
  PinActions: No

# Network Information
Network:
  Access: Public

# Order Processing Service Data Flow
dataFlow:
  - name: OrderProcessingFlow
    description: Processes customer orders and updates inventory.
    source: OrderSubmissionPortal
    EncryptionTransit: Yes
    Authentication:
      Exist: Yes
      Type: API Keys
    Authorization: admin
    Protocol: HTTPS
    Communication:
      Type: REST APIs
    interactions:
      - from: OrderSubmissionPortal
        to: OrderProcessingService
        method: RESTful API
        protocol: HTTPS
      - from: OrderProcessingService
        to: InventoryDatabase
        method: Update
        protocol: JDBC
    servicesInvolved: [OrderSubmissionPortal, OrderProcessingService, InventoryDatabase]
```
   
