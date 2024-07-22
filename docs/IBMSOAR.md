## About the connector
IBM Security QRadar SOAR is a software platform designed to help organizations manage and respond to security incidents effectively. It provides a comprehensive approach to incident response by integrating with various security tools and automating processes to streamline incident handling.
<p>This document provides information about the IBM Security QRadar SOAR Connector, which facilitates automated interactions, with a IBM Security QRadar SOAR server using FortiSOAR&trade; playbooks. Add the IBM Security QRadar SOAR Connector as a step in FortiSOAR&trade; playbooks and perform automated operations with IBM Security QRadar SOAR.</p>

### Version information

Connector Version: 1.0.0


Authored By: Fortinet

Certified: No

## Installing the connector
<p>Use the <strong>Content Hub</strong> to install the connector. For the detailed procedure to install a connector, click <a href="https://docs.fortinet.com/document/fortisoar/0.0.0/installing-a-connector/1/installing-a-connector" target="_top">here</a>.</p><p>You can also use the <code>yum</code> command as a root user to install the connector:</p>
<pre>yum install cyops-connector-ibm-security-qradar-soar</pre>

## Prerequisites to configuring the connector
- You must have the credentials of IBM Security QRadar SOAR server to which you will connect and perform automated operations.
- The FortiSOAR&trade; server should have outbound connectivity to port 443 on the IBM Security QRadar SOAR server.

## Minimum Permissions Required
- Not applicable

## Configuring the connector
For the procedure to configure a connector, click [here](https://docs.fortinet.com/document/fortisoar/0.0.0/configuring-a-connector/1/configuring-a-connector)
### Configuration parameters
<p>In FortiSOAR&trade;, on the Connectors page, click the <strong>IBM Security QRadar SOAR</strong> connector row (if you are in the <strong>Grid</strong> view on the Connectors page) and in the <strong>Configurations</strong> tab enter the required configuration details:</p>
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Server URL</td><td>Specify the URL of the IBM Resilient server to connect and perform automated operations.
</td>
</tr><tr><td>API Key</td><td>Specify the API key to access the endpoint to connect and perform the automated operations
</td>
</tr><tr><td>API Secret</td><td>Specify the API Secret to access the endpoint to connect and perform the automated operations
</td>
</tr><tr><td>Organisation ID</td><td>Specify the ID of the organisation to access the endpoint to connect and perform the automated operations
</td>
</tr><tr><td>Verify SSL</td><td>Specifies whether the SSL certificate for the server is to be verified or not. <br/>By default, this option is set to True.</td></tr>
</tbody></table>

## Actions supported by the connector
The following automated operations can be included in playbooks and you can also use the annotations to access operations from FortiSOAR&trade; release 4.10.0 and onwards:
<table border=1><thead><tr><th>Function</th><th>Description</th><th>Annotation and Category</th></tr></thead><tbody><tr><td>Create Incident</td><td>Creates a incident in IBM Security QRadar SOAR based on the incident name, and other input parameters that you have specified.</td><td>create_incident <br/>Investigation</td></tr>
<tr><td>Get Open Incidents</td><td>Retrieves all open incidents from IBM Security QRadar SOAR.</td><td>get_open_incidents <br/>Investigation</td></tr>
<tr><td>Get Incident Details</td><td>Retrieves a specific incident from IBM Security QRadar SOAR based on the incident ID that you have specified.</td><td>get_incident_details <br/>Investigation</td></tr>
<tr><td>Update Incident</td><td>Updates an incident in IBM Security QRadar SOAR based on the incident ID, and other input parameters that you have specified.</td><td>update_incident <br/>Investigation</td></tr>
<tr><td>Close Incident</td><td>Closed an incident in IBM Security QRadar SOAR based on the incident ID you have specified.</td><td>close_incident <br/>Investigation</td></tr>
</tbody></table>

### operation: Create Incident
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Incident Name</td><td>Specify a name of the incident to create in IBM Security QRadar SOAR.
</td></tr><tr><td>Custom Properties</td><td>(Optional) Specify the additional properties, in the JSON format, that you want to specify for the incident being created in IBM Security QRadar SOAR. The additional properties signify additional fields associated with the incident.
</td></tr></tbody></table>

#### Output

 The output contains a non-dictionary value.

### operation: Get Open Incidents
#### Input parameters
None.

#### Output

 The output contains a non-dictionary value.

### operation: Get Incident Details
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Incident ID</td><td>Specify the incident ID to retrieve its details from IBM Security QRadar SOAR.
</td></tr></tbody></table>

#### Output

 The output contains a non-dictionary value.

### operation: Update Incident
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Incident ID</td><td>Specify the ID of the incident to update in IBM Security QRadar SOAR.
</td></tr><tr><td>Incident Name</td><td>(Optional) Specify the name of the incident to update in IBM Security QRadar SOAR.
</td></tr><tr><td>Description</td><td>(Optional) Specify a description of the incident to update in IBM Security QRadar SOAR.
</td></tr><tr><td>Severity</td><td>(Optional) Specify the severity of the incident to update in IBM Security QRadar SOAR. You can choose from the following options: Low, Medium, or High.
</td></tr><tr><td>Incident Type</td><td>(Optional) Specify the type of the incident to update in IBM Security QRadar SOAR. You can choose from the following options: CommunicationError, DenialOfService, ImproperDisposal:DigitalAsset, etc.
</td></tr><tr><td>NIST Attack Vectors</td><td>(Optional) Specify the nist attack vectors to update in IBM Security QRadar SOAR. You can choose from the following options: Attrition, E-mail, External/RemovableMedia, etc.
</td></tr><tr><td>Resolution</td><td>(Optional) Specify the resolution to update in IBM Security QRadar SOAR. You can choose from the following options: Unresolved, Duplicate, Not an Issue, or Resolved.
</td></tr><tr><td>Resolution Summary</td><td>(Optional) Specify a summary of the resolution to update in IBM Security QRadar SOAR.
</td></tr><tr><td>Custom Properties</td><td>(Optional) Specify the additional properties, in the JSON format, that you want to specify for the incident being updated in IBM Security QRadar SOAR. The additional properties signify additional fields associated with the incident.
</td></tr></tbody></table>

#### Output

 The output contains a non-dictionary value.

### operation: Close Incident
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Incident ID</td><td>Specify the ID of the incident to close in IBM Security QRadar SOAR.
</td></tr></tbody></table>

#### Output

 The output contains a non-dictionary value.
## Included playbooks
The `Sample - ibm-security-qradar-soar - 1.0.0` playbook collection comes bundled with the IBM Security QRadar SOAR connector. These playbooks contain steps using which you can perform all supported actions. You can see bundled playbooks in the **Automation** > **Playbooks** section in FortiSOAR&trade; after importing the IBM Security QRadar SOAR connector.

- Close Incident
- Create Incident
- Get Incident Details
- Get Open Incidents
- Update Incident

**Note**: If you are planning to use any of the sample playbooks in your environment, ensure that you clone those playbooks and move them to a different collection since the sample playbook collection gets deleted during connector upgrade and delete.
