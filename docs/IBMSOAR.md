## About the connector
IBM Security QRadar SOAR is a software platform designed to help organizations manage and respond to security incidents effectively. It provides a comprehensive approach to incident response by integrating with various security tools and automating processes to streamline incident handling.
<p>This document provides information about the IBM Security QRadar SOAR Connector, which facilitates automated interactions, with a IBM Security QRadar SOAR server using FortiSOAR&trade; playbooks. Add the IBM Security QRadar SOAR Connector as a step in FortiSOAR&trade; playbooks and perform automated operations with IBM Security QRadar SOAR.</p>

### Version information

Connector Version: 1.1.0


Authored By: Fortinet

Certified: No
## Release Notes for version 1.1.0
Following enhancements have been made to the IBM Security QRadar SOAR Connector in version 1.1.0:
<ul>
<li>The previous connector version 1.0.0, which used deprecated REST APIs of IBM Security QRadar SOAR, has been re-developed to support the new APIs.</li>
</ul>

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
</tr><tr><td>Organization ID</td><td>Specify the ID of the organization to access the endpoint to connect and perform the automated operations
</td>
</tr><tr><td>Verify SSL</td><td>Specifies whether the SSL certificate for the server is to be verified or not. <br/>By default, this option is set to True.</td></tr>
</tbody></table>

## Actions supported by the connector
The following automated operations can be included in playbooks and you can also use the annotations to access operations from FortiSOAR&trade; release 4.10.0 and onwards:
<table border=1><thead><tr><th>Function</th><th>Description</th><th>Annotation and Category</th></tr></thead><tbody><tr><td>Create Incident</td><td>Creates a incident in IBM Security QRadar SOAR based on the incident name, and other input parameters that you have specified.</td><td>create_incident <br/>Investigation</td></tr>
<tr><td>Search Incidents</td><td>Retrieves all incidents from IBM Security QRadar SOAR based on the input parameters you have specified.</td><td>search_incidents <br/>Investigation</td></tr>
<tr><td>Get Incidents Simulations</td><td>Retrieve a list of simulations from IBM Security QRadar SOAR.</td><td>get_incident_simulations <br/>Investigation</td></tr>
<tr><td>Get Incident Details</td><td>Retrieves a specific incident from IBM Security QRadar SOAR based on the incident ID that you have specified.</td><td>get_incident_details <br/>Investigation</td></tr>
<tr><td>Get Incident Tasks</td><td>Retrieve a list of tasks for the incident from IBM Security QRadar SOAR.</td><td>get_incident_tasks <br/>Investigation</td></tr>
<tr><td>Update Incident</td><td>Updates an incident in IBM Security QRadar SOAR based on the incident ID, and other input parameters that you have specified.</td><td>update_incident <br/>Investigation</td></tr>
<tr><td>Close Incident</td><td>Closed an incident in IBM Security QRadar SOAR based on the incident ID you have specified.</td><td>close_incident <br/>Investigation</td></tr>
<tr><td>Get Incident Artifacts</td><td>Retrieves all artifacts that are associated with an incidents from IBM Security QRadar SOAR based on the input parameters you have specified.</td><td>get_incident_artifacts <br/>Investigation</td></tr>
<tr><td>Get Incident Notes</td><td>Retrieves all the notes associated with an incident from IBM Security QRadar SOAR based on the incident ID that you have specified.</td><td>get_incident_notes <br/>Investigation</td></tr>
<tr><td>Get Incident Attachments</td><td>Retrieves all the attachments associated with an incident from IBM Security QRadar SOAR based on the incident ID that you have specified.</td><td>get_incident_attachments <br/>Investigation</td></tr>
<tr><td>Get Incident Attachment Details</td><td>Retrieves all the attachment details associated with an incident from IBM Security QRadar SOAR based on the incident ID that you have specified.</td><td>get_incident_attachment_details <br/>Investigation</td></tr>
<tr><td>Get All Incident Details</td><td>Retrieves all details associated with an incident from IBM Security QRadar SOAR based on the incident ID that you have specified.</td><td>get_all_incident_details <br/>Investigation</td></tr>
</tbody></table>

### operation: Create Incident
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Incident Name</td><td>Specify a name of the incident to create in IBM Security QRadar SOAR.
</td></tr><tr><td>Discovered Date</td><td>Specify the discovered date of the incident to create in IBM Security QRadar SOAR.
</td></tr><tr><td>Description</td><td>Specify a description of the incident to create in IBM Security QRadar SOAR.
</td></tr><tr><td>Include Full Data</td><td>If false an incidentDTO is returned instead of the default fullIncidentDataDTO. The fullIncidentDataDTO contains everything about the incident. The incidentDTO will contain just a high level details.
</td></tr><tr><td>Include Tasks Property</td><td>If true the fullIncidentDataDTO tasks property gets filled in also. The default is false. Note that this parameter is ignored if "Include Full Data" is false.
</td></tr><tr><td>Incident Data Types</td><td>Specify the information about the types of data that were lost (e.g First Name, Last Name, Credit card number, etc.)
</td></tr><tr><td>Record Counts</td><td>Specify the information about the counts of records that were lost for the different geographical regions.
</td></tr><tr><td>Regulators</td><td>Specify the information about the regulators that are in effect for the incident. Note that the ids property of the regulatorsDTO contains non-state/province regulators. So for example, you'd include the ID of the "GLB Act" regulator here. State regulators will be used if record counts are specified for that state.
</td></tr><tr><td>Hipaa</td><td>Specify the  information required by HIPAA. If HIPAA does not apply to this incident then the hipaa propert can be empty.
</td></tr><tr><td>Artifacts</td><td>Specify the list of tasks for the incident.
</td></tr><tr><td>Findings</td><td>Specify the list of findings for the incident.
</td></tr><tr><td>Comments</td><td>Specify the some notes for the incident.
</td></tr><tr><td>Custom Properties</td><td>(Optional) Specify the additional properties, in the JSON format, that you want to specify for the incident being created in IBM Security QRadar SOAR. The additional properties signify additional fields associated with the incident.
</td></tr></tbody></table>

#### Output

 The output contains a non-dictionary value.

### operation: Search Incidents
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Filters</td><td>Specify the filters to apply in the query to retrieve filtered records from IBM Security QRadar SOAR.
</td></tr><tr><td>Include Records</td><td>Select to include or exclude total count of the incidents that match the given filters in the response. This is set to true by default.
</td></tr><tr><td>Return Level</td><td>Select the incident data structure returned. Possible values are Partial, Normal, or Full.
</td></tr><tr><td>Field Handle</td><td>Specify the list of custom fields returned with the incident data.
</td></tr><tr><td>Length</td><td>The maximum number of records to return in the response. Possible values are: Null or any value less than 1 to retrieve all records, up to the server-configured maximum limit. If the value is greater than 0 and exceeds the server-configured limit, an error will be thrown.
</td></tr><tr><td>Start</td><td>Specify the paging to retrieve the first indicator record from IBM Security QRadar SOAR.
</td></tr><tr><td>Records Total</td><td>The total number of records to be fetched for the current query from IBM Security QRadar SOAR.
</td></tr><tr><td>Sorts</td><td>Specify the sorts to apply in the query to retrieve filtered records from IBM Security QRadar SOAR.
</td></tr><tr><td>Logic Type</td><td>Specify the logic type to apply to these filters. Defaults to ANY if logic type is not specified.
</td></tr></tbody></table>

#### Output

 The output contains a non-dictionary value.

### operation: Get Incidents Simulations
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Want Closed</td><td>Select this option, if closed simulations are to be returned (as well as open ones), otherwise it will return only open simulations.
</td></tr></tbody></table>

#### Output

 The output contains a non-dictionary value.

### operation: Get Incident Details
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Incident ID</td><td>Specify the incident ID to retrieve its details from IBM Security QRadar SOAR.
</td></tr><tr><td>Version</td><td>Specify the latest version that the client already has. If the server hasn't changed since that version then an "HTTP 304 Not Modified" will be returned.
</td></tr><tr><td>Include Findings</td><td>Determines whether the findings of an incident will be returned. If this value is true, the findings will be returned. The default is to return the findings.
</td></tr></tbody></table>

#### Output

 The output contains a non-dictionary value.

### operation: Get Incident Tasks
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Incident ID</td><td>Specify the incident ID to retrieve its details from IBM Security QRadar SOAR.
</td></tr><tr><td>Want Layouts</td><td>Select this option, if tasks layout property gets filled in also. By default it set as false.
</td></tr><tr><td>Want Notes</td><td>Select this option, if tasks note property gets filled in also. By default it set as false.
</td></tr></tbody></table>

#### Output

 The output contains a non-dictionary value.

### operation: Update Incident
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Incident ID</td><td>Specify the ID of the incident to update in IBM Security QRadar SOAR.
</td></tr><tr><td>Changes</td><td>Specify the list of changes to apply to the database object.
</td></tr><tr><td>Version</td><td>Specify the version of the object as you know it to be. If the version number matches, the PATCH changes are accepted without conflict checking.
</td></tr></tbody></table>

#### Output

 The output contains a non-dictionary value.

### operation: Close Incident
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Incident ID</td><td>Specify the ID of the incident to close in IBM Security QRadar SOAR.
</td></tr></tbody></table>

#### Output

 The output contains a non-dictionary value.

### operation: Get Incident Artifacts
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Incident ID</td><td>Specify the ID of the incident to retrieve it's artifacts from IBM Security QRadar SOAR.
</td></tr><tr><td>Filters</td><td>Specify the filters to apply in the query to retrieve filtered records from IBM Security QRadar SOAR.
</td></tr><tr><td>Include Records</td><td>Select to include or exclude total count of the incidents that match the given filters in the response. This is set to true by default.
</td></tr><tr><td>Return Level</td><td>Select the incident data structure returned. Possible values are Partial, Normal, or Full.
</td></tr><tr><td>Field Handle</td><td>Specify the list of custom fields returned with the incident data.
</td></tr><tr><td>Start</td><td>Specify the paging to retrieve the first indicator record from IBM Security QRadar SOAR.
</td></tr><tr><td>Length</td><td>The maximum number of records to return in the response. Possible values are: Null or any value less than 1 to retrieve all records, up to the server-configured maximum limit. If the value is greater than 0 and exceeds the server-configured limit, an error will be thrown.
</td></tr><tr><td>Records Total</td><td>The total number of records to be fetched for the current query from IBM Security QRadar SOAR.
</td></tr><tr><td>Sorts</td><td>Specify the sorts to apply in the query to retrieve filtered records from IBM Security QRadar SOAR.
</td></tr><tr><td>Logic Type</td><td>Specify the logic type to apply to these filters. Defaults to ANY if logic type is not specified.
</td></tr></tbody></table>

#### Output

 No output schema is available at this time.

### operation: Get Incident Notes
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Incident ID</td><td>Specify the ID of the incident to retrieve notes from IBM Security QRadar SOAR.
</td></tr></tbody></table>

#### Output

 No output schema is available at this time.

### operation: Get Incident Attachments
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Incident ID</td><td>Specify the ID of the incident to retrieve attachments from IBM Security QRadar SOAR.
</td></tr></tbody></table>

#### Output

 No output schema is available at this time.

### operation: Get Incident Attachment Details
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Incident ID</td><td>Specify the ID of the incident to retrieve attachments from IBM Security QRadar SOAR.
</td></tr></tbody></table>

#### Output

 No output schema is available at this time.

### operation: Get All Incident Details
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Incident ID</td><td>Specify the ID of the incident to retrieve it's details from IBM Security QRadar SOAR.
</td></tr><tr><td>Filters</td><td>Specify the filters to apply in the query to retrieve filtered records from IBM Security QRadar SOAR.
</td></tr><tr><td>Start</td><td>Specify the paging to retrieve the first indicator record from IBM Security QRadar SOAR.
</td></tr><tr><td>Length</td><td>The maximum number of records to return in the response. Possible values are: Null or any value less than 1 to retrieve all records, up to the server-configured maximum limit. If the value is greater than 0 and exceeds the server-configured limit, an error will be thrown.
</td></tr></tbody></table>

#### Output

 No output schema is available at this time.
## Included playbooks
The `Sample - IBM Security QRadar SOAR - 1.1.0` playbook collection comes bundled with the IBM Security QRadar SOAR connector. These playbooks contain steps using which you can perform all supported actions. You can see bundled playbooks in the **Automation** > **Playbooks** section in FortiSOAR&trade; after importing the IBM Security QRadar SOAR connector.

- Close Incident
- Create Incident
- Get All Incident Details
- Get Incident Artifacts
- Get Incident Attachment Details
- Get Incident Attachments
- Get Incident Details
- Get Incident Notes
- Get Incident Tasks
- Get Incidents Simulations
- Search Incidents
- Update Incident

**Note**: If you are planning to use any of the sample playbooks in your environment, ensure that you clone those playbooks and move them to a different collection since the sample playbook collection gets deleted during connector upgrade and delete.
