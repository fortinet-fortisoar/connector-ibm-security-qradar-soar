"""
Copyright start
MIT License
Copyright (c) 2024 Fortinet Inc
Copyright end
"""

SEVERITY = {
    'Low': 4,
    'Medium': 5,
    'High': 6
}

INCIDENT_TYPE = {
    'CommunicationError': 17,
    'DenialOfService': 21,
    'ImproperDisposal:DigitalAsset': 6,
    'ImproperDisposal:documents/files': 7,
    'LostDocuments/files/records': 4,
    'LostPC/laptop/tablet': 3,
    'LostPDA/smartphone': 1,
    'LostStorageDevice/media': 8,
    'Malware': 19,
    'NotAnIssue': 23,
    'Other': 18,
    'Phishing': 22,
    'StolenDocuments/files/records': 11,
    'StolenPC/laptop/tablet': 12,
    'StolenPDA/Smartphone': 13,
    'StolenStorageDevice/media': 14,
    'SystemIntrusion': 20,
    'TBD/Unknown': 16,
    'Vendor/3rdPartyError': 15
}

NIST = {
    'Attrition': 2,
    'E-mail': 4,
    'External/RemovableMedia': 1,
    'Impersonation': 5,
    'ImproperUsage': 6,
    'Loss/TheftOfEquipment': 7,
    'Other': 8,
    'Web': 3
}

RESOLUTION_TO_ID = {
    'Unresolved': 7,
    'Duplicate': 8,
    'Not an Issue': 9,
    'Resolved': 10
}
