 # Update of https://raw.githubusercontent.com/aws-samples/aws-security-hub-scan-with-trivy/master/sechub_parser.py 
 # according to the new trivy json report format
 # - and environment variables (AWS_REGION -> AWS_DEFAULT_REGION, docker_name -> IMAGE_REPO_NAME, docker_tag -> IMAGE_TAG
 # - and workaround with 'Title' field (has missed for some vulnerabilities in trivy report
 # 

import json
import boto3
import datetime
import os

# import sechub + sts boto3 client
securityhub = boto3.client('securityhub')
sts = boto3.client('sts')

# retrieve account id from STS GetCallerID
getAccount = sts.get_caller_identity()
awsAccount = str(getAccount['Account'])
# retrieve env vars from codebuild
awsRegion = os.environ['AWS_DEFAULT_REGION']
codebuildBuildArn = os.environ['CODEBUILD_BUILD_ARN']
containerName = os.environ['IMAGE_REPO_NAME']
containerTag = os.environ['IMAGE_TAG']

# open Trivy vuln report & parse out vuln info
with open('results.json') as json_file:
    data = json.load(json_file)
    if data['Results'][0]['Vulnerabilities'] is None:
        print('No vulnerabilities')
    else:
        for p in data['Results'][0]['Vulnerabilities']:
            cveId = str(p['VulnerabilityID'])
            cveTitle = str(p['Title']) if 'Title' in p else str(p['VulnerabilityID'])
            cveDescription = str(p['Description'])
            cveDescription = (cveDescription[:1021] + '..') if len(cveDescription) > 1021 else cveDescription
            packageName = str(p['PkgName'])
            installedVersion = str(p['InstalledVersion'])
            fixedVersion = str(p['FixedVersion'])
            trivySeverity = str(p['Severity'])
            cveReference = str(p['References'][0])
            # create ISO 8601 timestamp
            iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
            # map Trivy severity to ASFF severity
            if trivySeverity == 'LOW':
                trivyProductSev = int(1)
                trivyNormalizedSev = trivyProductSev * 10
            elif trivySeverity == 'MEDIUM':
                trivyProductSev = int(4)
                trivyNormalizedSev = trivyProductSev * 10
            elif trivySeverity == 'HIGH':
                trivyProductSev = int(7)
                trivyNormalizedSev = trivyProductSev * 10
            elif trivySeverity == 'CRITICAL':
                trivyProductSev = int(9)
                trivyNormalizedSev = trivyProductSev * 10
            else:
                print('No vulnerability information found')
            try:
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': containerName + ':' + containerTag + '/' + cveId,
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + ':product/aquasecurity/aquasecurity',
                            'GeneratorId': codebuildBuildArn,
                            'AwsAccountId': awsAccount,
                            'Types': [ 'Software and Configuration Checks/Vulnerabilities/CVE' ],
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': {
                                'Product': trivyProductSev,
                                'Normalized': trivyNormalizedSev
                            },
                            'Title': 'Trivy found a vulnerability to ' + cveId + ' in container ' + containerName,
                            'Description': cveDescription,
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'More information on this vulnerability is provided in the hyperlink',
                                    'Url': cveReference
                                }
                            },
                            'ProductFields': { 'Product Name': 'Trivy' },
                            'Resources': [
                                {
                                    'Type': 'Container',
                                    'Id': containerName + ':' + containerTag,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Container': { 'ImageName': containerName + ':' + containerTag },
                                        'Other': {
                                            'CVE ID': cveId,
                                            'CVE Title': cveTitle,
                                            'Installed Package': packageName + ' ' + installedVersion,
                                            'Patched Package': packageName + ' ' + fixedVersion
                                        }
                                    }
                                },
                            ],
                            'RecordState': 'ACTIVE'
                        }
                    ]
                )
                print(response)
            except Exception as e:
                print(e)
                raise
