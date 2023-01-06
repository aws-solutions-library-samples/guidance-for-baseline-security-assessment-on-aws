## Introduction
Baseline Security Assessment is designed to raise customer foundational security awareness by performing an automated assessment of a Well Architected custom Security lens.

This guidance will allow customers to assess foundational security setup in their AWS account as is specifically targeted at SMB customers. It consists of a cloud formation template that a Lambda function and associated role. The Lambda function first deploys a Well architected custom lens - Baseline Security Assessment in the customer account. It them perform an assessment of the custom lens by using the AWS API and reading resources from the customer account. The assessment may identify "No Risk", "Medium Risk", "High Risk" issues. The customer can then navigate to the AWS Well Architected service in the AWS console and view the assessment. For each issue a link to a guiding document on how to fix the issue is displayed to the customer.

A lot of customer (especially SMB customer) do not pay adequate attention to foundational security setup in their AWS account. An automated assessment: * brings security concerns to the customer's attention * provides guidance on how to mitigate risks This in turn will help improve customer security posture as well foster engagement between customer and field time on matters of security proactively rather than reactively as a response to security inciden

## Support

The sample code; software libraries; command line tools; proofs of concept; templates; or other related technology (including any of the foregoing that are provided by our personnel) is provided to you as AWS Content under the AWS Customer Agreement, or the relevant written agreement between you and AWS (whichever applies). You should not use this AWS Content in your production accounts, or on production or other critical data. You are responsible for testing, securing, and optimizing the AWS Content, such as sample code, as appropriate for production grade use based on your specific quality control practices and standards. Deploying AWS Content may incur AWS charges for creating or using AWS chargeable resources, such as running Amazon EC2 instances or using Amazon S3 storage.

## Prerequisities

Access to AWS account in order to allow for the creation of IAM Policies, IAM Roles and deployment of a Lambda.

## Architecture

<img src="/assets/Security_Essentials.jpg" style="width:75vw">

## Deployment

### Manual
1. Download the CloudFormation template from deployment folder named security_essentials_deployment.template
2. Login to your AWS Account
3. Navigate to the CloudFormation console.
4. Upload template.

### AWS CLI
1. Navigate to the deployment folder
2. Run the command --> aws cloudformation create-stack --stack-name baseline-security-assessment --template-body file://security_essentials_deployment.template --capabilities CAPABILITY_AUTO_EXPAND CAPABILITY_NAMED_IAM

## Access the Baseline Security Assessment Report
1. After the status of the template changes to CREATE_COMPLETE, navigate to the AWS Well Architected Controller.
2. Navigate to ResourcesInAccount --> Baseline Security Assessment.
3. Click Generate Report. Baseline Security Assessment report gets downloaded.
