# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
import json
import urllib3
import cfnresponse
import boto3
import botocore
import datetime
import os

wa_client = boto3.client('wellarchitected')
s3_client = boto3.client("s3")
acc_client = boto3.client('account')
iam_client = boto3.client('iam')
ec2_client = boto3.client('ec2')
waf_client = boto3.client('wafv2')
sec_client = boto3.client('secretsmanager')
ctr_client = boto3.client('cloudtrail')
elb_client = boto3.client('elbv2')
coe_client = boto3.client('ce')
cwt_client = boto3.client('cloudwatch')
cfn_client = boto3.client('cloudfront')
ssm_client = boto3.client('ssm')
aa_client = boto3.client('accessanalyzer')

################################################################################
def update_answer_for_assessment_question(question_id, workload_id, lens_arn, selected_choices):
    wa_client.update_answer(
        WorkloadId=workload_id,
        LensAlias=lens_arn,
        QuestionId=question_id,
        SelectedChoices=selected_choices
    )

################################################################################
def check_access_analyzer():
    selected_choice = 'so_08_accann_no'
    selected_choices = []    

    response = aa_client.list_analyzers()
    if response['analyzers']:
        selected_choice = 'so_08_accany'
            
    selected_choices.append(selected_choice)
    
    return selected_choices
    
################################################################################
def check_patch_automation():
    selected_choice = 'so_06_pn_no'
    selected_choices = []    

    response = ssm_client.describe_patch_groups()
    if len(response['Mappings']) > 0:
        baseline_response = ssm_client.describe_patch_baselines()
        if len(baseline_response['BaselineIdentities']) > 0:
            for patch_group in response['Mappings']:
                grpstate_response = ssm_client.describe_patch_group_state(PatchGroup=patch_group['PatchGroup'])
                if grpstate_response['Instances'] > 0:
                    selected_choice = 'so_06_py'
                    break
            
    selected_choices.append(selected_choice)
    return selected_choices
    
################################################################################
def check_ebs_encrypted():
    selected_choice = 'so_07_voly'
    selected_choices = []
    
    response = ec2_client.describe_volumes()
    for volume in response['Volumes']:
        if not volume['Encrypted']:
            selected_choice = 'so_07_voln'
            break
    
    selected_choices.append(selected_choice)
    return selected_choices
    
################################################################################
def check_s3_static_website():
    selected_choice = 'so_07_ps3ns'
    selected_choices = []
    
    response = s3_client.list_buckets()
    for bucket in response['Buckets']:
        try:
            web_response = s3_client.get_bucket_website(Bucket=bucket['Name'])
            try:
                access_resp = s3_client.get_public_access_block(Bucket=bucket['Name'])
                if access_resp['PublicAccessBlockConfiguration']['BlockPublicAcls'] == False:
                    selected_choice = 'so_07_ps3y'
            except botocore.exceptions.ClientError as e:
                print(e.response['Error']['Code'])
        except botocore.exceptions.ClientError as e:
            if not e.response['Error']['Code'] == 'NoSuchWebsiteConfiguration':
                raise e
    
    selected_choices.append(selected_choice)
    
    args = {'MaxItems': '100'}
    is_truncated = True
    while is_truncated:
        cfn_response = cfn_client.list_distributions(**args)
        
        is_truncated = cfn_response['DistributionList']['IsTruncated']
        if is_truncated:
            args['Marker'] = cfn_response['DistributionList']['NextMarker']
        if 'Items' in cfn_response['DistributionList']:
            for cfn in cfn_response['DistributionList']['Items']:
                for cfn_item in cfn['Origins']['Items']:
                    if 'S3OriginConfig' in cfn_item:
                        if cfn_item['S3OriginConfig']['OriginAccessIdentity'] == '':
                            if 'so_07_ps3n' not in selected_choices:
                                selected_choices.append('so_07_ps3n')
                        else:
                            if 'so_07_ps3os' not in selected_choices:
                                selected_choices.append('so_07_ps3os')  
    return selected_choices

################################################################################
def check_billing_alarm_configured():
    selected_choice = 'so_08_cban_no'
    
    response = cwt_client.describe_alarms(AlarmTypes=['MetricAlarm'])
    for alarm in response['MetricAlarms']:
        if alarm['Namespace'] == 'AWS/Billing':
            selected_choice = 'so_08_cbay'
            break
    
    if not selected_choice == 'so_08_cbay':
        cwt_client_nv = boto3.client('cloudwatch', region_name='us-east-1')
        response = cwt_client_nv.describe_alarms(AlarmTypes=['MetricAlarm'])
        for alarm in response['MetricAlarms']:
            if alarm['Namespace'] == 'AWS/Billing':
                selected_choice = 'so_08_cbay'
                break

    selected_choices = []
    selected_choices.append(selected_choice)
    return selected_choices

################################################################################
def check_anomaly_detection_configured():
    selected_choice = 'so_08_cadn_no'
    try:
        response = coe_client.get_anomaly_monitors()
        if len(response['AnomalyMonitors']) > 0:
            selected_choice = 'so_08_cady'
    except botocore.exceptions.ClientError as e:
        print('access exception: cost explorer  not setup ')
    
    selected_choices = []
    selected_choices.append(selected_choice)
    return selected_choices

################################################################################
def check_cloudtrail_enabled():
    selected_choice = 'so_08_ctn_no'
    selected_choices = []        
    response = ctr_client.describe_trails()
    if len(response['trailList']) > 0:
        selected_choice = 'so_08_cty'
    selected_choices.append(selected_choice)
    return selected_choices

################################################################################
def check_https_only():
    selected_choice = 'so_05_https'
    response = elb_client.describe_load_balancers()
    load_balancers = response['LoadBalancers']
    for load_balancer in load_balancers:
        listener_response = elb_client.describe_listeners(LoadBalancerArn=load_balancer['LoadBalancerArn'])
        listeners = listener_response['Listeners']
        for listener in listeners:
            if (not listener['Protocol'] == 'HTTPS') and (not listener['Protocol'] == 'TLS'):
                if listener['Protocol'] == 'HTTP':
                    for default_action in listener['DefaultActions']:
                        if not default_action['Type'] == 'redirect':
                            selected_choice = 'so_05_http_no'
                        elif not default_action['RedirectConfig']['Port'] == 443 and not default_action['RedirectConfig']['Host'] == '#{host}':
                            selected_choice = 'so_05_http_no'
                else:
                    selected_choice = 'so_05_http_no'
                    
            if not selected_choice == 'so_05_http_no' and (not listener['Protocol'] == 'HTTPS') and (not listener['Protocol'] == 'TLS'):
                rule_response = elb_client.describe_rules(ListenerArn=listener['ListenerArn'])
                for rule in rule_response['Rules']:
                    for action in rule['Actions']:
                        if action['Type'] == 'forward':
                            selected_choice = 'so_05_http_no' 
                            break;
                    if selected_choice == 'so_05_http_no':
                        break;
            
    selected_choices = []
    selected_choices.append(selected_choice)
    return selected_choices    
 
################################################################################
def is_policy_restriced(actions):
    hasFullList = False
    hasFullGet = False
    hasFullPut = False
    hasFullDescribe = False
    hasFullPermission = False
    hasTooManyPermissions = False
    for action in actions:
        if 'secretsmanager:List*' in action:
            hasFullList = True       
        if 'secretsmanager:Get*' in action:
            hasFullGet = True
        if 'secretsmanager:Put*' in action:
            hasFullPut = True
        if 'secretsmanager:Describe*' in action:
            hasFullDescribe = True
        if 'secretsmanager:*' in action:    
            hasFullPermission = True
    if (hasFullDescribe and hasFullPut and hasFullGet and hasFullList) or hasFullPermission:
            hasTooManyPermissions = True
    
    return hasTooManyPermissions        
   
################################################################################
def check_policies_for_secret_engine_access(policies):   
    hasTooManyPermissions = False
    
    for policy in policies:
        response = iam_client.get_policy(PolicyArn=policy['PolicyArn'])
        pv_response = iam_client.get_policy_version(PolicyArn=policy['PolicyArn'], VersionId=response['Policy']['DefaultVersionId'])
        document = (pv_response['PolicyVersion']['Document'])
        for stmt in document['Statement']:
            if type(stmt) == str:
                statement = document['Statement']
            else:
                statement = stmt
            if type(statement['Action']) == list:
                 actions = statement['Action']
            else:
                actions = []
                actions.append(statement['Action'])
            hasTooManyPermissions = is_policy_restriced(actions)
            if hasTooManyPermissions:
                break
        if hasTooManyPermissions:
            break
    return hasTooManyPermissions

################################################################################
def check_sac_by_user_policies(user_name):
    hasTooManyPermissions = False
    isTruncated = True
    args = {'MaxItems': 12, 'UserName': user_name}
    while isTruncated == True and hasTooManyPermissions == False:    
        response = iam_client.list_attached_user_policies(**args)
        if len(response['AttachedPolicies']) > 0:
            hasTooManyPermissions = check_policies_for_secret_engine_access(response['AttachedPolicies'])
        
        isTruncated = response['IsTruncated']
        if response['IsTruncated'] == True:
            args['Marker'] = response['Marker']
    return hasTooManyPermissions
                
################################################################################
def check_sac_by_group_policies(group_name):
    hasTooManyPermissions = False
    isTruncated = True
    args = {'MaxItems': 12, 'GroupName': group_name}
    while isTruncated == True and hasTooManyPermissions == False:    
        response = iam_client.list_attached_group_policies(**args)
        if len(response['AttachedPolicies']) > 0:
            hasTooManyPermissions = check_policies_for_secret_engine_access(response['AttachedPolicies'])
        
        isTruncated = response['IsTruncated']
        if response['IsTruncated'] == True:
            args['Marker'] = response['Marker']
    return hasTooManyPermissions
        
################################################################################
def check_sac_by_role_policies(role_name):
    hasTooManyPermissions = False
    isTruncated = True
    args = {'MaxItems': 12, 'RoleName': role_name}
    while isTruncated == True and hasTooManyPermissions == False:    
        response = iam_client.list_attached_role_policies(**args)
        if len(response['AttachedPolicies']) > 0:
            hasTooManyPermissions = check_policies_for_secret_engine_access(response['AttachedPolicies'])
        
        isTruncated = response['IsTruncated']
        if response['IsTruncated'] == True:
            args['Marker'] = response['Marker']
    return hasTooManyPermissions
    
################################################################################
def check_user_sec_access_controlled():
    isTruncated = True
    hasTooManyPermissions = False
    args = {'MaxItems': 12}
    while isTruncated == True and hasTooManyPermissions == False:
        response = iam_client.list_users(**args)
        
        for user in response['Users']:
            hasTooManyPermissions = check_sac_by_user_policies(user['UserName'])
        
        isTruncated = response['IsTruncated']
        if response['IsTruncated'] == True:
            args['Marker'] = response['Marker']
    return hasTooManyPermissions    
            
################################################################################
def check_group_sec_access_controlled():            
    isTruncated = True
    hasTooManyPermissions = False
    args = {'MaxItems': 12}
    while isTruncated == True and hasTooManyPermissions == False:
        response = iam_client.list_groups(**args)
        
        for group in response['Groups']:
            hasTooManyPermissions = check_sac_by_group_policies(group['GroupName'])
            
        isTruncated = response['IsTruncated']
        if response['IsTruncated'] == True:
            args['Marker'] = response['Marker']  
    return hasTooManyPermissions
        
################################################################################
def check_role_sec_access_controlled():
    isTruncated = True
    hasTooManyPermissions = False
    args = {'MaxItems': 12}
    while isTruncated == True and hasTooManyPermissions == False:
        response = iam_client.list_roles(**args)
        
        for role in response['Roles']:
            hasTooManyPermissions = check_sac_by_role_policies(role['RoleName'])
        
        isTruncated = response['IsTruncated']
        if response['IsTruncated'] == True:
            args['Marker'] = response['Marker']
    return hasTooManyPermissions
    
################################################################################
def check_secrets_access_controlled():   
    selected_choice = 'so_04_amsy'    
    hasTooManyPermissions = check_role_sec_access_controlled()
    if not hasTooManyPermissions:
        hasTooManyPermissions = check_group_sec_access_controlled()
    if not hasTooManyPermissions:
        hasTooManyPermissions = check_user_sec_access_controlled()
        
    if hasTooManyPermissions:
        selected_choice = 'so_04_ams_no'
    selected_choices = []
    selected_choices.append(selected_choice)
    return selected_choices    

################################################################################
def check_public_access_blocked_for_s3():
    
    selected_choice = 'so_07_bpay'
    selected_choices = []    
    response = s3_client.list_buckets();
    if response['Buckets']:
        for bucket in response['Buckets']:
            try:
                access_resp = s3_client.get_public_access_block(Bucket=bucket['Name'])
                if access_resp['PublicAccessBlockConfiguration']['BlockPublicAcls'] == False:
                    selected_choice = 'so_07_bpan_no'
                    break
            except botocore.exceptions.ClientError as e:
                print('public access blocked for bucket')

    selected_choices.append(selected_choice)
    return selected_choices 
        
################################################################################
def check_secrets_rotation_enabled():    
    response = sec_client.list_secrets();
    selected_choice = 'so_04_sra_no'
    selected_choices = []    
    if response['SecretList']:
        selected_choice = 'so_04_sry'
        for secret in response['SecretList']:
            sec_response = sec_client.describe_secret(SecretId=secret['ARN'])
            if (not 'RotationEnabled' in sec_response) or sec_response['RotationEnabled'] == False:
                selected_choice = 'so_04_srn'
                break
    selected_choices.append(selected_choice)
    return selected_choices
    
################################################################################
def check_secrets_stored_in_secrets_manager():
    response = sec_client.list_secrets();
    selected_choice = 'so_04_ssns'
    selected_choices = []    
    if response['SecretList']:
        selected_choice = 'so_04_ssse'
    selected_choices.append(selected_choice)
    return selected_choices
    
################################################################################
def check_waf():
    response = waf_client.list_web_acls(Scope='REGIONAL')
    selected_choice = 'so_05_waf_no'
    selected_choices = []
    if response['WebACLs']:
        for webacl in response['WebACLs']:
            response = waf_client.list_resources_for_web_acl(WebACLArn=webacl['ARN'])
            if response['ResourceArns']:
                selected_choice = 'so_05_wafy'
    
    selected_choices.append(selected_choice)
    return selected_choices

################################################################################
def check_remote_access_configuration():
    selected_choices = []
    selected_choice = 'so_05_ras'
    response = ec2_client.describe_security_groups()
    if response['SecurityGroups']:
        for sec_group in response['SecurityGroups']:
            if sec_group['IpPermissions']:
                for perm in sec_group['IpPermissions']:
                    if 'FromPort' in perm and (perm['FromPort'] == 22 or perm['FromPort'] == 3389):
                        selected_choice = 'so_05_rai'
                        for iprange in perm['IpRanges']:
                            if iprange['CidrIp'] == '0.0.0.0/0':
                                selected_choice = 'so_05_raw_no'
                                break
                    if selected_choice == 'so_05_raw_no':
                        break
            if selected_choice == 'so_05_raw_no':
                break
        
    selected_choices.append(selected_choice)      
    return selected_choices

################################################################################
def check_vpc_configuration():
    selected_choices = []
    filters = []
    fltr = {'Name':'is-default', 'Values':['true']}
    filters.append(fltr)
    response = ec2_client.describe_vpcs(
        Filters=filters
    )
    
    if response['Vpcs']:
        selected_choice = 'so_05_vpcd_no'
        selected_choices.append(selected_choice)
        
    filters = []
    fltr = {'Name':'is-default', 'Values':['false']}
    filters.append(fltr)
    response = ec2_client.describe_vpcs(
        Filters=filters
    )
    
    if response['Vpcs']:
        selected_choice = 'so_05_vpcc'
        selected_choices.append(selected_choice) 
        
    filters = []
    fltr = {'Name':'default', 'Values':['false']}
    filters.append(fltr)
    response = ec2_client.describe_network_acls(
        Filters=filters
    ) 
    
    if response['NetworkAcls']:
        selected_choice = 'so_05_vpcn'
        selected_choices.append(selected_choice)   
        
    response = ec2_client.describe_security_groups()
    if response['SecurityGroups']:
        selected_choice = 'so_05_vpcs'
        selected_choices.append(selected_choice)
    
    return selected_choices

################################################################################
def check_iam_users_api_key_rotated():
    resource = boto3.resource('iam')
    selected_choice = 'so_03_api_iun'
    
    try:
        for user in resource.users.all():
            response = iam_client.list_access_keys(UserName=user.user_name)
            if response['AccessKeyMetadata']:
                for key in user.access_keys.all():
                    selected_choice = 'so_03_api_iuy'
                    created_date = key.create_date
                    native = created_date.replace(tzinfo=None)
                    today_date = datetime.datetime.today()
                    delta = today_date - native
                    if delta.days > 7:
                        selected_choice = 'so_03_api_iu_no'
                        break
            if selected_choice == 'so_03_api_iu_no':
                break
    except botocore.exceptions.ClientError as e:
        print(e.response['Error']['Code'])
        
    selected_choices = []
    selected_choices.append(selected_choice)
    
    return selected_choices  

################################################################################
def check_root_account_access_key_created():
    response = iam_client.get_account_summary()
    if response['SummaryMap']['AccountAccessKeysPresent']:
        selected_choice = 'so_03_api_ru_no'
    else:
        selected_choice = 'so_03_api_run'
        
    selected_choices = []
    selected_choices.append(selected_choice)
    
    return selected_choices    
    
################################################################################    
def check_password_policy_created():
    selected_choices = []
    try:
        response = iam_client.get_account_password_policy()
        if response['PasswordPolicy']['MaxPasswordAge'] > 0:
             selected_choices.append('so_02_ppr_ppc')
            #  selected_choices.append('so_02_ppr_prc')
    except iam_client.exceptions.NoSuchEntityException as e:
        selected_choices.append('so_02_ppr_no')
    
    return selected_choices
    
################################################################################
def check_user_segregation():
    
    selected_choice = 'so_02_pbac_lp'
    pagination_token = 'PaginationToken'

    while pagination_token != '':    
        if pagination_token == 'PaginationToken':
            response = iam_client.list_users(MaxItems=50)
        else:
            response = iam_client.list_users(MaxItems=50, PaginationToken=pagination_token) 
        pagination_token = ''    
        if 'PaginationToken' in response:
            pagination_token = response['PaginationToken']            

        users = response['Users']
        for user in users:
            policy_response = iam_client.list_attached_user_policies(
                UserName=user['UserName']
            )
            if policy_response['AttachedPolicies']:
                selected_choice = 'so_02_pbac_no'
    
        response = iam_client.list_groups(MaxItems=50)
        groups = response['Groups']
        if not groups:
            selected_choice = 'so_02_pbac_no'
            
        selected_choices = []
        selected_choices.append(selected_choice)
    
    return selected_choices
    
################################################################################
def check_mfa_enabled():
    response = iam_client.get_account_summary()
    selected_choice = ''
    if response['SummaryMap']['AccountMFAEnabled']:
        selected_choice = 'so_02_mfa_ry'

        
    pagination_token = 'PaginationToken'
    selected_choice_users = 'so_02_mfa_uy'
    while pagination_token != '': 
        if pagination_token == 'PaginationToken':
            response = iam_client.list_users(MaxItems=50)
        else:
            response = iam_client.list_users(MaxItems=50, PaginationToken=pagination_token)
        pagination_token = ''    
        if 'PaginationToken' in response:
            pagination_token = response['PaginationToken']
            
        users = response['Users']    
        for user in users:
            if not 'MFAOptions' in user:
                pagination_token = ''
                selected_choice_users = ''
        
    selected_choices = []
    if selected_choice == '' and  selected_choice_users == '':
            selected_choices.append('so_02_mfa_no')
    else:
        if selected_choice != '':
            selected_choices.append(selected_choice)
        if selected_choice_users != '':            
            selected_choices.append(selected_choice_users)
    
    return selected_choices

################################################################################
def assess_alternate_contact():
    alternateContactsSet = True
    try:
        response = acc_client.get_alternate_contact(
            AlternateContactType='BILLING'
        )
    except acc_client.exceptions.ResourceNotFoundException as e:
        alternateContactsSet = False
    
    try:
        response = acc_client.get_alternate_contact(
            AlternateContactType='SECURITY'
        )
    except acc_client.exceptions.ResourceNotFoundException:
        alternateContactsSet = False
        
    try:
        response = acc_client.get_alternate_contact(
            AlternateContactType='OPERATIONS'
        )
    except acc_client.exceptions.ResourceNotFoundException:
        alternateContactsSet = False

    selected_choice='so_01_aci_no'
    if alternateContactsSet:
        selected_choice='so_01_aci_y'
        
    selected_choices = []
    selected_choices.append(selected_choice)
        
    return selected_choices
    
################################################################################
def assess_questions(question_list, workload_id, lens_arn):
    for question in question_list:
        selected_choices = []
        try:
            if question['QuestionId'] == 'so_01_aci':
                selected_choices = assess_alternate_contact()              
            if question['QuestionId'] == 'so_02_mfa':
                selected_choices = check_mfa_enabled()
            if question['QuestionId'] == 'so_02_pbac':
                selected_choices = check_user_segregation()
            if question['QuestionId'] == 'so_02_ppr':
                selected_choices = check_password_policy_created()  
            if question['QuestionId'] == 'so_03_api_ru':
                selected_choices =  check_root_account_access_key_created()
            if question['QuestionId'] == 'so_03_api_iu':
                selected_choices = check_iam_users_api_key_rotated()
            if question['QuestionId'] == 'so_04_ss':  
                selected_choices = check_secrets_stored_in_secrets_manager()
            if question['QuestionId'] == 'so_04_sr':  
                selected_choices = check_secrets_rotation_enabled()
            if question['QuestionId'] == 'so_04_ams':
                selected_choices = check_secrets_access_controlled()
            if question['QuestionId'] == 'so_05_ss':
                selected_choices = check_vpc_configuration()
            if question['QuestionId'] == 'so_05_rai':
                selected_choices = check_remote_access_configuration()
            if question['QuestionId'] == 'so_05_waf':
                selected_choices = check_waf()       
            if question['QuestionId'] == 'so_05_https':
                selected_choices = check_https_only()
            if question['QuestionId'] == 'so_06_p':
                selected_choices = check_patch_automation()                
            if question['QuestionId'] == 'so_07_bpa':
                selected_choices = check_public_access_blocked_for_s3()
            if question['QuestionId'] == 'so_07_ps3':
                selected_choices = check_s3_static_website()
            if question['QuestionId'] == 'so_08_ct':
                selected_choices = check_cloudtrail_enabled()
            if question['QuestionId'] == 'so_08_cad':
                selected_choices = check_anomaly_detection_configured()
            if question['QuestionId'] == 'so_08_cba':
                selected_choices = check_billing_alarm_configured() 
            if question['QuestionId'] == 'so_08_accana':
                selected_choices = check_access_analyzer()
            if len(selected_choices) > 0:
                update_answer_for_assessment_question(question['QuestionId'], workload_id, lens_arn, selected_choices)
        except botocore.exceptions.ClientError as e:
            print(e.response['Error']['Code'])
            print('Error occured when assessing Question {}'.format(question['QuestionId']))

################################################################################
def list_answers(lens_arn, workload_id):
    response = wa_client.list_answers(
        WorkloadId=workload_id,
        LensAlias=lens_arn,
        MaxResults=50
    )
    
    return response['AnswerSummaries']
    
################################################################################
def create_workload(lens_arn, date_time_ref):
    runtime_region = os.environ['AWS_REGION']

    response = wa_client.create_workload(
        WorkloadName='ResourcesInAccount_' + date_time_ref,
        Environment='PRODUCTION',
        Description='workload created to perform security assessment',
        ReviewOwner='AWS SecAssesser Solution',
        Lenses=[
            lens_arn
        ],
        AwsRegions=[
            runtime_region
        ]
    )
    return response['WorkloadId']

################################################################################
def create_custom_lens(lense, date_time_ref):
    
    http = urllib3.PoolManager()
    resp = http.request('GET', "https://artifacts.kits.eventoutfitters.aws.dev/industries/smb/security-essentials/security_essentials_custom_lens.json")
    
    file_content = resp.data
    json_data = json.loads(file_content)
    json_data['name'] = 'Baseline_Security_Assessment_' + date_time_ref
    
    if lense:
        response = wa_client.import_lens(
            JSONString=json.dumps(json_data),
            LensAlias=lense['LensArn']
        )
    else:
        response = wa_client.import_lens(
            JSONString=json.dumps(json_data)
            
        )
    
    lens_arn = response['LensArn']
        
    wa_client.create_lens_version(
        LensVersion='1',
        LensAlias=lens_arn
    )    
    
    return lens_arn
    
################################################################################
def get_lens(lense_name):
    
    response = wa_client.list_lenses(
        LensType='CUSTOM_SELF',
        LensName=lense_name
    )
    
    found_lense = []
    lenses = response['LensSummaries']
    for lense in lenses:
        if lense['LensName'] == lense_name:
            found_lense = lense
 
    return found_lense

################################################################################    
def start_assessment(event, date_time_ref):
    lense = get_lens('Security Essentials')
    lens_arn = create_custom_lens(lense, date_time_ref)
    workload_id = create_workload(lens_arn, date_time_ref)
    question_list = list_answers(lens_arn, workload_id)
    assess_questions(question_list, workload_id, lens_arn) 

################################################################################    
def delete_assessment(event):
    workload_name  = 'ResourcesInAccount_' + event['PhysicalResourceId']
    response = wa_client.list_workloads()
    for workload in response['WorkloadSummaries']:
        if workload['WorkloadName'] == workload_name:
            workload_id = workload['WorkloadId']
            wa_client.delete_workload(WorkloadId=workload_id)
    
    lens_name = 'Baseline_Security_Assessment_' + event['PhysicalResourceId'] 
    response = wa_client.list_lenses(LensName=lens_name) 
    for lens in response['LensSummaries']:
        lens_id = lens['LensArn']
        wa_client.delete_lens(LensAlias=lens_id, LensStatus='PUBLISHED')   

################################################################################
def handler(event, context):
    date_time_ref = datetime.datetime.now().strftime('%Y%m%d%H%M%S')
    if event['RequestType'] in ['Create']:
        start_assessment(event, date_time_ref)
        
    if event['RequestType'] in ['Delete']:
        delete_assessment(event)

    cfnresponse.send(event, context, cfnresponse.SUCCESS, {}, date_time_ref)