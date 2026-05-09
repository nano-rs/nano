//! AWS CloudTrail generator for management-plane events
//!
//! Produces realistic CloudTrail JSON covering EC2, Lambda, S3, IAM, KMS, RDS,
//! VPC, and more. Includes suspicious caller patterns with elevated access-denied
//! and risky operations for security analysis.
//!
//! Ported from `scripts/generate-aws-cloudtrail-logs.py`.

use chrono::{DateTime, Duration, Utc};
use rand::Rng;
use uuid::Uuid;

use crate::entity::Entity;
use crate::event::Event;

// =============================================================================
// Constants
// =============================================================================

const ACCOUNTS: &[(&str, &str)] = &[
    ("123456789012", "acme-production"),
    ("234567890123", "acme-staging"),
    ("345678901234", "acme-development"),
    ("456789012345", "acme-security"),
];

const REGIONS: &[&str] = &[
    "us-east-1",
    "us-east-2",
    "us-west-2",
    "us-west-1",
    "eu-west-1",
    "eu-west-2",
    "eu-central-1",
    "ap-southeast-1",
    "ap-northeast-1",
];

const USER_AGENTS: &[&str] = &[
    "aws-cli/2.15.0 Python/3.11.6 Darwin/23.0.0 source/arm64 prompt/off",
    "Boto3/1.34.0 Python/3.10.12 Linux/5.15.0-1041-aws",
    "aws-sdk-java/2.20.0 Linux/5.15.0-1041-aws OpenJDK_64-Bit_Server_VM/17.0.8+7",
    "aws-sdk-go/1.44.0 (go1.20; linux; amd64)",
    "console.amazonaws.com",
    "[S3Console/0.4, aws-internal/3 aws-sdk-java/1.12.540]",
    "terraform-provider-aws/5.30.0",
    "aws-sdk-nodejs/3.400.0 linux/v18.17.0",
    "cloudformation.amazonaws.com",
    "APN/1.0 HashiCorp/1.0 Terraform/1.6.0",
];

/// (name, type, ip, has_mfa, is_suspicious)
const CALLERS: &[(&str, &str, &str, bool, bool)] = &[
    ("john.smith", "IAMUser", "203.0.113.50", true, false),
    ("jane.doe", "IAMUser", "203.0.113.51", true, false),
    ("bob.wilson", "IAMUser", "203.0.113.52", true, false),
    ("alice.johnson", "IAMUser", "198.51.100.10", true, false),
    ("charlie.brown", "IAMUser", "198.51.100.11", false, false),
    ("admin-ops", "IAMUser", "203.0.113.100", true, false),
    ("intern01", "IAMUser", "198.51.100.25", false, false),
    ("deploy-pipeline", "AssumedRole", "10.0.0.50", false, false),
    ("monitoring-agent", "AssumedRole", "10.0.0.51", false, false),
    ("backup-service", "AssumedRole", "10.0.0.52", false, false),
    ("eks-node-role", "AssumedRole", "10.0.1.10", false, false),
    // Suspicious callers
    ("contractor-acme", "IAMUser", "89.248.167.131", false, true),
    ("intern01", "IAMUser", "45.155.205.233", false, true),
];

/// (event_source, event_name, change_type, weight, service_group)
struct Op {
    event_source: &'static str,
    resource_type: &'static str,
    name_prefix: &'static str,
    event_name: &'static str,
    change_type: &'static str,
    weight: u32,
    #[allow(dead_code)]
    service_group: &'static str,
}

// Macro to reduce boilerplate defining operations
macro_rules! ops {
    ($src:expr, $rtype:expr, $prefix:expr, $group:expr, [ $(($name:expr, $change:expr, $w:expr)),* $(,)? ]) => {
        &[ $( Op {
            event_source: $src,
            resource_type: $rtype,
            name_prefix: $prefix,
            event_name: $name,
            change_type: $change,
            weight: $w,
            service_group: $group,
        } ),* ]
    };
}

const COMPUTE_EC2_INSTANCE: &[Op] = ops!(
    "ec2.amazonaws.com", "instance", "i-", "compute",
    [
        ("RunInstances", "create", 8),
        ("StartInstances", "access", 15),
        ("StopInstances", "update", 10),
        ("RebootInstances", "update", 5),
        ("TerminateInstances", "delete", 3),
        ("DescribeInstances", "access", 30),
        ("ModifyInstanceAttribute", "update", 8),
        ("CreateTags", "update", 10),
    ]
);

const COMPUTE_EC2_SG: &[Op] = ops!(
    "ec2.amazonaws.com", "security_group", "sg-", "compute",
    [
        ("CreateSecurityGroup", "create", 5),
        ("DeleteSecurityGroup", "delete", 2),
        ("AuthorizeSecurityGroupIngress", "permission_change", 10),
        ("RevokeSecurityGroupIngress", "permission_change", 5),
        ("AuthorizeSecurityGroupEgress", "permission_change", 5),
        ("DescribeSecurityGroups", "access", 20),
    ]
);

const COMPUTE_LAMBDA: &[Op] = ops!(
    "lambda.amazonaws.com", "function", "fn-", "compute",
    [
        ("CreateFunction20150331", "create", 5),
        ("UpdateFunctionCode20150331v2", "update", 10),
        ("UpdateFunctionConfiguration20150331v2", "update", 8),
        ("DeleteFunction20150331", "delete", 2),
        ("GetFunction20150331v2", "access", 15),
        ("Invoke", "access", 25),
        ("ListFunctions20150331", "access", 10),
    ]
);

const COMPUTE_ECS: &[Op] = ops!(
    "ecs.amazonaws.com", "service", "svc-", "compute",
    [
        ("CreateService", "create", 3),
        ("UpdateService", "update", 10),
        ("DeleteService", "delete", 2),
        ("DescribeServices", "access", 20),
        ("RegisterTaskDefinition", "create", 8),
        ("RunTask", "access", 15),
    ]
);

const STORAGE_S3: &[Op] = ops!(
    "s3.amazonaws.com", "bucket", "", "storage",
    [
        ("CreateBucket", "create", 3),
        ("DeleteBucket", "delete", 1),
        ("PutBucketPolicy", "permission_change", 8),
        ("DeleteBucketPolicy", "permission_change", 3),
        ("PutBucketAcl", "permission_change", 5),
        ("PutPublicAccessBlock", "permission_change", 5),
        ("DeletePublicAccessBlock", "permission_change", 3),
        ("GetBucketPolicy", "access", 10),
        ("ListBuckets", "access", 20),
        ("PutBucketEncryption", "update", 5),
    ]
);

const STORAGE_KMS: &[Op] = ops!(
    "kms.amazonaws.com", "key", "key-", "storage",
    [
        ("CreateKey", "create", 3),
        ("ScheduleKeyDeletion", "delete", 1),
        ("EnableKey", "update", 3),
        ("DisableKey", "update", 2),
        ("Encrypt", "access", 20),
        ("Decrypt", "access", 25),
        ("GenerateDataKey", "access", 15),
        ("DescribeKey", "access", 10),
        ("CreateAlias", "update", 5),
        ("PutKeyPolicy", "permission_change", 3),
    ]
);

const STORAGE_SECRETS: &[Op] = ops!(
    "secretsmanager.amazonaws.com", "secret", "secret-", "storage",
    [
        ("CreateSecret", "create", 5),
        ("DeleteSecret", "delete", 2),
        ("GetSecretValue", "access", 25),
        ("PutSecretValue", "update", 10),
        ("RotateSecret", "update", 5),
        ("DescribeSecret", "access", 15),
        ("ListSecrets", "access", 10),
    ]
);

const IAM_USER: &[Op] = ops!(
    "iam.amazonaws.com", "user", "user-", "iam",
    [
        ("CreateUser", "create", 5),
        ("DeleteUser", "delete", 2),
        ("AttachUserPolicy", "permission_change", 8),
        ("DetachUserPolicy", "permission_change", 4),
        ("CreateAccessKey", "permission_change", 5),
        ("DeleteAccessKey", "permission_change", 3),
        ("ListUsers", "access", 15),
        ("GetUser", "access", 10),
        ("CreateLoginProfile", "permission_change", 3),
    ]
);

const IAM_ROLE: &[Op] = ops!(
    "iam.amazonaws.com", "role", "role-", "iam",
    [
        ("CreateRole", "create", 5),
        ("DeleteRole", "delete", 2),
        ("AttachRolePolicy", "permission_change", 10),
        ("DetachRolePolicy", "permission_change", 5),
        ("UpdateAssumeRolePolicy", "permission_change", 5),
        ("ListRoles", "access", 15),
        ("GetRole", "access", 10),
    ]
);

const IAM_POLICY: &[Op] = ops!(
    "iam.amazonaws.com", "policy", "policy-", "iam",
    [
        ("CreatePolicy", "create", 5),
        ("DeletePolicy", "delete", 2),
        ("CreatePolicyVersion", "update", 8),
        ("ListPolicies", "access", 15),
        ("GetPolicy", "access", 10),
    ]
);

const IAM_STS: &[Op] = ops!(
    "sts.amazonaws.com", "session", "session-", "iam",
    [
        ("AssumeRole", "access", 30),
        ("GetCallerIdentity", "access", 20),
        ("GetSessionToken", "access", 10),
        ("AssumeRoleWithSAML", "access", 5),
    ]
);

const NETWORK_VPC: &[Op] = ops!(
    "ec2.amazonaws.com", "vpc", "vpc-", "networking",
    [
        ("CreateVpc", "create", 3),
        ("DeleteVpc", "delete", 1),
        ("ModifyVpcAttribute", "update", 5),
        ("DescribeVpcs", "access", 20),
        ("CreateSubnet", "create", 5),
        ("DeleteSubnet", "delete", 2),
    ]
);

const NETWORK_NACL: &[Op] = ops!(
    "ec2.amazonaws.com", "nacl", "acl-", "networking",
    [
        ("CreateNetworkAcl", "create", 3),
        ("DeleteNetworkAcl", "delete", 1),
        ("CreateNetworkAclEntry", "permission_change", 8),
        ("DeleteNetworkAclEntry", "permission_change", 4),
        ("DescribeNetworkAcls", "access", 15),
    ]
);

const NETWORK_ELB: &[Op] = ops!(
    "elasticloadbalancing.amazonaws.com", "loadbalancer", "elb-", "networking",
    [
        ("CreateLoadBalancer", "create", 3),
        ("DeleteLoadBalancer", "delete", 1),
        ("ModifyLoadBalancerAttributes", "update", 5),
        ("DescribeLoadBalancers", "access", 15),
        ("CreateTargetGroup", "create", 5),
        ("RegisterTargets", "update", 8),
    ]
);

const NETWORK_R53: &[Op] = ops!(
    "route53.amazonaws.com", "hosted_zone", "zone-", "networking",
    [
        ("CreateHostedZone", "create", 2),
        ("DeleteHostedZone", "delete", 1),
        ("ChangeResourceRecordSets", "update", 10),
        ("ListHostedZones", "access", 10),
        ("GetHostedZone", "access", 8),
    ]
);

const DATABASE_RDS: &[Op] = ops!(
    "rds.amazonaws.com", "db_instance", "db-", "database",
    [
        ("CreateDBInstance", "create", 3),
        ("DeleteDBInstance", "delete", 1),
        ("ModifyDBInstance", "update", 8),
        ("RebootDBInstance", "update", 3),
        ("StopDBInstance", "update", 3),
        ("StartDBInstance", "update", 3),
        ("DescribeDBInstances", "access", 20),
        ("CreateDBSnapshot", "create", 5),
    ]
);

const DATABASE_DDB: &[Op] = ops!(
    "dynamodb.amazonaws.com", "table", "table-", "database",
    [
        ("CreateTable", "create", 3),
        ("DeleteTable", "delete", 1),
        ("UpdateTable", "update", 5),
        ("DescribeTable", "access", 20),
        ("ListTables", "access", 10),
        ("UpdateContinuousBackups", "update", 3),
    ]
);

const DATABASE_CACHE: &[Op] = ops!(
    "elasticache.amazonaws.com", "cluster", "cache-", "database",
    [
        ("CreateCacheCluster", "create", 3),
        ("DeleteCacheCluster", "delete", 1),
        ("ModifyCacheCluster", "update", 5),
        ("DescribeCacheClusters", "access", 15),
        ("CreateReplicationGroup", "create", 3),
    ]
);

/// Service groups with weights: (name, op_tables, weight)
const SERVICE_GROUPS: &[(&str, &[&[Op]], u32)] = &[
    (
        "compute",
        &[
            COMPUTE_EC2_INSTANCE,
            COMPUTE_EC2_SG,
            COMPUTE_LAMBDA,
            COMPUTE_ECS,
        ],
        30,
    ),
    (
        "storage",
        &[STORAGE_S3, STORAGE_KMS, STORAGE_SECRETS],
        25,
    ),
    (
        "iam",
        &[IAM_USER, IAM_ROLE, IAM_POLICY, IAM_STS],
        15,
    ),
    (
        "networking",
        &[NETWORK_VPC, NETWORK_NACL, NETWORK_ELB, NETWORK_R53],
        15,
    ),
    (
        "database",
        &[DATABASE_RDS, DATABASE_DDB, DATABASE_CACHE],
        15,
    ),
];

// Resource name suffixes by type
fn resource_suffix(resource_type: &str, rng: &mut impl Rng) -> String {
    match resource_type {
        "instance" => {
            let s = ["0a1b2c3d4", "0b2c3d4e5", "0c3d4e5f6", "0d4e5f6a7", "0e5f6a7b8", "0f6a7b8c9"];
            s[rng.random_range(0..s.len())].to_string()
        }
        "security_group" => {
            let s = ["01a2b3c4", "02b3c4d5", "03c4d5e6", "04d5e6f7", "05e6f7a8"];
            s[rng.random_range(0..s.len())].to_string()
        }
        "function" => {
            let s = ["api-handler", "data-processor", "image-resizer", "auth-validator", "event-router", "cron-job", "webhook-receiver"];
            s[rng.random_range(0..s.len())].to_string()
        }
        "service" => {
            let s = ["web-prod", "api-prod", "workers-prod", "web-staging", "batch-processor"];
            s[rng.random_range(0..s.len())].to_string()
        }
        "bucket" => {
            let s = ["acme-prod-data", "acme-prod-logs", "acme-staging-data", "acme-backups", "acme-static-assets", "acme-ml-models", "acme-audit-logs"];
            s[rng.random_range(0..s.len())].to_string()
        }
        "key" => {
            let s = ["prod-encryption", "staging-encryption", "secrets-key", "s3-server-side", "rds-encryption", "ebs-default"];
            s[rng.random_range(0..s.len())].to_string()
        }
        "secret" => {
            let s = ["prod/db-password", "prod/api-key", "staging/db-password", "prod/oauth-secret", "deploy/github-token", "monitoring/pagerduty"];
            s[rng.random_range(0..s.len())].to_string()
        }
        "user" => {
            let s = ["john.smith", "jane.doe", "svc-deploy", "svc-monitoring", "auditor", "contractor"];
            s[rng.random_range(0..s.len())].to_string()
        }
        "role" => {
            let s = ["deploy-pipeline", "lambda-execution", "eks-node", "ecs-task", "admin-access", "read-only-audit", "cross-account"];
            s[rng.random_range(0..s.len())].to_string()
        }
        "policy" => {
            let s = ["deploy-access", "s3-read-only", "admin-full", "security-audit", "billing-view", "network-admin"];
            s[rng.random_range(0..s.len())].to_string()
        }
        "session" => {
            let s = ["deploy-session", "admin-session", "audit-session", "cross-account-session"];
            s[rng.random_range(0..s.len())].to_string()
        }
        "vpc" => {
            let s = ["0a1b2c3d4", "0b2c3d4e5", "0c3d4e5f6"];
            s[rng.random_range(0..s.len())].to_string()
        }
        "nacl" => {
            let s = ["01a2b3c4", "02b3c4d5", "03c4d5e6"];
            s[rng.random_range(0..s.len())].to_string()
        }
        "loadbalancer" => {
            let s = ["web-prod", "api-prod", "internal-prod", "staging-web"];
            s[rng.random_range(0..s.len())].to_string()
        }
        "hosted_zone" => {
            let s = ["Z0123456789ABC", "Z9876543210DEF", "Z1122334455AAB"];
            s[rng.random_range(0..s.len())].to_string()
        }
        "db_instance" => {
            let s = ["prod-primary", "prod-replica", "staging-primary", "analytics-warehouse"];
            s[rng.random_range(0..s.len())].to_string()
        }
        "table" => {
            let s = ["users", "orders", "sessions", "events", "audit-log", "configs"];
            s[rng.random_range(0..s.len())].to_string()
        }
        "cluster" => {
            let s = ["prod-redis", "staging-redis", "session-store", "rate-limiter"];
            s[rng.random_range(0..s.len())].to_string()
        }
        _ => format!("resource-{}", rng.random_range(1000u32..9999)),
    }
}

// =============================================================================
// Generator
// =============================================================================

pub struct CloudTrailGenerator;

impl CloudTrailGenerator {
    pub fn new() -> Self {
        Self
    }

    pub fn generate(
        &self,
        timestamp: DateTime<Utc>,
        _entity: &Entity,
        rng: &mut impl Rng,
    ) -> Event {
        // Pick a caller
        let caller = CALLERS[rng.random_range(0..CALLERS.len())];
        let (caller_name, caller_type, caller_ip, caller_mfa, is_suspicious) = caller;

        // Pick service group (weighted)
        let (svc_group, op_tables) = self.pick_service_group(rng, is_suspicious);

        // Pick an op table from the group, then a weighted operation
        let table = op_tables[rng.random_range(0..op_tables.len())];

        // For suspicious callers, bias toward risky ops
        let op = if is_suspicious && rng.random_bool(0.3) {
            let risky: Vec<&Op> = table
                .iter()
                .filter(|o| o.change_type == "delete" || o.change_type == "permission_change")
                .collect();
            if risky.is_empty() {
                self.weighted_pick(table, rng)
            } else {
                risky[rng.random_range(0..risky.len())]
            }
        } else {
            self.weighted_pick(table, rng)
        };

        // Account (suspicious favor production)
        let account = if is_suspicious {
            ACCOUNTS[rng.random_range(0..2)]
        } else {
            ACCOUNTS[rng.random_range(0..ACCOUNTS.len())]
        };
        let (account_id, account_alias) = account;

        let region = REGIONS[rng.random_range(0..REGIONS.len())];

        // Resource name
        let suffix = resource_suffix(op.resource_type, rng);
        let resource_name = format!("{}{}", op.name_prefix, suffix);

        // ARN
        let resource_arn =
            self.build_arn(op.event_source, op.resource_type, &resource_name, account_id, region);

        // MFA (10% chance of dropping MFA even for MFA users)
        let effective_mfa = caller_mfa && !rng.random_bool(0.1);

        // Status outcome
        let (error_code, error_message) = if is_suspicious {
            self.pick_status_suspicious(rng)
        } else {
            self.pick_status_normal(rng)
        };

        let read_only = op.change_type == "access";
        let user_agent = USER_AGENTS[rng.random_range(0..USER_AGENTS.len())];

        // Build user identity
        let user_identity = self.build_user_identity(
            caller_name,
            caller_type,
            caller_ip,
            effective_mfa,
            account_id,
            timestamp,
            rng,
        );

        // Request parameters
        let request_params =
            self.build_request_params(op.event_name, &resource_name, &resource_arn, account_id, rng);

        // Response elements (only for successful mutating calls)
        let response_elements = if error_code.is_none() && !read_only {
            self.build_response_elements(op.event_name, &resource_name, &resource_arn, timestamp, rng)
        } else {
            None
        };

        let event_id = Uuid::now_v7().to_string();
        let request_id = Uuid::now_v7().to_string();

        // AWS resource type string
        let service_upper = op
            .event_source
            .split('.')
            .next()
            .unwrap_or("aws")
            .to_uppercase();
        let resource_type_pascal = op
            .resource_type
            .split('_')
            .map(|w| {
                let mut c = w.chars();
                match c.next() {
                    None => String::new(),
                    Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
                }
            })
            .collect::<String>();

        let mut event = serde_json::json!({
            "eventVersion": "1.09",
            "userIdentity": user_identity,
            "eventTime": timestamp.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            "eventSource": op.event_source,
            "eventName": op.event_name,
            "awsRegion": region,
            "sourceIPAddress": caller_ip,
            "userAgent": user_agent,
            "requestParameters": request_params,
            "responseElements": response_elements,
            "requestID": request_id,
            "eventID": event_id,
            "readOnly": read_only,
            "eventType": "AwsApiCall",
            "managementEvent": true,
            "recipientAccountId": account_id,
            "eventCategory": "Management",
            "resources": [{
                "type": format!("AWS::{}::{}", service_upper, resource_type_pascal),
                "ARN": resource_arn,
            }],
            "additionalEventData": {
                "SignatureVersion": "SigV4",
                "CipherSuite": "ECDHE-RSA-AES128-GCM-SHA256",
                "AuthenticationMethod": "AuthHeader",
            },
        });

        if let Some(code) = error_code {
            event["errorCode"] = serde_json::json!(code);
            event["errorMessage"] = serde_json::json!(error_message.unwrap());
        }

        if caller_type == "IAMUser" {
            event["additionalEventData"]["MFAUsed"] =
                serde_json::json!(if effective_mfa { "Yes" } else { "No" });
        }

        // _nanosiem helper fields for parser extraction
        event["_nanosiem"] = serde_json::json!({
            "accountAlias": account_alias,
            "cloudService": svc_group,
            "changeType": op.change_type,
            "resourceName": resource_name,
            "resourceType": op.resource_type,
            "mfaAuthenticated": effective_mfa,
            "callerType": caller_type,
            "callerName": caller_name,
            "status": if error_code.is_some() { "Failure" } else { "Success" },
        });

        let label_caller = caller_name;
        let label_action = op.event_name;

        Event {
            message: serde_json::to_string(&event).unwrap(),
            timestamp: timestamp.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
            source_type: "aws_cloudtrail".to_string(),
            display_label: format!(
                "[cloudtrail] {} {} {}",
                label_caller, label_action, resource_name
            ),
        }
    }

    fn pick_service_group<'a>(
        &self,
        rng: &mut impl Rng,
        is_suspicious: bool,
    ) -> (&'static str, &'static [&'static [Op]]) {
        // Suspicious callers favor IAM ops
        if is_suspicious && rng.random_bool(0.4) {
            return ("iam", &[IAM_USER, IAM_ROLE, IAM_POLICY, IAM_STS]);
        }

        let total: u32 = SERVICE_GROUPS.iter().map(|(_, _, w)| w).sum();
        let mut r = rng.random_range(0..total);
        for &(name, tables, weight) in SERVICE_GROUPS {
            if r < weight {
                return (name, tables);
            }
            r -= weight;
        }
        let last = SERVICE_GROUPS.last().unwrap();
        (last.0, last.1)
    }

    fn weighted_pick<'a>(&self, ops: &'a [Op], rng: &mut impl Rng) -> &'a Op {
        let total: u32 = ops.iter().map(|o| o.weight).sum();
        let mut r = rng.random_range(0..total);
        for op in ops {
            if r < op.weight {
                return op;
            }
            r -= op.weight;
        }
        ops.last().unwrap()
    }

    fn pick_status_normal(
        &self,
        rng: &mut impl Rng,
    ) -> (Option<&'static str>, Option<&'static str>) {
        let r: f64 = rng.random();
        if r < 0.80 {
            (None, None)
        } else if r < 0.88 {
            (
                Some("AccessDeniedException"),
                Some("User is not authorized to perform this operation"),
            )
        } else if r < 0.93 {
            (
                Some("ResourceNotFoundException"),
                Some("The specified resource does not exist"),
            )
        } else if r < 0.96 {
            (
                Some("LimitExceededException"),
                Some("Rate limit exceeded"),
            )
        } else if r < 0.98 {
            (
                Some("ConflictException"),
                Some("The resource already exists"),
            )
        } else {
            (Some("InternalFailure"), Some("An internal error occurred"))
        }
    }

    fn pick_status_suspicious(
        &self,
        rng: &mut impl Rng,
    ) -> (Option<&'static str>, Option<&'static str>) {
        let r: f64 = rng.random();
        if r < 0.50 {
            (None, None)
        } else if r < 0.75 {
            (
                Some("AccessDeniedException"),
                Some("User is not authorized to perform this operation"),
            )
        } else if r < 0.85 {
            (
                Some("ResourceNotFoundException"),
                Some("The specified resource does not exist"),
            )
        } else if r < 0.90 {
            (
                Some("LimitExceededException"),
                Some("Rate limit exceeded"),
            )
        } else if r < 0.95 {
            (
                Some("InvalidAccessKeyId"),
                Some("The security token in the request is invalid"),
            )
        } else {
            (Some("InternalFailure"), Some("An internal error occurred"))
        }
    }

    fn build_user_identity(
        &self,
        name: &str,
        caller_type: &str,
        _ip: &str,
        mfa: bool,
        account_id: &str,
        ts: DateTime<Utc>,
        rng: &mut impl Rng,
    ) -> serde_json::Value {
        let principal_id_prefix = if caller_type == "IAMUser" {
            "AIDA"
        } else {
            "AROA"
        };
        let principal_suffix = format!("{:016X}", rng.random_range(0u64..u64::MAX));

        if caller_type == "IAMUser" {
            serde_json::json!({
                "type": "IAMUser",
                "principalId": format!("{}{}", principal_id_prefix, principal_suffix),
                "arn": format!("arn:aws:iam::{}:user/{}", account_id, name),
                "accountId": account_id,
                "userName": name,
                "accessKeyId": format!("AKIA{:016X}", rng.random_range(0u64..u64::MAX)),
            })
        } else {
            let session_id = format!("{:08x}", rng.random_range(0u32..u32::MAX));
            let role_arn = format!("arn:aws:iam::{}:role/{}", account_id, name);
            let creation = ts - Duration::hours(rng.random_range(1..8) as i64);
            serde_json::json!({
                "type": "AssumedRole",
                "principalId": format!("{}{}:session-{}", principal_id_prefix, principal_suffix, session_id),
                "arn": format!("arn:aws:sts::{}:assumed-role/{}/session-{}", account_id, name, session_id),
                "accountId": account_id,
                "accessKeyId": format!("ASIA{:016X}", rng.random_range(0u64..u64::MAX)),
                "sessionContext": {
                    "sessionIssuer": {
                        "type": "Role",
                        "principalId": format!("AROA{:016X}", rng.random_range(0u64..u64::MAX)),
                        "arn": role_arn,
                        "accountId": account_id,
                        "userName": name,
                    },
                    "attributes": {
                        "creationDate": creation.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
                        "mfaAuthenticated": if mfa { "true" } else { "false" },
                    },
                },
            })
        }
    }

    fn build_arn(
        &self,
        event_source: &str,
        resource_type: &str,
        resource_name: &str,
        account_id: &str,
        region: &str,
    ) -> String {
        let service = event_source.replace(".amazonaws.com", "");

        let global_services = ["iam", "sts", "s3", "route53"];
        let arn_region = if global_services.contains(&service.as_str()) {
            ""
        } else {
            region
        };

        if service == "s3" {
            return format!("arn:aws:s3:::{}", resource_name);
        }

        let resource_path = match (service.as_str(), resource_type) {
            ("ec2", "instance") => format!("instance/{}", resource_name),
            ("ec2", "security_group") => format!("security-group/{}", resource_name),
            ("ec2", "vpc") => format!("vpc/{}", resource_name),
            ("ec2", "nacl") => format!("network-acl/{}", resource_name),
            ("lambda", "function") => format!("function:{}", resource_name),
            ("ecs", "service") => format!("service/{}", resource_name),
            ("kms", "key") => format!("key/{}", resource_name),
            ("secretsmanager", "secret") => format!("secret:{}", resource_name),
            ("iam", "user") => format!("user/{}", resource_name),
            ("iam", "role") => format!("role/{}", resource_name),
            ("iam", "policy") => format!("policy/{}", resource_name),
            ("sts", "session") => format!("assumed-role/{}", resource_name),
            ("elasticloadbalancing", "loadbalancer") => {
                format!("loadbalancer/app/{}", resource_name)
            }
            ("route53", "hosted_zone") => format!("hostedzone/{}", resource_name),
            ("rds", "db_instance") => format!("db:{}", resource_name),
            ("dynamodb", "table") => format!("table/{}", resource_name),
            ("elasticache", "cluster") => format!("cluster:{}", resource_name),
            _ => format!("{}/{}", resource_type, resource_name),
        };

        format!(
            "arn:aws:{}:{}:{}:{}",
            service, arn_region, account_id, resource_path
        )
    }

    fn build_request_params(
        &self,
        event_name: &str,
        resource_name: &str,
        resource_arn: &str,
        account_id: &str,
        rng: &mut impl Rng,
    ) -> serde_json::Value {
        match event_name {
            // EC2 instances
            "RunInstances" => {
                let instance_types = ["t3.micro", "t3.medium", "m5.large", "m5.xlarge", "c5.2xlarge", "r5.large"];
                let key_names = ["prod-key", "staging-key", "dev-key"];
                serde_json::json!({
                    "instanceType": instance_types[rng.random_range(0..instance_types.len())],
                    "imageId": format!("ami-{:08x}", rng.random_range(0u32..u32::MAX)),
                    "minCount": 1, "maxCount": 1,
                    "subnetId": format!("subnet-{:08x}", rng.random_range(0u32..u32::MAX)),
                    "keyName": key_names[rng.random_range(0..key_names.len())],
                })
            }
            "StartInstances" | "StopInstances" | "TerminateInstances" | "RebootInstances" => {
                serde_json::json!({"instancesSet": {"items": [{"instanceId": resource_name}]}})
            }
            "DescribeInstances" => serde_json::json!({"filterSet": {}, "instancesSet": {}}),

            // Security groups
            "CreateSecurityGroup" => serde_json::json!({
                "groupName": resource_name,
                "groupDescription": format!("Security group for {}", resource_name),
                "vpcId": format!("vpc-{:08x}", rng.random_range(0u32..u32::MAX)),
            }),
            "AuthorizeSecurityGroupIngress" | "RevokeSecurityGroupIngress" => {
                let ports = [22u16, 80, 443, 3306, 5432, 6379, 8080];
                let port = ports[rng.random_range(0..ports.len())];
                let cidrs = ["0.0.0.0/0", "10.0.0.0/8", "172.16.0.0/12", "203.0.113.0/24"];
                serde_json::json!({
                    "groupId": resource_name,
                    "ipPermissions": {"items": [{
                        "ipProtocol": if rng.random_bool(0.8) { "tcp" } else { "udp" },
                        "fromPort": port, "toPort": port,
                        "ipRanges": {"items": [{"cidrIp": cidrs[rng.random_range(0..cidrs.len())]}]},
                    }]},
                })
            }

            // Lambda
            "CreateFunction20150331" => {
                let runtimes = ["python3.12", "nodejs20.x", "java21", "go1.x"];
                let mem_sizes = [128, 256, 512, 1024];
                serde_json::json!({
                    "functionName": resource_name,
                    "runtime": runtimes[rng.random_range(0..runtimes.len())],
                    "handler": "index.handler",
                    "memorySize": mem_sizes[rng.random_range(0..mem_sizes.len())],
                })
            }
            "Invoke" => serde_json::json!({"functionName": resource_name}),

            // S3
            "CreateBucket" | "DeleteBucket" => serde_json::json!({"bucketName": resource_name}),
            "PutBucketPolicy" => serde_json::json!({
                "bucketName": resource_name,
                "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[...]}",
            }),
            "DeleteBucketPolicy" | "PutBucketAcl" => {
                serde_json::json!({"bucketName": resource_name})
            }
            "PutPublicAccessBlock" => serde_json::json!({
                "bucketName": resource_name,
                "PublicAccessBlockConfiguration": {
                    "BlockPublicAcls": true, "BlockPublicPolicy": true,
                    "IgnorePublicAcls": true, "RestrictPublicBuckets": true,
                },
            }),
            "DeletePublicAccessBlock" => serde_json::json!({"bucketName": resource_name}),

            // IAM users
            "CreateUser" | "DeleteUser" | "GetUser" => {
                serde_json::json!({"userName": resource_name})
            }
            "AttachUserPolicy" | "DetachUserPolicy" => {
                let policies = [
                    "AdministratorAccess",
                    "PowerUserAccess",
                    "ReadOnlyAccess",
                    "S3FullAccess",
                    "EC2FullAccess",
                ];
                serde_json::json!({
                    "userName": resource_name,
                    "policyArn": format!("arn:aws:iam::{}:policy/{}", account_id, policies[rng.random_range(0..policies.len())]),
                })
            }
            "CreateAccessKey" | "DeleteAccessKey" => {
                serde_json::json!({"userName": resource_name})
            }

            // IAM roles
            "CreateRole" | "DeleteRole" | "GetRole" => {
                serde_json::json!({"roleName": resource_name})
            }
            "AttachRolePolicy" | "DetachRolePolicy" => {
                let policies = [
                    "AmazonS3FullAccess",
                    "AmazonEC2FullAccess",
                    "AmazonDynamoDBFullAccess",
                    "CloudWatchFullAccess",
                ];
                serde_json::json!({
                    "roleName": resource_name,
                    "policyArn": format!("arn:aws:iam::aws:policy/{}", policies[rng.random_range(0..policies.len())]),
                })
            }

            // STS
            "AssumeRole" => serde_json::json!({
                "roleArn": resource_arn,
                "roleSessionName": format!("session-{:08x}", rng.random_range(0u32..u32::MAX)),
            }),

            // KMS
            "Encrypt" | "Decrypt" | "GenerateDataKey" => {
                serde_json::json!({"keyId": resource_arn})
            }
            "CreateKey" => serde_json::json!({
                "description": format!("Encryption key for {}", resource_name),
                "keyUsage": "ENCRYPT_DECRYPT",
            }),

            // Secrets Manager
            "GetSecretValue" | "PutSecretValue" | "DescribeSecret" => {
                serde_json::json!({"secretId": resource_arn})
            }
            "CreateSecret" => serde_json::json!({"name": resource_name}),

            // RDS
            "CreateDBInstance" => {
                let db_classes = ["db.t3.medium", "db.r5.large", "db.r5.xlarge"];
                let engines = ["postgres", "mysql", "aurora-postgresql"];
                serde_json::json!({
                    "dBInstanceIdentifier": resource_name,
                    "dBInstanceClass": db_classes[rng.random_range(0..db_classes.len())],
                    "engine": engines[rng.random_range(0..engines.len())],
                })
            }
            "ModifyDBInstance" | "DeleteDBInstance" | "StopDBInstance" | "StartDBInstance"
            | "RebootDBInstance" => serde_json::json!({"dBInstanceIdentifier": resource_name}),

            // DynamoDB
            "CreateTable" => serde_json::json!({
                "tableName": resource_name,
                "billingMode": if rng.random_bool(0.5) { "PAY_PER_REQUEST" } else { "PROVISIONED" },
            }),
            "DescribeTable" | "DeleteTable" | "UpdateTable" => {
                serde_json::json!({"tableName": resource_name})
            }

            // VPC
            "CreateVpc" => {
                let cidrs = ["10.0.0.0/16", "172.16.0.0/16", "192.168.0.0/16"];
                serde_json::json!({"cidrBlock": cidrs[rng.random_range(0..cidrs.len())]})
            }
            "ChangeResourceRecordSets" => {
                let actions = ["CREATE", "UPSERT", "DELETE"];
                serde_json::json!({
                    "hostedZoneId": resource_name,
                    "changeBatch": {"changes": [{"action": actions[rng.random_range(0..actions.len())], "resourceRecordSet": {"name": "app.example.com", "type": "A"}}]},
                })
            }

            // ELB
            "CreateLoadBalancer" => serde_json::json!({
                "name": resource_name,
                "type": if rng.random_bool(0.6) { "application" } else { "network" },
                "scheme": if rng.random_bool(0.7) { "internet-facing" } else { "internal" },
            }),

            // Fallback
            _ => serde_json::json!({"resourceName": resource_name}),
        }
    }

    fn build_response_elements(
        &self,
        event_name: &str,
        resource_name: &str,
        resource_arn: &str,
        ts: DateTime<Utc>,
        rng: &mut impl Rng,
    ) -> Option<serde_json::Value> {
        match event_name {
            "RunInstances" => Some(serde_json::json!({
                "instancesSet": {"items": [{"instanceId": resource_name, "currentState": {"name": "pending"}}]}
            })),
            "StartInstances" => Some(serde_json::json!({
                "instancesSet": {"items": [{"instanceId": resource_name, "currentState": {"name": "running"}}]}
            })),
            "StopInstances" => Some(serde_json::json!({
                "instancesSet": {"items": [{"instanceId": resource_name, "currentState": {"name": "stopped"}}]}
            })),
            "TerminateInstances" => Some(serde_json::json!({
                "instancesSet": {"items": [{"instanceId": resource_name, "currentState": {"name": "shutting-down"}}]}
            })),
            "CreateAccessKey" => Some(serde_json::json!({
                "accessKey": {
                    "accessKeyId": format!("AKIA{:016X}", rng.random_range(0u64..u64::MAX)),
                    "status": "Active",
                    "userName": resource_name,
                }
            })),
            "AssumeRole" => {
                let expiry = ts + Duration::hours(1);
                Some(serde_json::json!({
                    "credentials": {
                        "accessKeyId": format!("ASIA{:016X}", rng.random_range(0u64..u64::MAX)),
                        "expiration": expiry.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
                    }
                }))
            }
            "CreateKey" => Some(serde_json::json!({
                "keyMetadata": {"keyId": resource_name, "arn": resource_arn, "keyState": "Enabled"}
            })),
            _ => None,
        }
    }
}
