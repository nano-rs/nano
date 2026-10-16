// SPDX-License-Identifier: AGPL-3.0-or-later
//! Run on a fresh disposable DB to cover the setup endpoint's repository path.
mod common;

use nanosiem_core::auth::{
    CreateUserRequest, GroupRepository, OidcRepository, OidcService, OidcUser, UserRepository,
};
use sqlx::PgPool;
use uuid::Uuid;

async fn version(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT version FROM public.grant_authority_version WHERE singleton")
        .fetch_one(pool)
        .await
        .unwrap()
}

#[tokio::test]
#[ignore = "requires fresh disposable PostgreSQL; run with --ignored"]
async fn setup_admin_membership_and_oidc_admission_advance_authority() {
    std::env::set_var(
        "NANOSIEM_ENCRYPTION_KEY",
        "nan3917-disposable-test-key-32bytes",
    );
    let pool = common::migrated_pool().await;
    let users = UserRepository::new(pool.clone());
    let groups = GroupRepository::new(pool.clone());
    let before = version(&pool).await;
    // Exactly the create_user call used by /api/setup/initialize. The nested
    // Everyone insert executes under migration 368's restricted search_path.
    let admin = users
        .create_user(&CreateUserRequest {
            email: format!("setup-{}@example.test", Uuid::new_v4()),
            name: "Setup admin".into(),
            password: "Disposable-3917-Password!".into(),
            group_ids: vec![],
        })
        .await
        .unwrap();
    assert!(version(&pool).await > before);
    assert!(groups
        .is_user_in_group(admin.id, Uuid::from_u128(1))
        .await
        .unwrap());
    // The setup handler creates its Admins group and assigns the Admin role.
    let admins: Uuid =
        sqlx::query_scalar("INSERT INTO groups(name,is_system) VALUES($1,FALSE) RETURNING id")
            .bind(format!("Admins {}", admin.id))
            .fetch_one(&pool)
            .await
            .unwrap();
    sqlx::query("INSERT INTO group_roles(group_id,role_id) VALUES($1,$2)")
        .bind(admins)
        .bind(Uuid::from_u128(1))
        .execute(&pool)
        .await
        .unwrap();
    users
        .set_user_groups(admin.id, &[admins, Uuid::from_u128(1)])
        .await
        .unwrap();
    assert!(groups.is_user_in_group(admin.id, admins).await.unwrap());

    let group = Uuid::new_v4();
    sqlx::query("INSERT INTO groups(id,name) VALUES($1,$2)")
        .bind(group)
        .bind(format!("Admission {group}"))
        .execute(&pool)
        .await
        .unwrap();
    let before = version(&pool).await;
    groups.add_user_to_group(admin.id, group).await.unwrap();
    assert!(version(&pool).await > before);
    assert!(groups.is_user_in_group(admin.id, group).await.unwrap());

    let provider = Uuid::new_v4();
    let policy = serde_json::json!({"mapped_groups_only":true,"mappings":[
        {"idp_group":"allowed","group_ids":[group]}
    ]});
    sqlx::query("INSERT INTO oidc_providers(id,name,slug,issuer,client_id,client_secret_encrypted,enabled,access_policy) VALUES($1,'Admission proof',$2,'https://issuer.example','fixture','x'::bytea,TRUE,$3)")
        .bind(provider).bind(format!("proof-{provider}")).bind(policy)
        .execute(&pool).await.unwrap();
    let service = OidcService::new(
        OidcRepository::new(pool.clone()),
        users,
        GroupRepository::new(pool.clone()),
    );
    let before = version(&pool).await;
    let (user, created) = service
        .provision_user(
            &OidcUser {
                subject: Uuid::new_v4().to_string(),
                email: format!("sso-{}@example.test", Uuid::new_v4()),
                email_verified: true,
                name: "SSO admission".into(),
                groups: vec!["allowed".into()],
                provider_id: provider,
            },
            None,
            None,
        )
        .await
        .unwrap();
    assert!(created);
    assert!(version(&pool).await > before);
    assert!(groups.is_user_in_group(user.id, group).await.unwrap());
    assert!(!groups
        .is_user_in_group(user.id, Uuid::from_u128(1))
        .await
        .unwrap());
}
