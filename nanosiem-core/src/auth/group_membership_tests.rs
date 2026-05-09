// SPDX-License-Identifier: AGPL-3.0-or-later

//! Property-based tests for group membership invariants
//!
//! Feature: authentication-rbac
//!
//! These tests verify the correctness properties for group membership:
//! - Property 14: Group Deletion Preserves Users
//! - Property 15: Everyone Group Membership

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use std::collections::{HashMap, HashSet};
    use uuid::Uuid;

    use crate::auth::types::builtin_groups;

    /// Simulated user for testing
    #[derive(Debug, Clone)]
    #[allow(dead_code)]
    struct TestUser {
        id: Uuid,
        email: String,
        name: String,
    }

    /// Simulated group for testing
    #[derive(Debug, Clone)]
    #[allow(dead_code)]
    struct TestGroup {
        id: Uuid,
        name: String,
        is_system: bool,
    }

    /// Simulated database state for testing group membership invariants
    #[derive(Debug, Clone)]
    struct TestDatabase {
        users: HashMap<Uuid, TestUser>,
        groups: HashMap<Uuid, TestGroup>,
        user_groups: HashSet<(Uuid, Uuid)>, // (user_id, group_id)
    }

    impl TestDatabase {
        fn new() -> Self {
            let mut db = Self {
                users: HashMap::new(),
                groups: HashMap::new(),
                user_groups: HashSet::new(),
            };

            // Create the built-in "Everyone" group
            db.groups.insert(
                builtin_groups::EVERYONE_ID,
                TestGroup {
                    id: builtin_groups::EVERYONE_ID,
                    name: "Everyone".to_string(),
                    is_system: true,
                },
            );

            db
        }

        /// Create a user and automatically add to Everyone group (simulates trigger)
        fn create_user(&mut self, email: String, name: String) -> Uuid {
            let id = Uuid::now_v7();
            self.users.insert(id, TestUser { id, email, name });

            // Simulate the database trigger that adds users to Everyone group
            self.user_groups.insert((id, builtin_groups::EVERYONE_ID));

            id
        }

        /// Create a non-system group
        fn create_group(&mut self, name: String) -> Uuid {
            let id = Uuid::now_v7();
            self.groups.insert(
                id,
                TestGroup {
                    id,
                    name,
                    is_system: false,
                },
            );
            id
        }

        /// Add user to a group
        fn add_user_to_group(&mut self, user_id: Uuid, group_id: Uuid) -> bool {
            if !self.users.contains_key(&user_id) || !self.groups.contains_key(&group_id) {
                return false;
            }
            self.user_groups.insert((user_id, group_id));
            true
        }

        /// Delete a group (simulates CASCADE behavior)
        /// Returns true if deletion was successful, false if group is system group
        fn delete_group(&mut self, group_id: Uuid) -> bool {
            if let Some(group) = self.groups.get(&group_id) {
                if group.is_system {
                    return false; // Cannot delete system groups
                }
            } else {
                return false; // Group doesn't exist
            }

            // Remove group
            self.groups.remove(&group_id);

            // Remove all user-group memberships for this group (CASCADE)
            self.user_groups.retain(|(_, gid)| *gid != group_id);

            true
        }

        /// Check if user exists
        fn user_exists(&self, user_id: Uuid) -> bool {
            self.users.contains_key(&user_id)
        }

        /// Check if user is in a group
        fn is_user_in_group(&self, user_id: Uuid, group_id: Uuid) -> bool {
            self.user_groups.contains(&(user_id, group_id))
        }

        /// Get all users
        fn get_all_user_ids(&self) -> Vec<Uuid> {
            self.users.keys().cloned().collect()
        }

        /// Remove user from a group (except Everyone)
        fn remove_user_from_group(&mut self, user_id: Uuid, group_id: Uuid) -> bool {
            // Cannot remove from Everyone group
            if group_id == builtin_groups::EVERYONE_ID {
                return false;
            }
            self.user_groups.remove(&(user_id, group_id))
        }
    }

    // Strategy for generating valid email addresses
    fn email_strategy() -> impl Strategy<Value = String> {
        "[a-z]{3,10}@[a-z]{3,8}\\.(com|org|net)"
    }

    // Strategy for generating user names
    fn name_strategy() -> impl Strategy<Value = String> {
        "[A-Z][a-z]{2,10} [A-Z][a-z]{2,10}"
    }

    // Strategy for generating group names
    fn group_name_strategy() -> impl Strategy<Value = String> {
        "[A-Z][a-z]{3,15}"
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        /// Feature: authentication-rbac, Property 14: Group Deletion Preserves Users
        ///
        /// *For any* group deletion operation, all users who were members of that group
        /// SHALL continue to exist in the system (not be deleted).
        ///
        /// **Validates: Requirements 6.6**
        #[test]
        fn prop_group_deletion_preserves_users(
            user_emails in prop::collection::vec(email_strategy(), 1..10),
            user_names in prop::collection::vec(name_strategy(), 1..10),
            group_names in prop::collection::vec(group_name_strategy(), 1..5),
        ) {
            let mut db = TestDatabase::new();

            // Create users
            let user_count = user_emails.len().min(user_names.len());
            let mut user_ids = Vec::new();
            for i in 0..user_count {
                let user_id = db.create_user(user_emails[i].clone(), user_names[i].clone());
                user_ids.push(user_id);
            }

            // Create groups
            let mut group_ids = Vec::new();
            for name in group_names {
                let group_id = db.create_group(name);
                group_ids.push(group_id);
            }

            // Add users to groups (each user to at least one group)
            for (i, user_id) in user_ids.iter().enumerate() {
                if !group_ids.is_empty() {
                    let group_idx = i % group_ids.len();
                    db.add_user_to_group(*user_id, group_ids[group_idx]);
                }
            }

            // Record which users exist before deletion
            let users_before: HashSet<Uuid> = db.get_all_user_ids().into_iter().collect();

            // Delete all non-system groups
            for group_id in &group_ids {
                db.delete_group(*group_id);
            }

            // Verify all users still exist after group deletion
            for user_id in &users_before {
                prop_assert!(
                    db.user_exists(*user_id),
                    "User {:?} was deleted when group was deleted, violating Property 14",
                    user_id
                );
            }

            // Verify user count is unchanged
            let users_after: HashSet<Uuid> = db.get_all_user_ids().into_iter().collect();
            prop_assert_eq!(
                users_before.len(),
                users_after.len(),
                "User count changed after group deletion"
            );
        }

        /// Feature: authentication-rbac, Property 15: Everyone Group Membership
        ///
        /// *For any* user in the system, that user SHALL be a member of the "Everyone" group.
        ///
        /// **Validates: Requirements 6.7**
        #[test]
        fn prop_everyone_group_membership(
            user_emails in prop::collection::vec(email_strategy(), 1..20),
            user_names in prop::collection::vec(name_strategy(), 1..20),
        ) {
            let mut db = TestDatabase::new();

            // Create users
            let user_count = user_emails.len().min(user_names.len());
            let mut user_ids = Vec::new();
            for i in 0..user_count {
                let user_id = db.create_user(user_emails[i].clone(), user_names[i].clone());
                user_ids.push(user_id);
            }

            // Verify every user is in the Everyone group
            for user_id in &user_ids {
                prop_assert!(
                    db.is_user_in_group(*user_id, builtin_groups::EVERYONE_ID),
                    "User {:?} is not in the Everyone group, violating Property 15",
                    user_id
                );
            }
        }

        /// Feature: authentication-rbac, Property 15: Everyone Group Membership (cannot be removed)
        ///
        /// *For any* user in the system, attempts to remove them from the "Everyone" group
        /// SHALL fail, ensuring they remain members.
        ///
        /// **Validates: Requirements 6.7**
        #[test]
        fn prop_cannot_remove_from_everyone_group(
            user_emails in prop::collection::vec(email_strategy(), 1..10),
            user_names in prop::collection::vec(name_strategy(), 1..10),
        ) {
            let mut db = TestDatabase::new();

            // Create users
            let user_count = user_emails.len().min(user_names.len());
            let mut user_ids = Vec::new();
            for i in 0..user_count {
                let user_id = db.create_user(user_emails[i].clone(), user_names[i].clone());
                user_ids.push(user_id);
            }

            // Try to remove each user from Everyone group
            for user_id in &user_ids {
                // Attempt to remove should fail
                let removed = db.remove_user_from_group(*user_id, builtin_groups::EVERYONE_ID);
                prop_assert!(
                    !removed,
                    "Was able to remove user {:?} from Everyone group, violating Property 15",
                    user_id
                );

                // User should still be in Everyone group
                prop_assert!(
                    db.is_user_in_group(*user_id, builtin_groups::EVERYONE_ID),
                    "User {:?} is no longer in Everyone group after removal attempt",
                    user_id
                );
            }
        }

        /// Feature: authentication-rbac, Property 14: Group Deletion Preserves Users (multiple groups)
        ///
        /// *For any* user belonging to multiple groups, deleting any of those groups
        /// SHALL preserve the user and their membership in other groups.
        ///
        /// **Validates: Requirements 6.6**
        #[test]
        fn prop_group_deletion_preserves_other_memberships(
            user_emails in prop::collection::vec(email_strategy(), 1..5),
            user_names in prop::collection::vec(name_strategy(), 1..5),
            group_names in prop::collection::vec(group_name_strategy(), 2..6),
        ) {
            let mut db = TestDatabase::new();

            // Create users
            let user_count = user_emails.len().min(user_names.len());
            let mut user_ids = Vec::new();
            for i in 0..user_count {
                let user_id = db.create_user(user_emails[i].clone(), user_names[i].clone());
                user_ids.push(user_id);
            }

            // Create groups
            let mut group_ids = Vec::new();
            for name in group_names {
                let group_id = db.create_group(name);
                group_ids.push(group_id);
            }

            // Add each user to all groups
            for user_id in &user_ids {
                for group_id in &group_ids {
                    db.add_user_to_group(*user_id, *group_id);
                }
            }

            // Delete the first group
            if !group_ids.is_empty() {
                let deleted_group = group_ids[0];
                let remaining_groups: Vec<Uuid> = group_ids[1..].to_vec();

                db.delete_group(deleted_group);

                // Verify all users still exist
                for user_id in &user_ids {
                    prop_assert!(
                        db.user_exists(*user_id),
                        "User {:?} was deleted when group was deleted",
                        user_id
                    );

                    // Verify user is still in remaining groups
                    for group_id in &remaining_groups {
                        prop_assert!(
                            db.is_user_in_group(*user_id, *group_id),
                            "User {:?} lost membership in group {:?} when another group was deleted",
                            user_id,
                            group_id
                        );
                    }

                    // Verify user is still in Everyone group
                    prop_assert!(
                        db.is_user_in_group(*user_id, builtin_groups::EVERYONE_ID),
                        "User {:?} lost membership in Everyone group",
                        user_id
                    );
                }
            }
        }
    }
}
