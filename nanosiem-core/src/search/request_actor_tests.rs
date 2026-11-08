// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;

#[tokio::test]
async fn spawned_tasks_inherit_the_actor_only_through_inherit() {
    let actor = Uuid::new_v4();
    with_request_actor(actor, async move {
        assert_eq!(current_request_actor(), Some(actor));
        let bare = tokio::spawn(async { current_request_actor() })
            .await
            .unwrap();
        assert_eq!(bare, None, "task locals never cross tokio::spawn on their own");
        let inherited = tokio::spawn(inherit(async { current_request_actor() }))
            .await
            .unwrap();
        assert_eq!(inherited, Some(actor));
    })
    .await;
    assert_eq!(current_request_actor(), None);
}

#[tokio::test]
async fn spawned_tasks_inherit_the_query_class() {
    use crate::search::admission::{current_query_class, with_query_class, QueryClass};
    with_query_class(QueryClass::Agent, async {
        let bare = tokio::spawn(async { current_query_class() }).await.unwrap();
        assert_eq!(bare, QueryClass::Human);
        let inherited = tokio::spawn(inherit(async { current_query_class() }))
            .await
            .unwrap();
        assert_eq!(inherited, QueryClass::Agent);
    })
    .await;
    assert_eq!(current_query_class(), QueryClass::Human);
}
