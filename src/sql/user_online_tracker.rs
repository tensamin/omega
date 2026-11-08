use crate::sql::connection_status::UserStatus;
use parking_lot::RwLock;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};

fn select_primary_route(previous_primary: Option<i64>, connected: &HashSet<i64>) -> Option<i64> {
    previous_primary
        .filter(|id| connected.contains(id))
        .or_else(|| connected.iter().min().copied())
}

fn sorted_vec(values: HashSet<i64>) -> Vec<i64> {
    let mut values = values.into_iter().collect::<Vec<_>>();
    values.sort_unstable();
    values
}

fn sorted_pairs(values: HashSet<(i64, i64)>) -> Vec<(i64, i64)> {
    let mut values = values.into_iter().collect::<Vec<_>>();
    values.sort_unstable();
    values
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientSessionRoute {
    pub omikron_id: i64,
    pub iota_id: i64,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct PresenceSubscriber {
    pub user_id: i64,
    pub session_id: i64,
    pub omikron_id: i64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PresenceIndices {
    pub sessions_by_user: HashMap<i64, HashSet<i64>>,
    pub sessions_by_omikron: HashMap<i64, HashSet<(i64, i64)>>,
    pub targets_by_subscriber: HashMap<(i64, i64), HashSet<i64>>,
    pub subscribers_by_omikron: HashMap<i64, HashSet<(i64, i64)>>,
    pub iotas_by_omikron: HashMap<i64, HashSet<i64>>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IotaRoute {
    pub primary_omikron_id: Option<i64>,
    pub connected_omikron_ids: HashSet<i64>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PresenceRoutes {
    pub iotas: HashMap<i64, IotaRoute>,
    pub sessions: HashMap<(i64, i64), ClientSessionRoute>,
    pub subscriptions: HashMap<i64, HashSet<PresenceSubscriber>>,
    pub indices: PresenceIndices,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RemovedOmikronState {
    pub iota_ids: Vec<i64>,
    pub session_user_ids: Vec<i64>,
    pub subscriber_sessions: Vec<(i64, i64)>,
}

/// All live presence state is kept together so routing cannot be overwritten
/// by a preference update.  Preferences are account-scoped, routes are
/// session-scoped, and effective state is always derived.
pub struct PresenceTracker {
    pub(crate) routes: RwLock<PresenceRoutes>,
    preferences: RwLock<HashMap<i64, UserStatus>>,
    pub observation_epoch: uuid::Uuid,
    observation_sequence: AtomicU64,
}

impl Default for PresenceTracker {
    fn default() -> Self {
        Self {
            routes: RwLock::new(PresenceRoutes::default()),
            preferences: RwLock::new(HashMap::new()),
            observation_epoch: uuid::Uuid::new_v4(),
            observation_sequence: AtomicU64::new(0),
        }
    }
}

impl PresenceTracker {
    fn remove_subscription_locked(routes: &mut PresenceRoutes, key: (i64, i64)) {
        let Some(targets) = routes.indices.targets_by_subscriber.remove(&key) else {
            return;
        };
        let mut omikron_ids = HashSet::new();
        for target_user_id in targets {
            if let Some(subscribers) = routes.subscriptions.get_mut(&target_user_id) {
                subscribers.retain(|subscriber| {
                    if (subscriber.user_id, subscriber.session_id) == key {
                        omikron_ids.insert(subscriber.omikron_id);
                        false
                    } else {
                        true
                    }
                });
                if subscribers.is_empty() {
                    routes.subscriptions.remove(&target_user_id);
                }
            }
        }
        for omikron_id in omikron_ids {
            if let Some(sessions) = routes.indices.subscribers_by_omikron.get_mut(&omikron_id) {
                sessions.remove(&key);
                if sessions.is_empty() {
                    routes.indices.subscribers_by_omikron.remove(&omikron_id);
                }
            }
        }
    }

    fn remove_session_locked(
        routes: &mut PresenceRoutes,
        key: (i64, i64),
        expected_omikron_id: Option<i64>,
    ) -> bool {
        let Some(route) = routes.sessions.get(&key) else {
            return false;
        };
        if expected_omikron_id.is_some_and(|id| route.omikron_id != id) {
            return false;
        }
        let route = routes.sessions.remove(&key).unwrap();
        if let Some(session_ids) = routes.indices.sessions_by_user.get_mut(&key.0) {
            session_ids.remove(&key.1);
            if session_ids.is_empty() {
                routes.indices.sessions_by_user.remove(&key.0);
            }
        }
        if let Some(session_keys) = routes
            .indices
            .sessions_by_omikron
            .get_mut(&route.omikron_id)
        {
            session_keys.remove(&key);
            if session_keys.is_empty() {
                routes.indices.sessions_by_omikron.remove(&route.omikron_id);
            }
        }
        Self::remove_subscription_locked(routes, key);
        true
    }

    fn insert_session_locked(
        routes: &mut PresenceRoutes,
        key: (i64, i64),
        route: ClientSessionRoute,
    ) {
        Self::remove_session_locked(routes, key, None);
        routes.sessions.insert(key, route.clone());
        routes
            .indices
            .sessions_by_user
            .entry(key.0)
            .or_default()
            .insert(key.1);
        routes
            .indices
            .sessions_by_omikron
            .entry(route.omikron_id)
            .or_default()
            .insert(key);
    }

    fn remove_iota_owner_locked(
        routes: &mut PresenceRoutes,
        iota_id: i64,
        omikron_id: i64,
    ) -> bool {
        let Some(route) = routes.iotas.get_mut(&iota_id) else {
            return false;
        };
        route.connected_omikron_ids.remove(&omikron_id);
        route.primary_omikron_id =
            select_primary_route(route.primary_omikron_id, &route.connected_omikron_ids);
        let empty = route.connected_omikron_ids.is_empty();
        if let Some(iotas) = routes.indices.iotas_by_omikron.get_mut(&omikron_id) {
            iotas.remove(&iota_id);
            if iotas.is_empty() {
                routes.indices.iotas_by_omikron.remove(&omikron_id);
            }
        }
        if empty {
            routes.iotas.remove(&iota_id);
        }
        empty
    }

    #[cfg(debug_assertions)]
    fn debug_assert_indices(routes: &PresenceRoutes) {
        debug_assert!(Self::check_indices(routes).is_ok());
    }

    #[cfg(not(debug_assertions))]
    fn debug_assert_indices(_: &PresenceRoutes) {}

    fn check_indices(routes: &PresenceRoutes) -> Result<(), String> {
        for (key, route) in &routes.sessions {
            if !routes
                .indices
                .sessions_by_user
                .get(&key.0)
                .is_some_and(|sessions| sessions.contains(&key.1))
            {
                return Err(format!("session {key:?} missing user index"));
            }
            if !routes
                .indices
                .sessions_by_omikron
                .get(&route.omikron_id)
                .is_some_and(|sessions| sessions.contains(key))
            {
                return Err(format!("session {key:?} missing Omikron index"));
            }
        }
        for (user_id, session_ids) in &routes.indices.sessions_by_user {
            for session_id in session_ids {
                if !routes.sessions.contains_key(&(*user_id, *session_id)) {
                    return Err(format!("stale user session index {user_id}:{session_id}"));
                }
            }
        }
        for (omikron_id, session_keys) in &routes.indices.sessions_by_omikron {
            for key in session_keys {
                if routes.sessions.get(key).map(|route| route.omikron_id) != Some(*omikron_id) {
                    return Err(format!("stale Omikron session index {omikron_id}:{key:?}"));
                }
            }
        }
        for (target_user_id, subscribers) in &routes.subscriptions {
            for subscriber in subscribers {
                let key = (subscriber.user_id, subscriber.session_id);
                if !routes
                    .indices
                    .targets_by_subscriber
                    .get(&key)
                    .is_some_and(|targets| targets.contains(target_user_id))
                {
                    return Err(format!("subscription {key:?} missing target index"));
                }
                if !routes
                    .indices
                    .subscribers_by_omikron
                    .get(&subscriber.omikron_id)
                    .is_some_and(|sessions| sessions.contains(&key))
                {
                    return Err(format!("subscription {key:?} missing Omikron index"));
                }
            }
        }
        for (key, targets) in &routes.indices.targets_by_subscriber {
            for target in targets {
                if !routes.subscriptions.get(target).is_some_and(|subscribers| {
                    subscribers
                        .iter()
                        .any(|subscriber| (subscriber.user_id, subscriber.session_id) == *key)
                }) {
                    return Err(format!("stale target index {key:?}:{target}"));
                }
            }
        }
        for (omikron_id, iota_ids) in &routes.indices.iotas_by_omikron {
            for iota_id in iota_ids {
                if !routes
                    .iotas
                    .get(iota_id)
                    .is_some_and(|route| route.connected_omikron_ids.contains(omikron_id))
                {
                    return Err(format!("stale Iota index {omikron_id}:{iota_id}"));
                }
            }
        }
        Ok(())
    }

    pub fn set_preference(&self, user_id: i64, status: UserStatus) {
        self.preferences.write().insert(user_id, status);
    }

    pub fn set_preferences(&self, preferences: HashMap<i64, UserStatus>) {
        self.preferences.write().extend(preferences);
    }

    pub fn load_preference(&self, user_id: i64, raw: &str) -> bool {
        let Some(status) = UserStatus::from_client_preference(raw) else {
            self.set_preference(user_id, UserStatus::user_online);
            return false;
        };
        self.set_preference(user_id, status);
        true
    }

    pub fn preference(&self, user_id: i64) -> UserStatus {
        self.preferences
            .read()
            .get(&user_id)
            .cloned()
            .unwrap_or(UserStatus::user_online)
    }

    #[cfg(test)]
    pub fn has_iota_route(&self, iota_id: i64) -> bool {
        self.routes
            .read()
            .iotas
            .get(&iota_id)
            .is_some_and(|route| !route.connected_omikron_ids.is_empty())
    }

    pub fn owns_iota_route(&self, iota_id: i64, omikron_id: i64) -> bool {
        self.routes
            .read()
            .iotas
            .get(&iota_id)
            .is_some_and(|route| route.connected_omikron_ids.contains(&omikron_id))
    }

    #[cfg(test)]
    pub fn has_active_session_for_iota(&self, user_id: i64, iota_id: i64) -> bool {
        let routes = self.routes.read();
        Self::active_session_for_iota(&routes, user_id, iota_id)
    }

    fn active_session_for_iota(routes: &PresenceRoutes, user_id: i64, iota_id: i64) -> bool {
        routes
            .indices
            .sessions_by_user
            .get(&user_id)
            .into_iter()
            .flat_map(|session_ids| session_ids.iter())
            .any(|session_id| {
                routes
                    .sessions
                    .get(&(user_id, *session_id))
                    .is_some_and(|route| {
                        route.iota_id == iota_id
                            && routes.iotas.get(&route.iota_id).is_some_and(|iota| {
                                iota.connected_omikron_ids.contains(&route.omikron_id)
                            })
                    })
            })
    }

    pub fn track_session(&self, user_id: i64, session_id: i64, omikron_id: i64, iota_id: i64) {
        let mut routes = self.routes.write();
        Self::insert_session_locked(
            &mut routes,
            (user_id, session_id),
            ClientSessionRoute {
                omikron_id,
                iota_id,
            },
        );
        Self::debug_assert_indices(&routes);
    }

    pub fn remove_session(&self, user_id: i64, session_id: i64, omikron_id: i64) -> bool {
        let mut routes = self.routes.write();
        let removed =
            Self::remove_session_locked(&mut routes, (user_id, session_id), Some(omikron_id));
        Self::debug_assert_indices(&routes);
        removed
    }

    pub fn remove_user_sessions(&self, user_id: i64) {
        let mut routes = self.routes.write();
        let session_ids = routes
            .indices
            .sessions_by_user
            .get(&user_id)
            .cloned()
            .unwrap_or_default();
        for session_id in session_ids {
            Self::remove_session_locked(&mut routes, (user_id, session_id), None);
        }
        Self::debug_assert_indices(&routes);
    }

    pub fn owns_session(&self, user_id: i64, session_id: i64, omikron_id: i64) -> bool {
        self.routes
            .read()
            .sessions
            .get(&(user_id, session_id))
            .is_some_and(|route| route.omikron_id == omikron_id)
    }

    pub fn resolve_public_state(&self, user_id: i64, iota_id: i64) -> UserStatus {
        self.observe_public_state(user_id, Some(iota_id)).0
    }

    /// Sequence the observation while both inputs are locked. Delayed pushes
    /// can then be compared with snapshots without ordering network tasks.
    pub fn observe_public_state(&self, user_id: i64, iota_id: Option<i64>) -> (UserStatus, u64) {
        let routes = self.routes.read();
        let preferences = self.preferences.read();
        let state = match iota_id {
            None => UserStatus::user_offline,
            Some(id)
                if !routes
                    .iotas
                    .get(&id)
                    .is_some_and(|route| !route.connected_omikron_ids.is_empty()) =>
            {
                UserStatus::iota_offline
            }
            Some(id) if !Self::active_session_for_iota(&routes, user_id, id) => {
                UserStatus::user_offline
            }
            Some(_) => preferences
                .get(&user_id)
                .cloned()
                .unwrap_or(UserStatus::user_online)
                .public_value(),
        };
        let sequence = self.observation_boundary();
        (state, sequence)
    }

    pub fn observation_boundary(&self) -> u64 {
        self.observation_sequence
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |sequence| {
                sequence.checked_add(1)
            })
            .expect("presence observation sequence exhausted")
            + 1
    }

    pub fn resolve_private_state(&self, user_id: i64) -> UserStatus {
        self.preference(user_id)
    }

    pub fn remove_omikron(&self, omikron_id: i64) -> RemovedOmikronState {
        let mut routes = self.routes.write();
        let iota_ids = routes
            .indices
            .iotas_by_omikron
            .remove(&omikron_id)
            .unwrap_or_default();
        for iota_id in &iota_ids {
            Self::remove_iota_owner_locked(&mut routes, *iota_id, omikron_id);
        }

        let subscriber_sessions = routes
            .indices
            .subscribers_by_omikron
            .remove(&omikron_id)
            .unwrap_or_default();

        let session_keys = routes
            .indices
            .sessions_by_omikron
            .remove(&omikron_id)
            .unwrap_or_default();
        let session_user_ids = session_keys
            .iter()
            .map(|(user_id, _)| *user_id)
            .collect::<HashSet<_>>();
        for key in &session_keys {
            Self::remove_session_locked(&mut routes, *key, Some(omikron_id));
        }
        for key in &subscriber_sessions {
            Self::remove_subscription_locked(&mut routes, *key);
        }
        Self::debug_assert_indices(&routes);

        RemovedOmikronState {
            iota_ids: sorted_vec(iota_ids),
            session_user_ids: sorted_vec(session_user_ids),
            subscriber_sessions: sorted_pairs(subscriber_sessions),
        }
    }

    pub fn remove_sessions_for_iota(&self, iota_id: i64, omikron_id: i64) {
        let mut routes = self.routes.write();
        let keys = routes
            .indices
            .sessions_by_omikron
            .get(&omikron_id)
            .into_iter()
            .flat_map(|keys| keys.iter())
            .filter(|key| {
                routes
                    .sessions
                    .get(key)
                    .is_some_and(|route| route.iota_id == iota_id)
            })
            .copied()
            .collect::<Vec<_>>();
        for key in &keys {
            Self::remove_session_locked(&mut routes, *key, Some(omikron_id));
        }
        Self::debug_assert_indices(&routes);
    }

    pub fn replace_subscription(
        &self,
        user_id: i64,
        session_id: i64,
        omikron_id: i64,
        user_ids: Vec<i64>,
    ) {
        let mut routes = self.routes.write();
        let key = (user_id, session_id);
        Self::remove_subscription_locked(&mut routes, key);
        for target_user_id in user_ids {
            let subscriber = PresenceSubscriber {
                user_id,
                session_id,
                omikron_id,
            };
            routes
                .subscriptions
                .entry(target_user_id)
                .or_default()
                .insert(subscriber.clone());
            routes
                .indices
                .targets_by_subscriber
                .entry(key)
                .or_default()
                .insert(target_user_id);
            routes
                .indices
                .subscribers_by_omikron
                .entry(omikron_id)
                .or_default()
                .insert(key);
        }
        Self::debug_assert_indices(&routes);
    }

    pub fn subscribers(&self, target_user_id: i64) -> Vec<PresenceSubscriber> {
        let mut subscribers = self
            .routes
            .read()
            .subscriptions
            .get(&target_user_id)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .collect::<Vec<_>>();
        subscribers.sort_by_key(|subscriber| {
            (
                subscriber.omikron_id,
                subscriber.user_id,
                subscriber.session_id,
            )
        });
        subscribers
    }

    pub fn sessions_owned_by(&self, omikron_id: i64) -> Vec<(i64, i64, ClientSessionRoute)> {
        let routes = self.routes.read();
        let mut sessions = routes
            .indices
            .sessions_by_omikron
            .get(&omikron_id)
            .into_iter()
            .flat_map(|keys| keys.iter())
            .filter_map(|key| {
                routes
                    .sessions
                    .get(key)
                    .map(|route| (key.0, key.1, route.clone()))
            })
            .collect::<Vec<_>>();
        sessions.sort_by_key(|(user_id, session_id, _)| (*user_id, *session_id));
        sessions
    }

    pub fn replace_omikron_snapshot(
        &self,
        omikron_id: i64,
        iota_ids: &[i64],
        sessions: &[(i64, i64, i64)],
    ) {
        let mut routes = self.routes.write();
        let old_sessions = routes
            .indices
            .sessions_by_omikron
            .get(&omikron_id)
            .cloned()
            .unwrap_or_default();
        let old_subscriber_sessions = routes
            .indices
            .subscribers_by_omikron
            .remove(&omikron_id)
            .unwrap_or_default();
        for key in &old_subscriber_sessions {
            Self::remove_subscription_locked(&mut routes, *key);
        }
        for key in &old_sessions {
            Self::remove_session_locked(&mut routes, *key, Some(omikron_id));
        }
        let old_iota_ids = routes
            .indices
            .iotas_by_omikron
            .get(&omikron_id)
            .cloned()
            .unwrap_or_default();
        for iota_id in old_iota_ids {
            Self::remove_iota_owner_locked(&mut routes, iota_id, omikron_id);
        }
        for iota_id in iota_ids {
            let route = routes.iotas.entry(*iota_id).or_default();
            route.connected_omikron_ids.insert(omikron_id);
            route.primary_omikron_id =
                select_primary_route(route.primary_omikron_id, &route.connected_omikron_ids);
            routes
                .indices
                .iotas_by_omikron
                .entry(omikron_id)
                .or_default()
                .insert(*iota_id);
        }
        for (user_id, session_id, iota_id) in sessions {
            Self::insert_session_locked(
                &mut routes,
                (*user_id, *session_id),
                ClientSessionRoute {
                    omikron_id,
                    iota_id: *iota_id,
                },
            );
        }
        Self::debug_assert_indices(&routes);
    }

    pub fn untrack_iota_connection(&self, iota_id: i64, omikron_id: i64) -> bool {
        let connections_empty = self.disconnect_iota(iota_id, omikron_id);
        self.remove_sessions_for_iota(iota_id, omikron_id);
        connections_empty
    }

    pub fn primary_iota_route(&self, iota_id: i64) -> Option<i64> {
        self.routes
            .read()
            .iotas
            .get(&iota_id)
            .and_then(|route| route.primary_omikron_id)
    }

    pub fn iota_connections(&self, iota_id: i64) -> Option<Vec<i64>> {
        let routes = self.routes.read();
        let route = routes.iotas.get(&iota_id)?;
        let mut ids = route
            .connected_omikron_ids
            .iter()
            .copied()
            .collect::<Vec<_>>();
        ids.sort_unstable();
        Some(ids)
    }

    pub fn routes_for_user(&self, user_id: i64) -> Vec<ClientSessionRoute> {
        let routes = self.routes.read();
        let mut user_routes = routes
            .indices
            .sessions_by_user
            .get(&user_id)
            .into_iter()
            .flat_map(|session_ids| session_ids.iter())
            .filter_map(|session_id| {
                routes
                    .sessions
                    .get(&(user_id, *session_id))
                    .map(|route| (*session_id, route.clone()))
            })
            .collect::<Vec<_>>();
        user_routes.sort_by_key(|(session_id, route)| (*session_id, route.omikron_id));
        user_routes.into_iter().map(|(_, route)| route).collect()
    }

    pub fn owns_user_route(&self, user_id: i64, omikron_id: i64) -> bool {
        let routes = self.routes.read();
        routes
            .indices
            .sessions_by_user
            .get(&user_id)
            .into_iter()
            .flat_map(|session_ids| session_ids.iter())
            .any(|session_id| {
                routes
                    .sessions
                    .get(&(user_id, *session_id))
                    .is_some_and(|route| route.omikron_id == omikron_id)
            })
    }

    pub fn user_route(&self, user_id: i64) -> Option<ClientSessionRoute> {
        self.routes_for_user(user_id).into_iter().next()
    }

    pub fn connect_iota(&self, iota_id: i64, omikron_id: i64) {
        self.connect_iota_with_priority(iota_id, omikron_id, false);
    }

    fn connect_iota_with_priority(&self, iota_id: i64, omikron_id: i64, primary: bool) {
        let mut routes = self.routes.write();
        let route = routes.iotas.entry(iota_id).or_default();
        route.connected_omikron_ids.insert(omikron_id);
        if primary || route.primary_omikron_id.is_none() {
            route.primary_omikron_id = Some(omikron_id);
        }
        routes
            .indices
            .iotas_by_omikron
            .entry(omikron_id)
            .or_default()
            .insert(iota_id);
        Self::debug_assert_indices(&routes);
    }

    pub fn disconnect_iota(&self, iota_id: i64, omikron_id: i64) -> bool {
        let mut routes = self.routes.write();
        let empty = Self::remove_iota_owner_locked(&mut routes, iota_id, omikron_id);
        Self::debug_assert_indices(&routes);
        empty
    }
}

#[cfg(test)]
mod tests {
    use super::{ClientSessionRoute, PresenceTracker};
    use crate::sql::connection_status::UserStatus;

    fn check_index_consistency(tracker: &PresenceTracker) -> Result<(), String> {
        PresenceTracker::check_indices(&tracker.routes.read())
    }

    #[test]
    fn presence_observations_order_delayed_pushes_against_snapshots_and_restart() {
        let tracker = PresenceTracker::default();
        tracker.connect_iota(11, 42);
        tracker.track_session(7, 3, 42, 11);
        let (online, old_push) = tracker.observe_public_state(7, Some(11));
        tracker.set_preference(7, UserStatus::user_dnd);
        let boundary = tracker.observation_boundary();
        let (dnd, snapshot) = tracker.observe_public_state(7, Some(11));
        tracker.disconnect_iota(11, 42);
        let (offline, newer_push) = tracker.observe_public_state(7, Some(11));
        assert_eq!(online, UserStatus::user_online);
        assert_eq!(dnd, UserStatus::user_dnd);
        assert_eq!(offline, UserStatus::iota_offline);
        assert!(old_push < boundary && boundary < snapshot && snapshot < newer_push);
        assert_ne!(
            tracker.observation_epoch,
            PresenceTracker::default().observation_epoch
        );
    }

    #[test]
    fn effective_state_is_derived_from_routes_and_preference() {
        let tracker = PresenceTracker::default();
        tracker.set_preference(7, UserStatus::user_online);
        assert_eq!(
            tracker.resolve_public_state(7, 11),
            UserStatus::iota_offline
        );

        tracker.connect_iota(11, 42);
        assert_eq!(
            tracker.resolve_public_state(7, 11),
            UserStatus::user_offline
        );

        tracker.track_session(7, 3, 42, 11);
        assert_eq!(tracker.resolve_public_state(7, 11), UserStatus::user_online);
        tracker.set_preference(7, UserStatus::user_invisible);
        assert_eq!(
            tracker.resolve_public_state(7, 11),
            UserStatus::user_offline
        );
    }

    #[test]
    fn session_must_match_assigned_iota_and_live_route() {
        let tracker = PresenceTracker::default();
        tracker.connect_iota(11, 42);
        tracker.track_session(7, 3, 42, 12);
        assert!(!tracker.has_active_session_for_iota(7, 11));
        assert_eq!(
            tracker.resolve_public_state(7, 11),
            UserStatus::user_offline
        );

        tracker.track_session(7, 3, 43, 11);
        assert!(!tracker.has_active_session_for_iota(7, 11));

        tracker.track_session(7, 3, 42, 11);
        assert!(tracker.has_active_session_for_iota(7, 11));
        tracker.disconnect_iota(11, 42);
        assert!(!tracker.has_active_session_for_iota(7, 11));
        assert_eq!(
            tracker.resolve_public_state(7, 11),
            UserStatus::iota_offline
        );
    }

    #[test]
    fn resolver_covers_all_public_preference_states() {
        let tracker = PresenceTracker::default();
        tracker.connect_iota(11, 42);
        tracker.track_session(7, 3, 42, 11);

        for (preference, expected) in [
            (UserStatus::user_online, UserStatus::user_online),
            (UserStatus::user_idle, UserStatus::user_idle),
            (UserStatus::user_dnd, UserStatus::user_dnd),
            (UserStatus::user_wc, UserStatus::user_wc),
            (UserStatus::user_invisible, UserStatus::user_offline),
        ] {
            tracker.set_preference(7, preference);
            assert_eq!(tracker.resolve_public_state(7, 11), expected);
        }
    }

    #[test]
    fn session_routes_replace_by_session_without_replacing_preferences() {
        let tracker = PresenceTracker::default();
        tracker.set_preference(7, UserStatus::user_dnd);
        tracker.connect_iota(11, 42);
        tracker.connect_iota(12, 43);
        tracker.track_session(7, 3, 42, 11);
        tracker.track_session(7, 4, 43, 12);

        assert_eq!(tracker.preference(7), UserStatus::user_dnd);
        assert_eq!(
            tracker.routes.read().sessions.get(&(7, 3)).cloned(),
            Some(ClientSessionRoute {
                omikron_id: 42,
                iota_id: 11,
            })
        );

        tracker.remove_session(7, 3, 42);
        assert!(!tracker.owns_session(7, 3, 42));
        assert!(tracker.owns_session(7, 4, 43));
        assert_eq!(tracker.preference(7), UserStatus::user_dnd);
    }

    #[test]
    fn subscriptions_are_authoritative_and_cleanup_is_scoped() {
        let tracker = PresenceTracker::default();
        tracker.replace_subscription(7, 3, 42, vec![20, 21, 20]);
        tracker.replace_subscription(7, 3, 42, vec![21, 22]);
        tracker.replace_subscription(8, 4, 43, vec![21]);

        assert_eq!(tracker.subscribers(20).len(), 0);
        assert_eq!(tracker.subscribers(21).len(), 2);
        assert_eq!(tracker.subscribers(22).len(), 1);

        tracker.remove_omikron(42);
        assert!(tracker.subscribers(22).is_empty());
        assert_eq!(tracker.subscribers(21).len(), 1);
    }

    #[test]
    fn losing_one_iota_route_keeps_iota_online() {
        let tracker = PresenceTracker::default();
        tracker.connect_iota(11, 42);
        tracker.connect_iota(11, 43);
        assert!(tracker.has_iota_route(11));

        assert!(!tracker.disconnect_iota(11, 42));
        assert!(tracker.has_iota_route(11));
        assert!(tracker.disconnect_iota(11, 43));
        assert!(!tracker.has_iota_route(11));
    }

    #[test]
    fn iota_connection_routes_track_primary_and_replacement() {
        let tracker = PresenceTracker::default();
        tracker.connect_iota(11, 42);
        tracker.connect_iota(11, 43);

        assert_eq!(tracker.iota_connections(11), Some(vec![42, 43]));
        assert_eq!(tracker.primary_iota_route(11), Some(42));

        tracker.untrack_iota_connection(11, 42);

        assert_eq!(tracker.iota_connections(11), Some(vec![43]));
        assert_eq!(tracker.primary_iota_route(11), Some(43));
    }

    #[test]
    fn snapshot_preserves_primary_and_uses_deterministic_fallback() {
        let tracker = PresenceTracker::default();
        tracker.connect_iota(11, 20);
        tracker.connect_iota(11, 30);
        assert_eq!(tracker.primary_iota_route(11), Some(20));

        tracker.replace_omikron_snapshot(30, &[11], &[]);
        assert_eq!(tracker.primary_iota_route(11), Some(20));

        tracker.replace_omikron_snapshot(20, &[11], &[]);
        assert_eq!(tracker.primary_iota_route(11), Some(30));
        tracker.replace_omikron_snapshot(30, &[11], &[]);
        assert_eq!(tracker.primary_iota_route(11), Some(20));
    }

    #[test]
    fn user_routes_are_sorted_by_session_then_omikron() {
        let tracker = PresenceTracker::default();
        tracker.track_session(7, 20, 30, 11);
        tracker.track_session(7, 10, 40, 11);
        assert_eq!(
            tracker
                .routes_for_user(7)
                .iter()
                .map(|route| route.omikron_id)
                .collect::<Vec<_>>(),
            vec![40, 30]
        );

        tracker.remove_session(7, 10, 40);
        assert_eq!(tracker.routes_for_user(7).len(), 1);
    }

    #[test]
    fn route_ownership_is_scoped_to_one_omikron() {
        let tracker = PresenceTracker::default();
        tracker.connect_iota(11, 42);
        tracker.track_session(7, 3, 42, 11);

        assert!(tracker.owns_user_route(7, 42));
        assert!(!tracker.owns_user_route(7, 43));
        assert!(tracker.owns_iota_route(11, 42));
        assert!(!tracker.owns_iota_route(11, 43));
    }

    #[test]
    fn stale_disconnect_cannot_remove_current_session_subscription() {
        let tracker = PresenceTracker::default();
        tracker.track_session(7, 3, 42, 11);
        tracker.replace_subscription(7, 3, 42, vec![20]);

        assert!(!tracker.remove_session(7, 3, 99));
        assert!(tracker.owns_session(7, 3, 42));
        assert_eq!(tracker.subscribers(20).len(), 1);

        assert!(tracker.remove_session(7, 3, 42));
        assert!(tracker.subscribers(20).is_empty());
    }

    #[test]
    fn private_state_is_not_affected_by_connectivity() {
        let tracker = PresenceTracker::default();
        tracker.set_preference(7, UserStatus::user_invisible);
        assert_eq!(tracker.resolve_private_state(7), UserStatus::user_invisible);
    }

    #[test]
    fn invalid_persisted_preference_falls_back_to_online() {
        let tracker = PresenceTracker::default();
        assert!(!tracker.load_preference(7, "user_offline"));
        assert_eq!(tracker.preference(7), UserStatus::user_online);
        assert!(!tracker.load_preference(7, "iota_offline"));
        assert_eq!(tracker.preference(7), UserStatus::user_online);
        assert!(tracker.load_preference(7, "user_invisible"));
        assert_eq!(tracker.preference(7), UserStatus::user_invisible);
        assert!(tracker.load_preference(7, "user_dnd"));
        assert_eq!(tracker.preference(7), UserStatus::user_dnd);
    }

    #[test]
    fn active_session_can_use_one_of_several_live_iota_routes() {
        let tracker = PresenceTracker::default();
        tracker.connect_iota(11, 42);
        tracker.connect_iota(11, 43);
        tracker.track_session(7, 3, 43, 11);

        assert!(tracker.has_active_session_for_iota(7, 11));
        tracker.disconnect_iota(11, 43);
        assert!(!tracker.has_active_session_for_iota(7, 11));
    }

    #[test]
    fn route_snapshot_replaces_only_one_omikron() {
        let tracker = PresenceTracker::default();
        tracker.connect_iota(11, 42);
        tracker.connect_iota(12, 43);
        tracker.track_session(7, 3, 42, 11);
        tracker.track_session(8, 4, 43, 12);
        tracker.replace_subscription(7, 3, 42, vec![20]);

        tracker.replace_omikron_snapshot(42, &[12], &[(9, 5, 12)]);

        assert!(!tracker.owns_session(7, 3, 42));
        assert!(tracker.owns_session(8, 4, 43));
        assert!(tracker.owns_session(9, 5, 42));
        assert!(tracker.subscribers(20).is_empty());
        assert!(tracker.has_iota_route(12));
    }

    #[test]
    fn omikron_cleanup_preserves_other_routes_and_preferences() {
        let tracker = PresenceTracker::default();
        tracker.set_preference(7, UserStatus::user_dnd);
        tracker.connect_iota(11, 42);
        tracker.connect_iota(11, 43);
        tracker.track_session(7, 3, 42, 11);
        tracker.track_session(7, 4, 43, 11);
        tracker.replace_subscription(7, 3, 42, vec![20]);
        tracker.replace_subscription(7, 4, 43, vec![21]);

        tracker.remove_omikron(42);

        assert!(tracker.has_iota_route(11));
        assert!(!tracker.owns_session(7, 3, 42));
        assert!(tracker.owns_session(7, 4, 43));
        assert!(tracker.subscribers(20).is_empty());
        assert_eq!(tracker.subscribers(21).len(), 1);
        assert_eq!(tracker.preference(7), UserStatus::user_dnd);
    }

    #[test]
    fn secondary_indices_follow_session_and_subscription_mutations() {
        let tracker = PresenceTracker::default();
        tracker.track_session(7, 3, 42, 11);
        tracker.replace_subscription(7, 3, 42, vec![20, 21, 20]);
        assert_eq!(
            tracker
                .routes
                .read()
                .indices
                .sessions_by_user
                .get(&7)
                .cloned(),
            Some([3].into_iter().collect())
        );
        assert_eq!(
            tracker
                .routes
                .read()
                .indices
                .targets_by_subscriber
                .get(&(7, 3))
                .cloned(),
            Some([20, 21].into_iter().collect())
        );
        assert!(check_index_consistency(&tracker).is_ok());

        tracker.replace_subscription(7, 3, 42, vec![22]);
        assert!(tracker.subscribers(20).is_empty());
        assert!(tracker.subscribers(21).is_empty());
        assert_eq!(tracker.subscribers(22).len(), 1);
        tracker.remove_session(7, 3, 42);
        assert!(check_index_consistency(&tracker).is_ok());
        assert!(tracker.routes.read().indices.sessions_by_user.is_empty());
        assert!(
            tracker
                .routes
                .read()
                .indices
                .targets_by_subscriber
                .is_empty()
        );
    }

    #[test]
    fn omikron_removal_returns_all_affected_identifiers() {
        let tracker = PresenceTracker::default();
        tracker.connect_iota(11, 42);
        tracker.track_session(7, 3, 42, 11);
        tracker.replace_subscription(7, 3, 42, vec![20]);

        let removed = tracker.remove_omikron(42);

        assert_eq!(removed.iota_ids, vec![11]);
        assert_eq!(removed.session_user_ids, vec![7]);
        assert_eq!(removed.subscriber_sessions, vec![(7, 3)]);
        assert!(check_index_consistency(&tracker).is_ok());
    }

    #[test]
    fn consistency_check_reports_corrupted_reverse_index() {
        let tracker = PresenceTracker::default();
        tracker.track_session(7, 3, 42, 11);
        tracker
            .routes
            .write()
            .indices
            .sessions_by_user
            .get_mut(&7)
            .unwrap()
            .clear();

        assert!(check_index_consistency(&tracker).is_err());
    }
}
