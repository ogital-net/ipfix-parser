//! Template store trait and optional bounded LRU implementation.
//!
//! The IPFIX parser is stateless: it does not hold templates between calls.
//! Callers manage template lifetime by implementing [`TemplateStore`] and
//! supplying an instance when decoding data records.
//!
//! The `std-store` feature gate enables [`SessionTemplateStore`], a bounded
//! LRU-backed multi-session store suitable for production UDP collectors.

use crate::template::{FieldSpecifier, TemplateId, TemplateRecord};

/// A read-only view of a template sufficient for decoding data records.
///
/// The `fields` slice must remain valid for the lifetime of any data-record
/// iterator constructed from this template.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct TemplateRef<'a> {
    /// The template ID.
    pub id: TemplateId,
    /// Number of scope fields (0 for regular templates).
    pub scope_field_count: u16,
    /// Field specifiers in declaration order.
    pub fields: &'a [FieldSpecifier],
}

impl<'a> TemplateRef<'a> {
    /// Construct a [`TemplateRef`] from its components.
    ///
    /// Most callers should obtain a `TemplateRef` from a [`TemplateStore`]
    /// rather than constructing one directly. This constructor is provided
    /// for callers that maintain their own template state outside of any
    /// [`TemplateStore`] implementation (e.g. fuzz harnesses, custom stores).
    #[inline]
    #[must_use]
    pub const fn new(id: TemplateId, scope_field_count: u16, fields: &'a [FieldSpecifier]) -> Self {
        Self {
            id,
            scope_field_count,
            fields,
        }
    }
}

impl<'a> From<TemplateRecord<'a>> for TemplateRef<'a> {
    #[inline]
    fn from(r: TemplateRecord<'a>) -> Self {
        Self {
            id: r.id,
            scope_field_count: r.scope_field_count,
            fields: r.fields,
        }
    }
}

/// Trait for types that store and retrieve IPFIX templates.
///
/// The library never calls `insert`; callers populate the store when
/// processing Template Sets and provide it when decoding Data Sets.
///
/// # Scoping
///
/// Per RFC 7011 §3.4.1 and RFC 7119 §4.1, a Template ID is unique within
/// the tuple `(Transport Session, Observation Domain ID)`. The library is
/// sans-io and has no visibility into transport sessions, so this trait is
/// scoped only by Observation Domain ID. Callers that aggregate IPFIX
/// streams from multiple transport sessions (e.g. a UDP collector that
/// peers with several exporters) **must** distinguish templates by some
/// session identifier in addition to the Observation Domain ID; otherwise
/// templates from one exporter can shadow another's at the same
/// `(odid, tid)` pair. The bundled [`SessionTemplateStore`] (gated by the
/// `std-store` feature) does this and additionally bounds memory use with
/// an LRU policy.
pub trait TemplateStore {
    /// Look up a template by Observation Domain ID and Template ID.
    ///
    /// Returns `None` if the template is not known.
    fn get(&self, odid: u32, id: TemplateId) -> Option<TemplateRef<'_>>;
}

/// Outcome of inserting a template into a [`SessionTemplateStore`].
///
/// IPFIX requires that a Template ID, once defined within a
/// `(Transport Session, Observation Domain ID)` scope, MUST NOT be
/// redefined with a different set of field specifiers unless it has first
/// been withdrawn (RFC 7011 §8). Detecting this condition is the purpose
/// of [`InsertOutcome::Collision`].
#[cfg(feature = "std-store")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[must_use = "an InsertOutcome of `Collision` indicates a protocol error from the exporter"]
pub enum InsertOutcome {
    /// No template was previously registered for this `(session, odid, tid)`;
    /// the new template was installed.
    ///
    /// If the store was at capacity, the least-recently-refreshed template
    /// in the entire store was evicted to make room. Such evictions are
    /// reported via the [`log`] crate at the `warn` level so operators can
    /// detect under-sized caches; consumers that do not want this logging
    /// can disable it through their `log` configuration.
    Inserted,
    /// A template with identical field specifiers and scope was already
    /// registered; the call refreshed the LRU position but otherwise made
    /// no change. Repeated identical Template Records are common (e.g.
    /// periodic refresh) and not a protocol error.
    AlreadyPresent,
    /// A different template was already registered for this
    /// `(session, odid, tid)`. The existing template is retained and the
    /// new one is **not** installed; per RFC 7011 §8 the exporter must
    /// withdraw the old template (call [`SessionTemplateStore::remove`])
    /// before redefining the ID. Callers should treat this as a protocol
    /// error from the exporter and typically log and drop subsequent data
    /// records that would have used the new definition.
    Collision,
}

#[cfg(feature = "std-store")]
#[derive(Debug, Clone)]
struct OwnedTemplate {
    id: TemplateId,
    scope_field_count: u16,
    fields: std::vec::Vec<FieldSpecifier>,
}

/// Default capacity for [`SessionTemplateStore::new`].
///
/// Sized for typical UDP collectors that aggregate a few hundred exporters,
/// each with a handful of templates. Tune via
/// [`SessionTemplateStore::with_capacity`] for larger or smaller deployments.
#[cfg(feature = "std-store")]
pub const DEFAULT_CAPACITY: u32 = 4096;

/// A bounded, multi-session [`TemplateStore`] keyed by a caller-supplied
/// session identifier `K` in addition to the Observation Domain ID and
/// Template ID.
///
/// IPFIX templates are unique within a `(Transport Session, Observation
/// Domain ID)` scope (RFC 7011 §3.4.1, RFC 7119 §4.1). For connection-
/// oriented transports (TCP, SCTP) the transport session is well-defined,
/// but for UDP — the most common deployment — there is no formal session.
/// In practice, UDP collectors distinguish exporters by some property of
/// the datagram source: the exporter's IP address, the `(IP, port)` pair,
/// or a richer 5-tuple.
///
/// This store lets the caller pick that key. Typical choices:
///
/// | Key type                   | What it identifies                       |
/// |----------------------------|------------------------------------------|
/// | `std::net::IpAddr`         | One exporter per host (most common).     |
/// | `std::net::SocketAddr`     | One exporter per `(host, port)`.         |
/// | `(IpAddr, IpAddr, u16)`    | A 5-tuple-style transport session.       |
/// | `u32` / `String` / etc.    | An application-defined identifier.       |
///
/// `K` need only implement [`Eq`], [`Hash`](std::hash::Hash), and [`Clone`].
///
/// # Capacity and `DoS` resistance
///
/// An IPFIX collector that accepts datagrams from arbitrary network sources
/// is exposed to denial-of-service via unbounded session growth: an
/// attacker can spoof source addresses to inject templates under many
/// distinct session keys until the store exhausts memory. To mitigate
/// this, this store is internally backed by an LRU cache with a fixed
/// global capacity (the total number of `(session, odid, tid)` entries it
/// will hold). When the cache is full, inserting a new entry evicts the
/// least-recently-refreshed entry across the entire store.
///
/// Callers should still authenticate exporters out-of-band (e.g. via
/// firewall ACLs, `IPsec`, or DTLS) — the LRU is a backstop, not a
/// substitute for access control.
///
/// ## LRU promotion semantics
///
/// LRU position is updated in two places:
///
/// 1. On a successful [`insert`](Self::insert) call (whether the entry is
///    new or already present), the corresponding entry becomes the
///    most-recently-used.
/// 2. **Read-side lookups via [`TemplateStore::get`] do not promote.**
///    The trait method takes `&self` and the store cannot mutate behind
///    an immutable reference.
///
/// In practice this is sufficient because RFC 7011 §10 requires UDP
/// exporters to periodically re-send their templates; each refresh
/// promotes the entry. Exporters that go silent will fall to the LRU tail
/// and be evicted before active exporters lose their templates.
///
/// ## Capacity tuning and logging
///
/// Whenever an insert evicts an entry, a `warn`-level message is emitted
/// via the [`log`] crate so operators can detect a too-small cache.
/// Consumers wire up any `log`-compatible backend (e.g. `env_logger`,
/// `tracing-log`, `slog-stdlog`) to receive these warnings; consumers that
/// do not initialize a logger silently drop them.
///
/// # Example
///
/// ```
/// # #[cfg(feature = "std-store")] {
/// use ipfix_parser::{FieldSpecifier, TemplateSetIter, TemplateSetKind, TemplateStore};
/// use ipfix_parser::store::SessionTemplateStore;
/// use std::net::{IpAddr, Ipv4Addr};
///
/// let peer: IpAddr = Ipv4Addr::new(192, 0, 2, 1).into();
/// let odid: u32 = 1;
///
/// // Decode a one-template Template Set body to obtain a TemplateRecord.
/// let mut tbuf = Vec::new();
/// tbuf.extend_from_slice(&256u16.to_be_bytes());
/// tbuf.extend_from_slice(&1u16.to_be_bytes());
/// tbuf.extend_from_slice(&8u16.to_be_bytes());
/// tbuf.extend_from_slice(&4u16.to_be_bytes());
/// let mut fbuf = [FieldSpecifier::EMPTY; 8];
/// let mut iter = TemplateSetIter::new(&tbuf, &mut fbuf, TemplateSetKind::Template);
/// let record = iter.next().expect("one record")?;
///
/// let mut store: SessionTemplateStore<IpAddr> = SessionTemplateStore::new();
/// let _ = store.insert(&peer, odid, &record);
///
/// // When decoding data records from the same peer:
/// let view = store.view(peer);
/// assert!(view.get(odid, 256).is_some());
/// # }
/// # Ok::<(), ipfix_parser::Error>(())
/// ```
///
/// Enable with the `std-store` feature.
#[cfg(feature = "std-store")]
#[derive(Debug)]
#[non_exhaustive]
pub struct SessionTemplateStore<K>
where
    K: std::hash::Hash + Eq,
{
    map: schnellru::LruMap<(K, u32, TemplateId), OwnedTemplate>,
}

#[cfg(feature = "std-store")]
impl<K> Default for SessionTemplateStore<K>
where
    K: std::hash::Hash + Eq,
{
    fn default() -> Self {
        Self::with_capacity(DEFAULT_CAPACITY)
    }
}

#[cfg(feature = "std-store")]
impl<K> SessionTemplateStore<K>
where
    K: Eq + std::hash::Hash,
{
    /// Create an empty store with the [default capacity](DEFAULT_CAPACITY).
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_CAPACITY)
    }

    /// Create an empty store with a specified maximum number of entries.
    ///
    /// `capacity` is the total number of `(session, odid, tid)` entries
    /// the store will hold before evicting the least-recently-refreshed
    /// entry on each insert. Choose a value that comfortably exceeds the
    /// product of (expected concurrent exporters) × (templates per
    /// exporter) for your deployment; if you observe `warn`-level
    /// eviction logs from this module under normal load, raise it.
    ///
    /// A `capacity` of 0 produces a store that always evicts on insert
    /// (i.e. effectively rejects all entries); this is rarely useful but
    /// not erroneous.
    #[must_use]
    pub fn with_capacity(capacity: u32) -> Self {
        Self {
            map: schnellru::LruMap::new(schnellru::ByLength::new(capacity)),
        }
    }

    /// Number of templates currently stored across all sessions.
    #[must_use]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Returns `true` if the store contains no templates.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Maximum number of templates the store will hold before evicting the
    /// least-recently-refreshed entry on insert.
    #[must_use]
    pub fn capacity(&self) -> u32 {
        self.map.limiter().max_length()
    }
}

#[cfg(feature = "std-store")]
impl<K> SessionTemplateStore<K>
where
    K: Eq + std::hash::Hash + Clone,
{
    /// Insert a template for `(session, odid, record.id)`, detecting
    /// collisions per RFC 7011 §8 and bumping the entry to the LRU front.
    ///
    /// If the store is at capacity and the entry is new, the least-
    /// recently-refreshed entry across the whole store is evicted to make
    /// room and a `warn`-level message is logged via the [`log`] crate.
    ///
    /// See [`InsertOutcome`] for the meaning of each return value.
    pub fn insert(&mut self, session: &K, odid: u32, record: &TemplateRecord<'_>) -> InsertOutcome {
        // First check for collisions / refresh without paying for a clone
        // of the session key.
        let key = (session.clone(), odid, record.id);

        if let Some(existing) = self.map.peek(&key) {
            let same = existing.scope_field_count == record.scope_field_count
                && existing.fields.as_slice() == record.fields;
            if !same {
                return InsertOutcome::Collision;
            }
            // Promote on refresh.
            let _ = self.map.get(&key);
            return InsertOutcome::AlreadyPresent;
        }

        // New entry. If the cache is full this insert will evict the LRU
        // entry; surface that as a `log::warn!` so operators can detect
        // an under-sized cache.
        let cap = self.map.limiter().max_length();
        if cap > 0 && self.map.len() >= cap as usize {
            log::warn!(
                target: "ipfix_parser::store",
                "SessionTemplateStore at capacity ({cap}); evicting least-recently-used template to insert a new one — consider increasing the capacity"
            );
        }
        let _ = self.map.insert(
            key,
            OwnedTemplate {
                id: record.id,
                scope_field_count: record.scope_field_count,
                fields: record.fields.to_vec(),
            },
        );
        InsertOutcome::Inserted
    }

    /// Remove one template within a session.
    pub fn remove(&mut self, session: &K, odid: u32, id: TemplateId) {
        let _ = self.map.remove(&(session.clone(), odid, id));
    }

    /// Remove every template associated with `session` (e.g. when a UDP
    /// exporter is considered dead, or a connection-oriented session is
    /// torn down).
    pub fn remove_session(&mut self, session: &K) {
        // schnellru's LruMap has no `retain`; collect matching keys and
        // remove them individually. `remove_session` is expected to be
        // called rarely (on session teardown), so the allocation here is
        // off the hot path.
        let to_remove: std::vec::Vec<(K, u32, TemplateId)> = self
            .map
            .iter()
            .filter(|((k, _, _), _)| k == session)
            .map(|((k, o, t), _)| (k.clone(), *o, *t))
            .collect();
        for key in to_remove {
            let _ = self.map.remove(&key);
        }
    }

    /// Return a [`TemplateStore`] view scoped to `session`. Lookups through
    /// the returned view will only find templates that were inserted under
    /// the same session key.
    #[inline]
    pub const fn view(&self, session: K) -> SessionView<'_, K> {
        SessionView {
            store: self,
            session,
        }
    }
}

/// A [`TemplateStore`] view of a [`SessionTemplateStore`] scoped to a
/// single session key. Constructed via [`SessionTemplateStore::view`].
#[cfg(feature = "std-store")]
#[derive(Debug)]
#[non_exhaustive]
pub struct SessionView<'a, K>
where
    K: std::hash::Hash + Eq,
{
    store: &'a SessionTemplateStore<K>,
    session: K,
}

#[cfg(feature = "std-store")]
impl<K> TemplateStore for SessionView<'_, K>
where
    K: Eq + std::hash::Hash + Clone,
{
    fn get(&self, odid: u32, id: TemplateId) -> Option<TemplateRef<'_>> {
        // `peek` rather than `get` to avoid LRU promotion; promotion
        // happens on insert (template refresh), see the type-level docs.
        self.store
            .map
            .peek(&(self.session.clone(), odid, id))
            .map(|t| TemplateRef {
                id: t.id,
                scope_field_count: t.scope_field_count,
                fields: &t.fields,
            })
    }
}

#[cfg(all(test, feature = "std-store"))]
mod tests {
    use super::*;
    use crate::template::VARIABLE_LENGTH;

    fn make_fields(count: usize) -> std::vec::Vec<FieldSpecifier> {
        (0..count)
            .map(|i| FieldSpecifier {
                information_element_id: u16::try_from(i).unwrap() + 1,
                enterprise_number: None,
                field_length: 4,
            })
            .collect()
    }

    const fn record_with(id: TemplateId, fields: &[FieldSpecifier]) -> TemplateRecord<'_> {
        TemplateRecord {
            id,
            scope_field_count: 0,
            fields,
        }
    }

    #[test]
    fn insert_and_get() {
        let mut store: SessionTemplateStore<()> = SessionTemplateStore::new();
        let fields = make_fields(2);
        assert_eq!(
            store.insert(&(), 1, &record_with(256, &fields)),
            InsertOutcome::Inserted
        );

        let view = store.view(());
        let t = view.get(1, 256).unwrap();
        assert_eq!(t.id, 256);
        assert_eq!(t.fields.len(), 2);
    }

    #[test]
    fn get_unknown_returns_none() {
        let store: SessionTemplateStore<()> = SessionTemplateStore::new();
        assert!(store.view(()).get(1, 256).is_none());
    }

    #[test]
    fn remove() {
        let mut store: SessionTemplateStore<()> = SessionTemplateStore::new();
        let fields = make_fields(1);
        let _ = store.insert(&(), 1, &record_with(256, &fields));
        store.remove(&(), 1, 256);
        assert!(store.view(()).get(1, 256).is_none());
    }

    #[test]
    fn different_odids_are_independent() {
        let mut store: SessionTemplateStore<()> = SessionTemplateStore::new();
        let fields = make_fields(1);
        let _ = store.insert(&(), 1, &record_with(256, &fields));
        assert!(store.view(()).get(2, 256).is_none());
    }

    #[test]
    fn variable_length_field_round_trips() {
        let mut store: SessionTemplateStore<()> = SessionTemplateStore::new();
        let fields = vec![FieldSpecifier {
            information_element_id: 82,
            enterprise_number: None,
            field_length: VARIABLE_LENGTH,
        }];
        let _ = store.insert(&(), 0, &record_with(257, &fields));
        let view = store.view(());
        let t = view.get(0, 257).unwrap();
        assert!(t.fields[0].is_variable_length());
    }

    #[test]
    fn identical_re_insert_is_no_op() {
        let mut store: SessionTemplateStore<()> = SessionTemplateStore::new();
        let fields = make_fields(3);
        assert_eq!(
            store.insert(&(), 1, &record_with(300, &fields)),
            InsertOutcome::Inserted
        );
        assert_eq!(
            store.insert(&(), 1, &record_with(300, &fields)),
            InsertOutcome::AlreadyPresent
        );
        assert_eq!(store.view(()).get(1, 300).unwrap().fields.len(), 3);
    }

    #[test]
    fn redefinition_with_different_fields_is_collision() {
        let mut store: SessionTemplateStore<()> = SessionTemplateStore::new();
        let fields_a = make_fields(2);
        let fields_b = make_fields(3);
        assert_eq!(
            store.insert(&(), 7, &record_with(256, &fields_a)),
            InsertOutcome::Inserted
        );
        assert_eq!(
            store.insert(&(), 7, &record_with(256, &fields_b)),
            InsertOutcome::Collision
        );
        // Original template is preserved.
        assert_eq!(store.view(()).get(7, 256).unwrap().fields.len(), 2);
    }

    #[test]
    fn redefinition_with_different_scope_count_is_collision() {
        let mut store: SessionTemplateStore<()> = SessionTemplateStore::new();
        let fields = make_fields(2);
        let record_a = TemplateRecord {
            id: 256,
            scope_field_count: 0,
            fields: &fields,
        };
        let record_b = TemplateRecord {
            id: 256,
            scope_field_count: 1,
            fields: &fields,
        };
        assert_eq!(store.insert(&(), 0, &record_a), InsertOutcome::Inserted);
        assert_eq!(store.insert(&(), 0, &record_b), InsertOutcome::Collision);
        assert_eq!(store.view(()).get(0, 256).unwrap().scope_field_count, 0);
    }

    #[test]
    fn remove_then_redefine_succeeds() {
        let mut store: SessionTemplateStore<()> = SessionTemplateStore::new();
        let fields_a = make_fields(2);
        let fields_b = make_fields(4);
        assert_eq!(
            store.insert(&(), 0, &record_with(256, &fields_a)),
            InsertOutcome::Inserted
        );
        store.remove(&(), 0, 256);
        assert_eq!(
            store.insert(&(), 0, &record_with(256, &fields_b)),
            InsertOutcome::Inserted
        );
        assert_eq!(store.view(()).get(0, 256).unwrap().fields.len(), 4);
    }

    #[test]
    fn session_store_isolates_by_key() {
        use std::net::{IpAddr, Ipv4Addr};

        let peer_a: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let peer_b: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        let fields_a = make_fields(2);
        let fields_b = make_fields(3);

        let mut store: SessionTemplateStore<IpAddr> = SessionTemplateStore::new();
        assert_eq!(
            store.insert(&peer_a, 0, &record_with(256, &fields_a)),
            InsertOutcome::Inserted
        );
        assert_eq!(
            // same TID, same ODID — but a different exporter
            store.insert(&peer_b, 0, &record_with(256, &fields_b)),
            InsertOutcome::Inserted
        );
        assert_eq!(store.len(), 2);

        // Each peer's view sees only its own template.
        assert_eq!(store.view(peer_a).get(0, 256).unwrap().fields.len(), 2);
        assert_eq!(store.view(peer_b).get(0, 256).unwrap().fields.len(), 3);
    }

    #[test]
    fn session_store_collision_within_one_session() {
        let fields_a = make_fields(2);
        let fields_b = make_fields(3);
        let mut store: SessionTemplateStore<u32> = SessionTemplateStore::new();
        assert_eq!(
            store.insert(&7, 0, &record_with(256, &fields_a)),
            InsertOutcome::Inserted
        );
        assert_eq!(
            store.insert(&7, 0, &record_with(256, &fields_b)),
            InsertOutcome::Collision
        );
        // Original retained.
        assert_eq!(store.view(7).get(0, 256).unwrap().fields.len(), 2);
    }

    #[test]
    fn session_store_remove_session_drops_only_that_key() {
        let fields = make_fields(1);
        let mut store: SessionTemplateStore<u32> = SessionTemplateStore::new();
        assert_eq!(
            store.insert(&1, 0, &record_with(256, &fields)),
            InsertOutcome::Inserted
        );
        assert_eq!(
            store.insert(&2, 0, &record_with(256, &fields)),
            InsertOutcome::Inserted
        );
        store.remove_session(&1);
        assert!(store.view(1).get(0, 256).is_none());
        assert!(store.view(2).get(0, 256).is_some());
    }

    #[test]
    fn session_store_view_is_a_template_store() {
        // Verify the view satisfies the trait bound so it can be passed to
        // `DataRecordIter::new` etc.
        fn takes_store<S: TemplateStore>(_s: &S) {}

        let store: SessionTemplateStore<u8> = SessionTemplateStore::new();
        let view = store.view(0);
        takes_store(&view);
    }

    #[test]
    fn lru_evicts_oldest_when_full() {
        let mut store: SessionTemplateStore<u32> = SessionTemplateStore::with_capacity(2);
        let fields = make_fields(1);

        let _ = store.insert(&1, 0, &record_with(256, &fields));
        let _ = store.insert(&2, 0, &record_with(256, &fields));
        assert_eq!(store.len(), 2);

        // Inserting a third entry must evict the oldest (session 1).
        let _ = store.insert(&3, 0, &record_with(256, &fields));
        assert_eq!(store.len(), 2);
        assert!(store.view(1).get(0, 256).is_none());
        assert!(store.view(2).get(0, 256).is_some());
        assert!(store.view(3).get(0, 256).is_some());
    }

    #[test]
    fn lru_refresh_promotes_entry() {
        let mut store: SessionTemplateStore<u32> = SessionTemplateStore::with_capacity(2);
        let fields = make_fields(1);
        let rec = record_with(256, &fields);

        let _ = store.insert(&1, 0, &rec);
        let _ = store.insert(&2, 0, &rec);
        // Refreshing session 1 should promote it ahead of session 2.
        assert_eq!(store.insert(&1, 0, &rec), InsertOutcome::AlreadyPresent);
        // Now inserting a third entry should evict session 2 (the LRU
        // entry), not session 1.
        let _ = store.insert(&3, 0, &rec);
        assert!(store.view(1).get(0, 256).is_some());
        assert!(store.view(2).get(0, 256).is_none());
        assert!(store.view(3).get(0, 256).is_some());
    }

    #[test]
    fn capacity_reports_configured_limit() {
        let store: SessionTemplateStore<u32> = SessionTemplateStore::with_capacity(17);
        assert_eq!(store.capacity(), 17);
    }
}
