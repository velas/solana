use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

/// Represent state of value at current version.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
pub enum State<V> {
    // Value exist, and was changed.
    Changed(V),
    // Value was removed.
    Removed,
}

impl<V> State<V> {
    fn by_ref(&self) -> State<&V> {
        match self {
            State::Changed(ref v) => State::Changed(v),
            State::Removed => State::Removed,
        }
    }
}

impl<T> From<State<T>> for Option<T> {
    fn from(state: State<T>) -> Option<T> {
        match state {
            State::Changed(value) => Some(value),
            State::Removed => None,
        }
    }
}

#[derive(Clone)]
pub struct Map<Version, Key, Value> {
    version: Version,
    state: BTreeMap<Key, State<Value>>,
    parent: Option<Arc<Map<Version, Key, Value>>>,
}

impl<Version, Key, Value> Default for Map<Version, Key, Value>
where
    Version: Default,
    Key: Ord,
{
    fn default() -> Self {
        Map::new()
    }
}

#[derive(Clone, Copy)]
pub enum KeyResult<V, T> {
    /// Value for existing key.
    Found(T),
    /// Key not found, Value is last looked version.
    NotFound(V),
}

impl<Version, Key, Value> Map<Version, Key, Value>
where
    Key: Ord,
{
    pub fn empty(version: Version) -> Self {
        Self {
            version,
            state: BTreeMap::new(),
            parent: None,
        }
    }

    // Create new versioned map.
    pub fn new() -> Self
    where
        Version: Default,
    {
        Self {
            version: Version::default(),
            state: BTreeMap::new(),
            parent: None,
        }
    }

    // Borrow value by key
    pub fn get(&self, key: &Key) -> KeyResult<&Version, Option<&Value>> {
        match (self.state.get(key), self.parent.as_ref()) {
            (Some(s), _) => KeyResult::Found(s.by_ref().into()),
            (None, Some(parent)) => parent.get(key),
            (None, None) => KeyResult::NotFound(&self.version),
        }
    }

    // Insert new key, didn't query key before inserting.
    pub fn insert(&mut self, key: Key, value: Value) {
        self.push_change(key, State::Changed(value));
    }

    // Remove key, didn't query key before inserting.
    pub fn remove(&mut self, key: Key) {
        self.push_change(key, State::Removed);
    }

    // Override state of key.
    fn push_change(&mut self, key: Key, value: State<Value>) {
        self.state.insert(key, value);
    }

    pub fn iter(&self) -> (&Version, impl Iterator<Item = (&Key, Option<&Value>)> + '_) {
        (
            &self.version,
            self.state
                .iter()
                .map(|(key, value)| (key, value.by_ref().into())),
        )
    }

    pub fn full_iter(
        &self,
    ) -> impl Iterator<Item = (&Version, impl Iterator<Item = (&Key, Option<&Value>)> + '_)> + '_
    {
        std::iter::once(self.iter()).chain(self.parent.as_ref().map(|parent| parent.iter()))
    }
}

impl<Version, Key, Value> Map<Version, Key, Value>
where
    Key: Ord,
{
    pub fn freeze(&mut self)
    where
        Version: Clone,
    {
        let this = Self {
            version: self.version.clone(),
            state: std::mem::take(&mut self.state),
            parent: self.parent.as_ref().map(Arc::clone),
        };
        self.parent = Some(Arc::new(this));
    }

    // Create new version from freezed one
    pub fn try_fork(&self, new_version: Version) -> Option<Self>
    where
        Version: Ord,
    {
        assert!(new_version > self.version);

        if !self.state.is_empty() {
            return None;
        }

        Some(Self {
            version: new_version,
            state: BTreeMap::new(),
            parent: self.parent.clone(),
        })
    }
}

impl<Version, Key, Value> fmt::Debug for Map<Version, Key, Value>
where
    Version: fmt::Debug,
    Key: fmt::Debug,
    Value: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Map")
            .field("version", &self.version)
            .field("state", &self.state)
            .field("parent", &"omited")
            .finish()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn store_and_get_simple() {
        let mut map: Map<(), _, _> = Map::new();
        map.insert("first", 1);
        map.insert("second", 2);
        assert_eq!(map.get(&"first"), Some(&1));
        assert_eq!(map.get(&"second"), Some(&2));
    }

    // Test that map can save version, and type of map is always remain the same.
    #[test]
    fn new_dynamic_version_insert_remove_test() {
        let mut map: Map<_, _, _> = Map::new();
        map.insert("first", 1);
        map.insert("second", 2);
        map.insert("third", 3);
        assert_eq!(map.get(&"first"), Some(&1));
        assert_eq!(map.get(&"second"), Some(&2));
        assert_eq!(map.get(&"third"), Some(&3));

        map.freeze_as(0);
        let mut map: Map<_, _, _> = map.try_fork().unwrap();

        map.remove("first");
        map.insert("third", 1);

        assert_eq!(map.get(&"first"), None);
        assert_eq!(map.get(&"second"), Some(&2));
        assert_eq!(map.get(&"third"), Some(&1));
    }

    // Same as new_dynamic_version_insert_remove_test but dont hide type of store.
    #[test]
    fn new_static_version_insert_remove_test() {
        let mut map: Map<_, _, _> = Map::new();
        map.insert("first", 1);
        map.insert("second", 2);
        map.insert("third", 3);
        assert_eq!(map.get(&"first"), Some(&1));
        assert_eq!(map.get(&"second"), Some(&2));
        assert_eq!(map.get(&"third"), Some(&3));

        map.freeze_as(0);
        let mut map = map.try_fork().unwrap();

        map.remove("first");
        map.insert("third", 1);

        assert_eq!(map.get(&"first"), None);
        assert_eq!(map.get(&"second"), Some(&2));
        assert_eq!(map.get(&"third"), Some(&1));
    }
}
