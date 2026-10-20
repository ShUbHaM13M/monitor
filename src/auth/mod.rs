pub mod api_key;
pub mod csrf;
mod extract;
pub mod password;
pub mod session;

use uuid::Uuid;

pub use extract::{CurrentUser, MaybeUser};

/// The organisation the current request is scoped to.
///
/// It can only be constructed inside `auth`, from a valid session, and every
/// tenant-data query in `db` takes one. Forgetting to scope a query to the
/// signed-in org is therefore a compile error rather than a data leak.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OrgId(Uuid);

impl OrgId {
    pub fn get(self) -> Uuid {
        self.0
    }
}
