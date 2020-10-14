//! The main Agent module. Contains the [Agent] type and all associated structures.
pub(crate) mod agent_config;
pub(crate) mod agent_error;
pub(crate) mod builder;
pub(crate) mod expiry;
pub(crate) mod http_agent;
pub(crate) mod nonce;
pub(crate) mod replica_api;
pub(crate) mod response;

pub mod status;
pub use agent_config::{AgentConfig, PasswordManager};
pub use agent_error::AgentError;
pub use builder::HttpAgentBuilder;
pub use expiry::Expiry;
pub use http_agent::HttpAgent;
pub use nonce::NonceFactory;
pub use response::{Replied, RequestStatusResponse};

#[cfg(test)]
mod agent_test;

use crate::export::Principal;
use crate::RequestId;
use async_trait::async_trait;

pub trait QueryBuilder<A, U>
where
    Self: std::marker::Sized,
    A: Agent<Self, U>,
    U: UpdateBuilder<A, Self>,
{
    fn new<P, M>(with_agent: &A, with_principal: P, with_method_name: M) -> Self
    where
        P: Into<Principal>,
        M: ToString;

    fn with_arg<Arg: Into<Vec<u8>>>(&mut self, arg: Arg) -> &mut Self;
}

pub trait UpdateBuilder<A, Q>
where
    Self: std::marker::Sized,
    A: Agent<Q, Self>,
    Q: QueryBuilder<A, Self>,
{
    fn new<P, M>(with_agent: &A, with_principal: P, with_method_name: M) -> Self
    where
        P: Into<Principal>,
        M: ToString;
}

/// A trait implemented by agents that makes calls (query or updates) to a Replica
/// (real or not). This is the low level trait that can be implemented in different
/// contexts and re-used by higher level types.
///
/// ```ignore
/// # // This test is ignored because it requires an ic to be running. We run these
/// # // in the ic-ref workflow.
/// use ic_agent::HttpAgent;
/// use ic_types::Principal;
/// use candid::{Encode, Decode, CandidType};
/// use serde::Deserialize;
///
/// #[derive(CandidType, Deserialize)]
/// struct CreateCanisterResult {
///   canister_id: candid::Principal,
/// }
///
/// # fn create_identity() -> impl ic_agent::Identity {
/// #     let rng = ring::rand::SystemRandom::new();
/// #     let key_pair = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng)
/// #         .expect("Could not generate a key pair.");
/// #
/// #     ic_agent::identity::BasicIdentity::from_key_pair(
/// #         ring::signature::Ed25519KeyPair::from_pkcs8(key_pair.as_ref())
/// #           .expect("Could not read the key pair."),
/// #     )
/// # }
/// #
/// # const URL: &'static str = concat!("http://localhost:", env!("IC_REF_PORT"));
/// #
/// async fn create_a_canister() -> Result<Principal, Box<dyn std::error::Error>> {
///   let agent = HttpAgent::builder()
///     .with_url(URL)
///     .with_identity(create_identity())
///     .build()?;
///   let management_canister_id = Principal::from_text("aaaaa-aa")?;
///
///   let waiter = delay::Delay::builder()
///     .throttle(std::time::Duration::from_millis(500))
///     .timeout(std::time::Duration::from_secs(60 * 5))
///     .build();
///
///   // Create a call to the management canister to create a new canister ID,
///   // and wait for a result.
///   let response = agent.update(&management_canister_id, "create_canister")
///     .with_arg(&Encode!()?)  // Empty Candid.
///     .call_and_wait(waiter)
///     .await?;
///
///   let result = Decode!(response.as_slice(), CreateCanisterResult)?;
///   let canister_id: Principal = Principal::from_text(&result.canister_id.to_text())?;
///   Ok(canister_id)
/// }
///
/// # let mut runtime = tokio::runtime::Runtime::new().unwrap();
/// # runtime.block_on(async {
/// let canister_id = create_a_canister().await.unwrap();
/// eprintln!("{}", canister_id);
/// # });
/// ```
///
/// This agent trait (and other types) does not understand Candid, and only acts on byte buffers.
#[async_trait]
pub trait Agent<Q, U>
where
    Self: Sized,
    Q: QueryBuilder<Self, U>,
    U: UpdateBuilder<Self, Q>,
{
    /// Returns a QueryBuilder enabling the construction of a query call without
    /// passing all arguments.
    fn query<P: Into<Principal>, S: ToString>(&self, canister: P, method: S) -> Q {
        Q::new(self, canister, method)
    }

    /// Returns an UpdateBuilder enabling the construction of an update call without
    /// passing all arguments.
    fn update<P: Into<Principal>, S: ToString>(&self, canister: P, method: S) -> U {
        U::new(self, canister, method)
    }

    /// Consume and execute a query from a query builder.
    async fn execute_query(&self, query: Q) -> Result<Vec<u8>, AgentError>;

    /// Consume and execute an update from an update builder.
    async fn execute_update(&self, update: U) -> Result<RequestId, AgentError>;
}
