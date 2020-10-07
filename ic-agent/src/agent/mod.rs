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
use delay::Waiter;
use reqwest::Method;
use serde::Serialize;
use status::Status;

use std::convert::TryFrom;
use std::time::Duration;

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
pub trait Agent {
    /// Returns a QueryBuilder enabling the construction of a query call without
    /// passing all arguments.
    fn query<P: Into<Principal>, S: ToString>(&self, canister: P, method: S) -> QueryBuilder<Self> {
        QueryBuilder::new(self, canister, method)
    }

    /// Returns an UpdateBuilder enabling the construction of an update call without
    /// passing all arguments.
    fn update<P: Into<Principal>, S: ToString>(
        &self,
        canister: P,
        method: S,
    ) -> UpdateBuilder<Self> {
        UpdateBuilder::new(self, canister, method)
    }

    /// Execute a query from a query builder.
    async fn execute_query(&self, query: QueryBuilder<Self>) -> Result<Vec<u8>, AgentError>;

    /// Execute an update from an update builder.
    async fn execute_update(&self, update: UpdateBuilder<Self>) -> Result<RequestId, AgentError>;
}

/// A Query Request Builder.
///
/// This makes it easier to do query calls without actually passing all arguments.
pub struct QueryBuilder<'agent, A: Agent> {
    agent: &'agent A,
    pub canister_id: Principal,
    pub method_name: String,
    pub arg: Vec<u8>,
    pub expiry: Expiry,
}

impl<'agent, A: Agent> QueryBuilder<'agent, A> {
    pub fn new(agent: &'agent A, canister_id: Principal, method_name: String) -> Self {
        Self {
            agent,
            canister_id,
            method_name,
            arg: vec![],
            expiry: Expiry::Unspecified,
        }
    }

    pub fn with_arg<Arg: AsRef<[u8]>>(&mut self, arg: Arg) -> &mut Self {
        self.arg = arg.as_ref().to_vec();
        self
    }

    /// Takes a SystemTime converts it to a Duration by calling
    /// duration_since(UNIX_EPOCH) to learn about where in time this SystemTime lies.
    /// The Duration is converted to nanoseconds and stored in ingress_expiry_datetime
    pub fn expire_at(&mut self, time: std::time::SystemTime) -> &mut Self {
        self.expiry = Expiry::DateTime(time);
        self
    }

    /// Takes a Duration (i.e. 30 sec/5 min 30 sec/1 h 30 min, etc.) and adds it to the
    /// Duration of the current SystemTime since the UNIX_EPOCH
    /// Subtracts a permitted drift from the sum to account for using system time and not block time.
    /// Converts the difference to nanoseconds and stores in ingress_expiry_datetime
    pub fn expire_after(&mut self, duration: std::time::Duration) -> &mut Self {
        self.expiry = Expiry::Delay(duration);
        self
    }

    /// Make a query call. This will return a byte vector.
    pub async fn call(self) -> Result<Vec<u8>, AgentError> {
        self.agent.execute_query(self).await
    }
}

/// An Update Request Builder.
///
/// This makes it easier to do update calls without actually passing all arguments or specifying
/// if you want to wait or not.
pub struct UpdateBuilder<'agent, A: Agent> {
    agent: &'agent A,
    canister_id: Principal,
    method_name: String,
    arg: Vec<u8>,
    expiry: Expiry,
}

impl<'agent, A: Agent> UpdateBuilder<'agent, A> {
    pub fn new(agent: &'agent A, canister_id: Principal, method_name: String) -> Self {
        Self {
            agent,
            canister_id,
            method_name,
            arg: vec![],
            expiry: Expiry::Unspecified,
        }
    }

    pub fn with_arg<Arg: AsRef<[u8]>>(&mut self, arg: Arg) -> &mut Self {
        self.arg = arg.as_ref().to_vec();
        self
    }

    /// Takes a SystemTime converts it to a Duration by calling
    /// duration_since(UNIX_EPOCH) to learn about where in time this SystemTime lies.
    /// The Duration is converted to nanoseconds and stored in ingress_expiry_datetime
    pub fn expire_at(&mut self, time: std::time::SystemTime) -> &mut Self {
        self.expiry = Expiry::DateTime(time);
        self
    }

    /// Takes a Duration (i.e. 30 sec/5 min 30 sec/1 h 30 min, etc.) and adds it to the
    /// Duration of the current SystemTime since the UNIX_EPOCH
    /// Subtracts a permitted drift from the sum to account for using system time and not block time.
    /// Converts the difference to nanoseconds and stores in ingress_expiry_datetime
    pub fn expire_after(&mut self, duration: std::time::Duration) -> &mut Self {
        self.expiry = Expiry::Delay(duration);
        self
    }

    /// Make an update call. This will call request_status on the RequestId in a loop and return
    /// the response as a byte vector.
    pub async fn call_and_wait<W: Waiter>(&self, mut waiter: W) -> Result<Vec<u8>, AgentError> {
        let request_id = self
            .agent
            .update_raw(
                &self.canister_id,
                self.method_name.as_str(),
                self.arg.as_slice(),
                self.ingress_expiry_datetime,
            )
            .await?;
        waiter.start();

        loop {
            match self
                .agent
                .request_status_raw(&request_id, self.ingress_expiry_datetime)
                .await?
            {
                RequestStatusResponse::Replied {
                    reply: Replied::CallReplied(arg),
                } => return Ok(arg),
                RequestStatusResponse::Rejected {
                    reject_code,
                    reject_message,
                } => {
                    return Err(AgentError::ReplicaError {
                        reject_code,
                        reject_message,
                    })
                }
                RequestStatusResponse::Unknown => (),
                RequestStatusResponse::Received => (),
                RequestStatusResponse::Processing => (),
                RequestStatusResponse::Done => {
                    return Err(AgentError::RequestStatusDoneNoReply(String::from(
                        request_id,
                    )))
                }
            };

            waiter
                .wait()
                .map_err(|_| AgentError::TimeoutWaitingForResponse())?;
        }
    }

    /// Make an update call. This will return a RequestId.
    /// The RequestId should then be used for request_status (most likely in a loop).
    pub async fn call(self) -> Result<RequestId, AgentError> {
        self.agent.execute_update(self)
    }
}
