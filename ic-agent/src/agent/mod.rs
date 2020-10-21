//! The main Agent module. Contains the [Agent] and Update traits.
use crate::export::Principal;
use crate::RequestId;

pub(crate) mod agent_config;
pub(crate) mod agent_error;
pub(crate) mod builder;
pub(crate) mod nonce;
pub(crate) mod replica_api;
pub(crate) mod response;

pub mod status;
pub use agent_config::{AgentConfig, PasswordManager};
pub use agent_error::AgentError;
pub use builder::AgentBuilder;
pub use nonce::NonceFactory;
pub use response::{Replied, RequestStatusResponse};

#[cfg(test)]
mod agent_test;

pub trait QueryBuilder: Sized {
    type Agent: Agent<QueryBuilder = Self>;

    fn with_arg_raw<A>(self, raw_argument: A) -> Self
    where
        A: Into<Vec<u8>>;

    fn call(self) -> Result<Vec<u8>, AgentError>;
}

pub trait UpdateBuilder: Sized {
    type Agent: Agent<UpdateBuilder = Self>;

    fn with_arg_raw<A>(self, raw_argument: A) -> Self
    where
        A: Into<Vec<u8>>;

    fn call(self) -> Result<RequestId, AgentError>;
}

pub trait Agent {
    type QueryBuilder: QueryBuilder<Agent = Self>;
    type UpdateBuilder: UpdateBuilder<Agent = Self>;

    fn query<P, M>(agent: &Self::Agent, principal: P, method_name: M) -> Self::QueryBuilder
    where
        P: Into<Principal>,
        M: Into<String>;

    fn update<P, M>(agent: &Self::Agent, principal: P, method_name: M) -> Self::UpdateBuilder
    where
        P: Into<Principal>,
        M: Into<String>;
}
