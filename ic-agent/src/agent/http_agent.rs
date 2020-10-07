use crate::agent::replica_api::{AsyncContent, Envelope, SyncContent};
use crate::agent::status::Status;
use crate::agent::{
    builder, replica_api, AgentConfig, Expiry, QueryBuilder, Replied, RequestStatusResponse,
    UpdateBuilder,
};
use crate::export::Principal;
use crate::{to_request_id, Agent, AgentError, Identity, NonceFactory, PasswordManager, RequestId};
use async_trait::async_trait;
use reqwest::Method;
use serde::Serialize;
use std::convert::TryFrom;
use std::time::Duration;

const DOMAIN_SEPARATOR: &[u8; 11] = b"\x0Aic-request";

/// A low level Agent to make calls to a Replica endpoint through HTTP.
pub struct HttpAgent {
    url: reqwest::Url,
    nonce_factory: NonceFactory,
    client: reqwest::Client,
    identity: Box<dyn Identity + Send + Sync>,
    password_manager: Option<Box<dyn PasswordManager + Send + Sync>>,
    ingress_expiry_duration: Duration,
}

impl HttpAgent {
    /// Create an instance of an [`AgentBuilder`] for building an [`Agent`]. This is simpler than
    /// using the [`AgentConfig`] and [`Agent::new()`].
    pub fn builder() -> builder::HttpAgentBuilder {
        Default::default()
    }

    /// Create an instance of an [`Agent`].
    pub fn new(config: AgentConfig) -> Result<Self, AgentError> {
        let url = config.url;
        let mut tls_config = rustls::ClientConfig::new();

        // Advertise support for HTTP/2
        tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        // Mozilla CA root store
        tls_config
            .root_store
            .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);

        Ok(HttpAgent {
            url: reqwest::Url::parse(&url)
                .and_then(|url| url.join("api/v1/"))
                .map_err(|_| AgentError::InvalidReplicaUrl(url.clone()))?,
            client: reqwest::Client::builder()
                .use_preconfigured_tls(tls_config)
                .build()
                .expect("Could not create HTTP client."),
            nonce_factory: config.nonce_factory,
            identity: config.identity,
            password_manager: config.password_manager,
            ingress_expiry_duration: config
                .ingress_expiry_duration
                .unwrap_or_else(|| Duration::from_secs(300)),
        })
    }

    fn calculate_expiry(&self, expiry: Expiry) -> u64 {
        let permitted_drift = Duration::from_secs(60);

        let time = match expiry {
            Expiry::Unspecified => std::time::SystemTime::now() + self.ingress_expiry_duration,
            Expiry::Delay(delay) => std::time::SystemTime::now() + delay,
            Expiry::DateTime(datetime) => datetime,
        };

        (time
            .duration_since(std::time::UNIX_EPOCH)
            .expect("Time wrapped around.")
            - permitted_drift)
            .as_nanos() as u64
    }

    fn construct_message(&self, request_id: &RequestId) -> Vec<u8> {
        let mut buf = vec![];
        buf.extend_from_slice(DOMAIN_SEPARATOR);
        buf.extend_from_slice(request_id.as_slice());
        buf
    }

    async fn request(
        &self,
        http_request: reqwest::Request,
    ) -> Result<(reqwest::StatusCode, reqwest::header::HeaderMap, Vec<u8>), AgentError> {
        let response = self
            .client
            .execute(
                http_request
                    .try_clone()
                    .expect("Could not clone a request."),
            )
            .await
            .map_err(AgentError::from)?;

        let http_status = response.status();
        let response_headers = response.headers().clone();
        let bytes = response.bytes().await?.to_vec();

        Ok((http_status, response_headers, bytes))
    }

    fn maybe_add_authorization(
        &self,
        http_request: &mut reqwest::Request,
        cached: bool,
    ) -> Result<(), AgentError> {
        if let Some(pm) = &self.password_manager {
            let maybe_user_pass = if cached {
                pm.cached(http_request.url().as_str())
            } else {
                pm.required(http_request.url().as_str()).map(Some)
            };

            if let Some((u, p)) = maybe_user_pass.map_err(AgentError::AuthenticationError)? {
                let auth = base64::encode(&format!("{}:{}", u, p));
                http_request.headers_mut().insert(
                    reqwest::header::AUTHORIZATION,
                    format!("Basic {}", auth).parse().unwrap(),
                );
            }
        }
        Ok(())
    }

    async fn execute<T: std::fmt::Debug + serde::Serialize>(
        &self,
        method: Method,
        endpoint: &str,
        envelope: Option<Envelope<T>>,
    ) -> Result<Vec<u8>, AgentError> {
        let mut body = None;
        if let Some(e) = envelope {
            let mut serialized_bytes = Vec::new();

            let mut serializer = serde_cbor::Serializer::new(&mut serialized_bytes);
            serializer.self_describe()?;
            e.serialize(&mut serializer)?;

            body = Some(serialized_bytes);
        }

        let url = self.url.join(endpoint)?;
        let mut http_request = reqwest::Request::new(method, url);
        http_request.headers_mut().insert(
            reqwest::header::CONTENT_TYPE,
            "application/cbor".parse().unwrap(),
        );

        self.maybe_add_authorization(&mut http_request, true)?;

        *http_request.body_mut() = body.map(reqwest::Body::from);

        let mut status;
        let mut headers;
        let mut body;
        loop {
            let request_result = self.request(http_request.try_clone().unwrap()).await?;
            status = request_result.0;
            headers = request_result.1;
            body = request_result.2;

            // If the server returned UNAUTHORIZED, and it is the first time we replay the call,
            // check if we can get the username/password for the HTTP Auth.
            if status == reqwest::StatusCode::UNAUTHORIZED {
                if self.url.scheme() == "https" || self.url.host_str() == Some("localhost") {
                    // If there is a password manager, get the username and password from it.
                    self.maybe_add_authorization(&mut http_request, false)?;
                } else {
                    return Err(AgentError::CannotUseAuthenticationOnNonSecureUrl());
                }
            } else {
                break;
            }
        }

        if status.is_client_error() || status.is_server_error() {
            Err(AgentError::HttpError {
                status: status.into(),
                content_type: headers
                    .get(reqwest::header::CONTENT_TYPE)
                    .and_then(|value| value.to_str().ok())
                    .map(|x| x.to_string()),
                content: body,
            })
        } else {
            Ok(body)
        }
    }

    async fn read_endpoint<A>(&self, request: SyncContent) -> Result<A, AgentError>
    where
        A: serde::de::DeserializeOwned,
    {
        let anonymous = Principal::anonymous();
        let request_id = to_request_id(&request)?;
        let sender = match &request {
            SyncContent::QueryRequest { sender, .. } => sender,
            SyncContent::RequestStatusRequest { .. } => &anonymous,
        };
        let msg = self.construct_message(&request_id);
        let signature = self
            .identity
            .sign(&msg, &sender)
            .map_err(AgentError::SigningError)?;
        let bytes = self
            .execute(
                Method::POST,
                "read",
                Some(Envelope {
                    content: request,
                    sender_pubkey: signature.public_key,
                    sender_sig: signature.signature,
                }),
            )
            .await?;

        serde_cbor::from_slice(&bytes).map_err(AgentError::InvalidCborData)
    }

    async fn submit_endpoint(&self, request: AsyncContent) -> Result<RequestId, AgentError> {
        let request_id = to_request_id(&request)?;
        let sender = match request.clone() {
            AsyncContent::CallRequest { sender, .. } => sender,
        };
        let msg = self.construct_message(&request_id);
        let signature = self
            .identity
            .sign(&msg, &sender)
            .map_err(AgentError::SigningError)?;
        let _ = self
            .execute(
                Method::POST,
                "submit",
                Some(Envelope {
                    content: request,
                    sender_pubkey: signature.public_key,
                    sender_sig: signature.signature,
                }),
            )
            .await?;

        Ok(request_id)
    }

    /// The simplest way to do a query call; sends a byte array and will return a byte vector.
    /// The encoding is left as an exercise to the user.
    async fn query_raw(
        &self,
        canister_id: Principal,
        method_name: String,
        arg: Vec<u8>,
        expiry: Expiry,
    ) -> Result<Vec<u8>, AgentError> {
        self.read_endpoint::<replica_api::QueryResponse>(SyncContent::QueryRequest {
            sender: self.identity.sender().map_err(AgentError::SigningError)?,
            canister_id,
            method_name,
            arg,
            ingress_expiry: self.calculate_expiry(expiry),
        })
        .await
        .and_then(|response| match response {
            replica_api::QueryResponse::Replied { reply } => Ok(reply.arg),
            replica_api::QueryResponse::Rejected {
                reject_code,
                reject_message,
            } => Err(AgentError::ReplicaError {
                reject_code,
                reject_message,
            }),
        })
    }

    /// The simplest way to do an update call; sends a byte array and will return a RequestId.
    /// The RequestId should then be used for request_status (most likely in a loop).
    async fn update_raw(
        &self,
        canister_id: Principal,
        method_name: String,
        arg: Vec<u8>,
        expiry: Expiry,
    ) -> Result<RequestId, AgentError> {
        self.submit_endpoint(AsyncContent::CallRequest {
            canister_id,
            method_name,
            arg,
            nonce: self.nonce_factory.generate().map(|b| b.as_slice().into()),
            sender: self.identity.sender().map_err(AgentError::SigningError)?,
            ingress_expiry: self.calculate_expiry(expiry),
        })
        .await
    }

    pub async fn request_status_raw(
        &self,
        request_id: &RequestId,
        ingress_expiry_datetime: Option<u64>,
    ) -> Result<RequestStatusResponse, AgentError> {
        self.read_endpoint(SyncContent::RequestStatusRequest {
            request_id: request_id.as_slice().into(),
            ingress_expiry: ingress_expiry_datetime.unwrap_or_else(|| self.get_expiry_date()),
        })
        .await
        .map(|response| match response {
            replica_api::Status::Replied { reply } => {
                let reply = match reply {
                    replica_api::RequestStatusResponseReplied::CallReply(reply) => {
                        Replied::CallReplied(reply.arg)
                    }
                };
                RequestStatusResponse::Replied { reply }
            }
            replica_api::Status::Rejected {
                reject_code,
                reject_message,
            } => RequestStatusResponse::Rejected {
                reject_code,
                reject_message,
            },
            replica_api::Status::Unknown {} => RequestStatusResponse::Unknown,
            replica_api::Status::Received {} => RequestStatusResponse::Received,
            replica_api::Status::Processing {} => RequestStatusResponse::Processing,
            replica_api::Status::Done {} => RequestStatusResponse::Done,
        })
    }

    /// Returns an UpdateBuilder enabling the construction of an update call without
    /// passing all arguments.
    pub fn update<S: ToString>(
        &self,
        canister_id: &Principal,
        method_name: S,
    ) -> UpdateBuilder<Self> {
        UpdateBuilder::new(self, canister_id.clone(), method_name.to_string())
    }

    /// Calls and returns the information returned by the status endpoint of a replica.
    pub async fn status(&self) -> Result<Status, AgentError> {
        let bytes = self.execute::<()>(Method::GET, "status", None).await?;

        let cbor: serde_cbor::Value =
            serde_cbor::from_slice(&bytes).map_err(AgentError::InvalidCborData)?;

        Status::try_from(&cbor).map_err(|_| AgentError::InvalidReplicaStatus)
    }

    /// Returns a QueryBuilder enabling the construction of a query call without
    /// passing all arguments.
    pub fn query<S: ToString>(
        &self,
        canister_id: &Principal,
        method_name: S,
    ) -> QueryBuilder<Self> {
        QueryBuilder::new(self, canister_id.clone(), method_name.to_string())
    }
}

#[async_trait]
impl Agent for HttpAgent {
    async fn execute_query(&self, query: QueryBuilder<'_, Self>) -> Result<Vec<u8>, AgentError> {
        self.query_raw(
            query.canister_id,
            query.method_name,
            query.arg,
            query.expiry,
        )
        .await
    }

    async fn execute_update(
        &self,
        update: UpdateBuilder<'_, Self>,
    ) -> Result<RequestId, AgentError> {
        self.update_raw(
            update.canister_id,
            update.method_name,
            update.arg,
            update.expiry,
        )
        .await
    }
}
