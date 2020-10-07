use crate::agent::{AgentConfig, HttpAgent};
use crate::{AgentError, Identity, NonceFactory, PasswordManager};

pub struct HttpAgentBuilder {
    config: AgentConfig,
}

impl Default for HttpAgentBuilder {
    fn default() -> Self {
        Self {
            config: Default::default(),
        }
    }
}

impl HttpAgentBuilder {
    /// Create an instance of [Agent] with the information from this builder.
    pub fn build(self) -> Result<HttpAgent, AgentError> {
        HttpAgent::new(self.config)
    }

    /// Set the URL of the [Agent].
    pub fn with_url<S: ToString>(self, url: S) -> Self {
        HttpAgentBuilder {
            config: AgentConfig {
                url: url.to_string(),
                ..self.config
            },
        }
    }

    /// Add a NonceFactory to this Agent. By default, no nonce is produced.
    pub fn with_nonce_factory(self, nonce_factory: NonceFactory) -> Self {
        HttpAgentBuilder {
            config: AgentConfig {
                nonce_factory,
                ..self.config
            },
        }
    }

    /// Add an identity provider for signing messages. This is required.
    pub fn with_identity<I>(self, identity: I) -> Self
    where
        I: 'static + Identity + Send + Sync,
    {
        HttpAgentBuilder {
            config: AgentConfig {
                identity: Box::new(identity),
                ..self.config
            },
        }
    }

    /// Same as [with_identity], but provides a boxed implementation instead
    /// of a direct type.
    pub fn with_boxed_identity(self, identity: Box<impl 'static + Identity + Send + Sync>) -> Self {
        HttpAgentBuilder {
            config: AgentConfig {
                identity,
                ..self.config
            },
        }
    }

    /// Set the password manager. If the Agent makes a connection which requires an
    /// HTTP Authentication, it will ask this provider for a username and password
    /// pair.
    pub fn with_password_manager<P>(self, password_manager: P) -> Self
    where
        P: 'static + PasswordManager + Send + Sync,
    {
        HttpAgentBuilder {
            config: AgentConfig {
                password_manager: Some(Box::new(password_manager)),
                ..self.config
            },
        }
    }

    /// Same as [with_password_manager], but provides a boxed implementation instead
    /// of a direct type.
    pub fn with_boxed_password_manager(
        self,
        password_manager: Box<impl 'static + PasswordManager + Send + Sync>,
    ) -> Self {
        HttpAgentBuilder {
            config: AgentConfig {
                password_manager: Some(password_manager),
                ..self.config
            },
        }
    }

    /// Provides a _default_ ingress expiry. This is the delta that will be applied
    /// at the time an update or query is made. The default expiry cannot be a
    /// fixed system time.
    pub fn with_ingress_expiry(self, duration: Option<std::time::Duration>) -> Self {
        HttpAgentBuilder {
            config: AgentConfig {
                ingress_expiry_duration: duration,
                ..self.config
            },
        }
    }
}
