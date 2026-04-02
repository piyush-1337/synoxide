use thiserror::Error;

pub type Result<T> = std::result::Result<T, SynoxideError>;

#[derive(Debug, Error)]
pub enum SynoxideError {
    #[error("{0}")]
    Parse(String)
}
