use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use validator::Validate;

use super::AuthError;
use super::claims::Claims;

#[derive(Clone)]
pub struct JwtParser {
    key: DecodingKey,
    validation: Validation,
}

impl JwtParser {
    const ALGORITHM: Algorithm = Algorithm::HS256;

    pub fn new(secret: &str) -> Self {
        let key = DecodingKey::from_secret(secret.as_bytes());
        let mut validation = Validation::new(Self::ALGORITHM);

        // Qdrant server is the only audience
        validation.validate_aud = false;

        // Expiration time leeway to account for clock skew
        validation.leeway = 30;

        // All claims are optional
        validation.required_spec_claims = Default::default();

        JwtParser { key, validation }
    }

    /// Decode the token and return the claims, this already validates the `exp` claim with some leeway.
    /// Returns None when the token doesn't look like a JWT.
    pub fn decode(&self, token: &str) -> Option<Result<Claims, AuthError>> {
        let claims = match decode::<Claims>(token, &self.key, &self.validation) {
            Ok(token_data) => token_data.claims,
            Err(e) => {
                return match e.kind() {
                    ErrorKind::ExpiredSignature | ErrorKind::InvalidSignature => {
                        Some(Err(AuthError::Forbidden(e.to_string())))
                    }
                    _ => None,
                };
            }
        };
        if let Err(e) = claims.validate() {
            return Some(Err(AuthError::Unauthorized(e.to_string())));
        }
        Some(Ok(claims))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use storage::rbac::{
        Access, CollectionAccess, CollectionAccessList, CollectionAccessMode, GlobalAccessMode,
    };

    use super::*;

    pub fn create_token(claims: &Claims) -> String {
        use jsonwebtoken::{EncodingKey, Header, encode};

        let key = EncodingKey::from_secret("secret".as_ref());
        let header = Header::new(JwtParser::ALGORITHM);
        encode(&header, claims, &key).unwrap()
    }

    #[test]
    fn test_jwt_parser() {
        let exp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();
        let claims = Claims {
            sub: None,
            exp: Some(exp),
            access: Access::Collection(CollectionAccessList(vec![CollectionAccess {
                collection: "collection".to_string(),
                access: CollectionAccessMode::ReadWrite,
                payload_decrypt: false,
                snapshot_export: false,
                #[expect(deprecated)]
                payload: None,
            }])),
            value_exists: None,
            subject: None,
        };
        let token = create_token(&claims);

        let secret = "secret";
        let parser = JwtParser::new(secret);
        let decoded_claims = parser.decode(&token).unwrap().unwrap();

        assert_eq!(claims, decoded_claims);
    }

    #[test]
    fn test_jwt_parser_preserves_payload_decrypt_collection_access() {
        let exp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();
        let claims = Claims {
            sub: None,
            exp: Some(exp),
            access: Access::Collection(CollectionAccessList(vec![CollectionAccess {
                collection: "encrypted_docs".to_string(),
                access: CollectionAccessMode::Read,
                payload_decrypt: true,
                snapshot_export: false,
                #[expect(deprecated)]
                payload: None,
            }])),
            value_exists: None,
            subject: None,
        };
        let token = create_token(&claims);

        let parser = JwtParser::new("secret");
        let decoded_claims = parser.decode(&token).unwrap().unwrap();

        assert_eq!(claims, decoded_claims);
        assert!(matches!(
            decoded_claims.access,
            Access::Collection(CollectionAccessList(ref collections))
                if collections
                    .iter()
                    .any(|access| access.collection == "encrypted_docs"
                        && access.payload_decrypt)
        ));
    }

    #[test]
    fn test_jwt_parser_preserves_snapshot_export_collection_access() {
        let exp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();
        let claims = Claims {
            sub: None,
            exp: Some(exp),
            access: Access::Collection(CollectionAccessList(vec![CollectionAccess {
                collection: "archive_docs".to_string(),
                access: CollectionAccessMode::Read,
                payload_decrypt: false,
                snapshot_export: true,
                #[expect(deprecated)]
                payload: None,
            }])),
            value_exists: None,
            subject: None,
        };
        let token = create_token(&claims);

        let parser = JwtParser::new("secret");
        let decoded_claims = parser.decode(&token).unwrap().unwrap();

        assert!(matches!(
            decoded_claims.access,
            Access::Collection(CollectionAccessList(ref collections))
                if collections
                    .iter()
                    .any(|access| access.collection == "archive_docs"
                        && access.snapshot_export)
        ));
    }

    #[test]
    fn test_jwt_parser_with_deprecated_payloads() {
        let exp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();
        let claims = Claims {
            sub: None,
            exp: Some(exp),
            access: Access::Collection(CollectionAccessList(vec![CollectionAccess {
                collection: "collection".to_string(),
                access: CollectionAccessMode::ReadWrite,
                payload_decrypt: false,
                snapshot_export: false,
                #[expect(deprecated)]
                payload: Some(json!({
                    "field1": "value",
                    "field2": 42,
                    "field3": true,
                })),
            }])),
            value_exists: None,
            subject: None,
        };
        let token = create_token(&claims);

        let secret = "secret";
        let parser = JwtParser::new(secret);
        assert!(parser.decode(&token).unwrap().is_err()); // Validation should fail due to PayloadConstraint
    }

    #[test]
    fn test_exp_validation() {
        let exp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs()
            - 31; // 31 seconds in the past, bigger than the 30 seconds leeway

        let mut claims = Claims {
            sub: None,
            exp: Some(exp),
            access: Access::Global(GlobalAccessMode::Read),
            value_exists: None,
            subject: None,
        };

        let token = create_token(&claims);

        let secret = "secret";
        let parser = JwtParser::new(secret);
        assert!(matches!(
            parser.decode(&token),
            Some(Err(AuthError::Forbidden(_)))
        ));

        // Remove the exp claim and it should work
        claims.exp = None;
        let token = create_token(&claims);

        let decoded_claims = parser.decode(&token).unwrap().unwrap();

        assert_eq!(claims, decoded_claims);
    }

    #[test]
    fn test_no_exp() {
        let claims = Claims {
            sub: None,
            exp: None,
            access: Access::Global(GlobalAccessMode::Read),
            value_exists: None,
            subject: None,
        };

        let token = create_token(&claims);

        let secret = "secret";
        let parser = JwtParser::new(secret);

        assert!(matches!(parser.decode(&token), Some(Ok(_))));
    }

    #[test]
    fn test_invalid_token() {
        let claims = Claims {
            sub: None,
            exp: None,
            access: Access::Global(GlobalAccessMode::Read),
            value_exists: None,
            subject: None,
        };
        let token = create_token(&claims);

        assert!(matches!(
            JwtParser::new("wrong-secret").decode(&token),
            Some(Err(AuthError::Forbidden(_)))
        ));

        assert!(JwtParser::new("secret").decode("foo.bar.baz").is_none());
    }
}
