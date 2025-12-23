use chrono::Utc;
use jsonwebtoken::TokenData;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::{Deserialize, Serialize};

/// HCAuth holds your Hack Club OAuth credentials.
///
/// This little backpack keeps your client ID, secret, and redirect URL ready
/// so you can fetch tokens and sniff out identities.
/// Because you like sniffing users, dont you ? :3
#[derive(Deserialize)]
pub struct HCAuth {
    /// Your app's client ID (like your paw print ID)
    client_id: String,
    /// Your app's secret (shhh, don't share your treats!)
    client_secrets: String,
    /// Where to redirect after login (like returning to your cozy den)
    redirect_uri: String,
}

/// API response for a user identity.
///
/// Contains the identity info and the scopes your token allows access to.
#[derive(Debug, Serialize, Deserialize)]
pub struct ApiResponse {
    /// The furry user info, yes, they are a furry
    /// you a gay furry :3
    pub identity: Identity,
    /// List of powers/scopes the user granted
    pub scopes: Vec<String>,
}

/// Claims extracted from a JWT.
///
/// These are the juicy bits inside the token, like your username and expiry.
#[derive(Debug, Deserialize)]
pub struct IdClaims {
    /// User ID pawprint
    pub sub: String,
    /// Issuer (who made this token)
    pub iss: String,
    /// Audience (who is allowed to use it)
    pub aud: String,
    /// Expiry timestamp (when the treat goes stale)
    pub exp: usize,
    /// Issued at timestamp
    pub iat: usize,

    /// Profile info
    pub name: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,

    /// Email info
    pub email: Option<String>,
    pub email_verified: Option<bool>,

    /// Hack Club-specific
    pub verification_status: Option<VerificationStatus>,
    pub ysws_eligible: Option<bool>,

    /// Optional address scope (OIDC standard)
    pub address: Option<AddressClaim>,
}

#[derive(Debug, Deserialize)]
pub struct AddressClaim {
    pub street_address: Option<String>,
    pub locality: Option<String>,
    pub region: Option<String>,
    pub postal_code: Option<String>,
    pub country: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct VerificationStatusCheck {
    result: VerificationStatus,
}

#[derive(Serialize)]
struct QueryParams<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    idv_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    slack_id: Option<&'a str>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Identity {
    pub id: String,
    pub ysws_eligible: bool,
    pub verification_status: Option<VerificationStatus>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub primary_email: String,
    pub slack_id: Option<String>,
    pub phone_number: Option<String>,
    pub birthday: Option<String>,
    pub legal_first_name: Option<String>,
    pub legal_last_name: Option<String>,
    pub addresses: Option<Vec<Address>>,
}

/// Verification status for a user.
///
/// Are they verified, pending, naughty, or just invisible in the woods?
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationStatus {
    NeedsSubmission,
    Pending,
    Ineligible,
    Verified,
    Rejected,
    NotFound,
    VerifiedButOver18,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Address {
    pub id: String,
    pub first_name: String,
    pub last_name: String,
    pub line_1: String,
    pub line_2: String,
    pub city: String,
    pub state: String,
    pub postal_code: String,
    pub country: String,
    pub phone_number: String,
    pub primary: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct UserInfo {
    pub sub: Option<String>,
    pub email: String,
    pub email_verified: bool,
    pub name: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub nickname: Option<String>,
    pub updated_at: Option<String>,
    pub slack_id: Option<String>,
    pub verification_status: Option<VerificationStatus>,
    pub ysws_eligible: Option<bool>,
}

#[derive(Serialize, Deserialize)]
pub struct Token {
    pub access_token: Option<String>,
    pub expires_in: Option<u32>,
    pub id_token: Option<String>,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Jwks {
    pub keys: Vec<Jwk>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Jwk {
    pub kty: Option<String>,
    pub n: Option<String>,
    pub e: Option<String>,
    pub kid: Option<String>,
    pub r#use: Option<String>,
    pub alg: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct UserIdentity {
    pub id: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct Identities {
    identities: Vec<UserIdentity>,
}

const URL_BASE: &str = "https://auth.hackclub.com";

impl Default for HCAuth {
    fn default() -> Self {
        Self::new()
    }
}

impl HCAuth {
    /// Creat New HCAuth by sniffing the config file :3
    pub fn new() -> Self {
        let config_str = std::fs::read_to_string("hca.toml").unwrap();
        let config: HCAuth = toml::from_str(config_str.as_str()).unwrap();
        config
    }

    /// Exchange an OAuth code for access and ID tokens.
    ///
    /// The code comes from the login flow; this gives you tasty treats to play with.
    pub async fn exchange_code(&self, code: String) -> Result<Token, reqwest::Error> {
        let client = reqwest::Client::new();
        let token = client
            .post("https://auth.hackclub.com/oauth/token")
            .form(&[
                ("client_id", self.client_id.clone()),
                ("client_secret", self.client_secrets.clone()),
                ("code", code),
                ("redirect_uri", self.redirect_uri.clone()),
                ("grant_type", "authorization_code".to_string()),
            ])
            .send()
            .await?
            .error_for_status()?
            .json::<Token>()
            .await?;
        Ok(token)
    }

    pub async fn refresh_token(&self, refresh_token: String) -> Result<Token, reqwest::Error> {
        let client = reqwest::Client::new();
        let token = client
            .post("https://auth.hackclub.com/oauth/token")
            .form(&[
                ("client_id", self.client_id.clone()),
                ("client_secret", self.client_secrets.clone()),
                ("refresh_token", refresh_token),
                ("grant_type", "refresh_token".to_string()),
            ])
            .send()
            .await?
            .error_for_status()?
            .json::<Token>()
            .await?;
        Ok(token)
    }

    /// Generate an OAuth URL for login with specific scopes.
    pub fn get_oauth_uri(&self, scopes: &[&str]) -> String {
        format!(
            "{}/oauth/authorize?client_id={}&redirect_uri={}&response_type=code&scope={}",
            URL_BASE,
            self.client_id,
            self.redirect_uri,
            scopes.join("+")
        )
    }

    /// Generate a re-auth URL to force the user to log in again.
    pub fn get_reauth_uri(&self, max_age: Option<u32>) -> String {
        format!(
            "{}/oauth/authorize?client_id={}&prompt=login&redirect_uri={}&max_age={}",
            URL_BASE,
            self.client_id,
            self.redirect_uri,
            max_age.unwrap_or(0)
        )
    }
    ///  Fetch the user's identity info from Hack Club API.
    pub async fn get_identity(&self, token: String) -> Result<ApiResponse, reqwest::Error> {
        let api_resp = reqwest::Client::new()
            .get(format!("{}/api/v1/me", URL_BASE))
            .bearer_auth(token)
            .send()
            .await?
            .error_for_status()?
            .json::<ApiResponse>()
            .await?;
        Ok(api_resp)
    }

    /// Get specifiq user identity using their id, extra function to sniff at ppl dare i say
    /// (requires a program key)
    pub async fn get_user_identity(
        &self,
        token: String,
        id: String,
    ) -> Result<UserIdentity, reqwest::Error> {
        let api_resp = reqwest::Client::new()
            .get(format!("{}/api/identities/{}", URL_BASE, id))
            .bearer_auth(token)
            .send()
            .await?
            .error_for_status()?
            .json::<UserIdentity>()
            .await?;
        Ok(api_resp)
    }

    /// get all specifiq user identity that have authorized your app
    pub async fn get_all_identities(
        &self,
        token: String,
    ) -> Result<Vec<UserIdentity>, reqwest::Error> {
        let api_resp = reqwest::Client::new()
            .get(format!("{}/api/identities/", URL_BASE))
            .bearer_auth(token)
            .send()
            .await?
            .error_for_status()?
            .json::<Identities>()
            .await?;
        Ok(api_resp.identities)
    }

    /// Check a user's verification status externally.
    ///
    /// Can pass `idv_id`, `email`, or `slack_id` to sniff them out.
    pub async fn external_check(
        &self,
        idv_id: Option<String>,
        email: Option<String>,
        slack_id: Option<String>,
    ) -> Result<VerificationStatus, reqwest::Error> {
        let params = QueryParams {
            idv_id: idv_id.as_deref(),
            email: email.as_deref(),
            slack_id: slack_id.as_deref(),
        };

        let status = reqwest::Client::new()
            .get(format!("{}/api/external/check", URL_BASE))
            .query(&params)
            .send()
            .await?
            .json::<VerificationStatusCheck>()
            .await?;
        Ok(status.result)
    }

    ///  Verify a JWT token using Hack Club's JWKs.
    ///
    /// Decodes and validates the token, returning the inner claims if it's good.
    pub async fn verify_jwt_token(
        &self,
        id_token: Option<String>,
    ) -> Result<IdClaims, Box<dyn std::error::Error>> {
        let id_token = id_token.ok_or("missing id_token")?;
        let jwks: Jwks = reqwest::Client::new()
            .get(format!("{}/oauth/discovery/keys", URL_BASE))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let header = decode_header(&id_token)?;
        let kid = header.kid.ok_or("missing kid in token")?;
        let jwk = jwks
            .keys
            .iter()
            .find(|k| k.kid.as_deref() == Some(&kid))
            .ok_or("no matching JWK")?;

        let n = jwk.n.as_ref().ok_or("JWK missing n")?;
        let e = jwk.e.as_ref().ok_or("JWK missing e")?;
        let decoding_key = DecodingKey::from_rsa_components(n, e)?;
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(std::slice::from_ref(&self.client_id));
        validation.set_issuer(&[URL_BASE]);
        let token_data: TokenData<IdClaims> =
            decode::<IdClaims>(&id_token, &decoding_key, &validation)?;
        let claims = token_data.claims;
        let now = Utc::now().timestamp() as usize;
        if claims.aud != self.client_id {
            return Err("invalid audience".into());
        }
        if claims.iss != URL_BASE {
            return Err("invalid issuer".into());
        }
        if claims.exp < now {
            return Err("token expired".into());
        }
        Ok(claims)
    }
}
