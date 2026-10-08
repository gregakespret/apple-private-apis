
// Implementing the SideStore Anisette v3 protocol

use std::{collections::HashMap, fs, io::Cursor, path::PathBuf};

use base64::engine::general_purpose;
use chrono::{DateTime, SubsecRound, Utc};
use log::debug;
use plist::{Data, Dictionary};
use reqwest::{Certificate, Client, ClientBuilder, Proxy, RequestBuilder};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use rand::Rng;
use sha2::{Sha256, Digest};
use tokio_tungstenite::{connect_async, tungstenite::Message};
use uuid::Uuid;
use futures_util::{stream::StreamExt, SinkExt};
use std::fmt::Write;
use base64::Engine;
use async_trait::async_trait;

use crate::{AnisetteError, AnisetteProvider, LoginClientInfo};

const APPLE_ROOT: &[u8] = include_bytes!("../../icloud-auth/src/apple_root.der");

fn plist_to_string<T: serde::Serialize>(value: &T) -> Result<String, plist::Error> {
    plist_to_buf(value).map(|val| String::from_utf8(val).unwrap())
}

fn plist_to_buf<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, plist::Error> {
    let mut buf: Vec<u8> = Vec::new();
    let writer = Cursor::new(&mut buf);
    plist::to_writer_xml(writer, &value)?;
    Ok(buf)
}

fn bin_serialize<S>(x: &[u8], s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    s.serialize_bytes(x)
}

fn bin_serialize_opt<S>(x: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    x.clone().map(|i| Data::new(i)).serialize(s)
}

fn bin_deserialize_opt<'de, D>(d: D) -> Result<Option<Vec<u8>>, D::Error>
where
    D: Deserializer<'de>,
{
    let s: Option<Data> = Deserialize::deserialize(d)?;
    Ok(s.map(|i| i.into()))
}

fn bin_deserialize_16<'de, D>(d: D) -> Result<[u8; 16], D::Error>
where
    D: Deserializer<'de>,
{
    let s: Data = Deserialize::deserialize(d)?;
    let s: Vec<u8> = s.into();
    Ok(s.try_into().unwrap())
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        write!(&mut s, "{:02x}", b).unwrap();
    }
    s
}
fn base64_encode(data: &[u8]) -> String {
    general_purpose::STANDARD.encode(data)
}


#[derive(Serialize, Deserialize)]
pub struct AnisetteState {
    #[serde(serialize_with = "bin_serialize", deserialize_with = "bin_deserialize_16")]
    keychain_identifier: [u8; 16],
    #[serde(serialize_with = "bin_serialize_opt", deserialize_with = "bin_deserialize_opt")]
    adi_pb: Option<Vec<u8>>,
}

impl Default for AnisetteState {
    fn default() -> Self {
        AnisetteState {
            keychain_identifier: rand::thread_rng().gen::<[u8; 16]>(),
            adi_pb: None
        }
    }
}

impl AnisetteState {
    pub fn new() -> AnisetteState {
        AnisetteState::default()
    }

    pub fn is_provisioned(&self) -> bool {
        self.adi_pb.is_some()
    }

    fn md_lu(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&self.keychain_identifier);
        hasher.finalize().into()
    }

    fn device_id(&self) -> String {
        Uuid::from_bytes(self.keychain_identifier).to_string()
    }
}
pub struct AnisetteClient {
    login_info: LoginClientInfo,
    url: String
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct ProvisionBodyData {
    header: Dictionary,
    request: Dictionary,
}

#[derive(Debug)]
pub struct AnisetteData {
    machine_id: String,
    one_time_password: String,
    routing_info: String,
    device_description: String,
    local_user_id: String,
    device_unique_identifier: String
}

impl AnisetteData {
    pub fn get_headers(&self) -> HashMap<String, String> {
        let dt: DateTime<Utc> = Utc::now().round_subsecs(0);

        HashMap::from_iter([
            ("X-Apple-I-Client-Time".to_string(), dt.format("%+").to_string().replace("+00:00", "Z")),
            ("X-Apple-I-TimeZone".to_string(), "UTC".to_string()),
            ("X-Apple-Locale".to_string(), "en_US".to_string()),
            ("X-Apple-I-MD-RINFO".to_string(), self.routing_info.clone()),
            ("X-Apple-I-MD-LU".to_string(), self.local_user_id.clone()),
            ("X-Mme-Device-Id".to_string(), self.device_unique_identifier.clone()),
            ("X-Apple-I-MD".to_string(), self.one_time_password.clone()),
            ("X-Apple-I-MD-M".to_string(), self.machine_id.clone()),
            ("X-Mme-Client-Info".to_string(), self.device_description.clone()),
        ].into_iter())
    }
}

fn make_reqwest() -> Result<Client, AnisetteError> {
    Ok(ClientBuilder::new()
        .http1_title_case_headers()
        .add_root_certificate(Certificate::from_der(APPLE_ROOT)?)
        // .proxy(Proxy::https("https://localhost:8080").unwrap())
        // .danger_accept_invalid_certs(true)
        .build()?)
}

impl AnisetteClient {
    pub async fn new(url: String, login_info: LoginClientInfo) -> Result<AnisetteClient, AnisetteError> {
        Ok(AnisetteClient {
            login_info,
            url
        })
    }

    fn build_apple_request(&self, state: &AnisetteState, mut builder: RequestBuilder) -> RequestBuilder {
        let dt: DateTime<Utc> = Utc::now().round_subsecs(0);

        // missing: Connection, Accept-Encdoing
        builder = builder.header("User-Agent", &self.login_info.akd_user_agent)
            .header("X-Apple-Baa-E", "-10000")
            .header("X-Apple-I-MD-LU", encode_hex(&state.md_lu()))
            .header("X-Mme-Device-Id", state.device_id())
            .header("X-Apple-Baa-Avail", "2")
            .header("X-Mme-Client-Info", &self.login_info.mme_client_info)
            .header("X-Apple-I-Client-Time", dt.format("%+").to_string())
            .header("Accept-Language", "en-US,en;q=0.9")
            .header("X-Apple-Client-App-Name", "akd")
            .header("Accept", "*/*")
            .header("Content-Type", "application/x-www-form-urlencoded") // not a bug, it's how you *think different*
            .header("X-Apple-Baa-UE", "AKAuthenticationError:-7066|com.apple.devicecheck.error.baa:-10000")
            .header("X-Apple-Host-Baa-E", "-7066");

        for item in &self.login_info.hardware_headers {
            builder = builder.header(item.0, item.1);
        }

        builder
    }

    pub async fn get_headers(&self, state: &AnisetteState) -> Result<AnisetteData, AnisetteError> {
        let path = format!("{}/v3/get_headers", self.url);
        let http_client = make_reqwest()?;

        #[derive(Serialize)]
        struct GetHeadersBody {
            identifier: String,
            adi_pb: String,
        }
        let body = GetHeadersBody {
            identifier: base64_encode(&state.keychain_identifier),
            adi_pb: base64_encode(state.adi_pb.as_ref().ok_or(AnisetteError::AnisetteNotProvisioned)?),
        };

        #[derive(Deserialize)]
        #[serde(tag = "result")]
        enum AnisetteHeaders {
            GetHeadersError {
                message: String
            },
            Headers {
                #[serde(rename = "X-Apple-I-MD-M")]
                machine_id: String,
                #[serde(rename = "X-Apple-I-MD")]
                one_time_password: String,
                #[serde(rename = "X-Apple-I-MD-RINFO")]
                routing_info: String,
            }
        }

        let resp = http_client.post(path)
            .json(&body)
            .send().await?;
        // Read the text before parsing it: a broken host answers with an HTML
        // error page, and reqwest's own JSON error keeps neither status nor text.
        let status = resp.status();
        let text = resp.text().await?;
        let headers: AnisetteHeaders = serde_json::from_str(&text).map_err(|e| {
            let snippet: String = text.chars().take(200).collect();
            AnisetteError::ServerError(format!("HTTP {status}, unreadable reply ({e}): {snippet}"))
        })?;
        match headers {
            AnisetteHeaders::GetHeadersError { message } => {
                if message.contains("-45061") {
                    Err(AnisetteError::AnisetteNotProvisioned)
                } else {
                    Err(AnisetteError::ServerError(message))
                }
            },
            AnisetteHeaders::Headers { machine_id, one_time_password, routing_info } => {
                Ok(AnisetteData {
                    machine_id,
                    one_time_password,
                    routing_info,
                    device_description: self.login_info.mme_client_info.clone(),
                    local_user_id: encode_hex(&state.md_lu()),
                    device_unique_identifier: state.device_id()
                })
            }
        }
    }

    pub async fn provision(&self, state: &mut AnisetteState) -> Result<(), AnisetteError> {
        debug!("Provisioning Anisette");
        let http_client = make_reqwest()?;
        let resp = self.build_apple_request(&state, http_client.get("https://gsa.apple.com/grandslam/GsService2/lookup"))
            .send().await?;
        let text = resp.text().await?;

        let protocol_val = plist::Value::from_reader(Cursor::new(text.as_str()))?;
        let urls = protocol_val.as_dictionary().unwrap().get("urls").unwrap().as_dictionary().unwrap();

        let start_provisioning_url = urls.get("midStartProvisioning").unwrap().as_string().unwrap();
        let end_provisioning_url = urls.get("midFinishProvisioning").unwrap().as_string().unwrap();
        debug!("Got provisioning urls: {} and {}", start_provisioning_url, end_provisioning_url);

        let provision_ws_url = format!("{}/v3/provisioning_session", self.url).replace("https://", "wss://");
        let (mut connection, _) = connect_async(&provision_ws_url).await?;


        #[derive(Deserialize)]
        #[serde(tag = "result")]
        enum ProvisionInput {
            GiveIdentifier,
            GiveStartProvisioningData,
            GiveEndProvisioningData {
                #[allow(dead_code)] // it's not even dead, rust just has problems
                cpim: String
            },
            ProvisioningSuccess {
                #[allow(dead_code)] // it's not even dead, rust just has problems
                adi_pb: String
            }
        }

        loop {
            // A socket dropped without a Close frame yields one error, then `None`
            // forever: `continue` on those spun here, never yielding, holding the lock.
            let data = match connection.next().await {
                Some(Ok(data)) => data,
                Some(Err(e)) => return Err(e.into()),
                None => return Err(tokio_tungstenite::tungstenite::Error::ConnectionClosed.into()),
            };
            if data.is_text() {
                let txt = data.to_text().unwrap();
                let msg: ProvisionInput = serde_json::from_str(txt)?;
                match msg {
                    ProvisionInput::GiveIdentifier => {
                        #[derive(Serialize)]
                        struct Identifier {
                            identifier: String // base64
                        }
                        let identifier = Identifier { identifier: base64_encode(&state.keychain_identifier) };
                        connection.send(Message::Text(serde_json::to_string(&identifier)?)).await?;
                    },
                    ProvisionInput::GiveStartProvisioningData => {
                        let http_client = make_reqwest()?;
                        let body_data = ProvisionBodyData { header: Dictionary::new(), request: Dictionary::new() };
                        let resp = self.build_apple_request(state, http_client.post(start_provisioning_url))
                            .body(plist_to_string(&body_data)?)
                            .send().await?;
                        let text = resp.text().await?;

                        let protocol_val = plist::Value::from_reader(Cursor::new(text.as_str()))?;
                        let spim = protocol_val.as_dictionary().unwrap().get("Response").unwrap().as_dictionary().unwrap()
                            .get("spim").unwrap().as_string().unwrap();

                        debug!("GiveStartProvisioningData");
                        #[derive(Serialize)]
                        struct Spim {
                            spim: String // base64
                        }
                        let spim = Spim { spim: spim.to_string() };
                        connection.send(Message::Text(serde_json::to_string(&spim)?)).await?;
                    },
                    ProvisionInput::GiveEndProvisioningData { cpim } => {
                        let http_client = make_reqwest()?;
                        let body_data = ProvisionBodyData { header: Dictionary::new(), request: Dictionary::from_iter([("cpim", cpim)].into_iter()) };
                        let resp = self.build_apple_request(state, http_client.post(end_provisioning_url))
                            .body(plist_to_string(&body_data)?)
                            .send().await?;
                        let text = resp.text().await?;

                        let protocol_val = plist::Value::from_reader(Cursor::new(text.as_str()))?;
                        let response = protocol_val.as_dictionary().unwrap().get("Response").unwrap().as_dictionary().unwrap();

                        debug!("GiveEndProvisioningData");

                        #[derive(Serialize)]
                        struct EndProvisioning<'t> {
                            ptm: &'t str,
                            tk: &'t str,
                        }
                        let end_provisioning = EndProvisioning {
                            ptm: response.get("ptm").unwrap().as_string().unwrap(),
                            tk: response.get("tk").unwrap().as_string().unwrap(),
                        };
                        connection.send(Message::Text(serde_json::to_string(&end_provisioning)?)).await?;
                    },
                    ProvisionInput::ProvisioningSuccess { adi_pb } => {
                        debug!("ProvisioningSuccess");
                        // The server's bytes: a malformed adi_pb is its error, not our panic.
                        let adi_pb = general_purpose::STANDARD.decode(adi_pb.trim()).map_err(|e| {
                            AnisetteError::ServerError(format!("provisioning sent an adi_pb that is not base64: {e}"))
                        })?;
                        state.adi_pb = Some(adi_pb);
                        connection.close(None).await?;
                        break;
                    }
                }
            } else if data.is_close() {
                break;
            }
        }

        Ok(())
    }
}


pub struct RemoteAnisetteProviderV3 {
    client_url: String,
    client: Option<AnisetteClient>,
    pub state: Option<AnisetteState>,
    configuration_path: PathBuf,
    info: LoginClientInfo
}

impl RemoteAnisetteProviderV3 {
    pub fn new(url: String, info: LoginClientInfo, configuration_path: PathBuf) -> RemoteAnisetteProviderV3 {
        RemoteAnisetteProviderV3 {
            client_url: url,
            client: None,
            state: None,
            configuration_path,
            info
        }
    }
}

impl AnisetteProvider for RemoteAnisetteProviderV3 {
    async fn get_anisette_headers(&mut self) -> Result<HashMap<String, String>, AnisetteError> {
        if self.client.is_none() {
            self.client = Some(AnisetteClient::new(self.client_url.clone(), self.info.clone()).await?);
        }
        let client = self.client.as_ref().unwrap();

        fs::create_dir_all(&self.configuration_path)?;

        let config_path = self.configuration_path.join("state.plist");
        if self.state.is_none() {
            self.state = Some(if let Ok(text) = plist::from_file(&config_path) {
                text
            } else {
                AnisetteState::new()
            });
        }

        let state = self.state.as_mut().unwrap();
        if !state.is_provisioned() {
            client.provision(state).await?;
            plist::to_file_xml(&config_path, state)?;
        }
        let data = match client.get_headers(&state).await {
            Ok(data) => data,
            Err(AnisetteError::AnisetteNotProvisioned) => {
                state.adi_pb = None;
                client.provision(state).await?;
                plist::to_file_xml(config_path, state)?;
                client.get_headers(&state).await?
            },
            Err(err) => return Err(err),
        };
        Ok(data.get_headers())
    }
}




#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Serves one HTTP response with `body`, then closes.
    async fn one_shot_server(body: &'static str) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 8192];
            let _ = socket.read(&mut request).await;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(), body,
            );
            socket.write_all(response.as_bytes()).await.unwrap();
        });
        url
    }

    fn provisioned_state() -> AnisetteState {
        AnisetteState { adi_pb: Some(vec![1, 2, 3]), ..AnisetteState::default() }
    }

    // A panic here takes down the caller's whole task, and the server's message
    // dies with it: the only thing left to report is "failed unexpectedly".
    #[tokio::test]
    async fn unknown_server_error_is_returned_with_its_message() {
        let url = one_shot_server(r#"{"result":"GetHeadersError","message":"-45054 something new"}"#).await;
        let client = AnisetteClient::new(url, LoginClientInfo::default()).await.unwrap();

        let err = client.get_headers(&provisioned_state()).await.err().expect("must be an error");

        assert!(matches!(err, AnisetteError::ServerError(ref m) if m.contains("-45054")), "{err:?}");
    }

    // The provider re-provisions on -45061 and used to panic on anything else,
    // so a flaky anisette host (an HTML error page, a dropped connection) killed
    // the login instead of failing it. The error must carry the page's text too,
    // or the cause is lost all the same.
    #[tokio::test]
    async fn provider_returns_a_broken_server_response_as_an_error() {
        let url = one_shot_server("<html>502 Bad Gateway</html>").await;
        let dir = std::env::temp_dir().join(format!("omnisette-test-{}", std::process::id()));
        let mut provider = RemoteAnisetteProviderV3::new(url, LoginClientInfo::default(), dir.clone());
        provider.state = Some(provisioned_state());

        let result = provider.get_anisette_headers().await;
        let _ = fs::remove_dir_all(&dir);

        assert!(matches!(result, Err(AnisetteError::ServerError(ref m)) if m.contains("502 Bad Gateway")), "{result:?}");
    }

    // -45061 is the one message the provider recovers from by re-provisioning.
    #[tokio::test]
    async fn not_provisioned_is_still_recognised() {
        let url = one_shot_server(r#"{"result":"GetHeadersError","message":"-45061"}"#).await;
        let client = AnisetteClient::new(url, LoginClientInfo::default()).await.unwrap();

        let err = client.get_headers(&provisioned_state()).await.err().expect("must be an error");

        assert!(matches!(err, AnisetteError::AnisetteNotProvisioned), "{err:?}");
    }
}
