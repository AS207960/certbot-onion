use std::sync::Arc;
use pyo3::{pyclass, pymethods, PyErr, PyResult};
use base64ct::Encoding;

#[pyclass(frozen)]
pub struct ArtiClient {
    client: Arc<arti_rpc_client_core::RpcConn>,
}

#[pyclass(frozen)]
pub struct ArtiOnionService {
    client: Arc<arti_rpc_client_core::RpcConn>,
    object_id: arti_rpc_client_core::ObjectId
}

#[pyclass(frozen)]
pub struct OnionCAA {
    #[pyo3(get)]
    caa: String,
    #[pyo3(get)]
    expiry: u64,
    #[pyo3(get)]
    signature: std::borrow::Cow<'static, [u8]>
}

#[pymethods]
impl ArtiClient {
    #[new]
    fn new(connection_string: Option<&str>) -> PyResult<Self> {
        let connection_string = if let Some(s) = connection_string {
            s.to_string()
        } else {
            if cfg!(target_os = "windows") {
                r"unix:\\.\pipe\arti\SOCKET".to_string()
            } else {
                let home = std::env::var("HOME").unwrap_or_default();
                format!("unix:{}/.local/run/arti/SOCKET", home)
            }
        };

        let builder = arti_rpc_client_core::RpcConnBuilder::from_connect_string(&connection_string)
            .map_err(|e| match e {
                arti_rpc_client_core::BuilderError::InvalidConnectString => PyErr::new::<pyo3::exceptions::PyValueError, _>("invalid connection string"),
                e => PyErr::new::<pyo3::exceptions::PyException, _>(e.to_string()),
            })?;
        let conn = builder.connect()
            .map_err(|e| match e {
                arti_rpc_client_core::ConnectError::SchemeNotSupported => PyErr::new::<pyo3::exceptions::PyValueError, _>("unsupported connection scheme"),
                arti_rpc_client_core::ConnectError::CannotConnect(e) => PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("cannot connect: {}", e)),
                arti_rpc_client_core::ConnectError::ProtoError(e) => PyErr::new::<pyo3::exceptions::PyConnectionError, _>(format!("protocol error: {}", e)),
                arti_rpc_client_core::ConnectError::BadMessage(e) => PyErr::new::<pyo3::exceptions::PyConnectionError, _>(format!("bad message: {}", e)),
                arti_rpc_client_core::ConnectError::AuthenticationRejected(e) => PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("authentication rejected: {}", e)),
                e => PyErr::new::<pyo3::exceptions::PyException, _>(e.to_string()),
            })?;

        Ok(Self {
            client: Arc::new(conn)
        })
    }

    fn session_id(&self) -> Option<&str> {
        self.client.session().map(|s| s.as_ref())
    }

    fn get_onion_service(&self, domain: &str) -> PyResult<ArtiOnionService> {
        let resp = self.client.execute(&ArtiRequest::new(self.client.session().unwrap(), "arti:x_acme_get_onion_service", ArtiOnionServiceRequest {
            domain
        }).encode())
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyConnectionError, _>(format!("protocol error: {}", e)))?
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("unable to find onion service: {}", e)))?;

        let resp = ArtiResponse::<ObjectIdResponse>::parse(&resp)?;

        Ok(ArtiOnionService {
            client: self.client.clone(),
            object_id: resp.result.id
        })
    }
}

#[pymethods]
impl ArtiOnionService {
    fn onion_name(&self) -> PyResult<String> {
        let resp = self.client.execute(&ArtiRequest::new(&self.object_id, "arti:x_acme_get_onion_service_name", ArtiOnionServiceNameRequest {}).encode())
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyConnectionError, _>(format!("protocol error: {}", e)))?
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("unable to get onion service name: {}", e)))?;

        let resp = ArtiResponse::<ArtiOnionServiceNameResponse>::parse(&resp)?;
        Ok(resp.result.domain)
    }

    fn make_csr(&self, ca_nonce: &[u8]) -> PyResult<std::borrow::Cow<[u8]>> {
        let resp = self.client.execute(&ArtiRequest::new(&self.object_id, "arti:x_acme_generate_onion_service_csr", ArtiCsrRequest {
            ca_nonce: base64ct::Base64::encode_string(ca_nonce)
        }).encode())
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyConnectionError, _>(format!("protocol error: {}", e)))?
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("unable to generate CSR: {}", e)))?;

        let resp = ArtiResponse::<ArtiCsrResponse>::parse(&resp)?;
        let csr = base64ct::Base64::decode_vec(&resp.result.csr)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyException, _>(format!("unable to decode CSR Base64: {}", e)))?;

        Ok(std::borrow::Cow::Owned(csr))
    }

    fn sign_caa(&self, expiry: u32) -> PyResult<OnionCAA> {
        let resp = self.client.execute(&ArtiRequest::new(&self.object_id, "arti:x_acme_get_onion_service_caa", ArtiCaaRequest {
            expiry,
        }).encode())
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyConnectionError, _>(format!("protocol error: {}", e)))?
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("unable to generate CAA: {}", e)))?;

        let resp = ArtiResponse::<ArtiCaaResponse>::parse(&resp)?;
        let signature = base64ct::Base64::decode_vec(&resp.result.signature)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyException, _>(format!("unable to decode CAA Base64: {}", e)))?;

        Ok(OnionCAA {
            caa: resp.result.caa,
            expiry: resp.result.expiry,
            signature: std::borrow::Cow::Owned(signature),
        })
    }
}

#[derive(serde::Serialize, Debug)]
struct ArtiRequest<'a, T> {
    obj: &'a arti_rpc_client_core::ObjectId,
    method: String,
    params: T,
}

impl<'a, T: serde::Serialize> ArtiRequest<'a, T> {
     fn new(obj: &'a arti_rpc_client_core::ObjectId, method: impl Into<String>, params: T) -> Self {
        Self {
            obj,
            method: method.into(),
            params,
        }
    }

    fn encode(&self) -> String {
        serde_json::to_string(self).unwrap()
    }
}

#[derive(serde::Deserialize, Debug)]
struct ArtiResponse<T> {
    #[allow(dead_code)]
    id: arti_rpc_client_core::ObjectId,
    result: T,
}

impl<T: serde::de::DeserializeOwned> ArtiResponse<T> {
    fn parse<S: AsRef<str>>(response: &S) -> PyResult<Self> {
        Ok(serde_json::from_str::<Self>(response.as_ref())
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyException, _>(e.to_string()))?)
    }
}

#[derive(serde::Serialize, Debug)]
struct ArtiOnionServiceRequest<'a> {
    domain: &'a str
}

#[derive(serde::Deserialize, Debug)]
struct ObjectIdResponse {
    id: arti_rpc_client_core::ObjectId,
}

#[derive(serde::Serialize, Debug)]
struct ArtiCsrRequest {
    ca_nonce: String
}

#[derive(serde::Deserialize, Debug)]
struct ArtiCsrResponse {
    csr: String
}

#[derive(serde::Serialize, Debug)]
struct ArtiCaaRequest {
    expiry: u32
}

#[derive(serde::Deserialize, Debug)]
struct ArtiCaaResponse {
    caa: String,
    expiry: u64,
    signature: String,
}

#[derive(serde::Serialize, Debug)]
struct ArtiOnionServiceNameRequest {}

#[derive(serde::Deserialize, Debug)]
struct ArtiOnionServiceNameResponse {
    domain: String
}