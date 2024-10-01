use foreign_types_shared::ForeignType;
use pyo3::{pyclass, pymethods, PyErr, PyResult};
use rand::Rng;

#[pyclass(frozen)]
pub struct PrivateKey {
    sk: ed25519_dalek::hazmat::ExpandedSecretKey,
    pk: ed25519_dalek::VerifyingKey,
}

#[pymethods]
impl PrivateKey {
    #[new]
    fn new(priv_key: &[u8]) -> PyResult<Self> {
        let sk = ed25519_dalek::hazmat::ExpandedSecretKey::from_slice(priv_key)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
        let pk = ed25519_dalek::VerifyingKey::from(&sk);

        Ok(Self {
            sk,
            pk,
        })
    }

    fn sign(&self, msg: &[u8]) -> PyResult<std::borrow::Cow<[u8]>> {
        let signature = ed25519_dalek::hazmat::raw_sign::<sha2::Sha512>(&self.sk, msg, &self.pk).to_bytes();
        Ok(std::borrow::Cow::Owned(signature.to_vec()))
    }

    fn make_csr(&self, ca_nonce: &[u8]) -> PyResult<std::borrow::Cow<[u8]>> {
        let mut rng = rand::thread_rng();
        let mut applicant_nonce = [0u8; 10];
        rng.fill(&mut applicant_nonce);
        drop(rng);

        let openssl_pk = openssl::pkey::PKey::public_key_from_raw_bytes(
            self.pk.as_bytes(), openssl::pkey::Id::ED25519
        ).unwrap();

        let mut builder = openssl::x509::X509ReqBuilder::new().unwrap();
        builder.set_version(0).unwrap();
        builder.set_pubkey(&openssl_pk).unwrap();
        let req = builder.build();

        unsafe {
            cvt(X509_REQ_add1_attr_by_txt(
                req.as_ptr(), b"2.23.140.41\0" as *const u8,
                openssl_sys::V_ASN1_OCTET_STRING,
                ca_nonce.as_ptr(), ca_nonce.len() as i32
            )).unwrap();
            cvt(X509_REQ_add1_attr_by_txt(
                req.as_ptr(), b"2.23.140.42\0" as *const u8,
                openssl_sys::V_ASN1_OCTET_STRING,
                applicant_nonce.as_ptr(), applicant_nonce.len() as i32
            )).unwrap();
        }

        let tbs_req = unsafe {
            let len = cvt(i2d_re_X509_REQ_tbs(req.as_ptr(), std::ptr::null_mut())).unwrap();
            let mut buf = vec![0u8; len as usize];
            cvt(i2d_re_X509_REQ_tbs(req.as_ptr(), &mut buf.as_mut_ptr())).unwrap();
            buf
        };

        let signature = ed25519_dalek::hazmat::raw_sign::<sha2::Sha512>(&self.sk, &tbs_req, &self.pk).to_bytes();

        let tbs_req: asn1::Sequence = asn1::parse_single(&tbs_req).unwrap();
        let req = asn1::write(|w| {
            w.write_element(&asn1::SequenceWriter::new(&|w| {
                w.write_element(&tbs_req)?;
                w.write_element(&asn1::SequenceWriter::new(&|w| {
                    w.write_element(&asn1::ObjectIdentifier::from_string("1.3.101.112").unwrap())
                }))?;
                w.write_element(&asn1::BitString::new(&signature, 0))?;
                Ok(())
            }))
        }).unwrap();

        Ok(std::borrow::Cow::Owned(req))
    }
}

extern "C" {
    fn i2d_re_X509_REQ_tbs(req: *const openssl_sys::X509_REQ, buf: *mut *mut u8) -> libc::c_int;
    fn X509_REQ_add1_attr_by_txt(
        req: *const openssl_sys::X509_REQ, attr_name: *const u8, attr_type: libc::c_int,
        bytes: *const u8, len: libc::c_int
    ) -> libc::c_int;
}

fn cvt(r: libc::c_int) -> Result<libc::c_int, openssl::error::ErrorStack> {
    if r <= 0 {
        Err(openssl::error::ErrorStack::get())
    } else {
        Ok(r)
    }
}