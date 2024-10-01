mod c_tor;
mod arti;

use pyo3::prelude::*;

#[pymodule]
fn _rust(_py: Python<'_>, m: &PyModule) -> PyResult<()> {
    m.add_class::<c_tor::PrivateKey>()?;
    m.add_class::<arti::ArtiClient>()?;
    m.add_class::<arti::ArtiOnionService>()?;

    Ok(())
}