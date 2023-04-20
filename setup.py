from setuptools import setup
from setuptools_rust import Binding, RustExtension

setup(
    rust_extensions=[RustExtension(
        "certbot_onion._rust",
        "rust/Cargo.toml",
        py_limited_api=True,
        features=["pyo3/abi3-py37"],
        binding=Binding.PyO3
    )],
)