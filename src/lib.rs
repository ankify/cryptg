use pyo3::{prelude::*, types::PyBytes, wrap_pyfunction};
use std::convert::TryInto;

/// Encrypts the input plain text with the 32-byte key and IV.
#[pyfunction]
#[pyo3(text_signature = "(plain, key, iv)")]
fn encrypt_ige(plain: &[u8], key: &[u8], iv: &[u8]) -> PyResult<Py<PyBytes>> {
    let key_array: [u8; 32] = key.try_into().map_err(|_| {
        pyo3::exceptions::PyValueError::new_err(format!(
            "Invalid key length: expected 32, got {}",
            key.len()
        ))
    })?;

    let iv_array: [u8; 32] = iv.try_into().map_err(|_| {
        pyo3::exceptions::PyValueError::new_err(format!(
            "Invalid IV length: expected 32, got {}",
            iv.len()
        ))
    })?;

    let cipher = grammers_crypto::encrypt_ige(plain, &key_array, &iv_array);
    Python::with_gil(|py| Ok(PyBytes::new(py, &cipher).into()))
}

/// Decrypts the input cipher text with the 32-byte key and IV.
#[pyfunction]
#[pyo3(text_signature = "(cipher, key, iv)")]
fn decrypt_ige(cipher: &[u8], key: &[u8], iv: &[u8]) -> PyResult<Py<PyBytes>> {
    let key_array: [u8; 32] = key.try_into().map_err(|_| {
        pyo3::exceptions::PyValueError::new_err(format!(
            "Invalid key length: expected 32, got {}",
            key.len()
        ))
    })?;

    let iv_array: [u8; 32] = iv.try_into().map_err(|_| {
        pyo3::exceptions::PyValueError::new_err(format!(
            "Invalid IV length: expected 32, got {}",
            iv.len()
        ))
    })?;

    let plain = grammers_crypto::decrypt_ige(cipher, &key_array, &iv_array);
    Python::with_gil(|py| Ok(PyBytes::new(py, &plain).into()))
}

/// Factorizes the pair of primes ``pq`` into ``(p, q)``.
#[pyfunction]
#[pyo3(text_signature = "(pq)")]
fn factorize_pq_pair(pq: u64) -> (u64, u64) {
    grammers_crypto::factorize::factorize(pq)
}

#[pymodule]
fn cryptg(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(encrypt_ige, m)?)?;
    m.add_function(wrap_pyfunction!(decrypt_ige, m)?)?;
    m.add_function(wrap_pyfunction!(factorize_pq_pair, m)?)?;
    Ok(())
}
