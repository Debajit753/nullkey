// bindings.cpp — expose the C++ core to Python as `import nullkey_core`.
#include <pybind11/pybind11.h>
#include "core.hpp"

namespace py = pybind11;

PYBIND11_MODULE(nullkey_core, m) {
    m.doc() = "Nullkey C++ crypto core (libsodium) — Phase 3";

    m.def("safety_number", [](py::bytes a, py::bytes b) {
        return nk::safety_number(std::string(a), std::string(b));
    });
    m.def("hkdf", [](py::bytes salt, py::bytes ikm, py::bytes info, size_t length) {
        return py::bytes(nk::hkdf(std::string(salt), std::string(ikm), std::string(info), length));
    });
    m.def("kdf_ck", [](py::bytes ck) {
        auto p = nk::kdf_ck(std::string(ck));
        return py::make_tuple(py::bytes(p.first), py::bytes(p.second));
    });
    m.def("msg_keys", [](py::bytes mk) {
        auto p = nk::msg_keys(std::string(mk));
        return py::make_tuple(py::bytes(p.first), py::bytes(p.second));
    });
    m.def("parse_header", [](py::bytes data) {
        auto h = nk::parse_header(std::string(data));
        return py::make_tuple(py::bytes(h.dh_pub), h.pn, h.n);
    });
    m.def("aead_encrypt", [](py::bytes key, py::bytes nonce, py::bytes pt, py::bytes ad) {
        return py::bytes(nk::aead_encrypt(std::string(key), std::string(nonce),
                                          std::string(pt), std::string(ad)));
    });
    m.def("aead_decrypt", [](py::bytes key, py::bytes nonce, py::bytes ct, py::bytes ad) {
        return py::bytes(nk::aead_decrypt(std::string(key), std::string(nonce),
                                          std::string(ct), std::string(ad)));
    });
}
