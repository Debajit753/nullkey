"""
Build the C++ core as a Python extension (Phase 3).

    python setup.py build_ext --inplace     # produces nullkey_core*.so here
    # or:  pip install -e .

Needs libsodium (brew install libsodium / apt install libsodium-dev) and pybind11.
"""
import os
import subprocess

from pybind11.setup_helpers import Pybind11Extension, build_ext
from setuptools import setup


def sodium_prefix():
    for guess in ("/opt/homebrew/opt/libsodium", "/usr/local/opt/libsodium", "/usr"):
        if os.path.exists(os.path.join(guess, "include", "sodium.h")):
            return guess
    try:
        p = subprocess.check_output(["brew", "--prefix", "libsodium"]).decode().strip()
        if os.path.exists(os.path.join(p, "include", "sodium.h")):
            return p
    except Exception:
        pass
    return "/usr"  # last resort; assumes libsodium on the default include path


SODIUM = sodium_prefix()

ext = Pybind11Extension(
    "nullkey_core",
    ["cpp/core.cpp", "cpp/bindings.cpp"],
    include_dirs=[os.path.join(SODIUM, "include"), "cpp"],
    library_dirs=[os.path.join(SODIUM, "lib")],
    libraries=["sodium"],
    cxx_std=17,
)

setup(
    name="nullkey_core",
    version="0.1.0",
    description="Nullkey C++ crypto core (libsodium) via pybind11",
    ext_modules=[ext],
    cmdclass={"build_ext": build_ext},
)
