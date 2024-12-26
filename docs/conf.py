# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

import os

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information
import sys
from pathlib import Path

import django

import simple_openid_connect

# configure python so that the source code is importable
BASE_PATH = Path(__file__).parent.parent
sys.path.append(str(BASE_PATH / "src"))

# configure the development django project so that sphinx can import the django integrations code
os.environ.setdefault(
    "DJANGO_SETTINGS_MODULE", "simple_openid_connect.integrations.django.settings"
)
django.setup()


project = "simple_openid_connect"
copyright = "2024, Fachschaft Informatik der Universität Hamburg"
author = "Fachschaft Informatik der Universität Hamburg"
release = "v" + simple_openid_connect.__version__

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = [
    "sphinx.ext.duration",
    "sphinx.ext.doctest",
    "sphinx.ext.autodoc",
    "sphinx.ext.autosummary",
    "sphinx.ext.intersphinx",
    "sphinx.ext.viewcode",
]

intersphinx_mapping = {
    "python": ("https://docs.python.org/3/", None),
    "sphinx": ("https://www.sphinx-doc.org/en/master/", None),
    "django": (
        "https://docs.djangoproject.com/en/stable/",
        "https://docs.djangoproject.com/en/stable/_objects/",
    ),
    "drf-spectacular": ("https://drf-spectacular.readthedocs.io/en/latest/", None),
}
intersphinx_disabled_domains = ["std"]

autodoc_default_options = {
    "members": True,
    "special-members": "__init__",
}

templates_path = ["_templates"]
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]


# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = "furo"
html_static_path = ["_static"]
