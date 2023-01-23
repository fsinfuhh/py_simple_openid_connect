Installation
============

You can install ``simple_openid_connect`` from `PyPi <https://pypi.org/project/simple_openid_connect/>`_::

    $ pip install simple_openid_connect

Alternatively, installing the latest development version from source can also be done::

    $ pip install git+https://github.com/fsinfuhh/py_simple_openid_connect.git


Additional features
-------------------

This library also has some extra features which can be enabled by also installing the relevant package extra.

.. note::
   Package extras can usually be installed by appending ``[$extra]`` to the package name e.g.::

   $ pip install simple_openid_connect[django]

.. list-table::
    :header-rows: 1

    * - Name
      - Package Feature
      - Integration Docs
      - Supported Versions
    * - `Django <https://www.djangoproject.com/>`_
      - ``django``
      - `Django Integration Docs <https://simple-openid-connect.readthedocs.io/en/stable/django-integration.html>`_
      - ``v3.2``, ``v4.0``, ``v4.1``
    * - `Django-Rest-Framework <https://www.django-rest-framework.org/>`_
      - ``djangorestframework``
      - `DRF Integration Docs <https://simple-openid-connect.readthedocs.io/en/stable/drf-integration.html>`_
      - ``v3.13``, ``v3.14``
