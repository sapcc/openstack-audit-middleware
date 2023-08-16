# Copyright (c) 2013 Hewlett-Packard Development Company, L.P.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import setuptools

VERSION = '1.2'
DESCRIPTION = 'OpenStack Audit Middleware'
LONG_DESCRIPTION = 'OpenStack Audit Middleware CADF audit trail from API calls'

# In python < 2.7.4, a lazy loading of package `pbr` will break
# setuptools if some other modules registered functions in `atexit`.
# solution from: http://bugs.python.org/issue15881#msg170215
try:
    import multiprocessing  # noqa
except ImportError:
    pass

setuptools.setup(
    name="openstack-audit-middleware",
    version=VERSION,
    author="notque (Nathan Oyler)",
    author_email="<nathan.oyler@sap.com>",
    description=DESCRIPTION,
    long_description_content_type="text/markdown",
    long_description=LONG_DESCRIPTION,
    keywords=['python', 'openstack', 'audit', 'cadf'],
    setup_requires=['pbr>=2.0.0'],
    pbr=True)

