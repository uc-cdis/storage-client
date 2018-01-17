from setuptools import setup, find_packages

setup(
    name="storageclient",
    version="0.1.0",
    description="Python client to interact with ceph/cleversafe backend",
    license="Apache",
    packages=find_packages(),
    install_requires=[
        'boto>=2.36.0',
        'botocore>=1.5.35',
        'requests>=2.5.2,<3.0.0',
        's3transfer==0.1.10',
        'jmespath==0.9.2',
        'pbr==2.0.0',
        'cdispyutils'
    ],
    dependency_links=[
        "git+https://github.com/uc-cdis/cdis-python-utils.git@0.2.2#egg=cdispyutils"
    ],
)
