from setuptools import setup, find_packages

setup(
    name="storageclient",
    version="0.1.0",
    description="Python client to interact with ceph/cleversafe backend",
    license="Apache",
    packages=find_packages(),
    install_requires=[
        "boto>=2.36.0,<3.0.0",
        "botocore>=1.7,<1.13.0",
        "urllib3>=1.20,<1.26",  # as required by botocore-1.12.253
        "six>=1.13.0",  # as required by google-api-core
        "requests>=2.5.2,<3.0.0",
        "s3transfer<0.3.0,>=0.2.0",
        "jmespath==0.9.2",
        "pbr==2.0.0",
        "cdislogging>=1.0.0,<2.0.0",
        "gen3cirrus>=1.0.0,<3.0.0",
    ],
)
