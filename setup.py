from setuptools import setup, find_packages

setup(
    name="storageclient",
    version="0.1.0",
    description="Python client to interact with ceph/cleversafe/google/aws backend",
    license="Apache",
    packages=find_packages(),
    install_requires=[
        "boto>=2.36.0",
        "botocore>=1.7",
        "urllib3>=1.26.5",  # as required by botocore-1.12.253
        "six>=1.13.0",  # as required by google-api-core
        "protobuf<3.18.0,>=3.12.0",  # as required by google-api-core
        "requests>=2.5.2",
        "s3transfer",
        "jmespath==0.9.2",
        "pbr==2.0.0",
        "cdislogging>=1.0.0",
        "gen3cirrus>=1.0.0",
    ],
)
