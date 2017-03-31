from setuptools import setup, find_packages

setup(
    name="storageclient",
    version="0.1.0",
    description="Python client to interact with ceph/cleversafe backend",
    license="Apache",
    packages=find_packages(),
    install_requires=[
        'boto==2.40.0',
    ],
)
