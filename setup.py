from setuptools import setup, find_packages

setup(
    name="storageclient",
    version="0.1.0",
    description="Python client to interact with ceph/cleversafe backend",
    license="Apache",
    packages=find_packages(),
    install_requires=[
        'boto==2.46.1',
        'botocore==1.5.35',
        'pyasn1==0.2.3',
        'requests==2.13.0',
        's3transfer==0.1.10',
        'jmespath==0.9.2',
        'pbr==2.0.0',
        'cdispyutils'
    ],
    dependency_links=[
        "git+ssh://git@github.com/uc-cdis/cdis-python-utils.git#egg=cdispyutils"
     ],
)
