import setuptools


setuptools.setup(
    name="TIPCommon",
    version="1.0.12",
    author="Itai Chaimsky",
    author_email="Support@siemplify.co",
    description="A TIP in-house replacment for siemplify built in SiemplifyUtils.py part of the SDK. Uncoupled to platform version",
    url="https://github.com/Siemplify/SiemplifyMarketPlace",
    packages=setuptools.find_packages(),
    install_requires=[
        'requests', 'chardet'
    ],
    classifiers=[
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Operating System :: OS Independent",
    ],
)
