import os
import zipfile
from typing import Union

import consts


def validate_tmp_dir():
    if not os.path.exists("tmp"):
        os.mkdir("tmp")


def zip_folder(path: str, logger) -> str:
    """
    :param logger: logger
    :param path: path of the file to zip
    :return: path of the zipped file
    """
    validate_tmp_dir()

    zip_name = f"{os.path.join('tmp', os.path.basename(path))}.zip"
    with zipfile.ZipFile(zip_name, "w") as outzip:
        for subdir, dirs, files in os.walk(path):
            for file in files:
                if any([file.endswith(ext) for ext in consts.INVALID_EXTENSIONS]):
                    logger.info(f"Found non dev file: {file}, Skipping...")
                    continue
                # Read file
                srcpath = os.path.join(subdir, file)
                dstpath_in_zip = os.path.relpath(srcpath, start=path)
                with open(srcpath, 'rb') as infile:
                    # Write to zip
                    outzip.writestr(dstpath_in_zip, infile.read())
                logger.info(f"Added {dstpath_in_zip} to {zip_name} archive")
    return zip_name


def read_file(path: str, mode: str = 'rb') -> Union[str, bytes]:
    """
    :param path: file path
    :param mode: like 'mode' attribute of open(). default is 'rb'
    :return: file content
    """
    with open(path, mode) as f:
        content = f.read()
    return content


def write_zip(path: str, name: str, file_binary: bytes) -> str:
    full_path = f"{os.path.join(path, name)}.zip"
    with open(full_path, "wb") as f:
        f.write(file_binary)
    return full_path


def get_integration_path(integration_name: str) -> str:
    return os.path.join(
        consts.INTEGRATIONS_FILE,
        get_valid_integration_identifier(integration_name)
    )


def get_valid_integration_identifier(integration_name: str) -> str:
    try:
        all_integration = os.listdir(consts.INTEGRATIONS_FILE)
        return list(filter(
            lambda i: integration_name.strip().lower() == i.strip().lower(),
            all_integration
        ))[0]
    except Exception:
        raise FileNotFoundError(f"couldn't find integration {integration_name} "
                                f"in {consts.INTEGRATIONS_FILE}")
