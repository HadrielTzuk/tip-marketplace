import argparse

EMPTY_ARGUMENT = ("", None)


def get_parsed_arguments(parser: argparse.ArgumentParser) -> argparse.Namespace:
    """
    Add arguments to the parser and return the parsed arguments
    Args:
        parser (argparse.ArgumentParser): A parser to parse the arguments

    Returns:
        The parsed arguments
    """
    parser.add_argument('-v', '--release_version', required=True, help='The version of the release notes')
    parser.add_argument('-m', '--minimum_version', required=False, help='The minimum Siemplify version for this release. The default value is 5.1')
    parser.add_argument('-d', '--release_date', required=False, help='Optional, the release date. The default value is today')

    return parser.parse_args()
