from __future__ import annotations

import argparse

import script_exceptions


EMPTY_ARGUMENT = ("", None)


def get_parsed_arguments(parser: argparse.ArgumentParser) -> argparse.Namespace:
    """
    Add arguments to the parser and return the parsed arguments

    Args:
        parser: A parser to parse the arguments

    Returns:
        The parsed arguments
    """
    parser.add_argument(
        '-a', '--all',
        action='store_true',
        help=(
            'Use this flag if you want the script to go over all the '
            'integrations in the marketplace. '
            'If both --integrations and --all are used, --all will override.'
        )
    )
    parser.add_argument(
        '-i', '--integrations',
        nargs='+',
        help=(
            'One or more specific integrations in the marketplace '
            'for the script to run on.\n'
            'If both --integrations and --all are used, --all will override.\n'
            'If an integration is both in -i and in -g, -g will override.\n'
            'Multiple files can be provided as such: '
            '-i integration1 integration2'
        )
    )
    parser.add_argument(
        '-g', '--ignore-integrations',
        nargs='+',
        help=(
            'One or more specific integrations in the marketplace '
            'for the script to skip when running.\n'
            'If both --integrations and --all are used, --all will override.\n'
            'If an integration is both in -i and in -g, -g will override.\n'
            'Multiple files can be provided as such: '
            '-g integration1 integration2'
        )
    )
    parser.add_argument(
        '-p', '--prettify',
        action='store_true',
        help=(
            'If used, an HTML parser will parse the flat widget end results '
            'to "prettify" it. The current defined parser is python\'s '
            'lxml.html parser'
        )
    )

    return parser.parse_args()


def validate_args(all_files: bool, integrations: list[str]) -> None:
    """
    Check if the values of the arguments provided to the program
    are sufficient to work with

    Args:
        all_files: Whether the program should check all the files in dir_path.
        integrations: Specific integration names to select.

    Raises:
        NotEnoughArgumentsError
    """
    if not all_files and not integrations:
        raise script_exceptions.NotEnoughArgumentsError(
            'Both --all was false and --integrations was empty. '
            'Please choose at least one'
        )

# Code TODOs:
# TODO: add docstrings to all functions
# TODO: add unit tests to all functions.

# Commitment TODOs:
# TODO: try making another type of template to see that everything is scalable
