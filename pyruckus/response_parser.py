"""Utility methods to parse a formatted Ruckus response into a dict."""
from collections import OrderedDict

from slugify import slugify

from pyruckus.const import SERIAL_NUMBER


def format_ruckus_value(value, force_str=False):
    """Format a string value into None, int, or bool if possible."""
    value = value.strip()

    if not value:
        return None

    if not force_str:
        if value.isnumeric():
            return int(value)

        if value in ["true", "Enabled", "Yes"]:
            return True
        if value in ["false", "Disabled", "No"]:
            return False

    return value


def parse_ruckus_key_value(response) -> dict:
    """Parse Ruckus nested key-value output into a dict."""
    root = {}
    indent = 0

    node = root
    breadcrumbs = OrderedDict({-1: root})
    is_header = None
    for line in response.splitlines():
        # Skip empty lines
        if not line.strip():
            continue

        # Line is a "header" instead of a key-value pair
        prev_is_header = is_header
        is_header = line.rstrip().endswith(":") and "= " not in line

        prev_indent = indent
        indent = len(line) - len(line.lstrip())

        # If the indent has decreased, remove nodes from the breadcrumbs
        i = None
        if indent < prev_indent or (
            is_header and prev_is_header and indent == prev_indent
        ):
            while i != indent and len(breadcrumbs) > 1:
                i, node = breadcrumbs.popitem()

        if is_header:
            # Remove colon, then strip whitespace
            key = slugify(line.rstrip(":"), separator="_")

            # Get last entry of breadcrumbs
            parent_node = next(reversed(breadcrumbs.values()))
            node = {}

            # If current header already exists, convert to list
            if key in parent_node:
                if isinstance(parent_node[key], list):
                    parent_node[key].append(node)
                else:
                    prev_node = parent_node[key]
                    parent_node[key] = [prev_node, node]
            else:
                parent_node[key] = node

            breadcrumbs[indent] = node
        else:
            key, _, value = line.partition("=")
            key = slugify(key, separator="_")
            value = format_ruckus_value(value, force_str=key == SERIAL_NUMBER)
            if key:
                node[key] = value

    return root
