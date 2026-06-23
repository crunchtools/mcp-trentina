import warnings

warnings.warn(
    "mcp-airlock-crunchtools has been renamed to mcp-trentina-crunchtools. "
    "Install the new package: pip install mcp-trentina-crunchtools",
    DeprecationWarning,
    stacklevel=2,
)

from mcp_trentina_crunchtools import main

main()
