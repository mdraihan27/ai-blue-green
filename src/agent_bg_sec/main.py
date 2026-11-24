"""Main CLI entrypoint for `agent-sec`."""

import utils.transport
import utils.session
import sys

from agent_bg_sec.cli.app import AgentSecCLI


def main() -> int:
    cli = AgentSecCLI()
    return cli.run()


if __name__ == "__main__":
    sys.exit(main())

