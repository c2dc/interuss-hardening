import os
import sys

from monitoring.mock_uss.app import webapp


def main(argv):
    del argv
    # Must match the default in start.sh and health_check.sh (5000). This was
    # 8071, which is another container's *host* port — a mock started without an
    # explicit MOCK_USS_PORT disagreed with its own healthcheck.
    port = int(os.environ.get("MOCK_USS_PORT", "5000"))
    webapp.setup()
    webapp.start_periodic_tasks_daemon()
    webapp.run(host="localhost", port=port)


if __name__ == "__main__":
    main(sys.argv)
