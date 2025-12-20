import warnings

warnings.filterwarnings("ignore", message="pkg_resources is deprecated")

import argparse
import inspect
import sys
from enum import Enum
from pathlib import Path
from time import time

from client import Client
from enroller import Enroller
from server import Server


class Timer:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled
        self.labels: list[str | None] = []
        self.tiks: list[float] = []

    def tik(self, label: str | None = None) -> None:
        self.tiks.append(time())
        self.labels.append(label)

    def tok(self) -> None:
        if not self.enabled:
            return

        st = self.tiks.pop()
        label = self.labels.pop()

        d = time() - st
        current_frame = inspect.currentframe()
        if current_frame is None or current_frame.f_back is None:
            print("Where is your stack?")
            return

        frame = current_frame.f_back
        filename = frame.f_code.co_filename
        lineno = frame.f_lineno
        if label is not None:
            print(f"{filename}:{lineno} {d:.3f}s ({label})")
        else:
            print(f"{filename}:{lineno} {d:.3f}s")


class Scenario(Enum):
    membership = "membership"
    identities = "identities"


def main(
    query_image: Path,
    database_dir: Path,
    scenario: Scenario,
    show_time: bool,
) -> None:
    t = Timer(enabled=show_time)

    t.tik("total")

    t.tik("client init")
    client = Client()
    t.tok()

    t.tik("enroller init")
    enroller = Enroller(database_dir)
    t.tok()

    t.tik("server init")
    server = Server()
    t.tok()

    # 1. Setup
    t.tik("setup")
    params = client.setup()
    t.tok()
    # 2. Enroll
    t.tik("enroll")
    database = enroller.enroll(params)
    t.tok()
    # 3. Query
    t.tik("query")
    query = client.query(query_image)
    t.tok()

    if scenario == Scenario.identities:
        # 4. Compute
        t.tik("compute")
        thresholds = server.compute_identities(params, database, query)
        t.tok()
        # 5. Extract
        t.tik("extract")
        identities = client.extract_identities(database.labels, thresholds)
        t.tok()

        print("Matched identities:", identities)
    else:
        # 4. Compute
        t.tik("compute")
        thresholds = server.compute_membership(params, database, query)
        t.tok()
        # 5. Extract
        t.tik("extract")
        membership = client.extract_membership(thresholds)
        t.tok()

        print("Membership status:", membership)

    t.tok()


if __name__ == "__main__":
    parser = argparse.ArgumentParser("HyDiaPy")
    parser.add_argument(
        "--query-image",
        help="Image with target face for the Client query",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--database-dir",
        help="Directory containing images of faces for the Enroller database",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--scenario",
        help="Protocol scenario: find all matched identities or just check membership",
        type=Scenario,
        default=Scenario.identities,
    )
    parser.add_argument(
        "--show-time",
        help="Measure execution time",
        action="store_true",
        default=False,
    )

    args = parser.parse_args(sys.argv[1:])
    main(args.query_image, args.database_dir, args.scenario, args.show_time)
