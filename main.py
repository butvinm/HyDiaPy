import argparse
import inspect
import sys
from enum import Enum
from pathlib import Path
from time import time

from client import Client
from enroller import Enroller
from server import Server

st = time()
lb = None


def tik(label: str | None = None) -> None:
    global st, lb
    st = time()
    lb = label


def tok() -> None:
    d = time() - st
    current_frame = inspect.currentframe()
    if current_frame is None or current_frame.f_back is None:
        print("Where is your stack?")
        return

    frame = current_frame.f_back
    filename = frame.f_code.co_filename
    lineno = frame.f_lineno
    if lb is not None:
        print(f"{filename}:{lineno} {d:.3f}s ({lb})")
    else:
        print(f"{filename}:{lineno} {d:.3f}s")


class Scenario(Enum):
    membership = "membership"
    identities = "identities"


def main(
    query_image: Path,
    database_dir: Path,
    scenario: Scenario,
) -> None:
    tik("client init")
    client = Client()
    tok()

    tik("enroller init")
    enroller = Enroller(database_dir)
    tok()

    tik("server init")
    server = Server()
    tok()

    # 1. Setup
    tik("setup")
    params = client.setup()
    tok()
    # 2. Enroll
    tik("enroll")
    database = enroller.enroll(params)
    tok()
    # 3. Query
    tik("query")
    query = client.query(query_image)
    tok()

    if scenario == Scenario.identities:
        # 4. Compute
        tik("compute")
        thresholds = server.compute_identities(params, database, query)
        tok()
        # 5. Extract
        tik("extract")
        identities = client.extract_identities(database.labels, thresholds)
        tok()

        print("Matched identities:", identities)
    else:
        # 4. Compute
        tik("compute")
        thresholds = server.compute_membership(params, database, query)
        tok()
        # 5. Extract
        tik("extract")
        membership = client.extract_membership(thresholds)
        tok()

        print("Membership status:", membership)


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

    args = parser.parse_args(sys.argv[1:])
    main(args.query_image, args.database_dir, args.scenario)
