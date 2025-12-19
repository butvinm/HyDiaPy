import itertools
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from face_recognition.api import np

from client import ClientParameters
from face_match import FaceEmbedding, norm_face_embedding
from openfhe import openfhe


@dataclass
class EnrollerDatabase:
    """Enroller database shared with Server."""

    database: list[list[openfhe.Ciphertext]]
    labels: list[str]


class Enroller:
    def __init__(
        self,
        database_dir: Path,
    ) -> None:
        self.database, self.labels = self._init_database(database_dir)

    def _init_database(
        self,
        database_dir: Path,
    ) -> tuple[list[FaceEmbedding], list[str]]:
        database = []
        labels = []
        for image_path in database_dir.iterdir():
            face_embedding = norm_face_embedding(image_path)
            label = image_path.stem
            database.append(face_embedding)
            labels.append(label)

        return database, labels

    def enroll(
        self,
        params: ClientParameters,
    ) -> EnrollerDatabase:
        database = []

        database_aligned = self.database.copy()
        if len(database_aligned) % params.embedding_dim != 0:
            padding_size = params.embedding_dim - len(database_aligned) % params.embedding_dim
            database_aligned.extend(np.zeros(params.embedding_dim) for _ in range(padding_size))

        for batch in itertools.batched(database_aligned, params.batch_size):
            encoded_batch = self._encode_batch(
                params.cc,
                params.pk,
                params.embedding_dim,
                params.batch_size,
                batch,
            )
            database.append(encoded_batch)

        return EnrollerDatabase(
            database=database,
            labels=self.labels,
        )

    def _encode_batch(
        self,
        cc: openfhe.CryptoContext,
        pk: openfhe.PublicKey,
        embedding_dim: int,
        batch_size: int,
        batch: Sequence[FaceEmbedding],
    ) -> list[openfhe.Ciphertext]:
        batch_diagonalized = [[0 for _ in range(batch_size)] for _ in range(embedding_dim)]

        for n, partition in enumerate(itertools.batched(batch, embedding_dim)):
            for i in range(embedding_dim):
                for j in range(embedding_dim):
                    batch_diagonalized[i][j + n * embedding_dim] = partition[j][(i + j) % embedding_dim]

        batch_encoded = []
        for i in range(embedding_dim):
            pt_row = cc.MakeCKKSPackedPlaintext(batch_diagonalized[i])
            ct_row = cc.Encrypt(pk, pt_row)
            batch_encoded.append(ct_row)

        return batch_encoded
