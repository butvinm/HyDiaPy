from pathlib import Path

import face_recognition as fr
from face_recognition.api import np

import openfhe

BATCH_SIZE = 0
EMBEDDING_DIM = 128
DATABASE_SIZE = 4
THRESHOLD = 0.90
MULT_DEPTH = 11

type FaceEmbedding = np.ndarray


def _generate_face_embedding(image_path: Path) -> FaceEmbedding:
    face_image = fr.load_image_file(image_path)
    face_embeddings = fr.face_encodings(face_image)
    if len(face_embeddings) != 1:
        raise Exception(f"Found {len(face_embeddings)} faces, expected 1. [{image_path}]")

    norm_face_embedding = face_embeddings[0] / np.linalg.norm(face_embeddings[0])
    return norm_face_embedding


class Client:
    def __init__(
        self,
        query_image_path: Path,
    ) -> None:
        self.query_embedding = _generate_face_embedding(query_image_path)

    def setup(self) -> tuple[openfhe.CryptoContext, openfhe.KeyPair]:
        global BATCH_SIZE
        parameters = openfhe.CCParamsCKKSRNS()
        parameters.SetSecurityLevel(openfhe.SecurityLevel.HEStd_128_classic)
        parameters.SetMultiplicativeDepth(MULT_DEPTH)
        parameters.SetScalingModSize(45)
        parameters.SetScalingTechnique(openfhe.ScalingTechnique.FIXEDMANUAL)

        cc = openfhe.GenCryptoContext(parameters)
        cc.Enable(openfhe.PKESchemeFeature.PKE)
        cc.Enable(openfhe.PKESchemeFeature.KEYSWITCH)
        cc.Enable(openfhe.PKESchemeFeature.LEVELEDSHE)
        cc.Enable(openfhe.PKESchemeFeature.ADVANCEDSHE)

        key_pair = cc.KeyGen()
        cc.EvalMultKeyGen(key_pair.secretKey)
        cc.EvalRotateKeyGen(key_pair.secretKey, range(EMBEDDING_DIM))

        BATCH_SIZE = cc.GetBatchSize()
        assert EMBEDDING_DIM <= (BATCH_SIZE // EMBEDDING_DIM)

        return cc, key_pair

    def query(
        self,
        cc: openfhe.CryptoContext,
        pk: openfhe.PublicKey,
    ) -> openfhe.Ciphertext:
        query = list(self.query_embedding)
        if len(query) < EMBEDDING_DIM:
            query.extend(0 for _ in range(EMBEDDING_DIM - len(self.query_embedding)))

        pt_query = cc.MakeCKKSPackedPlaintext(query)
        return cc.Encrypt(pk, pt_query)

    def extract(
        self,
        cc: openfhe.CryptoContext,
        sk: openfhe.PrivateKey,
        result: openfhe.Ciphertext,
        lables: list[str],
    ) -> list[str] | None:
        score = cc.Decrypt(result, sk).GetCKKSPackedValue()
        return [label for label, score in zip(lables, score) if abs(score) > 1]


class Enroller:
    def __init__(
        self,
        images_path: Path,
    ) -> None:
        self.database, self.database_labels = self._generate_database(images_path)

    def _generate_database(
        self,
        images_path: Path,
    ) -> tuple[list[FaceEmbedding], list[str]]:
        database = []
        labels = []
        for image_path in images_path.glob("*_base.jpg"):
            face_embedding = _generate_face_embedding(image_path)
            database.append(face_embedding)
            labels.append(image_path.name.removesuffix("_base.jpg"))

        if len(database) > EMBEDDING_DIM:
            raise Exception("Database size large than l is not supported yet")

        if len(database) < EMBEDDING_DIM:
            database.extend(np.zeros(EMBEDDING_DIM) for _ in range(EMBEDDING_DIM - len(database)))

        return database, labels

    def enroll(
        self,
        cc: openfhe.CryptoContext,
        pk: openfhe.PublicKey,
    ) -> tuple[list[openfhe.Ciphertext], list[str]]:
        diag_database = [[0 for _ in range(BATCH_SIZE)] for _ in range(EMBEDDING_DIM)]
        ct_diag_database = []

        for i in range(EMBEDDING_DIM):
            for j in range(EMBEDDING_DIM):
                diag_database[i][j] = self.database[j][(i + j) % EMBEDDING_DIM]

            pt_row = cc.MakeCKKSPackedPlaintext(diag_database[i])
            ct_row = cc.Encrypt(pk, pt_row)
            ct_diag_database.append(ct_row)

        return ct_diag_database, self.database_labels


class Server:
    def compute(
        self,
        cc: openfhe.CryptoContext,
        ct_diag_database: list[openfhe.Ciphertext],
        ct_query: openfhe.Ciphertext,
        threshold: float,
    ) -> openfhe.Ciphertext:
        score = self._compute_score(cc, ct_diag_database, ct_query)
        score_threshold = self._compute_threshold(cc, threshold, score)
        return score_threshold

    def _compute_score(
        self,
        cc: openfhe.CryptoContext,
        ct_diag_database: list[openfhe.Ciphertext],
        ct_query: openfhe.Ciphertext,
    ) -> openfhe.Ciphertext:
        scores: list[openfhe.Ciphertext] = []
        for i in range(EMBEDDING_DIM):
            ct_query_i = cc.EvalRotate(ct_query, i)
            s = cc.EvalMultNoRelin(ct_diag_database[i], ct_query_i)
            scores.append(s)

        for i in range(1, EMBEDDING_DIM):
            scores[0] = cc.EvalAdd(scores[0], scores[i])

        cc.RelinearizeInPlace(scores[0])
        cc.RescaleInPlace(scores[0])
        return scores[0]

    def _compute_threshold(
        self,
        cc: openfhe.CryptoContext,
        threshold: float,
        score: openfhe.Ciphertext,
    ) -> openfhe.Ciphertext:
        x = cc.EvalChebyshevFunction(
            lambda x: 1.0 if float(x) >= threshold else -1.0,
            score,
            a=-1.0,
            b=1.0,
            degree=59,
        )
        xx = cc.EvalPoly(x, [0, 315 / 128, 0, -420 / 128, 0, 378 / 128, 0, -180 / 128, 0, 35 / 128])
        xxx = cc.EvalAdd(xx, 1)
        return xxx


def main():
    client = Client(Path("./data/obama_1.jpg"))
    enroller = Enroller(images_path=Path("./data"))
    server = Server()

    # 1. Setup
    cc, key_pair = client.setup()
    # 2. Enroll
    ct_diag_database, database_labels = enroller.enroll(cc, key_pair.publicKey)
    # 3. Query
    ct_query = client.query(cc, key_pair.publicKey)
    # 4. Compute
    result = server.compute(cc, ct_diag_database, ct_query, THRESHOLD)
    # 5. Extract
    matches = client.extract(cc, key_pair.secretKey, result, database_labels)
    print("Matches:", matches)


if __name__ == "__main__":
    main()
