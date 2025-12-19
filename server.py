import openfhe
from client import ClientParameters
from enroller import EnrollerDatabase


class Server:
    def compute_identities(
        self,
        params: ClientParameters,
        database: EnrollerDatabase,
        query: openfhe.Ciphertext,
    ) -> list[openfhe.Ciphertext]:
        thresholds = []
        for batch in database.database:
            score = self._compute_score(params.cc, params.embedding_dim, query, batch)
            threshold = self._compute_threshold(params.cc, params.similarity_threshold, score)
            thresholds.append(threshold)

        return thresholds

    def _compute_score(
        self,
        cc: openfhe.CryptoContext,
        embedding_dim: int,
        query: openfhe.Ciphertext,
        batch: list[openfhe.Ciphertext],
    ) -> openfhe.Ciphertext:
        scores = []
        for i in range(embedding_dim):
            ct_query_i = cc.EvalRotate(query, i)
            s = cc.EvalMultNoRelin(batch[i], ct_query_i)
            scores.append(s)

        for i in range(1, embedding_dim):
            cc.EvalAddInPlace(scores[0], scores[i])

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
