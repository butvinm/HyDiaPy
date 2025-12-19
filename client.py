import itertools
from dataclasses import dataclass
from pathlib import Path

import openfhe
from face_match import norm_face_embedding

EMBEDDING_DIM = 128

SIMILARITY_THRESHOLD = 0.9


@dataclass
class ClientParameters:
    """Public Client parameters shared with other parties."""

    cc: openfhe.CryptoContext
    pk: openfhe.PublicKey
    ring_dim: int
    batch_size: int
    embedding_dim: int
    similarity_threshold: float


class Client:
    def __init__(self) -> None:
        self.cc, self.key_pair, self.ring_dim, self.batch_size = self._init_crypto_context()

    def _init_crypto_context(self) -> tuple[openfhe.CryptoContext, openfhe.KeyPair, int, int]:
        parameters = openfhe.CCParamsCKKSRNS()
        parameters.SetSecurityLevel(openfhe.SecurityLevel.HEStd_128_classic)
        parameters.SetMultiplicativeDepth(11)
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

        ring_dim = cc.GetRingDimension()
        batch_size = cc.GetBatchSize()

        return cc, key_pair, ring_dim, batch_size

    def setup(self) -> ClientParameters:
        return ClientParameters(
            cc=self.cc,
            pk=self.key_pair.publicKey,
            ring_dim=self.ring_dim,
            batch_size=self.batch_size,
            embedding_dim=EMBEDDING_DIM,
            similarity_threshold=SIMILARITY_THRESHOLD,
        )

    def query(
        self,
        query_image: Path,
    ) -> openfhe.Ciphertext:
        face_embedding = norm_face_embedding(query_image)
        partitions_count = self.batch_size // EMBEDDING_DIM
        query_aligned = list(itertools.chain(*itertools.repeat(face_embedding, partitions_count)))
        query_pt = self.cc.MakeCKKSPackedPlaintext(query_aligned)
        query_ct = self.cc.Encrypt(self.key_pair.publicKey, query_pt)
        return query_ct

    def extract_identities(
        self,
        labels: list[str],
        thresholds: list[openfhe.Ciphertext],
    ) -> list[str]:
        identities = []
        i = 0
        for batch in thresholds:
            thresholds_pt = self.cc.Decrypt(self.key_pair.secretKey, batch).GetCKKSPackedValue()
            for threshold in thresholds_pt:
                if abs(threshold) > 1:
                    identities.append(labels[i])

                i += 1

        return identities
