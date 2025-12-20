import collections.abc
import typing
from typing import ClassVar, overload

ADVANCEDSHE: PKESchemeFeature
AND: BINGATE
AP: BINFHE_METHOD
BEHZ: MultiplicationTechnique
BFVRNS_SCHEME: SCHEME
BGVRNS_SCHEME: SCHEME
BINARY: SERBINARY
BOOTSTRAPPED: BINFHE_OUTPUT
BV: KeySwitchTechnique
CKKSRNS_SCHEME: SCHEME
COEFFICIENT: Format
COMPACT: COMPRESSION_LEVEL
COMPLEX: CKKSDataType
COMPOSITESCALINGAUTO: ScalingTechnique
COMPOSITESCALINGMANUAL: ScalingTechnique
EVALUATION: Format
EXEC_EVALUATION: ExecutionMode
EXEC_NOISE_ESTIMATION: ExecutionMode
EXTENDED: EncryptionTechnique
FHE: PKESchemeFeature
FIXEDAUTO: ScalingTechnique
FIXEDMANUAL: ScalingTechnique
FIXED_NOISE_DECRYPT: DecryptionNoiseMode
FIXED_NOISE_HRA: ProxyReEncryptionMode
FIXED_NOISE_MULTIPARTY: MultipartyMode
FLEXIBLEAUTO: ScalingTechnique
FLEXIBLEAUTOEXT: ScalingTechnique
FRESH: BINFHE_OUTPUT
GAUSSIAN: SecretKeyDist
GINX: BINFHE_METHOD
HEStd_128_classic: SecurityLevel
HEStd_192_classic: SecurityLevel
HEStd_256_classic: SecurityLevel
HEStd_NotSet: SecurityLevel
HPS: MultiplicationTechnique
HPSPOVERQ: MultiplicationTechnique
HPSPOVERQLEVELED: MultiplicationTechnique
HYBRID: KeySwitchTechnique
INDCPA: ProxyReEncryptionMode
INVALID_KS_TECH: KeySwitchTechnique
INVALID_METHOD: BINFHE_METHOD
INVALID_MULTIPARTY_MODE: MultipartyMode
INVALID_OUTPUT: BINFHE_OUTPUT
INVALID_RS_TECHNIQUE: ScalingTechnique
INVALID_SCHEME: SCHEME
JSON: SERJSON
KEYSWITCH: PKESchemeFeature
LEVELEDSHE: PKESchemeFeature
LMKCDEY: BINFHE_METHOD
MEDIUM: BINFHE_PARAMSET
MULTIPARTY: PKESchemeFeature
NAND: BINGATE
NOISE_FLOODING_DECRYPT: DecryptionNoiseMode
NOISE_FLOODING_HRA: ProxyReEncryptionMode
NOISE_FLOODING_MULTIPARTY: MultipartyMode
NOR: BINGATE
NORESCALE: ScalingTechnique
NOT_SET: ProxyReEncryptionMode
OR: BINGATE
PKE: PKESchemeFeature
PRE: PKESchemeFeature
PUB_ENCRYPT: KEYGEN_MODE
REAL: CKKSDataType
SCHEMESWITCH: PKESchemeFeature
SIGNED_MOD_TEST: BINFHE_PARAMSET
SLACK: COMPRESSION_LEVEL
SPARSE_TERNARY: SecretKeyDist
STANDARD: EncryptionTechnique
STD128: BINFHE_PARAMSET
STD128Q: BINFHE_PARAMSET
STD128Q_3: BINFHE_PARAMSET
STD128Q_3_LMKCDEY: BINFHE_PARAMSET
STD128Q_4: BINFHE_PARAMSET
STD128Q_4_LMKCDEY: BINFHE_PARAMSET
STD128Q_LMKCDEY: BINFHE_PARAMSET
STD128_3: BINFHE_PARAMSET
STD128_3_LMKCDEY: BINFHE_PARAMSET
STD128_4: BINFHE_PARAMSET
STD128_4_LMKCDEY: BINFHE_PARAMSET
STD128_AP: BINFHE_PARAMSET
STD128_LMKCDEY: BINFHE_PARAMSET
STD192: BINFHE_PARAMSET
STD192Q: BINFHE_PARAMSET
STD192Q_3: BINFHE_PARAMSET
STD192Q_4: BINFHE_PARAMSET
STD256: BINFHE_PARAMSET
STD256Q: BINFHE_PARAMSET
STD256Q_3: BINFHE_PARAMSET
STD256Q_4: BINFHE_PARAMSET
SYM_ENCRYPT: KEYGEN_MODE
TOY: BINFHE_PARAMSET
UNIFORM_TERNARY: SecretKeyDist
XNOR: BINGATE
XNOR_FAST: BINGATE
XOR: BINGATE
XOR_FAST: BINGATE

class BINFHE_METHOD:
    """Members:

    INVALID_METHOD

    AP

    GINX

    LMKCDEY"""

    __members__: ClassVar[dict] = ...  # read-only
    AP: ClassVar[BINFHE_METHOD] = ...
    GINX: ClassVar[BINFHE_METHOD] = ...
    INVALID_METHOD: ClassVar[BINFHE_METHOD] = ...
    LMKCDEY: ClassVar[BINFHE_METHOD] = ...
    __entries: ClassVar[dict] = ...
    def __init__(self, value: typing.SupportsInt) -> None:
        """__init__(self: openfhe.openfhe.BINFHE_METHOD, value: typing.SupportsInt) -> None"""
    def __eq__(self, other: object) -> bool:
        """__eq__(self: object, other: object, /) -> bool"""
    def __hash__(self) -> int:
        """__hash__(self: object, /) -> int"""
    def __index__(self) -> int:
        """__index__(self: openfhe.openfhe.BINFHE_METHOD, /) -> int"""
    def __int__(self) -> int:
        """__int__(self: openfhe.openfhe.BINFHE_METHOD, /) -> int"""
    def __ne__(self, other: object) -> bool:
        """__ne__(self: object, other: object, /) -> bool"""
    @property
    def name(self) -> str:
        """name(self: object, /) -> str

        name(self: object, /) -> str
        """
    @property
    def value(self) -> int:
        """(arg0: openfhe.openfhe.BINFHE_METHOD) -> int"""

class BINFHE_OUTPUT:
    """Members:

    INVALID_OUTPUT

    FRESH

    BOOTSTRAPPED"""

    __members__: ClassVar[dict] = ...  # read-only
    BOOTSTRAPPED: ClassVar[BINFHE_OUTPUT] = ...
    FRESH: ClassVar[BINFHE_OUTPUT] = ...
    INVALID_OUTPUT: ClassVar[BINFHE_OUTPUT] = ...
    __entries: ClassVar[dict] = ...
    def __init__(self, value: typing.SupportsInt) -> None:
        """__init__(self: openfhe.openfhe.BINFHE_OUTPUT, value: typing.SupportsInt) -> None"""
    def __eq__(self, other: object) -> bool:
        """__eq__(self: object, other: object, /) -> bool"""
    def __hash__(self) -> int:
        """__hash__(self: object, /) -> int"""
    def __index__(self) -> int:
        """__index__(self: openfhe.openfhe.BINFHE_OUTPUT, /) -> int"""
    def __int__(self) -> int:
        """__int__(self: openfhe.openfhe.BINFHE_OUTPUT, /) -> int"""
    def __ne__(self, other: object) -> bool:
        """__ne__(self: object, other: object, /) -> bool"""
    @property
    def name(self) -> str:
        """name(self: object, /) -> str

        name(self: object, /) -> str
        """
    @property
    def value(self) -> int:
        """(arg0: openfhe.openfhe.BINFHE_OUTPUT) -> int"""

class BINFHE_PARAMSET:
    """Members:

    TOY

    MEDIUM

    STD128_LMKCDEY

    STD128_AP

    STD128

    STD192

    STD256

    STD128Q

    STD128Q_LMKCDEY

    STD192Q

    STD256Q

    STD128_3

    STD128_3_LMKCDEY

    STD128Q_3

    STD128Q_3_LMKCDEY

    STD192Q_3

    STD256Q_3

    STD128_4

    STD128_4_LMKCDEY

    STD128Q_4

    STD128Q_4_LMKCDEY

    STD192Q_4

    STD256Q_4

    SIGNED_MOD_TEST"""

    __members__: ClassVar[dict] = ...  # read-only
    MEDIUM: ClassVar[BINFHE_PARAMSET] = ...
    SIGNED_MOD_TEST: ClassVar[BINFHE_PARAMSET] = ...
    STD128: ClassVar[BINFHE_PARAMSET] = ...
    STD128Q: ClassVar[BINFHE_PARAMSET] = ...
    STD128Q_3: ClassVar[BINFHE_PARAMSET] = ...
    STD128Q_3_LMKCDEY: ClassVar[BINFHE_PARAMSET] = ...
    STD128Q_4: ClassVar[BINFHE_PARAMSET] = ...
    STD128Q_4_LMKCDEY: ClassVar[BINFHE_PARAMSET] = ...
    STD128Q_LMKCDEY: ClassVar[BINFHE_PARAMSET] = ...
    STD128_3: ClassVar[BINFHE_PARAMSET] = ...
    STD128_3_LMKCDEY: ClassVar[BINFHE_PARAMSET] = ...
    STD128_4: ClassVar[BINFHE_PARAMSET] = ...
    STD128_4_LMKCDEY: ClassVar[BINFHE_PARAMSET] = ...
    STD128_AP: ClassVar[BINFHE_PARAMSET] = ...
    STD128_LMKCDEY: ClassVar[BINFHE_PARAMSET] = ...
    STD192: ClassVar[BINFHE_PARAMSET] = ...
    STD192Q: ClassVar[BINFHE_PARAMSET] = ...
    STD192Q_3: ClassVar[BINFHE_PARAMSET] = ...
    STD192Q_4: ClassVar[BINFHE_PARAMSET] = ...
    STD256: ClassVar[BINFHE_PARAMSET] = ...
    STD256Q: ClassVar[BINFHE_PARAMSET] = ...
    STD256Q_3: ClassVar[BINFHE_PARAMSET] = ...
    STD256Q_4: ClassVar[BINFHE_PARAMSET] = ...
    TOY: ClassVar[BINFHE_PARAMSET] = ...
    __entries: ClassVar[dict] = ...
    def __init__(self, value: typing.SupportsInt) -> None:
        """__init__(self: openfhe.openfhe.BINFHE_PARAMSET, value: typing.SupportsInt) -> None"""
    def __eq__(self, other: object) -> bool:
        """__eq__(self: object, other: object, /) -> bool"""
    def __hash__(self) -> int:
        """__hash__(self: object, /) -> int"""
    def __index__(self) -> int:
        """__index__(self: openfhe.openfhe.BINFHE_PARAMSET, /) -> int"""
    def __int__(self) -> int:
        """__int__(self: openfhe.openfhe.BINFHE_PARAMSET, /) -> int"""
    def __ne__(self, other: object) -> bool:
        """__ne__(self: object, other: object, /) -> bool"""
    @property
    def name(self) -> str:
        """name(self: object, /) -> str

        name(self: object, /) -> str
        """
    @property
    def value(self) -> int:
        """(arg0: openfhe.openfhe.BINFHE_PARAMSET) -> int"""

class BINGATE:
    """Members:

    OR

    AND

    NOR

    NAND

    XOR_FAST

    XNOR_FAST

    XOR

    XNOR"""

    __members__: ClassVar[dict] = ...  # read-only
    AND: ClassVar[BINGATE] = ...
    NAND: ClassVar[BINGATE] = ...
    NOR: ClassVar[BINGATE] = ...
    OR: ClassVar[BINGATE] = ...
    XNOR: ClassVar[BINGATE] = ...
    XNOR_FAST: ClassVar[BINGATE] = ...
    XOR: ClassVar[BINGATE] = ...
    XOR_FAST: ClassVar[BINGATE] = ...
    __entries: ClassVar[dict] = ...
    def __init__(self, value: typing.SupportsInt) -> None:
        """__init__(self: openfhe.openfhe.BINGATE, value: typing.SupportsInt) -> None"""
    def __eq__(self, other: object) -> bool:
        """__eq__(self: object, other: object, /) -> bool"""
    def __hash__(self) -> int:
        """__hash__(self: object, /) -> int"""
    def __index__(self) -> int:
        """__index__(self: openfhe.openfhe.BINGATE, /) -> int"""
    def __int__(self) -> int:
        """__int__(self: openfhe.openfhe.BINGATE, /) -> int"""
    def __ne__(self, other: object) -> bool:
        """__ne__(self: object, other: object, /) -> bool"""
    @property
    def name(self) -> str:
        """name(self: object, /) -> str

        name(self: object, /) -> str
        """
    @property
    def value(self) -> int:
        """(arg0: openfhe.openfhe.BINGATE) -> int"""

class BinFHEContext:
    def __init__(self) -> None:
        """__init__(self: openfhe.openfhe.BinFHEContext) -> None"""
    def BTKeyGen(self, sk: LWEPrivateKey, keygenMode: KEYGEN_MODE = ...) -> None:
        """BTKeyGen(self: openfhe.openfhe.BinFHEContext, sk: openfhe.openfhe.LWEPrivateKey, keygenMode: openfhe.openfhe.KEYGEN_MODE = <KEYGEN_MODE.SYM_ENCRYPT: 0>) -> None


        Generates bootstrapping keys.

        :param sk: The secret key.
        :type sk: LWEPrivateKey

        """
    def Bootstrap(self, ct: LWECiphertext, extended: bool = ...) -> LWECiphertext:
        """Bootstrap(self: openfhe.openfhe.BinFHEContext, ct: openfhe.openfhe.LWECiphertext, extended: bool = False) -> openfhe.openfhe.LWECiphertext"""
    def ClearBTKeys(self) -> None:
        """ClearBTKeys(self: openfhe.openfhe.BinFHEContext) -> None"""
    def Decrypt(self, sk: LWEPrivateKey, ct: LWECiphertext, p: typing.SupportsInt = ...) -> int:
        """Decrypt(self: openfhe.openfhe.BinFHEContext, sk: openfhe.openfhe.LWEPrivateKey, ct: openfhe.openfhe.LWECiphertext, p: typing.SupportsInt = 4) -> int


        Decrypts a ciphertext using a secret key.

        :param sk: The secret key.
        :type sk: LWEPrivateKey
        :param ct: The ciphertext.
        :type ct: LWECiphertext
        :param p: Plaintext modulus (default 4).
        :type p: int
        :return: The plaintext.
        :rtype: int

        """
    def Encrypt(
        self,
        sk: LWEPrivateKey,
        m: typing.SupportsInt,
        output: BINFHE_OUTPUT = ...,
        p: typing.SupportsInt = ...,
        mod: typing.SupportsInt = ...,
    ) -> LWECiphertext:
        """Encrypt(self: openfhe.openfhe.BinFHEContext, sk: openfhe.openfhe.LWEPrivateKey, m: typing.SupportsInt, output: openfhe.openfhe.BINFHE_OUTPUT = <BINFHE_OUTPUT.BOOTSTRAPPED: 2>, p: typing.SupportsInt = 4, mod: typing.SupportsInt = 0) -> openfhe.openfhe.LWECiphertext


        Encrypts a bit or integer using a secret key (symmetric key encryption).

        :param sk: The secret key.
        :type sk: LWEPrivateKey
        :param m: The plaintext.
        :type m: int
        :param output: FRESH to generate a fresh ciphertext, BOOTSTRAPPED to generate a refreshed ciphertext (default).
        :type output: BINFHE_OUTPUT
        :param p: Plaintext modulus (default 4).
        :type p: int
        :param mod: Encrypt according to mod instead of m_q if mod != 0.
        :type mod: int
        :return: The ciphertext.
        :rtype: LWECiphertext

        """
    @overload
    def EvalBinGate(self, gate: BINGATE, ct1: LWECiphertext, ct2: LWECiphertext, extended: bool = ...) -> LWECiphertext:
        """EvalBinGate(*args, **kwargs)
        Overloaded function.

        1. EvalBinGate(self: openfhe.openfhe.BinFHEContext, gate: openfhe.openfhe.BINGATE, ct1: openfhe.openfhe.LWECiphertext, ct2: openfhe.openfhe.LWECiphertext, extended: bool = False) -> openfhe.openfhe.LWECiphertext


            Evaluates a binary gate (calls bootstrapping as a subroutine).

            :param gate: The gate; can be AND, OR, NAND, NOR, XOR, or XNOR.
            :type gate: BINGATE
            :param ct1: First ciphertext.
            :type ct1: LWECiphertext
            :param ct2: Second ciphertext.
            :type ct2: LWECiphertext
            :return: The resulting ciphertext.
            :rtype: LWECiphertext


        2. EvalBinGate(self: openfhe.openfhe.BinFHEContext, gate: openfhe.openfhe.BINGATE, ctvector: collections.abc.Sequence[openfhe.openfhe.LWECiphertext], extended: bool = False) -> openfhe.openfhe.LWECiphertext
        """
    @overload
    def EvalBinGate(self, gate: BINGATE, ctvector: collections.abc.Sequence[LWECiphertext], extended: bool = ...) -> LWECiphertext:
        """EvalBinGate(*args, **kwargs)
        Overloaded function.

        1. EvalBinGate(self: openfhe.openfhe.BinFHEContext, gate: openfhe.openfhe.BINGATE, ct1: openfhe.openfhe.LWECiphertext, ct2: openfhe.openfhe.LWECiphertext, extended: bool = False) -> openfhe.openfhe.LWECiphertext


            Evaluates a binary gate (calls bootstrapping as a subroutine).

            :param gate: The gate; can be AND, OR, NAND, NOR, XOR, or XNOR.
            :type gate: BINGATE
            :param ct1: First ciphertext.
            :type ct1: LWECiphertext
            :param ct2: Second ciphertext.
            :type ct2: LWECiphertext
            :return: The resulting ciphertext.
            :rtype: LWECiphertext


        2. EvalBinGate(self: openfhe.openfhe.BinFHEContext, gate: openfhe.openfhe.BINGATE, ctvector: collections.abc.Sequence[openfhe.openfhe.LWECiphertext], extended: bool = False) -> openfhe.openfhe.LWECiphertext
        """
    def EvalConstant(self, arg0: bool) -> LWECiphertext:
        """EvalConstant(self: openfhe.openfhe.BinFHEContext, arg0: bool) -> openfhe.openfhe.LWECiphertext"""
    def EvalDecomp(self, ct: LWECiphertext) -> list[LWECiphertext]:
        """EvalDecomp(self: openfhe.openfhe.BinFHEContext, ct: openfhe.openfhe.LWECiphertext) -> list[openfhe.openfhe.LWECiphertext]


        Evaluate ciphertext decomposition

        :param ct: ciphertext to be bootstrapped
        :type ct: LWECiphertext
        :return: a list with the resulting ciphertexts
        :rtype: List[LWECiphertext]

        """
    def EvalFloor(self, ct: LWECiphertext, roundbits: typing.SupportsInt = ...) -> LWECiphertext:
        """EvalFloor(self: openfhe.openfhe.BinFHEContext, ct: openfhe.openfhe.LWECiphertext, roundbits: typing.SupportsInt = 0) -> openfhe.openfhe.LWECiphertext


        Evaluate a round down function

        :param ct: ciphertext to be bootstrapped
        :type ct: LWECiphertext
        :param roundbits: number of bits to be rounded
        :type roundbits: int
        :return: the resulting ciphertext
        :rtype: LWECiphertext

        """
    def EvalFunc(self, ct: LWECiphertext, LUT: collections.abc.Sequence[typing.SupportsInt]) -> LWECiphertext:
        """EvalFunc(self: openfhe.openfhe.BinFHEContext, ct: openfhe.openfhe.LWECiphertext, LUT: collections.abc.Sequence[typing.SupportsInt]) -> openfhe.openfhe.LWECiphertext


        Evaluate an arbitrary function

        :param ct: ciphertext to be bootstrapped
        :type ct: LWECiphertext
        :param LUT: the look-up table of the to-be-evaluated function
        :type LUT: List[int]
        :return: the resulting ciphertext
        :rtype: LWECiphertext

        """
    def EvalNOT(self, ct: LWECiphertext) -> LWECiphertext:
        """EvalNOT(self: openfhe.openfhe.BinFHEContext, ct: openfhe.openfhe.LWECiphertext) -> openfhe.openfhe.LWECiphertext


        Evaluates the NOT gate.

        :param ct: The input ciphertext.
        :type ct: LWECiphertext
        :return: The resulting ciphertext.
        :rtype: LWECiphertext

        """
    def EvalSign(self, ct: LWECiphertext, schemeSwitch: bool = ...) -> LWECiphertext:
        """EvalSign(self: openfhe.openfhe.BinFHEContext, ct: openfhe.openfhe.LWECiphertext, schemeSwitch: bool = False) -> openfhe.openfhe.LWECiphertext


        Evaluate a sign function over large precisions

        :param ct: ciphertext to be bootstrapped
        :type ct: LWECiphertext
        :param schemeSwitch: flag that indicates if it should be compatible to scheme switching
        :type schemeSwitch: bool
        :return: the resulting ciphertext
        :rtype: LWECiphertext

        """
    @overload
    def GenerateBinFHEContext(self, set: BINFHE_PARAMSET, method: BINFHE_METHOD = ...) -> None:
        """GenerateBinFHEContext(*args, **kwargs)
        Overloaded function.

        1. GenerateBinFHEContext(self: openfhe.openfhe.BinFHEContext, set: openfhe.openfhe.BINFHE_PARAMSET, method: openfhe.openfhe.BINFHE_METHOD = <BINFHE_METHOD.GINX: 2>) -> None


            Creates a crypto context using predefined parameters sets. Recommended for most users.

            :param set: the parameter set: TOY, MEDIUM, STD128, STD192, STD256 with variants
            :type set: BINFHE_PARAMSET
            :param method: the bootstrapping method (DM or CGGI or LMKCDEY)
            :type method: BINFHE_METHOD
            :return: The created crypto context.
            :rtype: BinFHEContext


        2. GenerateBinFHEContext(self: openfhe.openfhe.BinFHEContext, set: openfhe.openfhe.BINFHE_PARAMSET, arbFunc: bool, logQ: typing.SupportsInt = 11, N: typing.SupportsInt = 0, method: openfhe.openfhe.BINFHE_METHOD = <BINFHE_METHOD.GINX: 2>, timeOptimization: bool = False) -> None


            Creates a crypto context using custom parameters. Should be used with care (only for advanced users familiar with LWE parameter selection).

            :param set: The parameter set: TOY, MEDIUM, STD128, STD192, STD256 with variants.
            :type set: BINFHE_PARAMSET
            :param arbFunc:  whether need to evaluate an arbitrary function using functional bootstrapping
            :type arbFunc: bool
            :param logQ:  log(input ciphertext modulus)
            :type logQ: int
            :param N:  ring dimension for RingGSW/RLWE used in bootstrapping
            :type N: int
            :param method: the bootstrapping method (DM or CGGI or LMKCDEY)
            :type method: BINFHE_METHOD
            :param timeOptimization:  whether to use dynamic bootstrapping technique
            :type timeOptimization: bool
            :return: creates the cryptocontext.
            :rtype: BinFHEContext

        """
    @overload
    def GenerateBinFHEContext(
        self,
        set: BINFHE_PARAMSET,
        arbFunc: bool,
        logQ: typing.SupportsInt = ...,
        N: typing.SupportsInt = ...,
        method: BINFHE_METHOD = ...,
        timeOptimization: bool = ...,
    ) -> None:
        """GenerateBinFHEContext(*args, **kwargs)
        Overloaded function.

        1. GenerateBinFHEContext(self: openfhe.openfhe.BinFHEContext, set: openfhe.openfhe.BINFHE_PARAMSET, method: openfhe.openfhe.BINFHE_METHOD = <BINFHE_METHOD.GINX: 2>) -> None


            Creates a crypto context using predefined parameters sets. Recommended for most users.

            :param set: the parameter set: TOY, MEDIUM, STD128, STD192, STD256 with variants
            :type set: BINFHE_PARAMSET
            :param method: the bootstrapping method (DM or CGGI or LMKCDEY)
            :type method: BINFHE_METHOD
            :return: The created crypto context.
            :rtype: BinFHEContext


        2. GenerateBinFHEContext(self: openfhe.openfhe.BinFHEContext, set: openfhe.openfhe.BINFHE_PARAMSET, arbFunc: bool, logQ: typing.SupportsInt = 11, N: typing.SupportsInt = 0, method: openfhe.openfhe.BINFHE_METHOD = <BINFHE_METHOD.GINX: 2>, timeOptimization: bool = False) -> None


            Creates a crypto context using custom parameters. Should be used with care (only for advanced users familiar with LWE parameter selection).

            :param set: The parameter set: TOY, MEDIUM, STD128, STD192, STD256 with variants.
            :type set: BINFHE_PARAMSET
            :param arbFunc:  whether need to evaluate an arbitrary function using functional bootstrapping
            :type arbFunc: bool
            :param logQ:  log(input ciphertext modulus)
            :type logQ: int
            :param N:  ring dimension for RingGSW/RLWE used in bootstrapping
            :type N: int
            :param method: the bootstrapping method (DM or CGGI or LMKCDEY)
            :type method: BINFHE_METHOD
            :param timeOptimization:  whether to use dynamic bootstrapping technique
            :type timeOptimization: bool
            :return: creates the cryptocontext.
            :rtype: BinFHEContext

        """
    def GenerateLUTviaFunction(self, f: collections.abc.Callable, p: typing.SupportsInt) -> list[int]:
        """GenerateLUTviaFunction(self: openfhe.openfhe.BinFHEContext, f: collections.abc.Callable, p: typing.SupportsInt) -> list[int]


        Generate the LUT for the to-be-evaluated function

        :param f: the to-be-evaluated function on an integer message and a plaintext modulus
        :type f: function(int, int) -> int
        :param p: plaintext modulus
        :type p: int
        :return: the resulting ciphertext
        :rtype: List[int]

        """
    def GetBeta(self) -> int:
        """GetBeta(self: openfhe.openfhe.BinFHEContext) -> int"""
    def GetBinFHEScheme(self, *args, **kwargs):
        """GetBinFHEScheme(self: openfhe.openfhe.BinFHEContext) -> lbcrypto::BinFHEScheme"""
    def GetLWEScheme(self, *args, **kwargs):
        """GetLWEScheme(self: openfhe.openfhe.BinFHEContext) -> lbcrypto::LWEEncryptionScheme"""
    def GetMaxPlaintextSpace(self) -> int:
        """GetMaxPlaintextSpace(self: openfhe.openfhe.BinFHEContext) -> int"""
    def GetParams(self, *args, **kwargs):
        """GetParams(self: openfhe.openfhe.BinFHEContext) -> lbcrypto::BinFHECryptoParams"""
    def GetPublicKey(self, *args, **kwargs):
        """GetPublicKey(self: openfhe.openfhe.BinFHEContext) -> lbcrypto::LWEPublicKeyImpl"""
    def GetRefreshKey(self, *args, **kwargs):
        """GetRefreshKey(self: openfhe.openfhe.BinFHEContext) -> lbcrypto::RingGSWACCKeyImpl"""
    def GetSwitchKey(self, *args, **kwargs):
        """GetSwitchKey(self: openfhe.openfhe.BinFHEContext) -> lbcrypto::LWESwitchingKeyImpl"""
    def Getn(self) -> int:
        """Getn(self: openfhe.openfhe.BinFHEContext) -> int"""
    def Getq(self) -> int:
        """Getq(self: openfhe.openfhe.BinFHEContext) -> int"""
    def KeyGen(self) -> LWEPrivateKey:
        """KeyGen(self: openfhe.openfhe.BinFHEContext) -> openfhe.openfhe.LWEPrivateKey


        Generates a secret key for the main LWE scheme.

        :return: The secret key.
        :rtype: LWEPrivateKey

        """
    def KeyGenN(self) -> LWEPrivateKey:
        """KeyGenN(self: openfhe.openfhe.BinFHEContext) -> openfhe.openfhe.LWEPrivateKey"""
    def KeyGenPair(self, *args, **kwargs):
        """KeyGenPair(self: openfhe.openfhe.BinFHEContext) -> lbcrypto::LWEKeyPairImpl"""
    def LoadBinary(self, arg0, arg1: typing.SupportsInt) -> None:
        """LoadBinary(self: openfhe.openfhe.BinFHEContext, arg0: cereal::BinaryInputArchive, arg1: typing.SupportsInt) -> None"""
    def LoadJSON(self, arg0, arg1: typing.SupportsInt) -> None:
        """LoadJSON(self: openfhe.openfhe.BinFHEContext, arg0: cereal::JSONInputArchive, arg1: typing.SupportsInt) -> None"""
    def LoadPortableBinary(self, arg0, arg1: typing.SupportsInt) -> None:
        """LoadPortableBinary(self: openfhe.openfhe.BinFHEContext, arg0: cereal::PortableBinaryInputArchive, arg1: typing.SupportsInt) -> None"""
    def SaveBinary(self, arg0, arg1: typing.SupportsInt) -> None:
        """SaveBinary(self: openfhe.openfhe.BinFHEContext, arg0: cereal::BinaryOutputArchive, arg1: typing.SupportsInt) -> None"""
    def SaveJSON(self, arg0, arg1: typing.SupportsInt) -> None:
        """SaveJSON(self: openfhe.openfhe.BinFHEContext, arg0: cereal::JSONOutputArchive, arg1: typing.SupportsInt) -> None"""
    def SavePortableBinary(self, arg0, arg1: typing.SupportsInt) -> None:
        """SavePortableBinary(self: openfhe.openfhe.BinFHEContext, arg0: cereal::PortableBinaryOutputArchive, arg1: typing.SupportsInt) -> None"""
    def SerializedObjectName(self) -> str:
        """SerializedObjectName(self: openfhe.openfhe.BinFHEContext) -> str


        Return the serialized object name

        :return: object name
        :rtype: std::string

        """
    def SerializedVersion(self) -> int:
        """SerializedVersion() -> int


        Return the serialized version number in use.

        :return: the version number
        :rtype: uint32_t

        """

class CCParamsBFVRNS:
    def __init__(self) -> None:
        """__init__(self: openfhe.openfhe.CCParamsBFVRNS) -> None"""
    def GetBatchSize(self) -> int:
        """GetBatchSize(self: openfhe.openfhe.CCParamsBFVRNS) -> int"""
    def GetCKKSDataType(self) -> CKKSDataType:
        """GetCKKSDataType(self: openfhe.openfhe.CCParamsBFVRNS) -> openfhe.openfhe.CKKSDataType"""
    def GetCompositeDegree(self) -> int:
        """GetCompositeDegree(self: openfhe.openfhe.CCParamsBFVRNS) -> int"""
    def GetDecryptionNoiseMode(self) -> DecryptionNoiseMode:
        """GetDecryptionNoiseMode(self: openfhe.openfhe.CCParamsBFVRNS) -> openfhe.openfhe.DecryptionNoiseMode"""
    def GetDesiredPrecision(self) -> float:
        """GetDesiredPrecision(self: openfhe.openfhe.CCParamsBFVRNS) -> float"""
    def GetDigitSize(self) -> int:
        """GetDigitSize(self: openfhe.openfhe.CCParamsBFVRNS) -> int"""
    def GetEncryptionTechnique(self) -> EncryptionTechnique:
        """GetEncryptionTechnique(self: openfhe.openfhe.CCParamsBFVRNS) -> openfhe.openfhe.EncryptionTechnique"""
    def GetEvalAddCount(self) -> int:
        """GetEvalAddCount(self: openfhe.openfhe.CCParamsBFVRNS) -> int"""
    def GetExecutionMode(self) -> ExecutionMode:
        """GetExecutionMode(self: openfhe.openfhe.CCParamsBFVRNS) -> openfhe.openfhe.ExecutionMode"""
    def GetFirstModSize(self) -> int:
        """GetFirstModSize(self: openfhe.openfhe.CCParamsBFVRNS) -> int"""
    def GetInteractiveBootCompressionLevel(self) -> COMPRESSION_LEVEL:
        """GetInteractiveBootCompressionLevel(self: openfhe.openfhe.CCParamsBFVRNS) -> openfhe.openfhe.COMPRESSION_LEVEL"""
    def GetKeySwitchCount(self) -> int:
        """GetKeySwitchCount(self: openfhe.openfhe.CCParamsBFVRNS) -> int"""
    def GetKeySwitchTechnique(self) -> KeySwitchTechnique:
        """GetKeySwitchTechnique(self: openfhe.openfhe.CCParamsBFVRNS) -> openfhe.openfhe.KeySwitchTechnique"""
    def GetMaxRelinSkDeg(self) -> int:
        """GetMaxRelinSkDeg(self: openfhe.openfhe.CCParamsBFVRNS) -> int"""
    def GetMultipartyMode(self) -> MultipartyMode:
        """GetMultipartyMode(self: openfhe.openfhe.CCParamsBFVRNS) -> openfhe.openfhe.MultipartyMode"""
    def GetMultiplicationTechnique(self) -> MultiplicationTechnique:
        """GetMultiplicationTechnique(self: openfhe.openfhe.CCParamsBFVRNS) -> openfhe.openfhe.MultiplicationTechnique"""
    def GetMultiplicativeDepth(self) -> int:
        """GetMultiplicativeDepth(self: openfhe.openfhe.CCParamsBFVRNS) -> int"""
    def GetNoiseEstimate(self) -> float:
        """GetNoiseEstimate(self: openfhe.openfhe.CCParamsBFVRNS) -> float"""
    def GetNumAdversarialQueries(self) -> float:
        """GetNumAdversarialQueries(self: openfhe.openfhe.CCParamsBFVRNS) -> float"""
    def GetNumLargeDigits(self) -> int:
        """GetNumLargeDigits(self: openfhe.openfhe.CCParamsBFVRNS) -> int"""
    def GetPREMode(self) -> ProxyReEncryptionMode:
        """GetPREMode(self: openfhe.openfhe.CCParamsBFVRNS) -> openfhe.openfhe.ProxyReEncryptionMode"""
    def GetPRENumHops(self) -> int:
        """GetPRENumHops(self: openfhe.openfhe.CCParamsBFVRNS) -> int"""
    def GetPlaintextModulus(self) -> int:
        """GetPlaintextModulus(self: openfhe.openfhe.CCParamsBFVRNS) -> int"""
    def GetRegisterWordSize(self) -> int:
        """GetRegisterWordSize(self: openfhe.openfhe.CCParamsBFVRNS) -> int"""
    def GetRingDim(self) -> int:
        """GetRingDim(self: openfhe.openfhe.CCParamsBFVRNS) -> int"""
    def GetScalingModSize(self) -> int:
        """GetScalingModSize(self: openfhe.openfhe.CCParamsBFVRNS) -> int"""
    def GetScalingTechnique(self) -> ScalingTechnique:
        """GetScalingTechnique(self: openfhe.openfhe.CCParamsBFVRNS) -> openfhe.openfhe.ScalingTechnique"""
    def GetScheme(self) -> SCHEME:
        """GetScheme(self: openfhe.openfhe.CCParamsBFVRNS) -> openfhe.openfhe.SCHEME"""
    def GetSecretKeyDist(self) -> SecretKeyDist:
        """GetSecretKeyDist(self: openfhe.openfhe.CCParamsBFVRNS) -> openfhe.openfhe.SecretKeyDist"""
    def GetSecurityLevel(self) -> SecurityLevel:
        """GetSecurityLevel(self: openfhe.openfhe.CCParamsBFVRNS) -> openfhe.openfhe.SecurityLevel"""
    def GetStandardDeviation(self) -> float:
        """GetStandardDeviation(self: openfhe.openfhe.CCParamsBFVRNS) -> float"""
    def GetStatisticalSecurity(self) -> float:
        """GetStatisticalSecurity(self: openfhe.openfhe.CCParamsBFVRNS) -> float"""
    def SetBatchSize(self, arg0: typing.SupportsInt) -> None:
        """SetBatchSize(self: openfhe.openfhe.CCParamsBFVRNS, arg0: typing.SupportsInt) -> None"""
    def SetCKKSDataType(self, arg0: CKKSDataType) -> None:
        """SetCKKSDataType(self: openfhe.openfhe.CCParamsBFVRNS, arg0: openfhe.openfhe.CKKSDataType) -> None"""
    def SetCompositeDegree(self, arg0: typing.SupportsInt) -> None:
        """SetCompositeDegree(self: openfhe.openfhe.CCParamsBFVRNS, arg0: typing.SupportsInt) -> None"""
    def SetDecryptionNoiseMode(self, arg0: DecryptionNoiseMode) -> None:
        """SetDecryptionNoiseMode(self: openfhe.openfhe.CCParamsBFVRNS, arg0: openfhe.openfhe.DecryptionNoiseMode) -> None"""
    def SetDesiredPrecision(self, arg0: typing.SupportsFloat) -> None:
        """SetDesiredPrecision(self: openfhe.openfhe.CCParamsBFVRNS, arg0: typing.SupportsFloat) -> None"""
    def SetDigitSize(self, arg0: typing.SupportsInt) -> None:
        """SetDigitSize(self: openfhe.openfhe.CCParamsBFVRNS, arg0: typing.SupportsInt) -> None"""
    def SetEncryptionTechnique(self, arg0: EncryptionTechnique) -> None:
        """SetEncryptionTechnique(self: openfhe.openfhe.CCParamsBFVRNS, arg0: openfhe.openfhe.EncryptionTechnique) -> None"""
    def SetEvalAddCount(self, arg0: typing.SupportsInt) -> None:
        """SetEvalAddCount(self: openfhe.openfhe.CCParamsBFVRNS, arg0: typing.SupportsInt) -> None"""
    def SetExecutionMode(self, arg0: ExecutionMode) -> None:
        """SetExecutionMode(self: openfhe.openfhe.CCParamsBFVRNS, arg0: openfhe.openfhe.ExecutionMode) -> None"""
    def SetFirstModSize(self, arg0: typing.SupportsInt) -> None:
        """SetFirstModSize(self: openfhe.openfhe.CCParamsBFVRNS, arg0: typing.SupportsInt) -> None"""
    def SetInteractiveBootCompressionLevel(self, arg0: COMPRESSION_LEVEL) -> None:
        """SetInteractiveBootCompressionLevel(self: openfhe.openfhe.CCParamsBFVRNS, arg0: openfhe.openfhe.COMPRESSION_LEVEL) -> None"""
    def SetKeySwitchCount(self, arg0: typing.SupportsInt) -> None:
        """SetKeySwitchCount(self: openfhe.openfhe.CCParamsBFVRNS, arg0: typing.SupportsInt) -> None"""
    def SetKeySwitchTechnique(self, arg0: KeySwitchTechnique) -> None:
        """SetKeySwitchTechnique(self: openfhe.openfhe.CCParamsBFVRNS, arg0: openfhe.openfhe.KeySwitchTechnique) -> None"""
    def SetMaxRelinSkDeg(self, arg0: typing.SupportsInt) -> None:
        """SetMaxRelinSkDeg(self: openfhe.openfhe.CCParamsBFVRNS, arg0: typing.SupportsInt) -> None"""
    def SetMultipartyMode(self, arg0: MultipartyMode) -> None:
        """SetMultipartyMode(self: openfhe.openfhe.CCParamsBFVRNS, arg0: openfhe.openfhe.MultipartyMode) -> None"""
    def SetMultiplicationTechnique(self, arg0: MultiplicationTechnique) -> None:
        """SetMultiplicationTechnique(self: openfhe.openfhe.CCParamsBFVRNS, arg0: openfhe.openfhe.MultiplicationTechnique) -> None"""
    def SetMultiplicativeDepth(self, arg0: typing.SupportsInt) -> None:
        """SetMultiplicativeDepth(self: openfhe.openfhe.CCParamsBFVRNS, arg0: typing.SupportsInt) -> None"""
    def SetNoiseEstimate(self, arg0: typing.SupportsFloat) -> None:
        """SetNoiseEstimate(self: openfhe.openfhe.CCParamsBFVRNS, arg0: typing.SupportsFloat) -> None"""
    def SetNumAdversarialQueries(self, arg0: typing.SupportsInt) -> None:
        """SetNumAdversarialQueries(self: openfhe.openfhe.CCParamsBFVRNS, arg0: typing.SupportsInt) -> None"""
    def SetNumLargeDigits(self, arg0: typing.SupportsInt) -> None:
        """SetNumLargeDigits(self: openfhe.openfhe.CCParamsBFVRNS, arg0: typing.SupportsInt) -> None"""
    def SetPREMode(self, arg0: ProxyReEncryptionMode) -> None:
        """SetPREMode(self: openfhe.openfhe.CCParamsBFVRNS, arg0: openfhe.openfhe.ProxyReEncryptionMode) -> None"""
    def SetPRENumHops(self, arg0: typing.SupportsInt) -> None:
        """SetPRENumHops(self: openfhe.openfhe.CCParamsBFVRNS, arg0: typing.SupportsInt) -> None"""
    def SetPlaintextModulus(self, arg0: typing.SupportsInt) -> None:
        """SetPlaintextModulus(self: openfhe.openfhe.CCParamsBFVRNS, arg0: typing.SupportsInt) -> None"""
    def SetRegisterWordSize(self, arg0: typing.SupportsInt) -> None:
        """SetRegisterWordSize(self: openfhe.openfhe.CCParamsBFVRNS, arg0: typing.SupportsInt) -> None"""
    def SetRingDim(self, arg0: typing.SupportsInt) -> None:
        """SetRingDim(self: openfhe.openfhe.CCParamsBFVRNS, arg0: typing.SupportsInt) -> None"""
    def SetScalingModSize(self, arg0: typing.SupportsInt) -> None:
        """SetScalingModSize(self: openfhe.openfhe.CCParamsBFVRNS, arg0: typing.SupportsInt) -> None"""
    def SetScalingTechnique(self, arg0: ScalingTechnique) -> None:
        """SetScalingTechnique(self: openfhe.openfhe.CCParamsBFVRNS, arg0: openfhe.openfhe.ScalingTechnique) -> None"""
    def SetSecretKeyDist(self, arg0: SecretKeyDist) -> None:
        """SetSecretKeyDist(self: openfhe.openfhe.CCParamsBFVRNS, arg0: openfhe.openfhe.SecretKeyDist) -> None"""
    def SetSecurityLevel(self, arg0: SecurityLevel) -> None:
        """SetSecurityLevel(self: openfhe.openfhe.CCParamsBFVRNS, arg0: openfhe.openfhe.SecurityLevel) -> None"""
    def SetStandardDeviation(self, arg0: typing.SupportsFloat) -> None:
        """SetStandardDeviation(self: openfhe.openfhe.CCParamsBFVRNS, arg0: typing.SupportsFloat) -> None"""
    def SetStatisticalSecurity(self, arg0: typing.SupportsInt) -> None:
        """SetStatisticalSecurity(self: openfhe.openfhe.CCParamsBFVRNS, arg0: typing.SupportsInt) -> None"""
    def SetThresholdNumOfParties(self, arg0: typing.SupportsInt) -> None:
        """SetThresholdNumOfParties(self: openfhe.openfhe.CCParamsBFVRNS, arg0: typing.SupportsInt) -> None"""

class CCParamsBGVRNS:
    def __init__(self) -> None:
        """__init__(self: openfhe.openfhe.CCParamsBGVRNS) -> None"""
    def GetBatchSize(self) -> int:
        """GetBatchSize(self: openfhe.openfhe.CCParamsBGVRNS) -> int"""
    def GetCKKSDataType(self) -> CKKSDataType:
        """GetCKKSDataType(self: openfhe.openfhe.CCParamsBGVRNS) -> openfhe.openfhe.CKKSDataType"""
    def GetCompositeDegree(self) -> int:
        """GetCompositeDegree(self: openfhe.openfhe.CCParamsBGVRNS) -> int"""
    def GetDecryptionNoiseMode(self) -> DecryptionNoiseMode:
        """GetDecryptionNoiseMode(self: openfhe.openfhe.CCParamsBGVRNS) -> openfhe.openfhe.DecryptionNoiseMode"""
    def GetDesiredPrecision(self) -> float:
        """GetDesiredPrecision(self: openfhe.openfhe.CCParamsBGVRNS) -> float"""
    def GetDigitSize(self) -> int:
        """GetDigitSize(self: openfhe.openfhe.CCParamsBGVRNS) -> int"""
    def GetEncryptionTechnique(self) -> EncryptionTechnique:
        """GetEncryptionTechnique(self: openfhe.openfhe.CCParamsBGVRNS) -> openfhe.openfhe.EncryptionTechnique"""
    def GetEvalAddCount(self) -> int:
        """GetEvalAddCount(self: openfhe.openfhe.CCParamsBGVRNS) -> int"""
    def GetExecutionMode(self) -> ExecutionMode:
        """GetExecutionMode(self: openfhe.openfhe.CCParamsBGVRNS) -> openfhe.openfhe.ExecutionMode"""
    def GetFirstModSize(self) -> int:
        """GetFirstModSize(self: openfhe.openfhe.CCParamsBGVRNS) -> int"""
    def GetInteractiveBootCompressionLevel(self) -> COMPRESSION_LEVEL:
        """GetInteractiveBootCompressionLevel(self: openfhe.openfhe.CCParamsBGVRNS) -> openfhe.openfhe.COMPRESSION_LEVEL"""
    def GetKeySwitchCount(self) -> int:
        """GetKeySwitchCount(self: openfhe.openfhe.CCParamsBGVRNS) -> int"""
    def GetKeySwitchTechnique(self) -> KeySwitchTechnique:
        """GetKeySwitchTechnique(self: openfhe.openfhe.CCParamsBGVRNS) -> openfhe.openfhe.KeySwitchTechnique"""
    def GetMaxRelinSkDeg(self) -> int:
        """GetMaxRelinSkDeg(self: openfhe.openfhe.CCParamsBGVRNS) -> int"""
    def GetMultipartyMode(self) -> MultipartyMode:
        """GetMultipartyMode(self: openfhe.openfhe.CCParamsBGVRNS) -> openfhe.openfhe.MultipartyMode"""
    def GetMultiplicationTechnique(self) -> MultiplicationTechnique:
        """GetMultiplicationTechnique(self: openfhe.openfhe.CCParamsBGVRNS) -> openfhe.openfhe.MultiplicationTechnique"""
    def GetMultiplicativeDepth(self) -> int:
        """GetMultiplicativeDepth(self: openfhe.openfhe.CCParamsBGVRNS) -> int"""
    def GetNoiseEstimate(self) -> float:
        """GetNoiseEstimate(self: openfhe.openfhe.CCParamsBGVRNS) -> float"""
    def GetNumAdversarialQueries(self) -> float:
        """GetNumAdversarialQueries(self: openfhe.openfhe.CCParamsBGVRNS) -> float"""
    def GetNumLargeDigits(self) -> int:
        """GetNumLargeDigits(self: openfhe.openfhe.CCParamsBGVRNS) -> int"""
    def GetPREMode(self) -> ProxyReEncryptionMode:
        """GetPREMode(self: openfhe.openfhe.CCParamsBGVRNS) -> openfhe.openfhe.ProxyReEncryptionMode"""
    def GetPRENumHops(self) -> int:
        """GetPRENumHops(self: openfhe.openfhe.CCParamsBGVRNS) -> int"""
    def GetPlaintextModulus(self) -> int:
        """GetPlaintextModulus(self: openfhe.openfhe.CCParamsBGVRNS) -> int"""
    def GetRegisterWordSize(self) -> int:
        """GetRegisterWordSize(self: openfhe.openfhe.CCParamsBGVRNS) -> int"""
    def GetRingDim(self) -> int:
        """GetRingDim(self: openfhe.openfhe.CCParamsBGVRNS) -> int"""
    def GetScalingModSize(self) -> int:
        """GetScalingModSize(self: openfhe.openfhe.CCParamsBGVRNS) -> int"""
    def GetScalingTechnique(self) -> ScalingTechnique:
        """GetScalingTechnique(self: openfhe.openfhe.CCParamsBGVRNS) -> openfhe.openfhe.ScalingTechnique"""
    def GetScheme(self) -> SCHEME:
        """GetScheme(self: openfhe.openfhe.CCParamsBGVRNS) -> openfhe.openfhe.SCHEME"""
    def GetSecretKeyDist(self) -> SecretKeyDist:
        """GetSecretKeyDist(self: openfhe.openfhe.CCParamsBGVRNS) -> openfhe.openfhe.SecretKeyDist"""
    def GetSecurityLevel(self) -> SecurityLevel:
        """GetSecurityLevel(self: openfhe.openfhe.CCParamsBGVRNS) -> openfhe.openfhe.SecurityLevel"""
    def GetStandardDeviation(self) -> float:
        """GetStandardDeviation(self: openfhe.openfhe.CCParamsBGVRNS) -> float"""
    def GetStatisticalSecurity(self) -> float:
        """GetStatisticalSecurity(self: openfhe.openfhe.CCParamsBGVRNS) -> float"""
    def SetBatchSize(self, arg0: typing.SupportsInt) -> None:
        """SetBatchSize(self: openfhe.openfhe.CCParamsBGVRNS, arg0: typing.SupportsInt) -> None"""
    def SetCKKSDataType(self, arg0: CKKSDataType) -> None:
        """SetCKKSDataType(self: openfhe.openfhe.CCParamsBGVRNS, arg0: openfhe.openfhe.CKKSDataType) -> None"""
    def SetCompositeDegree(self, arg0: typing.SupportsInt) -> None:
        """SetCompositeDegree(self: openfhe.openfhe.CCParamsBGVRNS, arg0: typing.SupportsInt) -> None"""
    def SetDecryptionNoiseMode(self, arg0: DecryptionNoiseMode) -> None:
        """SetDecryptionNoiseMode(self: openfhe.openfhe.CCParamsBGVRNS, arg0: openfhe.openfhe.DecryptionNoiseMode) -> None"""
    def SetDesiredPrecision(self, arg0: typing.SupportsFloat) -> None:
        """SetDesiredPrecision(self: openfhe.openfhe.CCParamsBGVRNS, arg0: typing.SupportsFloat) -> None"""
    def SetDigitSize(self, arg0: typing.SupportsInt) -> None:
        """SetDigitSize(self: openfhe.openfhe.CCParamsBGVRNS, arg0: typing.SupportsInt) -> None"""
    def SetEncryptionTechnique(self, arg0: EncryptionTechnique) -> None:
        """SetEncryptionTechnique(self: openfhe.openfhe.CCParamsBGVRNS, arg0: openfhe.openfhe.EncryptionTechnique) -> None"""
    def SetEvalAddCount(self, arg0: typing.SupportsInt) -> None:
        """SetEvalAddCount(self: openfhe.openfhe.CCParamsBGVRNS, arg0: typing.SupportsInt) -> None"""
    def SetExecutionMode(self, arg0: ExecutionMode) -> None:
        """SetExecutionMode(self: openfhe.openfhe.CCParamsBGVRNS, arg0: openfhe.openfhe.ExecutionMode) -> None"""
    def SetFirstModSize(self, arg0: typing.SupportsInt) -> None:
        """SetFirstModSize(self: openfhe.openfhe.CCParamsBGVRNS, arg0: typing.SupportsInt) -> None"""
    def SetInteractiveBootCompressionLevel(self, arg0: COMPRESSION_LEVEL) -> None:
        """SetInteractiveBootCompressionLevel(self: openfhe.openfhe.CCParamsBGVRNS, arg0: openfhe.openfhe.COMPRESSION_LEVEL) -> None"""
    def SetKeySwitchCount(self, arg0: typing.SupportsInt) -> None:
        """SetKeySwitchCount(self: openfhe.openfhe.CCParamsBGVRNS, arg0: typing.SupportsInt) -> None"""
    def SetKeySwitchTechnique(self, arg0: KeySwitchTechnique) -> None:
        """SetKeySwitchTechnique(self: openfhe.openfhe.CCParamsBGVRNS, arg0: openfhe.openfhe.KeySwitchTechnique) -> None"""
    def SetMaxRelinSkDeg(self, arg0: typing.SupportsInt) -> None:
        """SetMaxRelinSkDeg(self: openfhe.openfhe.CCParamsBGVRNS, arg0: typing.SupportsInt) -> None"""
    def SetMultipartyMode(self, arg0: MultipartyMode) -> None:
        """SetMultipartyMode(self: openfhe.openfhe.CCParamsBGVRNS, arg0: openfhe.openfhe.MultipartyMode) -> None"""
    def SetMultiplicationTechnique(self, arg0: MultiplicationTechnique) -> None:
        """SetMultiplicationTechnique(self: openfhe.openfhe.CCParamsBGVRNS, arg0: openfhe.openfhe.MultiplicationTechnique) -> None"""
    def SetMultiplicativeDepth(self, arg0: typing.SupportsInt) -> None:
        """SetMultiplicativeDepth(self: openfhe.openfhe.CCParamsBGVRNS, arg0: typing.SupportsInt) -> None"""
    def SetNoiseEstimate(self, arg0: typing.SupportsFloat) -> None:
        """SetNoiseEstimate(self: openfhe.openfhe.CCParamsBGVRNS, arg0: typing.SupportsFloat) -> None"""
    def SetNumAdversarialQueries(self, arg0: typing.SupportsInt) -> None:
        """SetNumAdversarialQueries(self: openfhe.openfhe.CCParamsBGVRNS, arg0: typing.SupportsInt) -> None"""
    def SetNumLargeDigits(self, arg0: typing.SupportsInt) -> None:
        """SetNumLargeDigits(self: openfhe.openfhe.CCParamsBGVRNS, arg0: typing.SupportsInt) -> None"""
    def SetPREMode(self, arg0: ProxyReEncryptionMode) -> None:
        """SetPREMode(self: openfhe.openfhe.CCParamsBGVRNS, arg0: openfhe.openfhe.ProxyReEncryptionMode) -> None"""
    def SetPRENumHops(self, arg0: typing.SupportsInt) -> None:
        """SetPRENumHops(self: openfhe.openfhe.CCParamsBGVRNS, arg0: typing.SupportsInt) -> None"""
    def SetPlaintextModulus(self, arg0: typing.SupportsInt) -> None:
        """SetPlaintextModulus(self: openfhe.openfhe.CCParamsBGVRNS, arg0: typing.SupportsInt) -> None"""
    def SetRegisterWordSize(self, arg0: typing.SupportsInt) -> None:
        """SetRegisterWordSize(self: openfhe.openfhe.CCParamsBGVRNS, arg0: typing.SupportsInt) -> None"""
    def SetRingDim(self, arg0: typing.SupportsInt) -> None:
        """SetRingDim(self: openfhe.openfhe.CCParamsBGVRNS, arg0: typing.SupportsInt) -> None"""
    def SetScalingModSize(self, arg0: typing.SupportsInt) -> None:
        """SetScalingModSize(self: openfhe.openfhe.CCParamsBGVRNS, arg0: typing.SupportsInt) -> None"""
    def SetScalingTechnique(self, arg0: ScalingTechnique) -> None:
        """SetScalingTechnique(self: openfhe.openfhe.CCParamsBGVRNS, arg0: openfhe.openfhe.ScalingTechnique) -> None"""
    def SetSecretKeyDist(self, arg0: SecretKeyDist) -> None:
        """SetSecretKeyDist(self: openfhe.openfhe.CCParamsBGVRNS, arg0: openfhe.openfhe.SecretKeyDist) -> None"""
    def SetSecurityLevel(self, arg0: SecurityLevel) -> None:
        """SetSecurityLevel(self: openfhe.openfhe.CCParamsBGVRNS, arg0: openfhe.openfhe.SecurityLevel) -> None"""
    def SetStandardDeviation(self, arg0: typing.SupportsFloat) -> None:
        """SetStandardDeviation(self: openfhe.openfhe.CCParamsBGVRNS, arg0: typing.SupportsFloat) -> None"""
    def SetStatisticalSecurity(self, arg0: typing.SupportsInt) -> None:
        """SetStatisticalSecurity(self: openfhe.openfhe.CCParamsBGVRNS, arg0: typing.SupportsInt) -> None"""
    def SetThresholdNumOfParties(self, arg0: typing.SupportsInt) -> None:
        """SetThresholdNumOfParties(self: openfhe.openfhe.CCParamsBGVRNS, arg0: typing.SupportsInt) -> None"""

class CCParamsCKKSRNS:
    def __init__(self) -> None:
        """__init__(self: openfhe.openfhe.CCParamsCKKSRNS) -> None"""
    def GetBatchSize(self) -> int:
        """GetBatchSize(self: openfhe.openfhe.CCParamsCKKSRNS) -> int"""
    def GetCKKSDataType(self) -> CKKSDataType:
        """GetCKKSDataType(self: openfhe.openfhe.CCParamsCKKSRNS) -> openfhe.openfhe.CKKSDataType"""
    def GetCompositeDegree(self) -> int:
        """GetCompositeDegree(self: openfhe.openfhe.CCParamsCKKSRNS) -> int"""
    def GetDecryptionNoiseMode(self) -> DecryptionNoiseMode:
        """GetDecryptionNoiseMode(self: openfhe.openfhe.CCParamsCKKSRNS) -> openfhe.openfhe.DecryptionNoiseMode"""
    def GetDesiredPrecision(self) -> float:
        """GetDesiredPrecision(self: openfhe.openfhe.CCParamsCKKSRNS) -> float"""
    def GetDigitSize(self) -> int:
        """GetDigitSize(self: openfhe.openfhe.CCParamsCKKSRNS) -> int"""
    def GetEncryptionTechnique(self) -> EncryptionTechnique:
        """GetEncryptionTechnique(self: openfhe.openfhe.CCParamsCKKSRNS) -> openfhe.openfhe.EncryptionTechnique"""
    def GetEvalAddCount(self) -> int:
        """GetEvalAddCount(self: openfhe.openfhe.CCParamsCKKSRNS) -> int"""
    def GetExecutionMode(self) -> ExecutionMode:
        """GetExecutionMode(self: openfhe.openfhe.CCParamsCKKSRNS) -> openfhe.openfhe.ExecutionMode"""
    def GetFirstModSize(self) -> int:
        """GetFirstModSize(self: openfhe.openfhe.CCParamsCKKSRNS) -> int"""
    def GetInteractiveBootCompressionLevel(self) -> COMPRESSION_LEVEL:
        """GetInteractiveBootCompressionLevel(self: openfhe.openfhe.CCParamsCKKSRNS) -> openfhe.openfhe.COMPRESSION_LEVEL"""
    def GetKeySwitchCount(self) -> int:
        """GetKeySwitchCount(self: openfhe.openfhe.CCParamsCKKSRNS) -> int"""
    def GetKeySwitchTechnique(self) -> KeySwitchTechnique:
        """GetKeySwitchTechnique(self: openfhe.openfhe.CCParamsCKKSRNS) -> openfhe.openfhe.KeySwitchTechnique"""
    def GetMaxRelinSkDeg(self) -> int:
        """GetMaxRelinSkDeg(self: openfhe.openfhe.CCParamsCKKSRNS) -> int"""
    def GetMultipartyMode(self) -> MultipartyMode:
        """GetMultipartyMode(self: openfhe.openfhe.CCParamsCKKSRNS) -> openfhe.openfhe.MultipartyMode"""
    def GetMultiplicationTechnique(self) -> MultiplicationTechnique:
        """GetMultiplicationTechnique(self: openfhe.openfhe.CCParamsCKKSRNS) -> openfhe.openfhe.MultiplicationTechnique"""
    def GetMultiplicativeDepth(self) -> int:
        """GetMultiplicativeDepth(self: openfhe.openfhe.CCParamsCKKSRNS) -> int"""
    def GetNoiseEstimate(self) -> float:
        """GetNoiseEstimate(self: openfhe.openfhe.CCParamsCKKSRNS) -> float"""
    def GetNumAdversarialQueries(self) -> float:
        """GetNumAdversarialQueries(self: openfhe.openfhe.CCParamsCKKSRNS) -> float"""
    def GetNumLargeDigits(self) -> int:
        """GetNumLargeDigits(self: openfhe.openfhe.CCParamsCKKSRNS) -> int"""
    def GetPREMode(self) -> ProxyReEncryptionMode:
        """GetPREMode(self: openfhe.openfhe.CCParamsCKKSRNS) -> openfhe.openfhe.ProxyReEncryptionMode"""
    def GetPRENumHops(self) -> int:
        """GetPRENumHops(self: openfhe.openfhe.CCParamsCKKSRNS) -> int"""
    def GetPlaintextModulus(self) -> int:
        """GetPlaintextModulus(self: openfhe.openfhe.CCParamsCKKSRNS) -> int"""
    def GetRegisterWordSize(self) -> int:
        """GetRegisterWordSize(self: openfhe.openfhe.CCParamsCKKSRNS) -> int"""
    def GetRingDim(self) -> int:
        """GetRingDim(self: openfhe.openfhe.CCParamsCKKSRNS) -> int"""
    def GetScalingModSize(self) -> int:
        """GetScalingModSize(self: openfhe.openfhe.CCParamsCKKSRNS) -> int"""
    def GetScalingTechnique(self) -> ScalingTechnique:
        """GetScalingTechnique(self: openfhe.openfhe.CCParamsCKKSRNS) -> openfhe.openfhe.ScalingTechnique"""
    def GetScheme(self) -> SCHEME:
        """GetScheme(self: openfhe.openfhe.CCParamsCKKSRNS) -> openfhe.openfhe.SCHEME"""
    def GetSecretKeyDist(self) -> SecretKeyDist:
        """GetSecretKeyDist(self: openfhe.openfhe.CCParamsCKKSRNS) -> openfhe.openfhe.SecretKeyDist"""
    def GetSecurityLevel(self) -> SecurityLevel:
        """GetSecurityLevel(self: openfhe.openfhe.CCParamsCKKSRNS) -> openfhe.openfhe.SecurityLevel"""
    def GetStandardDeviation(self) -> float:
        """GetStandardDeviation(self: openfhe.openfhe.CCParamsCKKSRNS) -> float"""
    def GetStatisticalSecurity(self) -> float:
        """GetStatisticalSecurity(self: openfhe.openfhe.CCParamsCKKSRNS) -> float"""
    def SetBatchSize(self, arg0: typing.SupportsInt) -> None:
        """SetBatchSize(self: openfhe.openfhe.CCParamsCKKSRNS, arg0: typing.SupportsInt) -> None"""
    def SetCKKSDataType(self, arg0: CKKSDataType) -> None:
        """SetCKKSDataType(self: openfhe.openfhe.CCParamsCKKSRNS, arg0: openfhe.openfhe.CKKSDataType) -> None"""
    def SetCompositeDegree(self, arg0: typing.SupportsInt) -> None:
        """SetCompositeDegree(self: openfhe.openfhe.CCParamsCKKSRNS, arg0: typing.SupportsInt) -> None"""
    def SetDecryptionNoiseMode(self, arg0: DecryptionNoiseMode) -> None:
        """SetDecryptionNoiseMode(self: openfhe.openfhe.CCParamsCKKSRNS, arg0: openfhe.openfhe.DecryptionNoiseMode) -> None"""
    def SetDesiredPrecision(self, arg0: typing.SupportsFloat) -> None:
        """SetDesiredPrecision(self: openfhe.openfhe.CCParamsCKKSRNS, arg0: typing.SupportsFloat) -> None"""
    def SetDigitSize(self, arg0: typing.SupportsInt) -> None:
        """SetDigitSize(self: openfhe.openfhe.CCParamsCKKSRNS, arg0: typing.SupportsInt) -> None"""
    def SetEncryptionTechnique(self, arg0: EncryptionTechnique) -> None:
        """SetEncryptionTechnique(self: openfhe.openfhe.CCParamsCKKSRNS, arg0: openfhe.openfhe.EncryptionTechnique) -> None"""
    def SetEvalAddCount(self, arg0: typing.SupportsInt) -> None:
        """SetEvalAddCount(self: openfhe.openfhe.CCParamsCKKSRNS, arg0: typing.SupportsInt) -> None"""
    def SetExecutionMode(self, arg0: ExecutionMode) -> None:
        """SetExecutionMode(self: openfhe.openfhe.CCParamsCKKSRNS, arg0: openfhe.openfhe.ExecutionMode) -> None"""
    def SetFirstModSize(self, arg0: typing.SupportsInt) -> None:
        """SetFirstModSize(self: openfhe.openfhe.CCParamsCKKSRNS, arg0: typing.SupportsInt) -> None"""
    def SetInteractiveBootCompressionLevel(self, arg0: COMPRESSION_LEVEL) -> None:
        """SetInteractiveBootCompressionLevel(self: openfhe.openfhe.CCParamsCKKSRNS, arg0: openfhe.openfhe.COMPRESSION_LEVEL) -> None"""
    def SetKeySwitchCount(self, arg0: typing.SupportsInt) -> None:
        """SetKeySwitchCount(self: openfhe.openfhe.CCParamsCKKSRNS, arg0: typing.SupportsInt) -> None"""
    def SetKeySwitchTechnique(self, arg0: KeySwitchTechnique) -> None:
        """SetKeySwitchTechnique(self: openfhe.openfhe.CCParamsCKKSRNS, arg0: openfhe.openfhe.KeySwitchTechnique) -> None"""
    def SetMaxRelinSkDeg(self, arg0: typing.SupportsInt) -> None:
        """SetMaxRelinSkDeg(self: openfhe.openfhe.CCParamsCKKSRNS, arg0: typing.SupportsInt) -> None"""
    def SetMultipartyMode(self, arg0: MultipartyMode) -> None:
        """SetMultipartyMode(self: openfhe.openfhe.CCParamsCKKSRNS, arg0: openfhe.openfhe.MultipartyMode) -> None"""
    def SetMultiplicationTechnique(self, arg0: MultiplicationTechnique) -> None:
        """SetMultiplicationTechnique(self: openfhe.openfhe.CCParamsCKKSRNS, arg0: openfhe.openfhe.MultiplicationTechnique) -> None"""
    def SetMultiplicativeDepth(self, arg0: typing.SupportsInt) -> None:
        """SetMultiplicativeDepth(self: openfhe.openfhe.CCParamsCKKSRNS, arg0: typing.SupportsInt) -> None"""
    def SetNoiseEstimate(self, arg0: typing.SupportsFloat) -> None:
        """SetNoiseEstimate(self: openfhe.openfhe.CCParamsCKKSRNS, arg0: typing.SupportsFloat) -> None"""
    def SetNumAdversarialQueries(self, arg0: typing.SupportsInt) -> None:
        """SetNumAdversarialQueries(self: openfhe.openfhe.CCParamsCKKSRNS, arg0: typing.SupportsInt) -> None"""
    def SetNumLargeDigits(self, arg0: typing.SupportsInt) -> None:
        """SetNumLargeDigits(self: openfhe.openfhe.CCParamsCKKSRNS, arg0: typing.SupportsInt) -> None"""
    def SetPREMode(self, arg0: ProxyReEncryptionMode) -> None:
        """SetPREMode(self: openfhe.openfhe.CCParamsCKKSRNS, arg0: openfhe.openfhe.ProxyReEncryptionMode) -> None"""
    def SetPRENumHops(self, arg0: typing.SupportsInt) -> None:
        """SetPRENumHops(self: openfhe.openfhe.CCParamsCKKSRNS, arg0: typing.SupportsInt) -> None"""
    def SetPlaintextModulus(self, arg0: typing.SupportsInt) -> None:
        """SetPlaintextModulus(self: openfhe.openfhe.CCParamsCKKSRNS, arg0: typing.SupportsInt) -> None"""
    def SetRegisterWordSize(self, arg0: typing.SupportsInt) -> None:
        """SetRegisterWordSize(self: openfhe.openfhe.CCParamsCKKSRNS, arg0: typing.SupportsInt) -> None"""
    def SetRingDim(self, arg0: typing.SupportsInt) -> None:
        """SetRingDim(self: openfhe.openfhe.CCParamsCKKSRNS, arg0: typing.SupportsInt) -> None"""
    def SetScalingModSize(self, arg0: typing.SupportsInt) -> None:
        """SetScalingModSize(self: openfhe.openfhe.CCParamsCKKSRNS, arg0: typing.SupportsInt) -> None"""
    def SetScalingTechnique(self, arg0: ScalingTechnique) -> None:
        """SetScalingTechnique(self: openfhe.openfhe.CCParamsCKKSRNS, arg0: openfhe.openfhe.ScalingTechnique) -> None"""
    def SetSecretKeyDist(self, arg0: SecretKeyDist) -> None:
        """SetSecretKeyDist(self: openfhe.openfhe.CCParamsCKKSRNS, arg0: openfhe.openfhe.SecretKeyDist) -> None"""
    def SetSecurityLevel(self, arg0: SecurityLevel) -> None:
        """SetSecurityLevel(self: openfhe.openfhe.CCParamsCKKSRNS, arg0: openfhe.openfhe.SecurityLevel) -> None"""
    def SetStandardDeviation(self, arg0: typing.SupportsFloat) -> None:
        """SetStandardDeviation(self: openfhe.openfhe.CCParamsCKKSRNS, arg0: typing.SupportsFloat) -> None"""
    def SetStatisticalSecurity(self, arg0: typing.SupportsInt) -> None:
        """SetStatisticalSecurity(self: openfhe.openfhe.CCParamsCKKSRNS, arg0: typing.SupportsInt) -> None"""
    def SetThresholdNumOfParties(self, arg0: typing.SupportsInt) -> None:
        """SetThresholdNumOfParties(self: openfhe.openfhe.CCParamsCKKSRNS, arg0: typing.SupportsInt) -> None"""

class CKKSDataType:
    """Members:

    REAL

    COMPLEX"""

    __members__: ClassVar[dict] = ...  # read-only
    COMPLEX: ClassVar[CKKSDataType] = ...
    REAL: ClassVar[CKKSDataType] = ...
    __entries: ClassVar[dict] = ...
    def __init__(self, value: typing.SupportsInt) -> None:
        """__init__(self: openfhe.openfhe.CKKSDataType, value: typing.SupportsInt) -> None"""
    def __eq__(self, other: object) -> bool:
        """__eq__(self: object, other: object, /) -> bool"""
    def __hash__(self) -> int:
        """__hash__(self: object, /) -> int"""
    def __index__(self) -> int:
        """__index__(self: openfhe.openfhe.CKKSDataType, /) -> int"""
    def __int__(self) -> int:
        """__int__(self: openfhe.openfhe.CKKSDataType, /) -> int"""
    def __ne__(self, other: object) -> bool:
        """__ne__(self: object, other: object, /) -> bool"""
    @property
    def name(self) -> str:
        """name(self: object, /) -> str

        name(self: object, /) -> str
        """
    @property
    def value(self) -> int:
        """(arg0: openfhe.openfhe.CKKSDataType) -> int"""

class COMPRESSION_LEVEL:
    """Members:

    COMPACT

    SLACK"""

    __members__: ClassVar[dict] = ...  # read-only
    COMPACT: ClassVar[COMPRESSION_LEVEL] = ...
    SLACK: ClassVar[COMPRESSION_LEVEL] = ...
    __entries: ClassVar[dict] = ...
    def __init__(self, value: typing.SupportsInt) -> None:
        """__init__(self: openfhe.openfhe.COMPRESSION_LEVEL, value: typing.SupportsInt) -> None"""
    def __eq__(self, other: object) -> bool:
        """__eq__(self: object, other: object, /) -> bool"""
    def __hash__(self) -> int:
        """__hash__(self: object, /) -> int"""
    def __index__(self) -> int:
        """__index__(self: openfhe.openfhe.COMPRESSION_LEVEL, /) -> int"""
    def __int__(self) -> int:
        """__int__(self: openfhe.openfhe.COMPRESSION_LEVEL, /) -> int"""
    def __ne__(self, other: object) -> bool:
        """__ne__(self: object, other: object, /) -> bool"""
    @property
    def name(self) -> str:
        """name(self: object, /) -> str

        name(self: object, /) -> str
        """
    @property
    def value(self) -> int:
        """(arg0: openfhe.openfhe.COMPRESSION_LEVEL) -> int"""

class Ciphertext:
    def __init__(self) -> None:
        """__init__(self: openfhe.openfhe.Ciphertext) -> None"""
    def Clone(self) -> Ciphertext:
        """Clone(self: openfhe.openfhe.Ciphertext) -> openfhe.openfhe.Ciphertext"""
    def GetCryptoContext(self, *args, **kwargs):
        """GetCryptoContext(self: openfhe.openfhe.Ciphertext) -> lbcrypto::CryptoContextImpl<lbcrypto::DCRTPolyImpl<bigintdyn::mubintvec<bigintdyn::ubint<unsigned long> > > >"""
    def GetElements(self) -> list[DCRTPoly]:
        """GetElements(self: openfhe.openfhe.Ciphertext) -> list[openfhe.openfhe.DCRTPoly]"""
    def GetElementsMutable(self) -> list[DCRTPoly]:
        """GetElementsMutable(self: openfhe.openfhe.Ciphertext) -> list[openfhe.openfhe.DCRTPoly]"""
    def GetEncodingType(self, *args, **kwargs):
        """GetEncodingType(self: openfhe.openfhe.Ciphertext) -> lbcrypto::PlaintextEncodings"""
    def GetLevel(self) -> int:
        """GetLevel(self: openfhe.openfhe.Ciphertext) -> int


        Get the number of scalings performed.

        :return: The level of the ciphertext.
        :rtype: int

        """
    def GetNoiseScaleDeg(self) -> int:
        """GetNoiseScaleDeg(self: openfhe.openfhe.Ciphertext) -> int"""
    def GetSlots(self) -> int:
        """GetSlots(self: openfhe.openfhe.Ciphertext) -> int"""
    def RemoveElement(self, index: typing.SupportsInt) -> None:
        """RemoveElement(self: openfhe.openfhe.Ciphertext, index: typing.SupportsInt) -> None


        Remove an element from the ciphertext inner vector given its index.

        :param index: The index of the element to remove.
        :type index: int

        """
    def SetElements(self, arg0: collections.abc.Sequence[DCRTPoly]) -> None:
        """SetElements(self: openfhe.openfhe.Ciphertext, arg0: collections.abc.Sequence[openfhe.openfhe.DCRTPoly]) -> None"""
    def SetElementsMove(self, arg0: collections.abc.Sequence[DCRTPoly]) -> None:
        """SetElementsMove(self: openfhe.openfhe.Ciphertext, arg0: collections.abc.Sequence[openfhe.openfhe.DCRTPoly]) -> None"""
    def SetLevel(self, level: typing.SupportsInt) -> None:
        """SetLevel(self: openfhe.openfhe.Ciphertext, level: typing.SupportsInt) -> None


        Set the number of scalings.

        :param level: The level to set.
        :type level: int

        """
    def SetNoiseScaleDeg(self, arg0: typing.SupportsInt) -> None:
        """SetNoiseScaleDeg(self: openfhe.openfhe.Ciphertext, arg0: typing.SupportsInt) -> None"""
    def SetSlots(self, arg0: typing.SupportsInt) -> None:
        """SetSlots(self: openfhe.openfhe.Ciphertext, arg0: typing.SupportsInt) -> None"""
    def __add__(self, arg0: Ciphertext) -> Ciphertext:
        """__add__(self: openfhe.openfhe.Ciphertext, arg0: openfhe.openfhe.Ciphertext) -> openfhe.openfhe.Ciphertext"""

class CryptoContext:
    def __init__(self) -> None:
        """__init__(self: openfhe.openfhe.CryptoContext) -> None"""
    @staticmethod
    def ClearEvalAutomorphismKeys() -> None:
        """ClearEvalAutomorphismKeys() -> None


        Flush EvalAutomorphismKey cache

        """
    def Compress(self, ciphertext: Ciphertext, towersLeft: typing.SupportsInt) -> Ciphertext:
        """Compress(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, towersLeft: typing.SupportsInt) -> openfhe.openfhe.Ciphertext"""
    @overload
    def Decrypt(self, privateKey: PrivateKey, ciphertext: Ciphertext) -> Plaintext:
        """Decrypt(*args, **kwargs)
        Overloaded function.

        1. Decrypt(self: openfhe.openfhe.CryptoContext, privateKey: openfhe.openfhe.PrivateKey, ciphertext: openfhe.openfhe.Ciphertext) -> openfhe.openfhe.Plaintext


        Decrypt a single ciphertext into the appropriate plaintext

        :param ciphertext: ciphertext to decrypt
        :type ciphertext: Ciphertext
        :param privateKey: decryption key
        :type privateKey: PrivateKey
        :return: decrypted plaintext
        :rtype: Plaintext


        2. Decrypt(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, privateKey: openfhe.openfhe.PrivateKey) -> openfhe.openfhe.Plaintext


        Decrypt a single ciphertext into the appropriate plaintext

        :param ciphertext: ciphertext to decrypt
        :type ciphertext: Ciphertext
        :param privateKey: decryption key
        :type privateKey: PrivateKey
        :return: decrypted plaintext
        :rtype: Plaintext

        """
    @overload
    def Decrypt(self, ciphertext: Ciphertext, privateKey: PrivateKey) -> Plaintext:
        """Decrypt(*args, **kwargs)
        Overloaded function.

        1. Decrypt(self: openfhe.openfhe.CryptoContext, privateKey: openfhe.openfhe.PrivateKey, ciphertext: openfhe.openfhe.Ciphertext) -> openfhe.openfhe.Plaintext


        Decrypt a single ciphertext into the appropriate plaintext

        :param ciphertext: ciphertext to decrypt
        :type ciphertext: Ciphertext
        :param privateKey: decryption key
        :type privateKey: PrivateKey
        :return: decrypted plaintext
        :rtype: Plaintext


        2. Decrypt(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, privateKey: openfhe.openfhe.PrivateKey) -> openfhe.openfhe.Plaintext


        Decrypt a single ciphertext into the appropriate plaintext

        :param ciphertext: ciphertext to decrypt
        :type ciphertext: Ciphertext
        :param privateKey: decryption key
        :type privateKey: PrivateKey
        :return: decrypted plaintext
        :rtype: Plaintext

        """
    @overload
    @staticmethod
    def DeserializeEvalAutomorphismKey(filename: str, sertype: SERBINARY) -> bool:
        """DeserializeEvalAutomorphismKey(*args, **kwargs)
        Overloaded function.

        1. DeserializeEvalAutomorphismKey(filename: str, sertype: openfhe.openfhe.SERBINARY) -> bool


            DeserializeEvalAutomorphismKey deserialize all keys in the serialization deserialized keys silently replace any existing matching keys deserialization will create CryptoContext if necessary

            :param filename: path for the file to deserialize from
            :type filename: str
            :param sertype: type of serialization
            :type sertype: SERJSON, SERBINARY
            :return: bool: true on success


        2. DeserializeEvalAutomorphismKey(filename: str, sertype: openfhe.openfhe.SERJSON) -> bool


            DeserializeEvalAutomorphismKey deserialize all keys in the serialization deserialized keys silently replace any existing matching keys deserialization will create CryptoContext if necessary

            :param filename: path for the file to deserialize from
            :type filename: str
            :param sertype: type of serialization
            :type sertype: SERJSON, SERBINARY
            :return: bool: true on success

        """
    @overload
    @staticmethod
    def DeserializeEvalAutomorphismKey(filename: str, sertype: SERJSON) -> bool:
        """DeserializeEvalAutomorphismKey(*args, **kwargs)
        Overloaded function.

        1. DeserializeEvalAutomorphismKey(filename: str, sertype: openfhe.openfhe.SERBINARY) -> bool


            DeserializeEvalAutomorphismKey deserialize all keys in the serialization deserialized keys silently replace any existing matching keys deserialization will create CryptoContext if necessary

            :param filename: path for the file to deserialize from
            :type filename: str
            :param sertype: type of serialization
            :type sertype: SERJSON, SERBINARY
            :return: bool: true on success


        2. DeserializeEvalAutomorphismKey(filename: str, sertype: openfhe.openfhe.SERJSON) -> bool


            DeserializeEvalAutomorphismKey deserialize all keys in the serialization deserialized keys silently replace any existing matching keys deserialization will create CryptoContext if necessary

            :param filename: path for the file to deserialize from
            :type filename: str
            :param sertype: type of serialization
            :type sertype: SERJSON, SERBINARY
            :return: bool: true on success

        """
    @overload
    @staticmethod
    def DeserializeEvalMultKey(filename: str, sertype: SERBINARY) -> bool:
        """DeserializeEvalMultKey(*args, **kwargs)
        Overloaded function.

        1. DeserializeEvalMultKey(filename: str, sertype: openfhe.openfhe.SERBINARY) -> bool


            DeserializeEvalMultKey deserialize all keys in the serialization deserialized keys silently replace any existing matching keys deserialization will create CryptoContext if necessary

            :param filename: path for the file to deserialize from
            :type filename: str
            :param sertype: type of serialization
            :type sertype: SERJSON, SERBINARY
            :return: bool: true on success


        2. DeserializeEvalMultKey(filename: str, sertype: openfhe.openfhe.SERJSON) -> bool


            DeserializeEvalMultKey deserialize all keys in the serialization deserialized keys silently replace any existing matching keys deserialization will create CryptoContext if necessary

            :param filename: path for the file to deserialize from
            :type filename: str
            :param sertype: type of serialization
            :type sertype: SERJSON, SERBINARY
            :return: bool: true on success

        """
    @overload
    @staticmethod
    def DeserializeEvalMultKey(filename: str, sertype: SERJSON) -> bool:
        """DeserializeEvalMultKey(*args, **kwargs)
        Overloaded function.

        1. DeserializeEvalMultKey(filename: str, sertype: openfhe.openfhe.SERBINARY) -> bool


            DeserializeEvalMultKey deserialize all keys in the serialization deserialized keys silently replace any existing matching keys deserialization will create CryptoContext if necessary

            :param filename: path for the file to deserialize from
            :type filename: str
            :param sertype: type of serialization
            :type sertype: SERJSON, SERBINARY
            :return: bool: true on success


        2. DeserializeEvalMultKey(filename: str, sertype: openfhe.openfhe.SERJSON) -> bool


            DeserializeEvalMultKey deserialize all keys in the serialization deserialized keys silently replace any existing matching keys deserialization will create CryptoContext if necessary

            :param filename: path for the file to deserialize from
            :type filename: str
            :param sertype: type of serialization
            :type sertype: SERJSON, SERBINARY
            :return: bool: true on success

        """
    def Enable(self, feature: PKESchemeFeature) -> None:
        """Enable(self: openfhe.openfhe.CryptoContext, feature: openfhe.openfhe.PKESchemeFeature) -> None


        Enable a particular feature for use with this CryptoContext

        :param feature: the feature that should be enabled.
                        The list of available features is defined in the PKESchemeFeature enum.
        :type feature: PKESchemeFeature

        """
    def Encrypt(self, publicKey: PublicKey, plaintext: Plaintext) -> Ciphertext:
        """Encrypt(self: openfhe.openfhe.CryptoContext, publicKey: openfhe.openfhe.PublicKey, plaintext: openfhe.openfhe.Plaintext) -> openfhe.openfhe.Ciphertext


        Encrypt a plaintext using a given public key

        :param plaintext: plaintext
        :type plaintext: Plaintext
        :param publicKey: public key
        :type publicKey: PublicKey
        :return: ciphertext (or null on failure)
        :rtype: Ciphertext

        """
    @overload
    def EvalAdd(self, ciphertext1: Ciphertext, ciphertext2: Ciphertext) -> Ciphertext:
        """EvalAdd(*args, **kwargs)
        Overloaded function.

        1. EvalAdd(self: openfhe.openfhe.CryptoContext, ciphertext1: openfhe.openfhe.Ciphertext, ciphertext2: openfhe.openfhe.Ciphertext) -> openfhe.openfhe.Ciphertext


        Homomorphic addition of two ciphertexts

        :param ciphertext1: first addend
        :type ciphertext1: Ciphertext
        :param ciphertext2: second addend
        :type ciphertext2: Ciphertext
        :return: the result as a new ciphertext
        :rtype: Ciphertext


        2. EvalAdd(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, scalar: typing.SupportsFloat) -> openfhe.openfhe.Ciphertext


        EvalAdd - OpenFHE EvalAdd method for a ciphertext and a real number. Supported only in CKKS.

        :param ciphertext: input ciphertext
        :type ciphertext: Ciphertext
        :param constant: a real number
        :type constant: float
        :return: new ciphertext for ciphertext + constant
        :rtype: Ciphertext


        3. EvalAdd(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, plaintext: openfhe.openfhe.Plaintext) -> openfhe.openfhe.Ciphertext


        EvalAdd - OpenFHE EvalAdd method for a ciphertext and plaintext

        :param ciphertext: input ciphertext
        :type ciphertext: Ciphertext
        :param plaintex: input plaintext
        :type plaintext: Plaintext
        :return: new ciphertext for ciphertext + constant
        :rtype: Ciphertext

        """
    @overload
    def EvalAdd(self, ciphertext: Ciphertext, scalar: typing.SupportsFloat) -> Ciphertext:
        """EvalAdd(*args, **kwargs)
        Overloaded function.

        1. EvalAdd(self: openfhe.openfhe.CryptoContext, ciphertext1: openfhe.openfhe.Ciphertext, ciphertext2: openfhe.openfhe.Ciphertext) -> openfhe.openfhe.Ciphertext


        Homomorphic addition of two ciphertexts

        :param ciphertext1: first addend
        :type ciphertext1: Ciphertext
        :param ciphertext2: second addend
        :type ciphertext2: Ciphertext
        :return: the result as a new ciphertext
        :rtype: Ciphertext


        2. EvalAdd(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, scalar: typing.SupportsFloat) -> openfhe.openfhe.Ciphertext


        EvalAdd - OpenFHE EvalAdd method for a ciphertext and a real number. Supported only in CKKS.

        :param ciphertext: input ciphertext
        :type ciphertext: Ciphertext
        :param constant: a real number
        :type constant: float
        :return: new ciphertext for ciphertext + constant
        :rtype: Ciphertext


        3. EvalAdd(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, plaintext: openfhe.openfhe.Plaintext) -> openfhe.openfhe.Ciphertext


        EvalAdd - OpenFHE EvalAdd method for a ciphertext and plaintext

        :param ciphertext: input ciphertext
        :type ciphertext: Ciphertext
        :param plaintex: input plaintext
        :type plaintext: Plaintext
        :return: new ciphertext for ciphertext + constant
        :rtype: Ciphertext

        """
    @overload
    def EvalAdd(self, ciphertext: Ciphertext, plaintext: Plaintext) -> Ciphertext:
        """EvalAdd(*args, **kwargs)
        Overloaded function.

        1. EvalAdd(self: openfhe.openfhe.CryptoContext, ciphertext1: openfhe.openfhe.Ciphertext, ciphertext2: openfhe.openfhe.Ciphertext) -> openfhe.openfhe.Ciphertext


        Homomorphic addition of two ciphertexts

        :param ciphertext1: first addend
        :type ciphertext1: Ciphertext
        :param ciphertext2: second addend
        :type ciphertext2: Ciphertext
        :return: the result as a new ciphertext
        :rtype: Ciphertext


        2. EvalAdd(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, scalar: typing.SupportsFloat) -> openfhe.openfhe.Ciphertext


        EvalAdd - OpenFHE EvalAdd method for a ciphertext and a real number. Supported only in CKKS.

        :param ciphertext: input ciphertext
        :type ciphertext: Ciphertext
        :param constant: a real number
        :type constant: float
        :return: new ciphertext for ciphertext + constant
        :rtype: Ciphertext


        3. EvalAdd(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, plaintext: openfhe.openfhe.Plaintext) -> openfhe.openfhe.Ciphertext


        EvalAdd - OpenFHE EvalAdd method for a ciphertext and plaintext

        :param ciphertext: input ciphertext
        :type ciphertext: Ciphertext
        :param plaintex: input plaintext
        :type plaintext: Plaintext
        :return: new ciphertext for ciphertext + constant
        :rtype: Ciphertext

        """
    @overload
    def EvalAddInPlace(self, ciphertext1: Ciphertext, ciphertext2: Ciphertext) -> None:
        """EvalAddInPlace(*args, **kwargs)
        Overloaded function.

        1. EvalAddInPlace(self: openfhe.openfhe.CryptoContext, ciphertext1: openfhe.openfhe.Ciphertext, ciphertext2: openfhe.openfhe.Ciphertext) -> None


        In-place homomorphic addition of two ciphertexts

        :param ciphertext1: ciphertext1
        :type ciphertext1: Ciphertext
        :param ciphertext2: second addend
        :type ciphertext2: Ciphertext
        :return: ciphertext1 contains ciphertext1 + ciphertext2


        2. EvalAddInPlace(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, plaintext: openfhe.openfhe.Plaintext) -> None


        In-place addition for a ciphertext and plaintext

        :param ciphertext: Input/output ciphertext
        :type ciphertext: Ciphertext
        :param plaintext: Input plaintext
        :type plaintext: Plaintext
        :return: ciphertext contains ciphertext + plaintext


        3. EvalAddInPlace(self: openfhe.openfhe.CryptoContext, plaintext: openfhe.openfhe.Plaintext, ciphertext: openfhe.openfhe.Ciphertext) -> None

        4. EvalAddInPlace(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, scalar: typing.SupportsFloat) -> None

        5. EvalAddInPlace(self: openfhe.openfhe.CryptoContext, scalar: typing.SupportsFloat, ciphertext: openfhe.openfhe.Ciphertext) -> None
        """
    @overload
    def EvalAddInPlace(self, ciphertext: Ciphertext, plaintext: Plaintext) -> None:
        """EvalAddInPlace(*args, **kwargs)
        Overloaded function.

        1. EvalAddInPlace(self: openfhe.openfhe.CryptoContext, ciphertext1: openfhe.openfhe.Ciphertext, ciphertext2: openfhe.openfhe.Ciphertext) -> None


        In-place homomorphic addition of two ciphertexts

        :param ciphertext1: ciphertext1
        :type ciphertext1: Ciphertext
        :param ciphertext2: second addend
        :type ciphertext2: Ciphertext
        :return: ciphertext1 contains ciphertext1 + ciphertext2


        2. EvalAddInPlace(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, plaintext: openfhe.openfhe.Plaintext) -> None


        In-place addition for a ciphertext and plaintext

        :param ciphertext: Input/output ciphertext
        :type ciphertext: Ciphertext
        :param plaintext: Input plaintext
        :type plaintext: Plaintext
        :return: ciphertext contains ciphertext + plaintext


        3. EvalAddInPlace(self: openfhe.openfhe.CryptoContext, plaintext: openfhe.openfhe.Plaintext, ciphertext: openfhe.openfhe.Ciphertext) -> None

        4. EvalAddInPlace(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, scalar: typing.SupportsFloat) -> None

        5. EvalAddInPlace(self: openfhe.openfhe.CryptoContext, scalar: typing.SupportsFloat, ciphertext: openfhe.openfhe.Ciphertext) -> None
        """
    @overload
    def EvalAddInPlace(self, plaintext: Plaintext, ciphertext: Ciphertext) -> None:
        """EvalAddInPlace(*args, **kwargs)
        Overloaded function.

        1. EvalAddInPlace(self: openfhe.openfhe.CryptoContext, ciphertext1: openfhe.openfhe.Ciphertext, ciphertext2: openfhe.openfhe.Ciphertext) -> None


        In-place homomorphic addition of two ciphertexts

        :param ciphertext1: ciphertext1
        :type ciphertext1: Ciphertext
        :param ciphertext2: second addend
        :type ciphertext2: Ciphertext
        :return: ciphertext1 contains ciphertext1 + ciphertext2


        2. EvalAddInPlace(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, plaintext: openfhe.openfhe.Plaintext) -> None


        In-place addition for a ciphertext and plaintext

        :param ciphertext: Input/output ciphertext
        :type ciphertext: Ciphertext
        :param plaintext: Input plaintext
        :type plaintext: Plaintext
        :return: ciphertext contains ciphertext + plaintext


        3. EvalAddInPlace(self: openfhe.openfhe.CryptoContext, plaintext: openfhe.openfhe.Plaintext, ciphertext: openfhe.openfhe.Ciphertext) -> None

        4. EvalAddInPlace(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, scalar: typing.SupportsFloat) -> None

        5. EvalAddInPlace(self: openfhe.openfhe.CryptoContext, scalar: typing.SupportsFloat, ciphertext: openfhe.openfhe.Ciphertext) -> None
        """
    @overload
    def EvalAddInPlace(self, ciphertext: Ciphertext, scalar: typing.SupportsFloat) -> None:
        """EvalAddInPlace(*args, **kwargs)
        Overloaded function.

        1. EvalAddInPlace(self: openfhe.openfhe.CryptoContext, ciphertext1: openfhe.openfhe.Ciphertext, ciphertext2: openfhe.openfhe.Ciphertext) -> None


        In-place homomorphic addition of two ciphertexts

        :param ciphertext1: ciphertext1
        :type ciphertext1: Ciphertext
        :param ciphertext2: second addend
        :type ciphertext2: Ciphertext
        :return: ciphertext1 contains ciphertext1 + ciphertext2


        2. EvalAddInPlace(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, plaintext: openfhe.openfhe.Plaintext) -> None


        In-place addition for a ciphertext and plaintext

        :param ciphertext: Input/output ciphertext
        :type ciphertext: Ciphertext
        :param plaintext: Input plaintext
        :type plaintext: Plaintext
        :return: ciphertext contains ciphertext + plaintext


        3. EvalAddInPlace(self: openfhe.openfhe.CryptoContext, plaintext: openfhe.openfhe.Plaintext, ciphertext: openfhe.openfhe.Ciphertext) -> None

        4. EvalAddInPlace(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, scalar: typing.SupportsFloat) -> None

        5. EvalAddInPlace(self: openfhe.openfhe.CryptoContext, scalar: typing.SupportsFloat, ciphertext: openfhe.openfhe.Ciphertext) -> None
        """
    @overload
    def EvalAddInPlace(self, scalar: typing.SupportsFloat, ciphertext: Ciphertext) -> None:
        """EvalAddInPlace(*args, **kwargs)
        Overloaded function.

        1. EvalAddInPlace(self: openfhe.openfhe.CryptoContext, ciphertext1: openfhe.openfhe.Ciphertext, ciphertext2: openfhe.openfhe.Ciphertext) -> None


        In-place homomorphic addition of two ciphertexts

        :param ciphertext1: ciphertext1
        :type ciphertext1: Ciphertext
        :param ciphertext2: second addend
        :type ciphertext2: Ciphertext
        :return: ciphertext1 contains ciphertext1 + ciphertext2


        2. EvalAddInPlace(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, plaintext: openfhe.openfhe.Plaintext) -> None


        In-place addition for a ciphertext and plaintext

        :param ciphertext: Input/output ciphertext
        :type ciphertext: Ciphertext
        :param plaintext: Input plaintext
        :type plaintext: Plaintext
        :return: ciphertext contains ciphertext + plaintext


        3. EvalAddInPlace(self: openfhe.openfhe.CryptoContext, plaintext: openfhe.openfhe.Plaintext, ciphertext: openfhe.openfhe.Ciphertext) -> None

        4. EvalAddInPlace(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, scalar: typing.SupportsFloat) -> None

        5. EvalAddInPlace(self: openfhe.openfhe.CryptoContext, scalar: typing.SupportsFloat, ciphertext: openfhe.openfhe.Ciphertext) -> None
        """
    def EvalAddMany(self, ciphertextVec: collections.abc.Sequence[Ciphertext]) -> Ciphertext:
        """EvalAddMany(self: openfhe.openfhe.CryptoContext, ciphertextVec: collections.abc.Sequence[openfhe.openfhe.Ciphertext]) -> openfhe.openfhe.Ciphertext"""
    def EvalAddManyInPlace(self, ciphertextVec: collections.abc.Sequence[Ciphertext]) -> Ciphertext:
        """EvalAddManyInPlace(self: openfhe.openfhe.CryptoContext, ciphertextVec: collections.abc.Sequence[openfhe.openfhe.Ciphertext]) -> openfhe.openfhe.Ciphertext"""
    @overload
    def EvalAddMutable(self, ciphertext1: Ciphertext, ciphertext2: Ciphertext) -> Ciphertext:
        """EvalAddMutable(*args, **kwargs)
        Overloaded function.

        1. EvalAddMutable(self: openfhe.openfhe.CryptoContext, ciphertext1: openfhe.openfhe.Ciphertext, ciphertext2: openfhe.openfhe.Ciphertext) -> openfhe.openfhe.Ciphertext


        Homomorphic addition of two mutable ciphertexts (they can be changed during the operation)

        :param ciphertext1: first addend
        :type ciphertext1: Ciphertext
        :param ciphertext2: second addend
        :type ciphertext2: Ciphertext
        :return: the result as a new ciphertext
        :rtype: Ciphertext


        2. EvalAddMutable(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, plaintext: openfhe.openfhe.Plaintext) -> openfhe.openfhe.Ciphertext


        Homomorphic addition a mutable ciphertext and plaintext

        :param ciphertext: ciphertext
        :type ciphertext: Ciphertext
        :param plaintext: plaintext
        :type plaintext: Plaintext
        :return: new ciphertext for ciphertext + plaintext
        :rtype: Ciphertext


        3. EvalAddMutable(self: openfhe.openfhe.CryptoContext, plaintext: openfhe.openfhe.Plaintext, ciphertext: openfhe.openfhe.Ciphertext) -> openfhe.openfhe.Ciphertext
        """
    @overload
    def EvalAddMutable(self, ciphertext: Ciphertext, plaintext: Plaintext) -> Ciphertext:
        """EvalAddMutable(*args, **kwargs)
        Overloaded function.

        1. EvalAddMutable(self: openfhe.openfhe.CryptoContext, ciphertext1: openfhe.openfhe.Ciphertext, ciphertext2: openfhe.openfhe.Ciphertext) -> openfhe.openfhe.Ciphertext


        Homomorphic addition of two mutable ciphertexts (they can be changed during the operation)

        :param ciphertext1: first addend
        :type ciphertext1: Ciphertext
        :param ciphertext2: second addend
        :type ciphertext2: Ciphertext
        :return: the result as a new ciphertext
        :rtype: Ciphertext


        2. EvalAddMutable(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, plaintext: openfhe.openfhe.Plaintext) -> openfhe.openfhe.Ciphertext


        Homomorphic addition a mutable ciphertext and plaintext

        :param ciphertext: ciphertext
        :type ciphertext: Ciphertext
        :param plaintext: plaintext
        :type plaintext: Plaintext
        :return: new ciphertext for ciphertext + plaintext
        :rtype: Ciphertext


        3. EvalAddMutable(self: openfhe.openfhe.CryptoContext, plaintext: openfhe.openfhe.Plaintext, ciphertext: openfhe.openfhe.Ciphertext) -> openfhe.openfhe.Ciphertext
        """
    @overload
    def EvalAddMutable(self, plaintext: Plaintext, ciphertext: Ciphertext) -> Ciphertext:
        """EvalAddMutable(*args, **kwargs)
        Overloaded function.

        1. EvalAddMutable(self: openfhe.openfhe.CryptoContext, ciphertext1: openfhe.openfhe.Ciphertext, ciphertext2: openfhe.openfhe.Ciphertext) -> openfhe.openfhe.Ciphertext


        Homomorphic addition of two mutable ciphertexts (they can be changed during the operation)

        :param ciphertext1: first addend
        :type ciphertext1: Ciphertext
        :param ciphertext2: second addend
        :type ciphertext2: Ciphertext
        :return: the result as a new ciphertext
        :rtype: Ciphertext


        2. EvalAddMutable(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, plaintext: openfhe.openfhe.Plaintext) -> openfhe.openfhe.Ciphertext


        Homomorphic addition a mutable ciphertext and plaintext

        :param ciphertext: ciphertext
        :type ciphertext: Ciphertext
        :param plaintext: plaintext
        :type plaintext: Plaintext
        :return: new ciphertext for ciphertext + plaintext
        :rtype: Ciphertext


        3. EvalAddMutable(self: openfhe.openfhe.CryptoContext, plaintext: openfhe.openfhe.Plaintext, ciphertext: openfhe.openfhe.Ciphertext) -> openfhe.openfhe.Ciphertext
        """
    def EvalAddMutableInPlace(self, ciphertext1: Ciphertext, ciphertext2: Ciphertext) -> None:
        """EvalAddMutableInPlace(self: openfhe.openfhe.CryptoContext, ciphertext1: openfhe.openfhe.Ciphertext, ciphertext2: openfhe.openfhe.Ciphertext) -> None


        Homomorphic addition a mutable ciphertext and plaintext

        :param ciphertext1: first addend
        :type ciphertext1: Ciphertext
        :param ciphertext2: second addend
        :type ciphertext2: Ciphertext
        :return: ciphertext1 contains ciphertext1 + ciphertext2

        """
    def EvalAtIndex(self, ciphertext: Ciphertext, index: typing.SupportsInt) -> Ciphertext:
        """EvalAtIndex(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, index: typing.SupportsInt) -> openfhe.openfhe.Ciphertext


        Rotates a ciphertext by an index (positive index is a left shift, negative index is a right shift). Uses a rotation key stored in a crypto context.

        :param ciphertext: input ciphertext
        :type ciphertext: Ciphertext
        :param i: rotation index
        :type i: int
        :return: a rotated ciphertext
        :rtype: Ciphertext

        """
    def EvalAtIndexKeyGen(
        self, privateKey: PrivateKey, indexList: collections.abc.Sequence[typing.SupportsInt], publicKey: PublicKey = ...
    ) -> None:
        """EvalAtIndexKeyGen(self: openfhe.openfhe.CryptoContext, privateKey: openfhe.openfhe.PrivateKey, indexList: collections.abc.Sequence[typing.SupportsInt], publicKey: openfhe.openfhe.PublicKey = None) -> None


        EvalAtIndexKeyGen generates evaluation keys for a list of rotation indices

        :param privateKey: the private key
        :type privateKey: PrivateKey
        :param indexList: list of indices
        :type indexList: list
        :param publicKey: the public key (used in NTRU schemes). Not used anymore.
        :type publicKey: PublicKey
        :return: None

        """
    def EvalAutomorphismKeyGen(self, privateKey: PrivateKey, indexList: collections.abc.Sequence[typing.SupportsInt]) -> EvalKeyMap:
        """EvalAutomorphismKeyGen(self: openfhe.openfhe.CryptoContext, privateKey: openfhe.openfhe.PrivateKey, indexList: collections.abc.Sequence[typing.SupportsInt]) -> openfhe.openfhe.EvalKeyMap


        Generate automophism keys for a given private key; Uses the private key for encryption

        :param privateKey: private key.
        :type privateKey: PrivateKey
        :param indexList: list of automorphism indices to be computed.
        :type indexList: list
        :return: returns the evaluation key
        :rtype: EvalKeyMap

        """
    def EvalBootstrap(
        self, ciphertext: Ciphertext, numIterations: typing.SupportsInt = ..., precision: typing.SupportsInt = ...
    ) -> Ciphertext:
        """EvalBootstrap(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, numIterations: typing.SupportsInt = 1, precision: typing.SupportsInt = 0) -> openfhe.openfhe.Ciphertext


        Defines the bootstrapping evaluation of ciphertext using either the FFT-like method or the linear method

        :param ciphertext: the input ciphertext
        :type ciphertext: Ciphertext
        :param numIterations: number of iterations to run iterative bootstrapping (Meta-BTS). Increasing the iterations increases the precision of bootstrapping
        :type numIterations: int
        :param precision: precision of initial bootstrapping algorithm. This value is determined by the user experimentally by first running EvalBootstrap with numIterations = 1 and precision = 0 (unused).
        :type precision: int
        :return: Ciphertext: the refreshed ciphertext
        :rtype: Ciphertext

        """
    def EvalBootstrapKeyGen(self, privateKey: PrivateKey, slots: typing.SupportsInt) -> None:
        """EvalBootstrapKeyGen(self: openfhe.openfhe.CryptoContext, privateKey: openfhe.openfhe.PrivateKey, slots: typing.SupportsInt) -> None


        Generates all automorphism keys for EvalBootstrap. Supported in CKKS only. EvalBootstrapKeyGen uses the baby-step/giant-step strategy.

        :param privateKey: private key.
        :type privateKey: PrivateKey
        :param slots: number of slots to support permutations on.
        :type slots: int
        :return: None

        """
    def EvalBootstrapSetup(
        self,
        levelBudget: collections.abc.Sequence[typing.SupportsInt] = ...,
        dim1: collections.abc.Sequence[typing.SupportsInt] = ...,
        slots: typing.SupportsInt = ...,
        correctionFactor: typing.SupportsInt = ...,
        precompute: bool = ...,
    ) -> None:
        """EvalBootstrapSetup(self: openfhe.openfhe.CryptoContext, levelBudget: collections.abc.Sequence[typing.SupportsInt] = [5, 4], dim1: collections.abc.Sequence[typing.SupportsInt] = [0, 0], slots: typing.SupportsInt = 0, correctionFactor: typing.SupportsInt = 0, precompute: bool = True) -> None


        Bootstrap functionality: There are three methods that have to be called in this specific order:

        1. EvalBootstrapSetup: computes and encodes the coefficients for encoding and decoding and stores the necessary parameters

        2. EvalBootstrapKeyGen: computes and stores the keys for rotations and conjugation

        3. EvalBootstrap: refreshes the given ciphertext Sets all parameters for both linear and FTT-like methods. Supported in CKKS only.

        :param levelBudget: vector of budgets for the amount of levels in encoding and decoding
        :type levelBudget: list
        :param dim1: vector of inner dimension in the baby-step giant-step routine for encoding and decodingl
        :type dim1: list
        :param slots: number of slots to be bootstraped
        :type slots: int
        :param correctionFactor: value to internally rescale message by to improve precision of bootstrapping. If set to 0, we use the default logic. This value is only used when NATIVE_SIZE=64.
        :type correctionFactor: int
        :return: None

        """
    def EvalCKKStoFHEW(self, ciphertext: Ciphertext, numCtxts: typing.SupportsInt = ...) -> list[LWECiphertext]:
        """EvalCKKStoFHEW(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, numCtxts: typing.SupportsInt = 0) -> list[openfhe.openfhe.LWECiphertext]


        Switches a CKKS ciphertext to a vector of FHEW ciphertexts.

        :param ciphertext: Input CKKS ciphertext.
        :type ciphertext: Ciphertext
        :param numCtxts: Number of coefficients to extract (defaults to number of slots if 0).
        :type numCtxts: int

        """
    def EvalCKKStoFHEWKeyGen(self, keyPair: KeyPair, lwesk: LWEPrivateKey) -> None:
        """EvalCKKStoFHEWKeyGen(self: openfhe.openfhe.CryptoContext, keyPair: openfhe.openfhe.KeyPair, lwesk: openfhe.openfhe.LWEPrivateKey) -> None


        Sets all parameters for switching from CKKS to FHEW.

        :param keyPair: CKKS key pair.
        :type keyPair: KeyPair
        :param lwesk: FHEW secret key.
        :type lwesk: LWEPrivateKey

        """
    def EvalCKKStoFHEWPrecompute(self, scale: typing.SupportsFloat = ...) -> None:
        """EvalCKKStoFHEWPrecompute(self: openfhe.openfhe.CryptoContext, scale: typing.SupportsFloat = 1.0) -> None


        Performs precomputations for CKKS homomorphic decoding. Allows setting a custom scale factor. Given as a separate method than EvalCKKStoFHEWSetup to allow the user to specify a scale that depends on the CKKS and FHEW cryptocontexts

        :param scale: Scaling factor for the linear transform matrix.
        :type scale: float

        """
    def EvalCKKStoFHEWSetup(self, schswchparams) -> LWEPrivateKey:
        """EvalCKKStoFHEWSetup(self: openfhe.openfhe.CryptoContext, schswchparams: lbcrypto::SchSwchParams) -> openfhe.openfhe.LWEPrivateKey


        Sets all parameters for switching from CKKS to FHEW.

        :param schswchparams: Parameters for CKKS-to-FHEW scheme switching.
        :type schswchparams: SchSwchParams
        :return: FHEW secret key.
        :rtype: LWEPrivateKey

        """
    def EvalChebyshevFunction(
        self,
        func: collections.abc.Callable[[typing.SupportsFloat], float],
        ciphertext: Ciphertext,
        a: typing.SupportsFloat,
        b: typing.SupportsFloat,
        degree: typing.SupportsInt,
    ) -> Ciphertext:
        """EvalChebyshevFunction(self: openfhe.openfhe.CryptoContext, func: collections.abc.Callable[[typing.SupportsFloat], float], ciphertext: openfhe.openfhe.Ciphertext, a: typing.SupportsFloat, b: typing.SupportsFloat, degree: typing.SupportsInt) -> openfhe.openfhe.Ciphertext


        Method for calculating Chebyshev evaluation on a ciphertext for a smooth input function over the range [a,b]. Supported only in CKKS.

        :param func: the function to be approximated
        :type func: function
        :param ciphertext: input ciphertext
        :type ciphertext: Ciphertext
        :param a: lower bound of argument for which the coefficients were found
        :type a: float
        :param b: upper bound of argument for which the coefficients were found
        :type b: float
        :param degree: Desired degree of approximation
        :type degree: int
        :return: the coefficients of the Chebyshev approximation.
        :rtype: Ciphertext

        """
    @overload
    def EvalChebyshevSeries(
        self,
        ciphertext: Ciphertext,
        coefficients: collections.abc.Sequence[typing.SupportsInt],
        a: typing.SupportsFloat,
        b: typing.SupportsFloat,
    ) -> Ciphertext:
        """EvalChebyshevSeries(*args, **kwargs)
        Overloaded function.

        1. EvalChebyshevSeries(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, coefficients: collections.abc.Sequence[typing.SupportsInt], a: typing.SupportsFloat, b: typing.SupportsFloat) -> openfhe.openfhe.Ciphertext


            Method for evaluating Chebyshev polynomial interpolation; first the range [a,b] is mapped to [-1,1] using linear transformation 1 + 2 (x-a)/(b-a) If the degree of the polynomial is less than 5, use EvalChebyshevSeriesLinear (naive linear method), otherwise, use EvalChebyshevSeriesPS (Paterson-Stockmeyer method). Supported only in CKKS.

            :param ciphertext: input ciphertext
            :type ciphertext: Ciphertext
            :param coefficients: is the vector of coefficients in Chebyshev expansion
            :type coefficients: list
            :param a: lower bound of argument for which the coefficients were found
            :type a: float
            :param b: upper bound of argument for which the coefficients were found
            :type b: float
            :return: the result of polynomial evaluation
            :rtype: Ciphertext


        2. EvalChebyshevSeries(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, coefficients: collections.abc.Sequence[typing.SupportsFloat], a: typing.SupportsFloat, b: typing.SupportsFloat) -> openfhe.openfhe.Ciphertext


            Method for evaluating Chebyshev polynomial interpolation; first the range [a,b] is mapped to [-1,1] using linear transformation 1 + 2 (x-a)/(b-a) If the degree of the polynomial is less than 5, use EvalChebyshevSeriesLinear (naive linear method), otherwise, use EvalChebyshevSeriesPS (Paterson-Stockmeyer method). Supported only in CKKS.

            :param ciphertext: input ciphertext
            :type ciphertext: Ciphertext
            :param coefficients: is the vector of coefficients in Chebyshev expansion
            :type coefficients: list
            :param a: lower bound of argument for which the coefficients were found
            :type a: float
            :param b: upper bound of argument for which the coefficients were found
            :type b: float
            :return: the result of polynomial evaluation
            :rtype: Ciphertext


        3. EvalChebyshevSeries(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, coefficients: collections.abc.Sequence[complex], a: typing.SupportsFloat, b: typing.SupportsFloat) -> openfhe.openfhe.Ciphertext


            Method for evaluating Chebyshev polynomial interpolation; first the range [a,b] is mapped to [-1,1] using linear transformation 1 + 2 (x-a)/(b-a) If the degree of the polynomial is less than 5, use EvalChebyshevSeriesLinear (naive linear method), otherwise, use EvalChebyshevSeriesPS (Paterson-Stockmeyer method). Supported only in CKKS.

            :param ciphertext: input ciphertext
            :type ciphertext: Ciphertext
            :param coefficients: is the vector of coefficients in Chebyshev expansion
            :type coefficients: list
            :param a: lower bound of argument for which the coefficients were found
            :type a: float
            :param b: upper bound of argument for which the coefficients were found
            :type b: float
            :return: the result of polynomial evaluation
            :rtype: Ciphertext

        """
    @overload
    def EvalChebyshevSeries(
        self,
        ciphertext: Ciphertext,
        coefficients: collections.abc.Sequence[typing.SupportsFloat],
        a: typing.SupportsFloat,
        b: typing.SupportsFloat,
    ) -> Ciphertext:
        """EvalChebyshevSeries(*args, **kwargs)
        Overloaded function.

        1. EvalChebyshevSeries(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, coefficients: collections.abc.Sequence[typing.SupportsInt], a: typing.SupportsFloat, b: typing.SupportsFloat) -> openfhe.openfhe.Ciphertext


            Method for evaluating Chebyshev polynomial interpolation; first the range [a,b] is mapped to [-1,1] using linear transformation 1 + 2 (x-a)/(b-a) If the degree of the polynomial is less than 5, use EvalChebyshevSeriesLinear (naive linear method), otherwise, use EvalChebyshevSeriesPS (Paterson-Stockmeyer method). Supported only in CKKS.

            :param ciphertext: input ciphertext
            :type ciphertext: Ciphertext
            :param coefficients: is the vector of coefficients in Chebyshev expansion
            :type coefficients: list
            :param a: lower bound of argument for which the coefficients were found
            :type a: float
            :param b: upper bound of argument for which the coefficients were found
            :type b: float
            :return: the result of polynomial evaluation
            :rtype: Ciphertext


        2. EvalChebyshevSeries(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, coefficients: collections.abc.Sequence[typing.SupportsFloat], a: typing.SupportsFloat, b: typing.SupportsFloat) -> openfhe.openfhe.Ciphertext


            Method for evaluating Chebyshev polynomial interpolation; first the range [a,b] is mapped to [-1,1] using linear transformation 1 + 2 (x-a)/(b-a) If the degree of the polynomial is less than 5, use EvalChebyshevSeriesLinear (naive linear method), otherwise, use EvalChebyshevSeriesPS (Paterson-Stockmeyer method). Supported only in CKKS.

            :param ciphertext: input ciphertext
            :type ciphertext: Ciphertext
            :param coefficients: is the vector of coefficients in Chebyshev expansion
            :type coefficients: list
            :param a: lower bound of argument for which the coefficients were found
            :type a: float
            :param b: upper bound of argument for which the coefficients were found
            :type b: float
            :return: the result of polynomial evaluation
            :rtype: Ciphertext


        3. EvalChebyshevSeries(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, coefficients: collections.abc.Sequence[complex], a: typing.SupportsFloat, b: typing.SupportsFloat) -> openfhe.openfhe.Ciphertext


            Method for evaluating Chebyshev polynomial interpolation; first the range [a,b] is mapped to [-1,1] using linear transformation 1 + 2 (x-a)/(b-a) If the degree of the polynomial is less than 5, use EvalChebyshevSeriesLinear (naive linear method), otherwise, use EvalChebyshevSeriesPS (Paterson-Stockmeyer method). Supported only in CKKS.

            :param ciphertext: input ciphertext
            :type ciphertext: Ciphertext
            :param coefficients: is the vector of coefficients in Chebyshev expansion
            :type coefficients: list
            :param a: lower bound of argument for which the coefficients were found
            :type a: float
            :param b: upper bound of argument for which the coefficients were found
            :type b: float
            :return: the result of polynomial evaluation
            :rtype: Ciphertext

        """
    @overload
    def EvalChebyshevSeries(
        self, ciphertext: Ciphertext, coefficients: collections.abc.Sequence[complex], a: typing.SupportsFloat, b: typing.SupportsFloat
    ) -> Ciphertext:
        """EvalChebyshevSeries(*args, **kwargs)
        Overloaded function.

        1. EvalChebyshevSeries(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, coefficients: collections.abc.Sequence[typing.SupportsInt], a: typing.SupportsFloat, b: typing.SupportsFloat) -> openfhe.openfhe.Ciphertext


            Method for evaluating Chebyshev polynomial interpolation; first the range [a,b] is mapped to [-1,1] using linear transformation 1 + 2 (x-a)/(b-a) If the degree of the polynomial is less than 5, use EvalChebyshevSeriesLinear (naive linear method), otherwise, use EvalChebyshevSeriesPS (Paterson-Stockmeyer method). Supported only in CKKS.

            :param ciphertext: input ciphertext
            :type ciphertext: Ciphertext
            :param coefficients: is the vector of coefficients in Chebyshev expansion
            :type coefficients: list
            :param a: lower bound of argument for which the coefficients were found
            :type a: float
            :param b: upper bound of argument for which the coefficients were found
            :type b: float
            :return: the result of polynomial evaluation
            :rtype: Ciphertext


        2. EvalChebyshevSeries(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, coefficients: collections.abc.Sequence[typing.SupportsFloat], a: typing.SupportsFloat, b: typing.SupportsFloat) -> openfhe.openfhe.Ciphertext


            Method for evaluating Chebyshev polynomial interpolation; first the range [a,b] is mapped to [-1,1] using linear transformation 1 + 2 (x-a)/(b-a) If the degree of the polynomial is less than 5, use EvalChebyshevSeriesLinear (naive linear method), otherwise, use EvalChebyshevSeriesPS (Paterson-Stockmeyer method). Supported only in CKKS.

            :param ciphertext: input ciphertext
            :type ciphertext: Ciphertext
            :param coefficients: is the vector of coefficients in Chebyshev expansion
            :type coefficients: list
            :param a: lower bound of argument for which the coefficients were found
            :type a: float
            :param b: upper bound of argument for which the coefficients were found
            :type b: float
            :return: the result of polynomial evaluation
            :rtype: Ciphertext


        3. EvalChebyshevSeries(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, coefficients: collections.abc.Sequence[complex], a: typing.SupportsFloat, b: typing.SupportsFloat) -> openfhe.openfhe.Ciphertext


            Method for evaluating Chebyshev polynomial interpolation; first the range [a,b] is mapped to [-1,1] using linear transformation 1 + 2 (x-a)/(b-a) If the degree of the polynomial is less than 5, use EvalChebyshevSeriesLinear (naive linear method), otherwise, use EvalChebyshevSeriesPS (Paterson-Stockmeyer method). Supported only in CKKS.

            :param ciphertext: input ciphertext
            :type ciphertext: Ciphertext
            :param coefficients: is the vector of coefficients in Chebyshev expansion
            :type coefficients: list
            :param a: lower bound of argument for which the coefficients were found
            :type a: float
            :param b: upper bound of argument for which the coefficients were found
            :type b: float
            :return: the result of polynomial evaluation
            :rtype: Ciphertext

        """
    @overload
    def EvalChebyshevSeriesLinear(
        self,
        ciphertext: Ciphertext,
        coefficients: collections.abc.Sequence[typing.SupportsInt],
        a: typing.SupportsFloat,
        b: typing.SupportsFloat,
    ) -> Ciphertext:
        """EvalChebyshevSeriesLinear(*args, **kwargs)
        Overloaded function.

        1. EvalChebyshevSeriesLinear(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, coefficients: collections.abc.Sequence[typing.SupportsInt], a: typing.SupportsFloat, b: typing.SupportsFloat) -> openfhe.openfhe.Ciphertext


            Naive linear method for evaluating Chebyshev polynomial interpolation; first the range [a,b] is mapped to [-1,1] using linear transformation 1 + 2 (x-a)/(b-a). Supported only in CKKS.

            :param ciphertext: input ciphertext
            :type ciphertext: Ciphertext
            :param coefficients:  is the vector of coefficients in Chebyshev expansion
            :type coefficients: list
            :param a: lower bound of argument for which the coefficients were found
            :type a: float
            :param b: upper bound of argument for which the coefficients were found
            :type b: float
            :return: the result of polynomial evaluation
            :rtype: Ciphertext


        2. EvalChebyshevSeriesLinear(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, coefficients: collections.abc.Sequence[typing.SupportsFloat], a: typing.SupportsFloat, b: typing.SupportsFloat) -> openfhe.openfhe.Ciphertext


            Naive linear method for evaluating Chebyshev polynomial interpolation; first the range [a,b] is mapped to [-1,1] using linear transformation 1 + 2 (x-a)/(b-a). Supported only in CKKS.

            :param ciphertext: input ciphertext
            :type ciphertext: Ciphertext
            :param coefficients:  is the vector of coefficients in Chebyshev expansion
            :type coefficients: list
            :param a: lower bound of argument for which the coefficients were found
            :type a: float
            :param b: upper bound of argument for which the coefficients were found
            :type b: float
            :return: the result of polynomial evaluation
            :rtype: Ciphertext


        3. EvalChebyshevSeriesLinear(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, coefficients: collections.abc.Sequence[complex], a: typing.SupportsFloat, b: typing.SupportsFloat) -> openfhe.openfhe.Ciphertext


            Naive linear method for evaluating Chebyshev polynomial interpolation; first the range [a,b] is mapped to [-1,1] using linear transformation 1 + 2 (x-a)/(b-a). Supported only in CKKS.

            :param ciphertext: input ciphertext
            :type ciphertext: Ciphertext
            :param coefficients:  is the vector of coefficients in Chebyshev expansion
            :type coefficients: list
            :param a: lower bound of argument for which the coefficients were found
            :type a: float
            :param b: upper bound of argument for which the coefficients were found
            :type b: float
            :return: the result of polynomial evaluation
            :rtype: Ciphertext

        """
    @overload
    def EvalChebyshevSeriesLinear(
        self,
        ciphertext: Ciphertext,
        coefficients: collections.abc.Sequence[typing.SupportsFloat],
        a: typing.SupportsFloat,
        b: typing.SupportsFloat,
    ) -> Ciphertext:
        """EvalChebyshevSeriesLinear(*args, **kwargs)
        Overloaded function.

        1. EvalChebyshevSeriesLinear(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, coefficients: collections.abc.Sequence[typing.SupportsInt], a: typing.SupportsFloat, b: typing.SupportsFloat) -> openfhe.openfhe.Ciphertext


            Naive linear method for evaluating Chebyshev polynomial interpolation; first the range [a,b] is mapped to [-1,1] using linear transformation 1 + 2 (x-a)/(b-a). Supported only in CKKS.

            :param ciphertext: input ciphertext
            :type ciphertext: Ciphertext
            :param coefficients:  is the vector of coefficients in Chebyshev expansion
            :type coefficients: list
            :param a: lower bound of argument for which the coefficients were found
            :type a: float
            :param b: upper bound of argument for which the coefficients were found
            :type b: float
            :return: the result of polynomial evaluation
            :rtype: Ciphertext


        2. EvalChebyshevSeriesLinear(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, coefficients: collections.abc.Sequence[typing.SupportsFloat], a: typing.SupportsFloat, b: typing.SupportsFloat) -> openfhe.openfhe.Ciphertext


            Naive linear method for evaluating Chebyshev polynomial interpolation; first the range [a,b] is mapped to [-1,1] using linear transformation 1 + 2 (x-a)/(b-a). Supported only in CKKS.

            :param ciphertext: input ciphertext
            :type ciphertext: Ciphertext
            :param coefficients:  is the vector of coefficients in Chebyshev expansion
            :type coefficients: list
            :param a: lower bound of argument for which the coefficients were found
            :type a: float
            :param b: upper bound of argument for which the coefficients were found
            :type b: float
            :return: the result of polynomial evaluation
            :rtype: Ciphertext


        3. EvalChebyshevSeriesLinear(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, coefficients: collections.abc.Sequence[complex], a: typing.SupportsFloat, b: typing.SupportsFloat) -> openfhe.openfhe.Ciphertext


            Naive linear method for evaluating Chebyshev polynomial interpolation; first the range [a,b] is mapped to [-1,1] using linear transformation 1 + 2 (x-a)/(b-a). Supported only in CKKS.

            :param ciphertext: input ciphertext
            :type ciphertext: Ciphertext
            :param coefficients:  is the vector of coefficients in Chebyshev expansion
            :type coefficients: list
            :param a: lower bound of argument for which the coefficients were found
            :type a: float
            :param b: upper bound of argument for which the coefficients were found
            :type b: float
            :return: the result of polynomial evaluation
            :rtype: Ciphertext

        """
    @overload
    def EvalChebyshevSeriesLinear(
        self, ciphertext: Ciphertext, coefficients: collections.abc.Sequence[complex], a: typing.SupportsFloat, b: typing.SupportsFloat
    ) -> Ciphertext:
        """EvalChebyshevSeriesLinear(*args, **kwargs)
        Overloaded function.

        1. EvalChebyshevSeriesLinear(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, coefficients: collections.abc.Sequence[typing.SupportsInt], a: typing.SupportsFloat, b: typing.SupportsFloat) -> openfhe.openfhe.Ciphertext


            Naive linear method for evaluating Chebyshev polynomial interpolation; first the range [a,b] is mapped to [-1,1] using linear transformation 1 + 2 (x-a)/(b-a). Supported only in CKKS.

            :param ciphertext: input ciphertext
            :type ciphertext: Ciphertext
            :param coefficients:  is the vector of coefficients in Chebyshev expansion
            :type coefficients: list
            :param a: lower bound of argument for which the coefficients were found
            :type a: float
            :param b: upper bound of argument for which the coefficients were found
            :type b: float
            :return: the result of polynomial evaluation
            :rtype: Ciphertext


        2. EvalChebyshevSeriesLinear(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, coefficients: collections.abc.Sequence[typing.SupportsFloat], a: typing.SupportsFloat, b: typing.SupportsFloat) -> openfhe.openfhe.Ciphertext


            Naive linear method for evaluating Chebyshev polynomial interpolation; first the range [a,b] is mapped to [-1,1] using linear transformation 1 + 2 (x-a)/(b-a). Supported only in CKKS.

            :param ciphertext: input ciphertext
            :type ciphertext: Ciphertext
            :param coefficients:  is the vector of coefficients in Chebyshev expansion
            :type coefficients: list
            :param a: lower bound of argument for which the coefficients were found
            :type a: float
            :param b: upper bound of argument for which the coefficients were found
            :type b: float
            :return: the result of polynomial evaluation
            :rtype: Ciphertext


        3. EvalChebyshevSeriesLinear(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, coefficients: collections.abc.Sequence[complex], a: typing.SupportsFloat, b: typing.SupportsFloat) -> openfhe.openfhe.Ciphertext


            Naive linear method for evaluating Chebyshev polynomial interpolation; first the range [a,b] is mapped to [-1,1] using linear transformation 1 + 2 (x-a)/(b-a). Supported only in CKKS.

            :param ciphertext: input ciphertext
            :type ciphertext: Ciphertext
            :param coefficients:  is the vector of coefficients in Chebyshev expansion
            :type coefficients: list
            :param a: lower bound of argument for which the coefficients were found
            :type a: float
            :param b: upper bound of argument for which the coefficients were found
            :type b: float
            :return: the result of polynomial evaluation
            :rtype: Ciphertext

        """
    @overload
    def EvalChebyshevSeriesPS(
        self,
        ciphertext: Ciphertext,
        coefficients: collections.abc.Sequence[typing.SupportsInt],
        a: typing.SupportsFloat,
        b: typing.SupportsFloat,
    ) -> Ciphertext:
        """EvalChebyshevSeriesPS(*args, **kwargs)
        Overloaded function.

        1. EvalChebyshevSeriesPS(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, coefficients: collections.abc.Sequence[typing.SupportsInt], a: typing.SupportsFloat, b: typing.SupportsFloat) -> openfhe.openfhe.Ciphertext


            Paterson-Stockmeyer method for evaluating Chebyshev polynomial interpolation; first the range [a,b] is mapped to [-1,1] using linear transformation 1 + 2 (x-a)/(b-a). Supported only in CKKS.

            :param ciphertext: input ciphertext
            :type ciphertext: Ciphertext
            :param coefficients: is the vector of coefficients in Chebyshev expansion
            :type coefficients: list
            :param a: lower bound of argument for which the coefficients were found
            :type a: float
            :param b: upper bound of argument for which the coefficients were found
            :type b: float
            :return: the result of polynomial evaluation
            :rtype: Ciphertext


        2. EvalChebyshevSeriesPS(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, coefficients: collections.abc.Sequence[typing.SupportsFloat], a: typing.SupportsFloat, b: typing.SupportsFloat) -> openfhe.openfhe.Ciphertext


            Paterson-Stockmeyer method for evaluating Chebyshev polynomial interpolation; first the range [a,b] is mapped to [-1,1] using linear transformation 1 + 2 (x-a)/(b-a). Supported only in CKKS.

            :param ciphertext: input ciphertext
            :type ciphertext: Ciphertext
            :param coefficients: is the vector of coefficients in Chebyshev expansion
            :type coefficients: list
            :param a: lower bound of argument for which the coefficients were found
            :type a: float
            :param b: upper bound of argument for which the coefficients were found
            :type b: float
            :return: the result of polynomial evaluation
            :rtype: Ciphertext


        3. EvalChebyshevSeriesPS(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, coefficients: collections.abc.Sequence[complex], a: typing.SupportsFloat, b: typing.SupportsFloat) -> openfhe.openfhe.Ciphertext


            Paterson-Stockmeyer method for evaluating Chebyshev polynomial interpolation; first the range [a,b] is mapped to [-1,1] using linear transformation 1 + 2 (x-a)/(b-a). Supported only in CKKS.

            :param ciphertext: input ciphertext
            :type ciphertext: Ciphertext
            :param coefficients: is the vector of coefficients in Chebyshev expansion
            :type coefficients: list
            :param a: lower bound of argument for which the coefficients were found
            :type a: float
            :param b: upper bound of argument for which the coefficients were found
            :type b: float
            :return: the result of polynomial evaluation
            :rtype: Ciphertext

        """
    @overload
    def EvalChebyshevSeriesPS(
        self,
        ciphertext: Ciphertext,
        coefficients: collections.abc.Sequence[typing.SupportsFloat],
        a: typing.SupportsFloat,
        b: typing.SupportsFloat,
    ) -> Ciphertext:
        """EvalChebyshevSeriesPS(*args, **kwargs)
        Overloaded function.

        1. EvalChebyshevSeriesPS(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, coefficients: collections.abc.Sequence[typing.SupportsInt], a: typing.SupportsFloat, b: typing.SupportsFloat) -> openfhe.openfhe.Ciphertext


            Paterson-Stockmeyer method for evaluating Chebyshev polynomial interpolation; first the range [a,b] is mapped to [-1,1] using linear transformation 1 + 2 (x-a)/(b-a). Supported only in CKKS.

            :param ciphertext: input ciphertext
            :type ciphertext: Ciphertext
            :param coefficients: is the vector of coefficients in Chebyshev expansion
            :type coefficients: list
            :param a: lower bound of argument for which the coefficients were found
            :type a: float
            :param b: upper bound of argument for which the coefficients were found
            :type b: float
            :return: the result of polynomial evaluation
            :rtype: Ciphertext


        2. EvalChebyshevSeriesPS(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, coefficients: collections.abc.Sequence[typing.SupportsFloat], a: typing.SupportsFloat, b: typing.SupportsFloat) -> openfhe.openfhe.Ciphertext


            Paterson-Stockmeyer method for evaluating Chebyshev polynomial interpolation; first the range [a,b] is mapped to [-1,1] using linear transformation 1 + 2 (x-a)/(b-a). Supported only in CKKS.

            :param ciphertext: input ciphertext
            :type ciphertext: Ciphertext
            :param coefficients: is the vector of coefficients in Chebyshev expansion
            :type coefficients: list
            :param a: lower bound of argument for which the coefficients were found
            :type a: float
            :param b: upper bound of argument for which the coefficients were found
            :type b: float
            :return: the result of polynomial evaluation
            :rtype: Ciphertext


        3. EvalChebyshevSeriesPS(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, coefficients: collections.abc.Sequence[complex], a: typing.SupportsFloat, b: typing.SupportsFloat) -> openfhe.openfhe.Ciphertext


            Paterson-Stockmeyer method for evaluating Chebyshev polynomial interpolation; first the range [a,b] is mapped to [-1,1] using linear transformation 1 + 2 (x-a)/(b-a). Supported only in CKKS.

            :param ciphertext: input ciphertext
            :type ciphertext: Ciphertext
            :param coefficients: is the vector of coefficients in Chebyshev expansion
            :type coefficients: list
            :param a: lower bound of argument for which the coefficients were found
            :type a: float
            :param b: upper bound of argument for which the coefficients were found
            :type b: float
            :return: the result of polynomial evaluation
            :rtype: Ciphertext

        """
    @overload
    def EvalChebyshevSeriesPS(
        self, ciphertext: Ciphertext, coefficients: collections.abc.Sequence[complex], a: typing.SupportsFloat, b: typing.SupportsFloat
    ) -> Ciphertext:
        """EvalChebyshevSeriesPS(*args, **kwargs)
        Overloaded function.

        1. EvalChebyshevSeriesPS(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, coefficients: collections.abc.Sequence[typing.SupportsInt], a: typing.SupportsFloat, b: typing.SupportsFloat) -> openfhe.openfhe.Ciphertext


            Paterson-Stockmeyer method for evaluating Chebyshev polynomial interpolation; first the range [a,b] is mapped to [-1,1] using linear transformation 1 + 2 (x-a)/(b-a). Supported only in CKKS.

            :param ciphertext: input ciphertext
            :type ciphertext: Ciphertext
            :param coefficients: is the vector of coefficients in Chebyshev expansion
            :type coefficients: list
            :param a: lower bound of argument for which the coefficients were found
            :type a: float
            :param b: upper bound of argument for which the coefficients were found
            :type b: float
            :return: the result of polynomial evaluation
            :rtype: Ciphertext


        2. EvalChebyshevSeriesPS(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, coefficients: collections.abc.Sequence[typing.SupportsFloat], a: typing.SupportsFloat, b: typing.SupportsFloat) -> openfhe.openfhe.Ciphertext


            Paterson-Stockmeyer method for evaluating Chebyshev polynomial interpolation; first the range [a,b] is mapped to [-1,1] using linear transformation 1 + 2 (x-a)/(b-a). Supported only in CKKS.

            :param ciphertext: input ciphertext
            :type ciphertext: Ciphertext
            :param coefficients: is the vector of coefficients in Chebyshev expansion
            :type coefficients: list
            :param a: lower bound of argument for which the coefficients were found
            :type a: float
            :param b: upper bound of argument for which the coefficients were found
            :type b: float
            :return: the result of polynomial evaluation
            :rtype: Ciphertext


        3. EvalChebyshevSeriesPS(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, coefficients: collections.abc.Sequence[complex], a: typing.SupportsFloat, b: typing.SupportsFloat) -> openfhe.openfhe.Ciphertext


            Paterson-Stockmeyer method for evaluating Chebyshev polynomial interpolation; first the range [a,b] is mapped to [-1,1] using linear transformation 1 + 2 (x-a)/(b-a). Supported only in CKKS.

            :param ciphertext: input ciphertext
            :type ciphertext: Ciphertext
            :param coefficients: is the vector of coefficients in Chebyshev expansion
            :type coefficients: list
            :param a: lower bound of argument for which the coefficients were found
            :type a: float
            :param b: upper bound of argument for which the coefficients were found
            :type b: float
            :return: the result of polynomial evaluation
            :rtype: Ciphertext

        """
    def EvalCompareSchemeSwitching(
        self,
        ciphertext1: Ciphertext,
        ciphertext2: Ciphertext,
        numCtxts: typing.SupportsInt = ...,
        numSlots: typing.SupportsInt = ...,
        pLWE: typing.SupportsInt = ...,
        scaleSign: typing.SupportsFloat = ...,
        unit: bool = ...,
    ) -> Ciphertext:
        """EvalCompareSchemeSwitching(self: openfhe.openfhe.CryptoContext, ciphertext1: openfhe.openfhe.Ciphertext, ciphertext2: openfhe.openfhe.Ciphertext, numCtxts: typing.SupportsInt = 0, numSlots: typing.SupportsInt = 0, pLWE: typing.SupportsInt = 0, scaleSign: typing.SupportsFloat = 1.0, unit: bool = False) -> openfhe.openfhe.Ciphertext


        Compares two CKKS ciphertexts using FHEW-based scheme switching and returns CKKS result.

        :param ciphertext1:  First input CKKS ciphertext.
        :type  ciphertext1:  Ciphertext.
        :param ciphertext2:  Second input CKKS ciphertext.
        :type  ciphertext2:  Ciphertext.
        :param numCtxts:     Number of coefficients to extract.
        :type  numCtxts:     int.
        :param numSlots:     Number of slots to encode in the result.
        :type  numSlots:     int.
        :param pLWE:         Target plaintext modulus for FHEW ciphertexts.
        :type  pLWE:         int.
        :param scaleSign:    Scaling factor for CKKS ciphertexts before switching.
        :type  scaleSign:    float.
        :param unit:         Indicates if input messages are normalized to unit circle.
        :type  unit:         bool.
        :return:             CKKS ciphertext encoding sign comparison result.
        :rtype:              Ciphertext

        """
    def EvalCompareSwitchPrecompute(self, pLWE: typing.SupportsInt = ..., scaleSign: typing.SupportsFloat = ..., unit: bool = ...) -> None:
        """EvalCompareSwitchPrecompute(self: openfhe.openfhe.CryptoContext, pLWE: typing.SupportsInt = 0, scaleSign: typing.SupportsFloat = 1.0, unit: bool = False) -> None


        Performs precomputations for scheme switching in CKKS-to-FHEW comparison. Given as a separate method than EvalSchemeSwitchingSetup to allow the user to specify a scale.

        :param pLWE:       Target plaintext modulus for FHEW ciphertexts.
        :type  pLWE:       int.
        :param scaleSign:  Scaling factor for CKKS ciphertexts before switching.
        :type  scaleSign:  float.
        :param unit:       Indicates if input messages are normalized to unit circle.
        :type  unit:       bool.

        """
    def EvalCos(self, ciphertext: Ciphertext, a: typing.SupportsFloat, b: typing.SupportsFloat, degree: typing.SupportsInt) -> Ciphertext:
        """EvalCos(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, a: typing.SupportsFloat, b: typing.SupportsFloat, degree: typing.SupportsInt) -> openfhe.openfhe.Ciphertext


        Evaluate approximate cosine function on a ciphertext using the Chebyshev approximation. Supported only in CKKS.

        :param ciphertext: input ciphertext
        :type ciphertext: Ciphertext
        :param a: lower bound of argument for which the coefficients were found
        :type a: float
        :param b: upper bound of argument for which the coefficients were found
        :type b: float
        :param degree: Desired degree of approximation
        :type degree: int
        :return: the result of polynomial evaluation.
        :rtype: Ciphertext

        """
    def EvalDivide(
        self, ciphertext: Ciphertext, a: typing.SupportsFloat, b: typing.SupportsFloat, degree: typing.SupportsInt
    ) -> Ciphertext:
        """EvalDivide(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, a: typing.SupportsFloat, b: typing.SupportsFloat, degree: typing.SupportsInt) -> openfhe.openfhe.Ciphertext


        Evaluate approximate division function 1/x where x >= 1 on a ciphertext using the Chebyshev approximation. Supported only in CKKS.

        :param ciphertext: input ciphertext
        :type ciphertext: Ciphertext
        :param a: lower bound of argument for which the coefficients were found
        :type a: float
        :param b: upper bound of argument for which the coefficients were found
        :type b: float
        :param degree: Desired degree of approximation
        :type degree: int
        :return: the result of polynomial evaluation.
        :rtype: Ciphertext

        """
    def EvalFHEWtoCKKS(
        self,
        LWECiphertexts: collections.abc.Sequence[LWECiphertext],
        numCtxts: typing.SupportsInt = ...,
        numSlots: typing.SupportsInt = ...,
        p: typing.SupportsInt = ...,
        pmin: typing.SupportsFloat = ...,
        pmax: typing.SupportsFloat = ...,
        dim1: typing.SupportsInt = ...,
    ) -> Ciphertext:
        """EvalFHEWtoCKKS(self: openfhe.openfhe.CryptoContext, LWECiphertexts: collections.abc.Sequence[openfhe.openfhe.LWECiphertext], numCtxts: typing.SupportsInt = 0, numSlots: typing.SupportsInt = 0, p: typing.SupportsInt = 4, pmin: typing.SupportsFloat = 0.0, pmax: typing.SupportsFloat = 2.0, dim1: typing.SupportsInt = 0) -> openfhe.openfhe.Ciphertext


        Switches a vector of FHEW ciphertexts to a single CKKS ciphertext.

        :param LWECiphertexts:  Input vector of FHEW ciphertexts.
        :type  LWECiphertexts:  list of LWECiphertext.
        :param numCtxts:        Number of values to encode.
        :type  numCtxts:        int
        :param numSlots:        Number of CKKS slots to use.
        :type  numSlots:        int
        :param p:               Plaintext modulus (default = 4).
        :type  p:               int.
        :param pmin:            Minimum expected plaintext value (default = 0.0).
        :type  pmin:            float.
        :param pmax:            Maximum expected plaintext value (default = 2.0).
        :type  pmax:            float.
        :param dim1:            Baby-step parameter (used in argmin).
        :type  dim1:            int.
        :return:                CKKS ciphertext encoding the input LWE messages.
        :rtype:                 Ciphertext

        """
    def EvalFHEWtoCKKSKeyGen(
        self,
        keyPair: KeyPair,
        lwesk: LWEPrivateKey,
        numSlots: typing.SupportsInt = ...,
        numCtxts: typing.SupportsInt = ...,
        dim1: typing.SupportsInt = ...,
        L: typing.SupportsInt = ...,
    ) -> None:
        """EvalFHEWtoCKKSKeyGen(self: openfhe.openfhe.CryptoContext, keyPair: openfhe.openfhe.KeyPair, lwesk: openfhe.openfhe.LWEPrivateKey, numSlots: typing.SupportsInt = 0, numCtxts: typing.SupportsInt = 0, dim1: typing.SupportsInt = 0, L: typing.SupportsInt = 0) -> None


        Generates keys for switching from FHEW to CKKS.

        :param keyPair:   CKKS key pair.
        :type keyPair:    KeyPair
        :param lwesk:     FHEW secret key.
        :type lwesk:      LWEPrivateKey
        :param numSlots:  Number of slots for CKKS encryption.
        :type numSlots:   int
        :param numCtxts:  Number of LWE ciphertext values to encrypt.
        :type numCtxts:   int
        :param dim1:      Baby-step parameter for linear transform.
        :type dim1:       int
        :param L:         Target level for homomorphic decoding matrix.
        :type L:          int

        """
    def EvalFHEWtoCKKSSetup(self, ccLWE: BinFHEContext, numSlotsCKKS: typing.SupportsInt = ..., logQ: typing.SupportsInt = ...) -> None:
        """EvalFHEWtoCKKSSetup(self: openfhe.openfhe.CryptoContext, ccLWE: openfhe.openfhe.BinFHEContext, numSlotsCKKS: typing.SupportsInt = 0, logQ: typing.SupportsInt = 25) -> None


        Sets parameters for switching from FHEW to CKKS. Requires existing CKKS context.

        :param ccLWE: Source FHEW crypto context.
        :type ccLWE: BinFHEContext
        :param numSlotsCKKS:  Number of slots in resulting CKKS ciphertext.
        :type numSlotsCKKS: int
        :param logQ: Ciphertext modulus size in FHEW (for high precision).
        :type logQ: int


        """
    def EvalFastRotation(self, ciphertext: Ciphertext, index: typing.SupportsInt, m: typing.SupportsInt, digits: Ciphertext) -> Ciphertext:
        """EvalFastRotation(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, index: typing.SupportsInt, m: typing.SupportsInt, digits: openfhe.openfhe.Ciphertext) -> openfhe.openfhe.Ciphertext


        EvalFastRotation implements the automorphism and key switching step of hoisted automorphisms.

        Please refer to Section 5 of Halevi and Shoup, "Faster Homomorphic
        linear transformations in HELib." for more details, link:
        https://eprint.iacr.org/2018/244.

        Generally, automorphisms are performed with three steps:
        (1) The automorphism is applied to the ciphertext.
        (2) The automorphed values are decomposed into digits.
        (3) Key switching is applied to enable further computations on the ciphertext.

        Hoisted automorphisms are a technique that performs the digit decomposition for the original ciphertext first,
        and then performs the automorphism and the key switching on the decomposed digits.
        The benefit of this is that the digit decomposition is independent of the automorphism rotation index,
        so it can be reused for multiple different indices.
        This can greatly improve performance when we have to compute many automorphisms on the same ciphertext.
        This routinely happens when we do permutations (EvalPermute).

        EvalFastRotation implements the automorphism and key switching step of hoisted automorphisms.

        This method assumes that all required rotation keys exist.
        This may not be true if we are using baby-step/giant-step key switching.
        Please refer to Section 5.1 of the above reference and EvalPermuteBGStepHoisted to see how to deal with this issue.

        :param ciphertext:  the input ciphertext to perform the automorphism on
        :type ciphertext: Ciphertext
        :param index: the index of the rotation. Positive indices correspond to left rotations and negative indices correspond to right rotations.
        :type index: int
        :param m: is the cyclotomic order
        :type m: int
        :param digits: the precomputed ciphertext created by EvalFastRotationPrecompute using the digit decomposition at the precomputation step
        :type digits: Ciphertext
        :return: the rotated ciphertext
        :rtype: Ciphertext

        """
    def EvalFastRotationExt(self, ciphertext: Ciphertext, index: typing.SupportsInt, digits: Ciphertext, addFirst: bool) -> Ciphertext:
        """EvalFastRotationExt(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, index: typing.SupportsInt, digits: openfhe.openfhe.Ciphertext, addFirst: bool) -> openfhe.openfhe.Ciphertext


        Only supported for hybrid key switching. Performs fast (hoisted) rotation and returns the results in the extended CRT basis P*Q

        :param ciphertext: input ciphertext
        :type ciphertext: Ciphertext
        :param index: the rotation index
        :type index: int
        :param digits: the precomputed ciphertext created by EvalFastRotationPrecompute
        :type digits: Ciphertext
        :param addFirst: if true, the first element c0 is also computed (otherwise ignored)
        :type addFirst: bool
        :return: resulting ciphertext
        :rtype: Ciphertext

        """
    def EvalFastRotationPrecompute(self, ciphertext: Ciphertext) -> Ciphertext:
        """EvalFastRotationPrecompute(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext) -> openfhe.openfhe.Ciphertext


        EvalFastRotationPrecompute implements the precomputation step of hoisted automorphisms.

        Please refer to Section 5 of Halevi and Shoup, "Faster Homomorphic
        linear transformations in HELib." for more details, link:
        https://eprint.iacr.org/2018/244.

        Generally, automorphisms are performed with three steps:
        (1) The automorphism is applied to the ciphertext.
        (2) The automorphed values are decomposed into digits.
        (3) Key switching is applied to enable further computations on the ciphertext.

        Hoisted automorphisms are a technique that performs the digit decomposition for the original ciphertext first,
        and then performs the automorphism and the key switching on the decomposed digits.
        The benefit of this is that the digit decomposition is independent of the automorphism rotation index,
        so it can be reused for multiple different indices.
        This can greatly improve performance when we have to compute many automorphisms on the same ciphertext.
        This routinely happens when we do permutations (EvalPermute).

        EvalFastRotationPrecompute implements the digit decomposition step of hoisted automorphisms.

        :param ciphertext: the input ciphertext on which to do the precomputation (digit decomposition)
        :type ciphertext: Ciphertext
        :return: the precomputed ciphertext created using the digit decomposition
        :rtype: Ciphertext

        """
    @overload
    def EvalInnerProduct(self, ciphertext1: Ciphertext, ciphertext2: Ciphertext, batchSize: typing.SupportsInt) -> Ciphertext:
        """EvalInnerProduct(*args, **kwargs)
        Overloaded function.

        1. EvalInnerProduct(self: openfhe.openfhe.CryptoContext, ciphertext1: openfhe.openfhe.Ciphertext, ciphertext2: openfhe.openfhe.Ciphertext, batchSize: typing.SupportsInt) -> openfhe.openfhe.Ciphertext


            Evaluates inner product in packed encoding (uses EvalSum)

            :param ciphertext1: first vector
            :type ciphertext1: Ciphertext
            :param ciphertext2: second vector
            :type ciphertext2: Ciphertext
            :param batchSize: size of the batch to be summed up
            :type batchSize: int
            :return: Ciphertext: resulting ciphertext
            :rtype: Ciphertext


        2. EvalInnerProduct(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, plaintext: openfhe.openfhe.Plaintext, batchSize: typing.SupportsInt) -> openfhe.openfhe.Ciphertext


            Evaluates inner product in packed encoding (uses EvalSum)

            :param ciphertext: first vector - ciphertext
            :type ciphertext: Ciphertext
            :param plaintext: second vector - plaintext
            :type plaintext: Plaintext
            :param batchSize: size of the batch to be summed up
            :type batchSize: int
            :return: Ciphertext: resulting ciphertext
            :rtype: Ciphertext

        """
    @overload
    def EvalInnerProduct(self, ciphertext: Ciphertext, plaintext: Plaintext, batchSize: typing.SupportsInt) -> Ciphertext:
        """EvalInnerProduct(*args, **kwargs)
        Overloaded function.

        1. EvalInnerProduct(self: openfhe.openfhe.CryptoContext, ciphertext1: openfhe.openfhe.Ciphertext, ciphertext2: openfhe.openfhe.Ciphertext, batchSize: typing.SupportsInt) -> openfhe.openfhe.Ciphertext


            Evaluates inner product in packed encoding (uses EvalSum)

            :param ciphertext1: first vector
            :type ciphertext1: Ciphertext
            :param ciphertext2: second vector
            :type ciphertext2: Ciphertext
            :param batchSize: size of the batch to be summed up
            :type batchSize: int
            :return: Ciphertext: resulting ciphertext
            :rtype: Ciphertext


        2. EvalInnerProduct(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, plaintext: openfhe.openfhe.Plaintext, batchSize: typing.SupportsInt) -> openfhe.openfhe.Ciphertext


            Evaluates inner product in packed encoding (uses EvalSum)

            :param ciphertext: first vector - ciphertext
            :type ciphertext: Ciphertext
            :param plaintext: second vector - plaintext
            :type plaintext: Plaintext
            :param batchSize: size of the batch to be summed up
            :type batchSize: int
            :return: Ciphertext: resulting ciphertext
            :rtype: Ciphertext

        """
    @overload
    def EvalLinearWSum(
        self, ciphertextVec: collections.abc.Sequence[Ciphertext], constantVec: collections.abc.Sequence[typing.SupportsInt]
    ) -> Ciphertext:
        """EvalLinearWSum(*args, **kwargs)
        Overloaded function.

        1. EvalLinearWSum(self: openfhe.openfhe.CryptoContext, ciphertextVec: collections.abc.Sequence[openfhe.openfhe.Ciphertext], constantVec: collections.abc.Sequence[typing.SupportsInt]) -> openfhe.openfhe.Ciphertext

        Evaluate a weighted sum of ciphertexts using scalar coefficients

        2. EvalLinearWSum(self: openfhe.openfhe.CryptoContext, ciphertextVec: collections.abc.Sequence[openfhe.openfhe.Ciphertext], constantVec: collections.abc.Sequence[typing.SupportsFloat]) -> openfhe.openfhe.Ciphertext

        Evaluate a weighted sum of ciphertexts using scalar coefficients

        3. EvalLinearWSum(self: openfhe.openfhe.CryptoContext, ciphertextVec: collections.abc.Sequence[openfhe.openfhe.Ciphertext], constantVec: collections.abc.Sequence[complex]) -> openfhe.openfhe.Ciphertext

        Evaluate a weighted sum of ciphertexts using scalar coefficients
        """
    @overload
    def EvalLinearWSum(
        self, ciphertextVec: collections.abc.Sequence[Ciphertext], constantVec: collections.abc.Sequence[typing.SupportsFloat]
    ) -> Ciphertext:
        """EvalLinearWSum(*args, **kwargs)
        Overloaded function.

        1. EvalLinearWSum(self: openfhe.openfhe.CryptoContext, ciphertextVec: collections.abc.Sequence[openfhe.openfhe.Ciphertext], constantVec: collections.abc.Sequence[typing.SupportsInt]) -> openfhe.openfhe.Ciphertext

        Evaluate a weighted sum of ciphertexts using scalar coefficients

        2. EvalLinearWSum(self: openfhe.openfhe.CryptoContext, ciphertextVec: collections.abc.Sequence[openfhe.openfhe.Ciphertext], constantVec: collections.abc.Sequence[typing.SupportsFloat]) -> openfhe.openfhe.Ciphertext

        Evaluate a weighted sum of ciphertexts using scalar coefficients

        3. EvalLinearWSum(self: openfhe.openfhe.CryptoContext, ciphertextVec: collections.abc.Sequence[openfhe.openfhe.Ciphertext], constantVec: collections.abc.Sequence[complex]) -> openfhe.openfhe.Ciphertext

        Evaluate a weighted sum of ciphertexts using scalar coefficients
        """
    @overload
    def EvalLinearWSum(
        self, ciphertextVec: collections.abc.Sequence[Ciphertext], constantVec: collections.abc.Sequence[complex]
    ) -> Ciphertext:
        """EvalLinearWSum(*args, **kwargs)
        Overloaded function.

        1. EvalLinearWSum(self: openfhe.openfhe.CryptoContext, ciphertextVec: collections.abc.Sequence[openfhe.openfhe.Ciphertext], constantVec: collections.abc.Sequence[typing.SupportsInt]) -> openfhe.openfhe.Ciphertext

        Evaluate a weighted sum of ciphertexts using scalar coefficients

        2. EvalLinearWSum(self: openfhe.openfhe.CryptoContext, ciphertextVec: collections.abc.Sequence[openfhe.openfhe.Ciphertext], constantVec: collections.abc.Sequence[typing.SupportsFloat]) -> openfhe.openfhe.Ciphertext

        Evaluate a weighted sum of ciphertexts using scalar coefficients

        3. EvalLinearWSum(self: openfhe.openfhe.CryptoContext, ciphertextVec: collections.abc.Sequence[openfhe.openfhe.Ciphertext], constantVec: collections.abc.Sequence[complex]) -> openfhe.openfhe.Ciphertext

        Evaluate a weighted sum of ciphertexts using scalar coefficients
        """
    @overload
    def EvalLinearWSumMutable(
        self, constantsVec: collections.abc.Sequence[typing.SupportsInt], ciphertextVec: collections.abc.Sequence[Ciphertext]
    ) -> Ciphertext:
        """EvalLinearWSumMutable(*args, **kwargs)
        Overloaded function.

        1. EvalLinearWSumMutable(self: openfhe.openfhe.CryptoContext, constantsVec: collections.abc.Sequence[typing.SupportsInt], ciphertextVec: collections.abc.Sequence[openfhe.openfhe.Ciphertext]) -> openfhe.openfhe.Ciphertext

        Evaluate a weighted sum (mutable version) with given coefficients

        2. EvalLinearWSumMutable(self: openfhe.openfhe.CryptoContext, constantsVec: collections.abc.Sequence[typing.SupportsFloat], ciphertextVec: collections.abc.Sequence[openfhe.openfhe.Ciphertext]) -> openfhe.openfhe.Ciphertext

        Evaluate a weighted sum (mutable version) with given coefficients

        3. EvalLinearWSumMutable(self: openfhe.openfhe.CryptoContext, constantsVec: collections.abc.Sequence[complex], ciphertextVec: collections.abc.Sequence[openfhe.openfhe.Ciphertext]) -> openfhe.openfhe.Ciphertext

        Evaluate a weighted sum (mutable version) with given coefficients
        """
    @overload
    def EvalLinearWSumMutable(
        self, constantsVec: collections.abc.Sequence[typing.SupportsFloat], ciphertextVec: collections.abc.Sequence[Ciphertext]
    ) -> Ciphertext:
        """EvalLinearWSumMutable(*args, **kwargs)
        Overloaded function.

        1. EvalLinearWSumMutable(self: openfhe.openfhe.CryptoContext, constantsVec: collections.abc.Sequence[typing.SupportsInt], ciphertextVec: collections.abc.Sequence[openfhe.openfhe.Ciphertext]) -> openfhe.openfhe.Ciphertext

        Evaluate a weighted sum (mutable version) with given coefficients

        2. EvalLinearWSumMutable(self: openfhe.openfhe.CryptoContext, constantsVec: collections.abc.Sequence[typing.SupportsFloat], ciphertextVec: collections.abc.Sequence[openfhe.openfhe.Ciphertext]) -> openfhe.openfhe.Ciphertext

        Evaluate a weighted sum (mutable version) with given coefficients

        3. EvalLinearWSumMutable(self: openfhe.openfhe.CryptoContext, constantsVec: collections.abc.Sequence[complex], ciphertextVec: collections.abc.Sequence[openfhe.openfhe.Ciphertext]) -> openfhe.openfhe.Ciphertext

        Evaluate a weighted sum (mutable version) with given coefficients
        """
    @overload
    def EvalLinearWSumMutable(
        self, constantsVec: collections.abc.Sequence[complex], ciphertextVec: collections.abc.Sequence[Ciphertext]
    ) -> Ciphertext:
        """EvalLinearWSumMutable(*args, **kwargs)
        Overloaded function.

        1. EvalLinearWSumMutable(self: openfhe.openfhe.CryptoContext, constantsVec: collections.abc.Sequence[typing.SupportsInt], ciphertextVec: collections.abc.Sequence[openfhe.openfhe.Ciphertext]) -> openfhe.openfhe.Ciphertext

        Evaluate a weighted sum (mutable version) with given coefficients

        2. EvalLinearWSumMutable(self: openfhe.openfhe.CryptoContext, constantsVec: collections.abc.Sequence[typing.SupportsFloat], ciphertextVec: collections.abc.Sequence[openfhe.openfhe.Ciphertext]) -> openfhe.openfhe.Ciphertext

        Evaluate a weighted sum (mutable version) with given coefficients

        3. EvalLinearWSumMutable(self: openfhe.openfhe.CryptoContext, constantsVec: collections.abc.Sequence[complex], ciphertextVec: collections.abc.Sequence[openfhe.openfhe.Ciphertext]) -> openfhe.openfhe.Ciphertext

        Evaluate a weighted sum (mutable version) with given coefficients
        """
    def EvalLogistic(
        self, ciphertext: Ciphertext, a: typing.SupportsFloat, b: typing.SupportsFloat, degree: typing.SupportsInt
    ) -> Ciphertext:
        """EvalLogistic(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, a: typing.SupportsFloat, b: typing.SupportsFloat, degree: typing.SupportsInt) -> openfhe.openfhe.Ciphertext


        Evaluate approximate logistic function 1/(1 + exp(-x)) on a ciphertext using the Chebyshev approximation. Supported only in CKKS.

        :param ciphertext: input ciphertext
        :type ciphertext: Ciphertext
        :param a: lower bound of argument for which the coefficients were found
        :type a: float
        :param b: upper bound of argument for which the coefficients were found
        :type b: float
        :param degree: Desired degree of approximation
        :type degree: int
        :return: the result of polynomial evaluation.
        :rtype: Ciphertext

        """
    def EvalMaxSchemeSwitching(
        self,
        ciphertext: Ciphertext,
        publicKey: PublicKey,
        numValues: typing.SupportsInt = ...,
        numSlots: typing.SupportsInt = ...,
        pLWE: typing.SupportsInt = ...,
        scaleSign: typing.SupportsFloat = ...,
    ) -> list[Ciphertext]:
        """EvalMaxSchemeSwitching(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, publicKey: openfhe.openfhe.PublicKey, numValues: typing.SupportsInt = 0, numSlots: typing.SupportsInt = 0, pLWE: typing.SupportsInt = 0, scaleSign: typing.SupportsFloat = 1.0) -> list[openfhe.openfhe.Ciphertext]


        Computes maximum and index from the first packed values using scheme switching.

        :param ciphertext:  Input CKKS ciphertext.
        :type  ciphertext:  Ciphertext.
        :param publicKey:   CKKS public key.
        :type  publicKey:   PublicKey.
        :param numValues:   Number of values to compare (we assume that numValues is a power of two).
        :type  numValues:   int.
        :param numSlots:    Number of output slots.
        :type  numSlots:    int.
        :param pLWE:        Target plaintext modulus for FHEW.
        :type  pLWE:        int.
        :param scaleSign:   Scaling factor before switching to FHEW.
        :type  scaleSign:   float.
        :return:            A vector of two CKKS ciphertexts: [max, argmax]. The ciphertexts have junk after the first slot in the first ciphertext and after numValues in the second ciphertext if oneHot=true and after the first slot if oneHot=false.
        :rtype:             list of Ciphertext.

        """
    def EvalMaxSchemeSwitchingAlt(
        self,
        ciphertext: Ciphertext,
        publicKey: PublicKey,
        numValues: typing.SupportsInt = ...,
        numSlots: typing.SupportsInt = ...,
        pLWE: typing.SupportsInt = ...,
        scaleSign: typing.SupportsFloat = ...,
    ) -> list[Ciphertext]:
        """EvalMaxSchemeSwitchingAlt(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, publicKey: openfhe.openfhe.PublicKey, numValues: typing.SupportsInt = 0, numSlots: typing.SupportsInt = 0, pLWE: typing.SupportsInt = 0, scaleSign: typing.SupportsFloat = 1.0) -> list[openfhe.openfhe.Ciphertext]


        Computes max and index via scheme switching, with more FHEW operations for better precision than EvalMaxSchemeSwitching.

        :param ciphertext:  Input CKKS ciphertext.
        :type  ciphertext:  Ciphertext.
        :param publicKey:   CKKS public key.
        :type  publicKey:   PublicKey.
        :param numValues:   Number of values to compare.
        :type  numValues:   int.
        :param numSlots:    Number of output slots.
        :type  numSlots:    int.
        :param pLWE:        Target plaintext modulus for FHEW.
        :type  pLWE:        int.
        :param scaleSign:   Scaling factor before switching to FHEW.
        :type  scaleSign:   float.
        :return:            A vector of two CKKS ciphertexts: [max, argmax].
        :rtype:             list of Ciphertext.

        """
    def EvalMerge(self, ciphertextVec: collections.abc.Sequence[Ciphertext]) -> Ciphertext:
        """EvalMerge(self: openfhe.openfhe.CryptoContext, ciphertextVec: collections.abc.Sequence[openfhe.openfhe.Ciphertext]) -> openfhe.openfhe.Ciphertext


        Merges multiple ciphertexts with encrypted results in slot 0 into a single ciphertext. The slot assignment is done based on the order of ciphertexts in the vector. Requires the generation of rotation keys for the indices that are needed.

        :param ciphertextVec: vector of ciphertexts to be merged.
        :type ciphertextVec: list
        :return: resulting ciphertext
        :rtype: Ciphertext

        """
    def EvalMinSchemeSwitching(
        self,
        ciphertext: Ciphertext,
        publicKey: PublicKey,
        numValues: typing.SupportsInt = ...,
        numSlots: typing.SupportsInt = ...,
        pLWE: typing.SupportsInt = ...,
        scaleSign: typing.SupportsFloat = ...,
    ) -> list[Ciphertext]:
        """EvalMinSchemeSwitching(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, publicKey: openfhe.openfhe.PublicKey, numValues: typing.SupportsInt = 0, numSlots: typing.SupportsInt = 0, pLWE: typing.SupportsInt = 0, scaleSign: typing.SupportsFloat = 1.0) -> list[openfhe.openfhe.Ciphertext]


        Computes minimum and index of the first packed values using scheme switching.

        :param ciphertext:  Input CKKS ciphertext.
        :type  ciphertext:  Ciphertext.
        :param publicKey:   CKKS public key.
        :type  publicKey:   PublicKey.
        :param numValues:   Number of values to compare (we assume that numValues is a power of two).
        :type  numValues:   int.
        :param numSlots:    Number of output slots.
        :type  numSlots:    int.
        :param pLWE:        Target plaintext modulus for FHEW.
        :type  pLWE:        int.
        :param scaleSign:   Scaling factor before switching to FHEW. The resulting FHEW ciphertexts will encrypt values modulo pLWE, so scaleSign should account for this pLWE and is given here only if the homomorphic decoding matrix is not scaled with the desired values
        :type  scaleSign:   float.
        :return: A vector of two CKKS ciphertexts: [min, argmin]. The ciphertexts have junk after the first slot in the first ciphertext
             and after numValues in the second ciphertext if oneHot=true and after the first slot if oneHot=false.
        :rtype:             list of Ciphertext.

        """
    def EvalMinSchemeSwitchingAlt(
        self,
        ciphertext: Ciphertext,
        publicKey: PublicKey,
        numValues: typing.SupportsInt = ...,
        numSlots: typing.SupportsInt = ...,
        pLWE: typing.SupportsInt = ...,
        scaleSign: typing.SupportsFloat = ...,
    ) -> list[Ciphertext]:
        """EvalMinSchemeSwitchingAlt(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, publicKey: openfhe.openfhe.PublicKey, numValues: typing.SupportsInt = 0, numSlots: typing.SupportsInt = 0, pLWE: typing.SupportsInt = 0, scaleSign: typing.SupportsFloat = 1.0) -> list[openfhe.openfhe.Ciphertext]


        Computes minimum and index using more FHEW operations than CKKS with higher precision, but slower than EvalMinSchemeSwitching.

        :param ciphertext:  Input CKKS ciphertext.
        :type  ciphertext:  Ciphertext.
        :param publicKey:   CKKS public key.
        :type  publicKey:   PublicKey.
        :param numValues:   Number of packed values to compare.
        :type  numValues:   int.
        :param numSlots:    Number of slots in the output ciphertexts.
        :type  numSlots:    int.
        :param pLWE:        Target plaintext modulus for FHEW ciphertexts.
        :type  pLWE:        int.
        :param scaleSign:   Scaling factor before switching to FHEW.
        :type  scaleSign:   float.
        :return:            A vector with two CKKS ciphertexts: [min, argmin].
        :rtype:             list of Ciphertext.

        """
    @overload
    def EvalMult(self, ciphertext1: Ciphertext, ciphertext2: Ciphertext) -> Ciphertext:
        """EvalMult(*args, **kwargs)
        Overloaded function.

        1. EvalMult(self: openfhe.openfhe.CryptoContext, ciphertext1: openfhe.openfhe.Ciphertext, ciphertext2: openfhe.openfhe.Ciphertext) -> openfhe.openfhe.Ciphertext


        EvalMult - OpenFHE EvalMult method for a pair of ciphertexts (uses a relinearization key from the crypto context)

        :param ciphertext1: multiplier
        :type ciphertext1: Ciphertext
        :param ciphertext2: multiplicand
        :type ciphertext2: Ciphertext
        :return: new ciphertext for ciphertext1 * ciphertext2
        :rtype: Ciphertext


        2. EvalMult(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, scalar: typing.SupportsFloat) -> openfhe.openfhe.Ciphertext


        Multiplication of a ciphertext by a real number. Supported only in CKKS.

        :param ciphertext: multiplier
        :type ciphertext: Ciphertext
        :param constant: multiplicand
        :type constant: float
        :return: the result of multiplication
        :rtype: Ciphertext


        3. EvalMult(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, plaintext: openfhe.openfhe.Plaintext) -> openfhe.openfhe.Ciphertext


        Multiplication of a ciphertext by a plaintext

        :param ciphertext: multiplier
        :type ciphertext: Ciphertext
        :param plaintext: multiplicand
        :type plaintext: Plaintext
        :return: the result of multiplication
        :rtype: Ciphertext


        4. EvalMult(self: openfhe.openfhe.CryptoContext, plaintext: openfhe.openfhe.Plaintext, ciphertext: openfhe.openfhe.Ciphertext) -> openfhe.openfhe.Ciphertext

        5. EvalMult(self: openfhe.openfhe.CryptoContext, scalar: typing.SupportsFloat, ciphertext: openfhe.openfhe.Ciphertext) -> openfhe.openfhe.Ciphertext
        """
    @overload
    def EvalMult(self, ciphertext: Ciphertext, scalar: typing.SupportsFloat) -> Ciphertext:
        """EvalMult(*args, **kwargs)
        Overloaded function.

        1. EvalMult(self: openfhe.openfhe.CryptoContext, ciphertext1: openfhe.openfhe.Ciphertext, ciphertext2: openfhe.openfhe.Ciphertext) -> openfhe.openfhe.Ciphertext


        EvalMult - OpenFHE EvalMult method for a pair of ciphertexts (uses a relinearization key from the crypto context)

        :param ciphertext1: multiplier
        :type ciphertext1: Ciphertext
        :param ciphertext2: multiplicand
        :type ciphertext2: Ciphertext
        :return: new ciphertext for ciphertext1 * ciphertext2
        :rtype: Ciphertext


        2. EvalMult(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, scalar: typing.SupportsFloat) -> openfhe.openfhe.Ciphertext


        Multiplication of a ciphertext by a real number. Supported only in CKKS.

        :param ciphertext: multiplier
        :type ciphertext: Ciphertext
        :param constant: multiplicand
        :type constant: float
        :return: the result of multiplication
        :rtype: Ciphertext


        3. EvalMult(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, plaintext: openfhe.openfhe.Plaintext) -> openfhe.openfhe.Ciphertext


        Multiplication of a ciphertext by a plaintext

        :param ciphertext: multiplier
        :type ciphertext: Ciphertext
        :param plaintext: multiplicand
        :type plaintext: Plaintext
        :return: the result of multiplication
        :rtype: Ciphertext


        4. EvalMult(self: openfhe.openfhe.CryptoContext, plaintext: openfhe.openfhe.Plaintext, ciphertext: openfhe.openfhe.Ciphertext) -> openfhe.openfhe.Ciphertext

        5. EvalMult(self: openfhe.openfhe.CryptoContext, scalar: typing.SupportsFloat, ciphertext: openfhe.openfhe.Ciphertext) -> openfhe.openfhe.Ciphertext
        """
    @overload
    def EvalMult(self, ciphertext: Ciphertext, plaintext: Plaintext) -> Ciphertext:
        """EvalMult(*args, **kwargs)
        Overloaded function.

        1. EvalMult(self: openfhe.openfhe.CryptoContext, ciphertext1: openfhe.openfhe.Ciphertext, ciphertext2: openfhe.openfhe.Ciphertext) -> openfhe.openfhe.Ciphertext


        EvalMult - OpenFHE EvalMult method for a pair of ciphertexts (uses a relinearization key from the crypto context)

        :param ciphertext1: multiplier
        :type ciphertext1: Ciphertext
        :param ciphertext2: multiplicand
        :type ciphertext2: Ciphertext
        :return: new ciphertext for ciphertext1 * ciphertext2
        :rtype: Ciphertext


        2. EvalMult(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, scalar: typing.SupportsFloat) -> openfhe.openfhe.Ciphertext


        Multiplication of a ciphertext by a real number. Supported only in CKKS.

        :param ciphertext: multiplier
        :type ciphertext: Ciphertext
        :param constant: multiplicand
        :type constant: float
        :return: the result of multiplication
        :rtype: Ciphertext


        3. EvalMult(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, plaintext: openfhe.openfhe.Plaintext) -> openfhe.openfhe.Ciphertext


        Multiplication of a ciphertext by a plaintext

        :param ciphertext: multiplier
        :type ciphertext: Ciphertext
        :param plaintext: multiplicand
        :type plaintext: Plaintext
        :return: the result of multiplication
        :rtype: Ciphertext


        4. EvalMult(self: openfhe.openfhe.CryptoContext, plaintext: openfhe.openfhe.Plaintext, ciphertext: openfhe.openfhe.Ciphertext) -> openfhe.openfhe.Ciphertext

        5. EvalMult(self: openfhe.openfhe.CryptoContext, scalar: typing.SupportsFloat, ciphertext: openfhe.openfhe.Ciphertext) -> openfhe.openfhe.Ciphertext
        """
    @overload
    def EvalMult(self, plaintext: Plaintext, ciphertext: Ciphertext) -> Ciphertext:
        """EvalMult(*args, **kwargs)
        Overloaded function.

        1. EvalMult(self: openfhe.openfhe.CryptoContext, ciphertext1: openfhe.openfhe.Ciphertext, ciphertext2: openfhe.openfhe.Ciphertext) -> openfhe.openfhe.Ciphertext


        EvalMult - OpenFHE EvalMult method for a pair of ciphertexts (uses a relinearization key from the crypto context)

        :param ciphertext1: multiplier
        :type ciphertext1: Ciphertext
        :param ciphertext2: multiplicand
        :type ciphertext2: Ciphertext
        :return: new ciphertext for ciphertext1 * ciphertext2
        :rtype: Ciphertext


        2. EvalMult(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, scalar: typing.SupportsFloat) -> openfhe.openfhe.Ciphertext


        Multiplication of a ciphertext by a real number. Supported only in CKKS.

        :param ciphertext: multiplier
        :type ciphertext: Ciphertext
        :param constant: multiplicand
        :type constant: float
        :return: the result of multiplication
        :rtype: Ciphertext


        3. EvalMult(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, plaintext: openfhe.openfhe.Plaintext) -> openfhe.openfhe.Ciphertext


        Multiplication of a ciphertext by a plaintext

        :param ciphertext: multiplier
        :type ciphertext: Ciphertext
        :param plaintext: multiplicand
        :type plaintext: Plaintext
        :return: the result of multiplication
        :rtype: Ciphertext


        4. EvalMult(self: openfhe.openfhe.CryptoContext, plaintext: openfhe.openfhe.Plaintext, ciphertext: openfhe.openfhe.Ciphertext) -> openfhe.openfhe.Ciphertext

        5. EvalMult(self: openfhe.openfhe.CryptoContext, scalar: typing.SupportsFloat, ciphertext: openfhe.openfhe.Ciphertext) -> openfhe.openfhe.Ciphertext
        """
    @overload
    def EvalMult(self, scalar: typing.SupportsFloat, ciphertext: Ciphertext) -> Ciphertext:
        """EvalMult(*args, **kwargs)
        Overloaded function.

        1. EvalMult(self: openfhe.openfhe.CryptoContext, ciphertext1: openfhe.openfhe.Ciphertext, ciphertext2: openfhe.openfhe.Ciphertext) -> openfhe.openfhe.Ciphertext


        EvalMult - OpenFHE EvalMult method for a pair of ciphertexts (uses a relinearization key from the crypto context)

        :param ciphertext1: multiplier
        :type ciphertext1: Ciphertext
        :param ciphertext2: multiplicand
        :type ciphertext2: Ciphertext
        :return: new ciphertext for ciphertext1 * ciphertext2
        :rtype: Ciphertext


        2. EvalMult(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, scalar: typing.SupportsFloat) -> openfhe.openfhe.Ciphertext


        Multiplication of a ciphertext by a real number. Supported only in CKKS.

        :param ciphertext: multiplier
        :type ciphertext: Ciphertext
        :param constant: multiplicand
        :type constant: float
        :return: the result of multiplication
        :rtype: Ciphertext


        3. EvalMult(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, plaintext: openfhe.openfhe.Plaintext) -> openfhe.openfhe.Ciphertext


        Multiplication of a ciphertext by a plaintext

        :param ciphertext: multiplier
        :type ciphertext: Ciphertext
        :param plaintext: multiplicand
        :type plaintext: Plaintext
        :return: the result of multiplication
        :rtype: Ciphertext


        4. EvalMult(self: openfhe.openfhe.CryptoContext, plaintext: openfhe.openfhe.Plaintext, ciphertext: openfhe.openfhe.Ciphertext) -> openfhe.openfhe.Ciphertext

        5. EvalMult(self: openfhe.openfhe.CryptoContext, scalar: typing.SupportsFloat, ciphertext: openfhe.openfhe.Ciphertext) -> openfhe.openfhe.Ciphertext
        """
    def EvalMultAndRelinearize(self, ciphertext1: Ciphertext, ciphertext2: Ciphertext) -> Ciphertext:
        """EvalMultAndRelinearize(self: openfhe.openfhe.CryptoContext, ciphertext1: openfhe.openfhe.Ciphertext, ciphertext2: openfhe.openfhe.Ciphertext) -> openfhe.openfhe.Ciphertext


        Homomorphic multiplication of two ciphertexts followed by relinearization to the lowest level

        :param ciphertext1: first input ciphertext
        :type ciphertext1: Ciphertext
        :param ciphertext2: second input ciphertext
        :type ciphertext2: Ciphertext
        :return: new ciphertext
        :rtype: Ciphertext

        """
    def EvalMultKeyGen(self, privateKey: PrivateKey) -> None:
        """EvalMultKeyGen(self: openfhe.openfhe.CryptoContext, privateKey: openfhe.openfhe.PrivateKey) -> None


        EvalMultKeyGen creates a key that can be used with the OpenFHE EvalMult operator.
        The new evaluation key is stored in cryptocontext.

        :param privateKey: the private key
        :type privateKey: PrivateKey

        """
    def EvalMultKeysGen(self, privateKey: PrivateKey) -> None:
        """EvalMultKeysGen(self: openfhe.openfhe.CryptoContext, privateKey: openfhe.openfhe.PrivateKey) -> None


        EvalMultsKeyGen creates a vector evalmult keys that can be used with the OpenFHE EvalMult operator.
        The 1st key (for s^2) is used for multiplication of ciphertexts of depth 1.
        The 2nd key (for s^3) is used for multiplication of ciphertexts of depth 2, etc.
        A vector of new evaluation keys is stored in cryptocontext.

        :param privateKey: the private key
        :type privateKey: PrivateKey

        """
    def EvalMultMany(self, ciphertextVec: collections.abc.Sequence[Ciphertext]) -> Ciphertext:
        """EvalMultMany(self: openfhe.openfhe.CryptoContext, ciphertextVec: collections.abc.Sequence[openfhe.openfhe.Ciphertext]) -> openfhe.openfhe.Ciphertext"""
    @overload
    def EvalMultMutable(self, ciphertext1: Ciphertext, ciphertext2: Ciphertext) -> Ciphertext:
        """EvalMultMutable(*args, **kwargs)
        Overloaded function.

        1. EvalMultMutable(self: openfhe.openfhe.CryptoContext, ciphertext1: openfhe.openfhe.Ciphertext, ciphertext2: openfhe.openfhe.Ciphertext) -> openfhe.openfhe.Ciphertext


        EvalMult - OpenFHE EvalMult method for a pair of mutable ciphertexts (uses a relinearization key from the crypto context)

        :param ciphertext1: multiplier
        :type ciphertext1: Ciphertext
        :param ciphertext2: multiplicand
        :type ciphertext2: Ciphertext
        :return: new ciphertext for ciphertext1 * ciphertext2
        :rtype: Ciphertext


        2. EvalMultMutable(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, plaintext: openfhe.openfhe.Plaintext) -> openfhe.openfhe.Ciphertext


        Multiplication of mutable ciphertext and plaintext
        :param ciphertext: multiplier
        :type ciphertext: Ciphertext
        :param plaintext: multiplicand
        :type plaintext: Plaintext
        :return: the result of multiplication
        :rtype: Ciphertext


        3. EvalMultMutable(self: openfhe.openfhe.CryptoContext, plaintext: openfhe.openfhe.Plaintext, ciphertext: openfhe.openfhe.Ciphertext) -> openfhe.openfhe.Ciphertext
        """
    @overload
    def EvalMultMutable(self, ciphertext: Ciphertext, plaintext: Plaintext) -> Ciphertext:
        """EvalMultMutable(*args, **kwargs)
        Overloaded function.

        1. EvalMultMutable(self: openfhe.openfhe.CryptoContext, ciphertext1: openfhe.openfhe.Ciphertext, ciphertext2: openfhe.openfhe.Ciphertext) -> openfhe.openfhe.Ciphertext


        EvalMult - OpenFHE EvalMult method for a pair of mutable ciphertexts (uses a relinearization key from the crypto context)

        :param ciphertext1: multiplier
        :type ciphertext1: Ciphertext
        :param ciphertext2: multiplicand
        :type ciphertext2: Ciphertext
        :return: new ciphertext for ciphertext1 * ciphertext2
        :rtype: Ciphertext


        2. EvalMultMutable(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, plaintext: openfhe.openfhe.Plaintext) -> openfhe.openfhe.Ciphertext


        Multiplication of mutable ciphertext and plaintext
        :param ciphertext: multiplier
        :type ciphertext: Ciphertext
        :param plaintext: multiplicand
        :type plaintext: Plaintext
        :return: the result of multiplication
        :rtype: Ciphertext


        3. EvalMultMutable(self: openfhe.openfhe.CryptoContext, plaintext: openfhe.openfhe.Plaintext, ciphertext: openfhe.openfhe.Ciphertext) -> openfhe.openfhe.Ciphertext
        """
    @overload
    def EvalMultMutable(self, plaintext: Plaintext, ciphertext: Ciphertext) -> Ciphertext:
        """EvalMultMutable(*args, **kwargs)
        Overloaded function.

        1. EvalMultMutable(self: openfhe.openfhe.CryptoContext, ciphertext1: openfhe.openfhe.Ciphertext, ciphertext2: openfhe.openfhe.Ciphertext) -> openfhe.openfhe.Ciphertext


        EvalMult - OpenFHE EvalMult method for a pair of mutable ciphertexts (uses a relinearization key from the crypto context)

        :param ciphertext1: multiplier
        :type ciphertext1: Ciphertext
        :param ciphertext2: multiplicand
        :type ciphertext2: Ciphertext
        :return: new ciphertext for ciphertext1 * ciphertext2
        :rtype: Ciphertext


        2. EvalMultMutable(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, plaintext: openfhe.openfhe.Plaintext) -> openfhe.openfhe.Ciphertext


        Multiplication of mutable ciphertext and plaintext
        :param ciphertext: multiplier
        :type ciphertext: Ciphertext
        :param plaintext: multiplicand
        :type plaintext: Plaintext
        :return: the result of multiplication
        :rtype: Ciphertext


        3. EvalMultMutable(self: openfhe.openfhe.CryptoContext, plaintext: openfhe.openfhe.Plaintext, ciphertext: openfhe.openfhe.Ciphertext) -> openfhe.openfhe.Ciphertext
        """
    def EvalMultMutableInPlace(self, ciphertext1: Ciphertext, ciphertext2: Ciphertext) -> None:
        """EvalMultMutableInPlace(self: openfhe.openfhe.CryptoContext, ciphertext1: openfhe.openfhe.Ciphertext, ciphertext2: openfhe.openfhe.Ciphertext) -> None


        In-place EvalMult method for a pair of mutable ciphertexts (uses a relinearization key from the crypto context)

        :param ciphertext1: multiplier
        :type ciphertext1: Ciphertext
        :param ciphertext2: multiplicand
        :type ciphertext2: Ciphertext

        """
    def EvalMultNoRelin(self, ciphertext1: Ciphertext, ciphertext2: Ciphertext) -> Ciphertext:
        """EvalMultNoRelin(self: openfhe.openfhe.CryptoContext, ciphertext1: openfhe.openfhe.Ciphertext, ciphertext2: openfhe.openfhe.Ciphertext) -> openfhe.openfhe.Ciphertext


        Homomorphic multiplication of two ciphertexts without relinearization

        :param ciphertext1: multiplier
        :type ciphertext1: Ciphertext
        :param ciphertext2: multiplicand
        :type ciphertext2: Ciphertext
        :return: new ciphertext for ciphertext1 * ciphertext2
        :rtype: Ciphertext

        """
    def EvalNegate(self, ciphertext: Ciphertext) -> Ciphertext:
        """EvalNegate(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext) -> openfhe.openfhe.Ciphertext


        Negates a ciphertext

        :param ciphertext: input ciphertext
        :type ciphertext: Ciphertext
        :return: new ciphertext: -ciphertext
        :rtype: Ciphertext

        """
    def EvalNegateInPlace(self, ciphertext: Ciphertext) -> None:
        """EvalNegateInPlace(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext) -> None


        In-place negation of a ciphertext

        :param ciphertext: input ciphertext
        :type ciphertext: Ciphertext

        """
    def EvalPoly(self, ciphertext: Ciphertext, coefficients: collections.abc.Sequence[typing.SupportsInt]) -> Ciphertext:
        """EvalPoly(*args, **kwargs)
        Overloaded function.

        1. EvalPoly(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, coefficients: collections.abc.Sequence[typing.SupportsInt]) -> openfhe.openfhe.Ciphertext


            Evaluates a polynomial (given as a power series) on a ciphertext (CKKS only). Use EvalPolyLinear() for low polynomial degrees (degree < 5), or EvalPolyPS() for higher degrees.

            :param ciphertext: Input ciphertext.
            :type ciphertext: Ciphertext
            :param coefficients: Polynomial coefficients (vector's size = (degree + 1)).
            :type coefficients: list
            :return: Ciphertext: Resulting ciphertext.
            :rtype: Ciphertext


        2. EvalPoly(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, coefficients: collections.abc.Sequence[typing.SupportsFloat]) -> openfhe.openfhe.Ciphertext


            Evaluates a polynomial (given as a power series) on a ciphertext (CKKS only). Use EvalPolyLinear() for low polynomial degrees (degree < 5), or EvalPolyPS() for higher degrees.

            :param ciphertext: Input ciphertext.
            :type ciphertext: Ciphertext
            :param coefficients: Polynomial coefficients (vector's size = (degree + 1)).
            :type coefficients: list
            :return: Ciphertext: Resulting ciphertext.
            :rtype: Ciphertext


        3. EvalPoly(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, coefficients: collections.abc.Sequence[complex]) -> openfhe.openfhe.Ciphertext


            Evaluates a polynomial (given as a power series) on a ciphertext (CKKS only). Use EvalPolyLinear() for low polynomial degrees (degree < 5), or EvalPolyPS() for higher degrees.

            :param ciphertext: Input ciphertext.
            :type ciphertext: Ciphertext
            :param coefficients: Polynomial coefficients (vector's size = (degree + 1)).
            :type coefficients: list
            :return: Ciphertext: Resulting ciphertext.
            :rtype: Ciphertext

        """
    @overload
    def EvalPolyLinear(self, ciphertext: Ciphertext, coefficients: collections.abc.Sequence[typing.SupportsInt]) -> Ciphertext:
        """EvalPolyLinear(*args, **kwargs)
        Overloaded function.

        1. EvalPolyLinear(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, coefficients: collections.abc.Sequence[typing.SupportsInt]) -> openfhe.openfhe.Ciphertext


            Naive method for polynomial evaluation for polynomials represented in the power series (fast only for small-degree polynomials; less than 10). Uses a binary tree computation of the polynomial powers. Supported only in CKKS.

            :param ciphertext: input ciphertext
            :type ciphertext: Ciphertext
            :param coefficients: is the vector of coefficients in the polynomial; the size of the vector is the degree of the polynomial
            :type coefficients: list
            :return: Ciphertext: the result of polynomial evaluation.
            :rtype: Ciphertext


        2. EvalPolyLinear(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, coefficients: collections.abc.Sequence[typing.SupportsFloat]) -> openfhe.openfhe.Ciphertext


            Naive method for polynomial evaluation for polynomials represented in the power series (fast only for small-degree polynomials; less than 10). Uses a binary tree computation of the polynomial powers. Supported only in CKKS.

            :param ciphertext: input ciphertext
            :type ciphertext: Ciphertext
            :param coefficients: is the vector of coefficients in the polynomial; the size of the vector is the degree of the polynomial
            :type coefficients: list
            :return: Ciphertext: the result of polynomial evaluation.
            :rtype: Ciphertext


        3. EvalPolyLinear(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, coefficients: collections.abc.Sequence[complex]) -> openfhe.openfhe.Ciphertext


            Naive method for polynomial evaluation for polynomials represented in the power series (fast only for small-degree polynomials; less than 10). Uses a binary tree computation of the polynomial powers. Supported only in CKKS.

            :param ciphertext: input ciphertext
            :type ciphertext: Ciphertext
            :param coefficients: is the vector of coefficients in the polynomial; the size of the vector is the degree of the polynomial
            :type coefficients: list
            :return: Ciphertext: the result of polynomial evaluation.
            :rtype: Ciphertext

        """
    @overload
    def EvalPolyLinear(self, ciphertext: Ciphertext, coefficients: collections.abc.Sequence[typing.SupportsFloat]) -> Ciphertext:
        """EvalPolyLinear(*args, **kwargs)
        Overloaded function.

        1. EvalPolyLinear(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, coefficients: collections.abc.Sequence[typing.SupportsInt]) -> openfhe.openfhe.Ciphertext


            Naive method for polynomial evaluation for polynomials represented in the power series (fast only for small-degree polynomials; less than 10). Uses a binary tree computation of the polynomial powers. Supported only in CKKS.

            :param ciphertext: input ciphertext
            :type ciphertext: Ciphertext
            :param coefficients: is the vector of coefficients in the polynomial; the size of the vector is the degree of the polynomial
            :type coefficients: list
            :return: Ciphertext: the result of polynomial evaluation.
            :rtype: Ciphertext


        2. EvalPolyLinear(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, coefficients: collections.abc.Sequence[typing.SupportsFloat]) -> openfhe.openfhe.Ciphertext


            Naive method for polynomial evaluation for polynomials represented in the power series (fast only for small-degree polynomials; less than 10). Uses a binary tree computation of the polynomial powers. Supported only in CKKS.

            :param ciphertext: input ciphertext
            :type ciphertext: Ciphertext
            :param coefficients: is the vector of coefficients in the polynomial; the size of the vector is the degree of the polynomial
            :type coefficients: list
            :return: Ciphertext: the result of polynomial evaluation.
            :rtype: Ciphertext


        3. EvalPolyLinear(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, coefficients: collections.abc.Sequence[complex]) -> openfhe.openfhe.Ciphertext


            Naive method for polynomial evaluation for polynomials represented in the power series (fast only for small-degree polynomials; less than 10). Uses a binary tree computation of the polynomial powers. Supported only in CKKS.

            :param ciphertext: input ciphertext
            :type ciphertext: Ciphertext
            :param coefficients: is the vector of coefficients in the polynomial; the size of the vector is the degree of the polynomial
            :type coefficients: list
            :return: Ciphertext: the result of polynomial evaluation.
            :rtype: Ciphertext

        """
    @overload
    def EvalPolyLinear(self, ciphertext: Ciphertext, coefficients: collections.abc.Sequence[complex]) -> Ciphertext:
        """EvalPolyLinear(*args, **kwargs)
        Overloaded function.

        1. EvalPolyLinear(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, coefficients: collections.abc.Sequence[typing.SupportsInt]) -> openfhe.openfhe.Ciphertext


            Naive method for polynomial evaluation for polynomials represented in the power series (fast only for small-degree polynomials; less than 10). Uses a binary tree computation of the polynomial powers. Supported only in CKKS.

            :param ciphertext: input ciphertext
            :type ciphertext: Ciphertext
            :param coefficients: is the vector of coefficients in the polynomial; the size of the vector is the degree of the polynomial
            :type coefficients: list
            :return: Ciphertext: the result of polynomial evaluation.
            :rtype: Ciphertext


        2. EvalPolyLinear(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, coefficients: collections.abc.Sequence[typing.SupportsFloat]) -> openfhe.openfhe.Ciphertext


            Naive method for polynomial evaluation for polynomials represented in the power series (fast only for small-degree polynomials; less than 10). Uses a binary tree computation of the polynomial powers. Supported only in CKKS.

            :param ciphertext: input ciphertext
            :type ciphertext: Ciphertext
            :param coefficients: is the vector of coefficients in the polynomial; the size of the vector is the degree of the polynomial
            :type coefficients: list
            :return: Ciphertext: the result of polynomial evaluation.
            :rtype: Ciphertext


        3. EvalPolyLinear(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, coefficients: collections.abc.Sequence[complex]) -> openfhe.openfhe.Ciphertext


            Naive method for polynomial evaluation for polynomials represented in the power series (fast only for small-degree polynomials; less than 10). Uses a binary tree computation of the polynomial powers. Supported only in CKKS.

            :param ciphertext: input ciphertext
            :type ciphertext: Ciphertext
            :param coefficients: is the vector of coefficients in the polynomial; the size of the vector is the degree of the polynomial
            :type coefficients: list
            :return: Ciphertext: the result of polynomial evaluation.
            :rtype: Ciphertext

        """
    @overload
    def EvalPolyPS(self, ciphertext: Ciphertext, coefficients: collections.abc.Sequence[typing.SupportsInt]) -> Ciphertext:
        """EvalPolyPS(*args, **kwargs)
        Overloaded function.

        1. EvalPolyPS(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, coefficients: collections.abc.Sequence[typing.SupportsInt]) -> openfhe.openfhe.Ciphertext


            Paterson-Stockmeyer method for evaluation for polynomials represented in the power series. Supported only in CKKS.

            :param ciphertext: input ciphertext
            :type ciphertext: Ciphertext
            :param coefficients: is the vector of coefficients in the polynomial; the size of the vector is the degree of the polynomial
            :type coefficients: list
            :return: Ciphertext: the result of polynomial evaluation.
            :rtype: Ciphertext


        2. EvalPolyPS(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, coefficients: collections.abc.Sequence[typing.SupportsFloat]) -> openfhe.openfhe.Ciphertext


            Paterson-Stockmeyer method for evaluation for polynomials represented in the power series. Supported only in CKKS.

            :param ciphertext: input ciphertext
            :type ciphertext: Ciphertext
            :param coefficients: is the vector of coefficients in the polynomial; the size of the vector is the degree of the polynomial
            :type coefficients: list
            :return: Ciphertext: the result of polynomial evaluation.
            :rtype: Ciphertext


        3. EvalPolyPS(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, coefficients: collections.abc.Sequence[complex]) -> openfhe.openfhe.Ciphertext


            Paterson-Stockmeyer method for evaluation for polynomials represented in the power series. Supported only in CKKS.

            :param ciphertext: input ciphertext
            :type ciphertext: Ciphertext
            :param coefficients: is the vector of coefficients in the polynomial; the size of the vector is the degree of the polynomial
            :type coefficients: list
            :return: Ciphertext: the result of polynomial evaluation.
            :rtype: Ciphertext

        """
    @overload
    def EvalPolyPS(self, ciphertext: Ciphertext, coefficients: collections.abc.Sequence[typing.SupportsFloat]) -> Ciphertext:
        """EvalPolyPS(*args, **kwargs)
        Overloaded function.

        1. EvalPolyPS(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, coefficients: collections.abc.Sequence[typing.SupportsInt]) -> openfhe.openfhe.Ciphertext


            Paterson-Stockmeyer method for evaluation for polynomials represented in the power series. Supported only in CKKS.

            :param ciphertext: input ciphertext
            :type ciphertext: Ciphertext
            :param coefficients: is the vector of coefficients in the polynomial; the size of the vector is the degree of the polynomial
            :type coefficients: list
            :return: Ciphertext: the result of polynomial evaluation.
            :rtype: Ciphertext


        2. EvalPolyPS(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, coefficients: collections.abc.Sequence[typing.SupportsFloat]) -> openfhe.openfhe.Ciphertext


            Paterson-Stockmeyer method for evaluation for polynomials represented in the power series. Supported only in CKKS.

            :param ciphertext: input ciphertext
            :type ciphertext: Ciphertext
            :param coefficients: is the vector of coefficients in the polynomial; the size of the vector is the degree of the polynomial
            :type coefficients: list
            :return: Ciphertext: the result of polynomial evaluation.
            :rtype: Ciphertext


        3. EvalPolyPS(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, coefficients: collections.abc.Sequence[complex]) -> openfhe.openfhe.Ciphertext


            Paterson-Stockmeyer method for evaluation for polynomials represented in the power series. Supported only in CKKS.

            :param ciphertext: input ciphertext
            :type ciphertext: Ciphertext
            :param coefficients: is the vector of coefficients in the polynomial; the size of the vector is the degree of the polynomial
            :type coefficients: list
            :return: Ciphertext: the result of polynomial evaluation.
            :rtype: Ciphertext

        """
    @overload
    def EvalPolyPS(self, ciphertext: Ciphertext, coefficients: collections.abc.Sequence[complex]) -> Ciphertext:
        """EvalPolyPS(*args, **kwargs)
        Overloaded function.

        1. EvalPolyPS(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, coefficients: collections.abc.Sequence[typing.SupportsInt]) -> openfhe.openfhe.Ciphertext


            Paterson-Stockmeyer method for evaluation for polynomials represented in the power series. Supported only in CKKS.

            :param ciphertext: input ciphertext
            :type ciphertext: Ciphertext
            :param coefficients: is the vector of coefficients in the polynomial; the size of the vector is the degree of the polynomial
            :type coefficients: list
            :return: Ciphertext: the result of polynomial evaluation.
            :rtype: Ciphertext


        2. EvalPolyPS(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, coefficients: collections.abc.Sequence[typing.SupportsFloat]) -> openfhe.openfhe.Ciphertext


            Paterson-Stockmeyer method for evaluation for polynomials represented in the power series. Supported only in CKKS.

            :param ciphertext: input ciphertext
            :type ciphertext: Ciphertext
            :param coefficients: is the vector of coefficients in the polynomial; the size of the vector is the degree of the polynomial
            :type coefficients: list
            :return: Ciphertext: the result of polynomial evaluation.
            :rtype: Ciphertext


        3. EvalPolyPS(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, coefficients: collections.abc.Sequence[complex]) -> openfhe.openfhe.Ciphertext


            Paterson-Stockmeyer method for evaluation for polynomials represented in the power series. Supported only in CKKS.

            :param ciphertext: input ciphertext
            :type ciphertext: Ciphertext
            :param coefficients: is the vector of coefficients in the polynomial; the size of the vector is the degree of the polynomial
            :type coefficients: list
            :return: Ciphertext: the result of polynomial evaluation.
            :rtype: Ciphertext

        """
    def EvalRotate(self, ciphertext: Ciphertext, index: typing.SupportsInt) -> Ciphertext:
        """EvalRotate(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, index: typing.SupportsInt) -> openfhe.openfhe.Ciphertext


        Rotates a ciphertext by an index (positive index is a left shift, negative index is a right shift). Uses a rotation key stored in a crypto context. Calls EvalAtIndex under the hood.

        :param ciphertext: input ciphertext
        :type ciphertext: Ciphertext
        :param index: rotation index
        :type index: int
        :return: a rotated ciphertext
        :rtype: Ciphertext

        """
    def EvalRotateKeyGen(
        self, privateKey: PrivateKey, indexList: collections.abc.Sequence[typing.SupportsInt], publicKey: PublicKey = ...
    ) -> None:
        """EvalRotateKeyGen(self: openfhe.openfhe.CryptoContext, privateKey: openfhe.openfhe.PrivateKey, indexList: collections.abc.Sequence[typing.SupportsInt], publicKey: openfhe.openfhe.PublicKey = None) -> None


        EvalRotateKeyGen generates evaluation keys for a list of indices. Calls EvalAtIndexKeyGen under the hood.

        :param privateKey: private key
        :type privateKey: PrivateKey
        :param indexList: list of integers representing the indices
        :type indexList: list
        :param publicKey: public key (used in NTRU schemes)
        :type publicKey: PublicKey

        """
    def EvalSchemeSwitchingKeyGen(self, keyPair: KeyPair, lwesk: LWEPrivateKey) -> None:
        """EvalSchemeSwitchingKeyGen(self: openfhe.openfhe.CryptoContext, keyPair: openfhe.openfhe.KeyPair, lwesk: openfhe.openfhe.LWEPrivateKey) -> None


        Generates keys for switching between CKKS and FHEW.

        :param keyPair:  CKKS key pair.
        :type  keyPair:  KeyPair.
        :param lwesk:    FHEW secret key.
        :type  lwesk:    LWEPrivateKey.

        """
    def EvalSchemeSwitchingSetup(self, schswchparams) -> LWEPrivateKey:
        """EvalSchemeSwitchingSetup(self: openfhe.openfhe.CryptoContext, schswchparams: lbcrypto::SchSwchParams) -> openfhe.openfhe.LWEPrivateKey


        Sets parameters for switching between CKKS and FHEW.

        :param schswchparams:  Scheme switching parameter object.
        :type  schswchparams:  SchSwchParams.
        :return:               FHEW secret key.
        :rtype:                LWEPrivateKey.

        """
    def EvalSin(self, ciphertext: Ciphertext, a: typing.SupportsFloat, b: typing.SupportsFloat, degree: typing.SupportsInt) -> Ciphertext:
        """EvalSin(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, a: typing.SupportsFloat, b: typing.SupportsFloat, degree: typing.SupportsInt) -> openfhe.openfhe.Ciphertext


        Evaluate approximate sine function on a ciphertext using the Chebyshev approximation. Supported only in CKKS.

        :param ciphertext: input ciphertext
        :type ciphertext: Ciphertext
        :param a: lower bound of argument for which the coefficients were found
        :type a: float
        :param b: upper bound of argument for which the coefficients were found
        :type b: float
        :param degree: Desired degree of approximation
        :type degree: int
        :return: the result of polynomial evaluation.
        :rtype: Ciphertext

        """
    def EvalSquare(self, ciphertext: Ciphertext) -> Ciphertext:
        """EvalSquare(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext) -> openfhe.openfhe.Ciphertext


        Efficient homomorphic squaring of a ciphertext - uses a relinearization key stored in the crypto context

        :param ciphertext: input ciphertext
        :type ciphertext: Ciphertext
        :return: squared ciphertext
        :rtype: Ciphertext

        """
    def EvalSquareInPlace(self, ciphertext: Ciphertext) -> None:
        """EvalSquareInPlace(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext) -> None


        In-place homomorphic squaring of a mutable ciphertext - uses a relinearization key stored in the crypto context

        :param ciphertext: input ciphertext
        :type ciphertext: Ciphertext
        :return: squared ciphertext

        """
    def EvalSquareMutable(self, ciphertext: Ciphertext) -> Ciphertext:
        """EvalSquareMutable(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext) -> openfhe.openfhe.Ciphertext


        Efficient homomorphic squaring of a mutable ciphertext - uses a relinearization key stored in the crypto context

        :param ciphertext: input ciphertext
        :type ciphertext: Ciphertext
        :return: squared ciphertext
        :rtype: Ciphertext

        """
    @overload
    def EvalSub(self, ciphertext1: Ciphertext, ciphertext2: Ciphertext) -> Ciphertext:
        """EvalSub(*args, **kwargs)
        Overloaded function.

        1. EvalSub(self: openfhe.openfhe.CryptoContext, ciphertext1: openfhe.openfhe.Ciphertext, ciphertext2: openfhe.openfhe.Ciphertext) -> openfhe.openfhe.Ciphertext


        Homomorphic subtraction of two ciphertexts

        :param ciphertext1: minuend
        :type ciphertext1: Ciphertext
        :param ciphertext2: subtrahend
        :type ciphertext2: Ciphertext
        :return: the result as a new ciphertext
        :rtype: Ciphertext


        2. EvalSub(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, scalar: typing.SupportsFloat) -> openfhe.openfhe.Ciphertext


        Subtraction of a ciphertext and a real number. Supported only in CKKS.

        :param ciphertext: input ciphertext
        :type ciphertext: Ciphertext
        :param constant: a real number
        :type constant: float
        :return: new ciphertext for ciphertext - constant
        :rtype: Ciphertext


        3. EvalSub(self: openfhe.openfhe.CryptoContext, scalar: typing.SupportsFloat, ciphertext: openfhe.openfhe.Ciphertext) -> openfhe.openfhe.Ciphertext

        4. EvalSub(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, plaintext: openfhe.openfhe.Plaintext) -> openfhe.openfhe.Ciphertext


        Subtraction of a ciphertext and a real number. Supported only in CKKS.

        :param ciphertext: minuend
        :type ciphertext: Ciphertext
        :param plaintext: subtrahend
        :type plaintext: Plaintext
        :return: new ciphertext for ciphertext - plaintext
        :rtype: Ciphertext


        5. EvalSub(self: openfhe.openfhe.CryptoContext, plaintext: openfhe.openfhe.Plaintext, ciphertext: openfhe.openfhe.Ciphertext) -> openfhe.openfhe.Ciphertext
        """
    @overload
    def EvalSub(self, ciphertext: Ciphertext, scalar: typing.SupportsFloat) -> Ciphertext:
        """EvalSub(*args, **kwargs)
        Overloaded function.

        1. EvalSub(self: openfhe.openfhe.CryptoContext, ciphertext1: openfhe.openfhe.Ciphertext, ciphertext2: openfhe.openfhe.Ciphertext) -> openfhe.openfhe.Ciphertext


        Homomorphic subtraction of two ciphertexts

        :param ciphertext1: minuend
        :type ciphertext1: Ciphertext
        :param ciphertext2: subtrahend
        :type ciphertext2: Ciphertext
        :return: the result as a new ciphertext
        :rtype: Ciphertext


        2. EvalSub(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, scalar: typing.SupportsFloat) -> openfhe.openfhe.Ciphertext


        Subtraction of a ciphertext and a real number. Supported only in CKKS.

        :param ciphertext: input ciphertext
        :type ciphertext: Ciphertext
        :param constant: a real number
        :type constant: float
        :return: new ciphertext for ciphertext - constant
        :rtype: Ciphertext


        3. EvalSub(self: openfhe.openfhe.CryptoContext, scalar: typing.SupportsFloat, ciphertext: openfhe.openfhe.Ciphertext) -> openfhe.openfhe.Ciphertext

        4. EvalSub(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, plaintext: openfhe.openfhe.Plaintext) -> openfhe.openfhe.Ciphertext


        Subtraction of a ciphertext and a real number. Supported only in CKKS.

        :param ciphertext: minuend
        :type ciphertext: Ciphertext
        :param plaintext: subtrahend
        :type plaintext: Plaintext
        :return: new ciphertext for ciphertext - plaintext
        :rtype: Ciphertext


        5. EvalSub(self: openfhe.openfhe.CryptoContext, plaintext: openfhe.openfhe.Plaintext, ciphertext: openfhe.openfhe.Ciphertext) -> openfhe.openfhe.Ciphertext
        """
    @overload
    def EvalSub(self, scalar: typing.SupportsFloat, ciphertext: Ciphertext) -> Ciphertext:
        """EvalSub(*args, **kwargs)
        Overloaded function.

        1. EvalSub(self: openfhe.openfhe.CryptoContext, ciphertext1: openfhe.openfhe.Ciphertext, ciphertext2: openfhe.openfhe.Ciphertext) -> openfhe.openfhe.Ciphertext


        Homomorphic subtraction of two ciphertexts

        :param ciphertext1: minuend
        :type ciphertext1: Ciphertext
        :param ciphertext2: subtrahend
        :type ciphertext2: Ciphertext
        :return: the result as a new ciphertext
        :rtype: Ciphertext


        2. EvalSub(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, scalar: typing.SupportsFloat) -> openfhe.openfhe.Ciphertext


        Subtraction of a ciphertext and a real number. Supported only in CKKS.

        :param ciphertext: input ciphertext
        :type ciphertext: Ciphertext
        :param constant: a real number
        :type constant: float
        :return: new ciphertext for ciphertext - constant
        :rtype: Ciphertext


        3. EvalSub(self: openfhe.openfhe.CryptoContext, scalar: typing.SupportsFloat, ciphertext: openfhe.openfhe.Ciphertext) -> openfhe.openfhe.Ciphertext

        4. EvalSub(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, plaintext: openfhe.openfhe.Plaintext) -> openfhe.openfhe.Ciphertext


        Subtraction of a ciphertext and a real number. Supported only in CKKS.

        :param ciphertext: minuend
        :type ciphertext: Ciphertext
        :param plaintext: subtrahend
        :type plaintext: Plaintext
        :return: new ciphertext for ciphertext - plaintext
        :rtype: Ciphertext


        5. EvalSub(self: openfhe.openfhe.CryptoContext, plaintext: openfhe.openfhe.Plaintext, ciphertext: openfhe.openfhe.Ciphertext) -> openfhe.openfhe.Ciphertext
        """
    @overload
    def EvalSub(self, ciphertext: Ciphertext, plaintext: Plaintext) -> Ciphertext:
        """EvalSub(*args, **kwargs)
        Overloaded function.

        1. EvalSub(self: openfhe.openfhe.CryptoContext, ciphertext1: openfhe.openfhe.Ciphertext, ciphertext2: openfhe.openfhe.Ciphertext) -> openfhe.openfhe.Ciphertext


        Homomorphic subtraction of two ciphertexts

        :param ciphertext1: minuend
        :type ciphertext1: Ciphertext
        :param ciphertext2: subtrahend
        :type ciphertext2: Ciphertext
        :return: the result as a new ciphertext
        :rtype: Ciphertext


        2. EvalSub(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, scalar: typing.SupportsFloat) -> openfhe.openfhe.Ciphertext


        Subtraction of a ciphertext and a real number. Supported only in CKKS.

        :param ciphertext: input ciphertext
        :type ciphertext: Ciphertext
        :param constant: a real number
        :type constant: float
        :return: new ciphertext for ciphertext - constant
        :rtype: Ciphertext


        3. EvalSub(self: openfhe.openfhe.CryptoContext, scalar: typing.SupportsFloat, ciphertext: openfhe.openfhe.Ciphertext) -> openfhe.openfhe.Ciphertext

        4. EvalSub(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, plaintext: openfhe.openfhe.Plaintext) -> openfhe.openfhe.Ciphertext


        Subtraction of a ciphertext and a real number. Supported only in CKKS.

        :param ciphertext: minuend
        :type ciphertext: Ciphertext
        :param plaintext: subtrahend
        :type plaintext: Plaintext
        :return: new ciphertext for ciphertext - plaintext
        :rtype: Ciphertext


        5. EvalSub(self: openfhe.openfhe.CryptoContext, plaintext: openfhe.openfhe.Plaintext, ciphertext: openfhe.openfhe.Ciphertext) -> openfhe.openfhe.Ciphertext
        """
    @overload
    def EvalSub(self, plaintext: Plaintext, ciphertext: Ciphertext) -> Ciphertext:
        """EvalSub(*args, **kwargs)
        Overloaded function.

        1. EvalSub(self: openfhe.openfhe.CryptoContext, ciphertext1: openfhe.openfhe.Ciphertext, ciphertext2: openfhe.openfhe.Ciphertext) -> openfhe.openfhe.Ciphertext


        Homomorphic subtraction of two ciphertexts

        :param ciphertext1: minuend
        :type ciphertext1: Ciphertext
        :param ciphertext2: subtrahend
        :type ciphertext2: Ciphertext
        :return: the result as a new ciphertext
        :rtype: Ciphertext


        2. EvalSub(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, scalar: typing.SupportsFloat) -> openfhe.openfhe.Ciphertext


        Subtraction of a ciphertext and a real number. Supported only in CKKS.

        :param ciphertext: input ciphertext
        :type ciphertext: Ciphertext
        :param constant: a real number
        :type constant: float
        :return: new ciphertext for ciphertext - constant
        :rtype: Ciphertext


        3. EvalSub(self: openfhe.openfhe.CryptoContext, scalar: typing.SupportsFloat, ciphertext: openfhe.openfhe.Ciphertext) -> openfhe.openfhe.Ciphertext

        4. EvalSub(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, plaintext: openfhe.openfhe.Plaintext) -> openfhe.openfhe.Ciphertext


        Subtraction of a ciphertext and a real number. Supported only in CKKS.

        :param ciphertext: minuend
        :type ciphertext: Ciphertext
        :param plaintext: subtrahend
        :type plaintext: Plaintext
        :return: new ciphertext for ciphertext - plaintext
        :rtype: Ciphertext


        5. EvalSub(self: openfhe.openfhe.CryptoContext, plaintext: openfhe.openfhe.Plaintext, ciphertext: openfhe.openfhe.Ciphertext) -> openfhe.openfhe.Ciphertext
        """
    @overload
    def EvalSubInPlace(self, ciphertext1: Ciphertext, ciphertext2: Ciphertext) -> None:
        """EvalSubInPlace(*args, **kwargs)
        Overloaded function.

        1. EvalSubInPlace(self: openfhe.openfhe.CryptoContext, ciphertext1: openfhe.openfhe.Ciphertext, ciphertext2: openfhe.openfhe.Ciphertext) -> None


        In-place homomorphic subtraction of two ciphertexts

        :param ciphertext1: minuend
        :type ciphertext1: Ciphertext
        :param ciphertext2: subtrahend
        :type ciphertext2: Ciphertext
        :return: the result as a new ciphertext


        2. EvalSubInPlace(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, scalar: typing.SupportsFloat) -> None


        In-place subtraction of a ciphertext and a real number. Supported only in CKKS.

        :param ciphertext: input ciphertext
        :type ciphertext: Ciphertext
        :param constant: a real number
        :type constant: float


        3. EvalSubInPlace(self: openfhe.openfhe.CryptoContext, scalar: typing.SupportsFloat, ciphertext: openfhe.openfhe.Ciphertext) -> None

        4. EvalSubInPlace(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, plaintext: openfhe.openfhe.Plaintext) -> None

        5. EvalSubInPlace(self: openfhe.openfhe.CryptoContext, plaintext: openfhe.openfhe.Plaintext, ciphertext: openfhe.openfhe.Ciphertext) -> None
        """
    @overload
    def EvalSubInPlace(self, ciphertext: Ciphertext, scalar: typing.SupportsFloat) -> None:
        """EvalSubInPlace(*args, **kwargs)
        Overloaded function.

        1. EvalSubInPlace(self: openfhe.openfhe.CryptoContext, ciphertext1: openfhe.openfhe.Ciphertext, ciphertext2: openfhe.openfhe.Ciphertext) -> None


        In-place homomorphic subtraction of two ciphertexts

        :param ciphertext1: minuend
        :type ciphertext1: Ciphertext
        :param ciphertext2: subtrahend
        :type ciphertext2: Ciphertext
        :return: the result as a new ciphertext


        2. EvalSubInPlace(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, scalar: typing.SupportsFloat) -> None


        In-place subtraction of a ciphertext and a real number. Supported only in CKKS.

        :param ciphertext: input ciphertext
        :type ciphertext: Ciphertext
        :param constant: a real number
        :type constant: float


        3. EvalSubInPlace(self: openfhe.openfhe.CryptoContext, scalar: typing.SupportsFloat, ciphertext: openfhe.openfhe.Ciphertext) -> None

        4. EvalSubInPlace(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, plaintext: openfhe.openfhe.Plaintext) -> None

        5. EvalSubInPlace(self: openfhe.openfhe.CryptoContext, plaintext: openfhe.openfhe.Plaintext, ciphertext: openfhe.openfhe.Ciphertext) -> None
        """
    @overload
    def EvalSubInPlace(self, scalar: typing.SupportsFloat, ciphertext: Ciphertext) -> None:
        """EvalSubInPlace(*args, **kwargs)
        Overloaded function.

        1. EvalSubInPlace(self: openfhe.openfhe.CryptoContext, ciphertext1: openfhe.openfhe.Ciphertext, ciphertext2: openfhe.openfhe.Ciphertext) -> None


        In-place homomorphic subtraction of two ciphertexts

        :param ciphertext1: minuend
        :type ciphertext1: Ciphertext
        :param ciphertext2: subtrahend
        :type ciphertext2: Ciphertext
        :return: the result as a new ciphertext


        2. EvalSubInPlace(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, scalar: typing.SupportsFloat) -> None


        In-place subtraction of a ciphertext and a real number. Supported only in CKKS.

        :param ciphertext: input ciphertext
        :type ciphertext: Ciphertext
        :param constant: a real number
        :type constant: float


        3. EvalSubInPlace(self: openfhe.openfhe.CryptoContext, scalar: typing.SupportsFloat, ciphertext: openfhe.openfhe.Ciphertext) -> None

        4. EvalSubInPlace(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, plaintext: openfhe.openfhe.Plaintext) -> None

        5. EvalSubInPlace(self: openfhe.openfhe.CryptoContext, plaintext: openfhe.openfhe.Plaintext, ciphertext: openfhe.openfhe.Ciphertext) -> None
        """
    @overload
    def EvalSubInPlace(self, ciphertext: Ciphertext, plaintext: Plaintext) -> None:
        """EvalSubInPlace(*args, **kwargs)
        Overloaded function.

        1. EvalSubInPlace(self: openfhe.openfhe.CryptoContext, ciphertext1: openfhe.openfhe.Ciphertext, ciphertext2: openfhe.openfhe.Ciphertext) -> None


        In-place homomorphic subtraction of two ciphertexts

        :param ciphertext1: minuend
        :type ciphertext1: Ciphertext
        :param ciphertext2: subtrahend
        :type ciphertext2: Ciphertext
        :return: the result as a new ciphertext


        2. EvalSubInPlace(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, scalar: typing.SupportsFloat) -> None


        In-place subtraction of a ciphertext and a real number. Supported only in CKKS.

        :param ciphertext: input ciphertext
        :type ciphertext: Ciphertext
        :param constant: a real number
        :type constant: float


        3. EvalSubInPlace(self: openfhe.openfhe.CryptoContext, scalar: typing.SupportsFloat, ciphertext: openfhe.openfhe.Ciphertext) -> None

        4. EvalSubInPlace(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, plaintext: openfhe.openfhe.Plaintext) -> None

        5. EvalSubInPlace(self: openfhe.openfhe.CryptoContext, plaintext: openfhe.openfhe.Plaintext, ciphertext: openfhe.openfhe.Ciphertext) -> None
        """
    @overload
    def EvalSubInPlace(self, plaintext: Plaintext, ciphertext: Ciphertext) -> None:
        """EvalSubInPlace(*args, **kwargs)
        Overloaded function.

        1. EvalSubInPlace(self: openfhe.openfhe.CryptoContext, ciphertext1: openfhe.openfhe.Ciphertext, ciphertext2: openfhe.openfhe.Ciphertext) -> None


        In-place homomorphic subtraction of two ciphertexts

        :param ciphertext1: minuend
        :type ciphertext1: Ciphertext
        :param ciphertext2: subtrahend
        :type ciphertext2: Ciphertext
        :return: the result as a new ciphertext


        2. EvalSubInPlace(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, scalar: typing.SupportsFloat) -> None


        In-place subtraction of a ciphertext and a real number. Supported only in CKKS.

        :param ciphertext: input ciphertext
        :type ciphertext: Ciphertext
        :param constant: a real number
        :type constant: float


        3. EvalSubInPlace(self: openfhe.openfhe.CryptoContext, scalar: typing.SupportsFloat, ciphertext: openfhe.openfhe.Ciphertext) -> None

        4. EvalSubInPlace(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, plaintext: openfhe.openfhe.Plaintext) -> None

        5. EvalSubInPlace(self: openfhe.openfhe.CryptoContext, plaintext: openfhe.openfhe.Plaintext, ciphertext: openfhe.openfhe.Ciphertext) -> None
        """
    @overload
    def EvalSubMutable(self, ciphertext1: Ciphertext, ciphertext2: Ciphertext) -> Ciphertext:
        """EvalSubMutable(*args, **kwargs)
        Overloaded function.

        1. EvalSubMutable(self: openfhe.openfhe.CryptoContext, ciphertext1: openfhe.openfhe.Ciphertext, ciphertext2: openfhe.openfhe.Ciphertext) -> openfhe.openfhe.Ciphertext


        Homomorphic subtraction of two mutable ciphertexts

        :param ciphertext1: minuend
        :type ciphertext1: Ciphertext
        :param ciphertext2: subtrahend
        :type ciphertext2: Ciphertext
        :return: the result as a new ciphertext


        2. EvalSubMutable(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, plaintext: openfhe.openfhe.Plaintext) -> openfhe.openfhe.Ciphertext


        Homomorphic subtraction of mutable ciphertext and plaintext

        :param ciphertext: minuend
        :type ciphertext: Ciphertext
        :param plaintext: subtrahend
        :type plaintext: Plaintext
        :return: new ciphertext for ciphertext - plaintext


        3. EvalSubMutable(self: openfhe.openfhe.CryptoContext, plaintext: openfhe.openfhe.Plaintext, ciphertext: openfhe.openfhe.Ciphertext) -> openfhe.openfhe.Ciphertext
        """
    @overload
    def EvalSubMutable(self, ciphertext: Ciphertext, plaintext: Plaintext) -> Ciphertext:
        """EvalSubMutable(*args, **kwargs)
        Overloaded function.

        1. EvalSubMutable(self: openfhe.openfhe.CryptoContext, ciphertext1: openfhe.openfhe.Ciphertext, ciphertext2: openfhe.openfhe.Ciphertext) -> openfhe.openfhe.Ciphertext


        Homomorphic subtraction of two mutable ciphertexts

        :param ciphertext1: minuend
        :type ciphertext1: Ciphertext
        :param ciphertext2: subtrahend
        :type ciphertext2: Ciphertext
        :return: the result as a new ciphertext


        2. EvalSubMutable(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, plaintext: openfhe.openfhe.Plaintext) -> openfhe.openfhe.Ciphertext


        Homomorphic subtraction of mutable ciphertext and plaintext

        :param ciphertext: minuend
        :type ciphertext: Ciphertext
        :param plaintext: subtrahend
        :type plaintext: Plaintext
        :return: new ciphertext for ciphertext - plaintext


        3. EvalSubMutable(self: openfhe.openfhe.CryptoContext, plaintext: openfhe.openfhe.Plaintext, ciphertext: openfhe.openfhe.Ciphertext) -> openfhe.openfhe.Ciphertext
        """
    @overload
    def EvalSubMutable(self, plaintext: Plaintext, ciphertext: Ciphertext) -> Ciphertext:
        """EvalSubMutable(*args, **kwargs)
        Overloaded function.

        1. EvalSubMutable(self: openfhe.openfhe.CryptoContext, ciphertext1: openfhe.openfhe.Ciphertext, ciphertext2: openfhe.openfhe.Ciphertext) -> openfhe.openfhe.Ciphertext


        Homomorphic subtraction of two mutable ciphertexts

        :param ciphertext1: minuend
        :type ciphertext1: Ciphertext
        :param ciphertext2: subtrahend
        :type ciphertext2: Ciphertext
        :return: the result as a new ciphertext


        2. EvalSubMutable(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, plaintext: openfhe.openfhe.Plaintext) -> openfhe.openfhe.Ciphertext


        Homomorphic subtraction of mutable ciphertext and plaintext

        :param ciphertext: minuend
        :type ciphertext: Ciphertext
        :param plaintext: subtrahend
        :type plaintext: Plaintext
        :return: new ciphertext for ciphertext - plaintext


        3. EvalSubMutable(self: openfhe.openfhe.CryptoContext, plaintext: openfhe.openfhe.Plaintext, ciphertext: openfhe.openfhe.Ciphertext) -> openfhe.openfhe.Ciphertext
        """
    def EvalSubMutableInPlace(self, ciphertext1: Ciphertext, ciphertext2: Ciphertext) -> None:
        """EvalSubMutableInPlace(self: openfhe.openfhe.CryptoContext, ciphertext1: openfhe.openfhe.Ciphertext, ciphertext2: openfhe.openfhe.Ciphertext) -> None


        In-place homomorphic subtraction of two mutable ciphertexts

        :param ciphertext1: minuend
        :type ciphertext1: Ciphertext
        :param ciphertext2: subtrahend
        :type ciphertext2: Ciphertext
        :return: the updated minuend

        """
    def EvalSum(self, ciphertext: Ciphertext, batchSize: typing.SupportsInt) -> Ciphertext:
        """EvalSum(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, batchSize: typing.SupportsInt) -> openfhe.openfhe.Ciphertext


        Function for evaluating a sum of all components in a vector.

        :param ciphertext: the input ciphertext
        :type ciphertext: Ciphertext
        :param batchSize: size of the batch
        :type batchSize: int
        :return: resulting ciphertext
        :rtype: Ciphertext

        """
    def EvalSumCols(self, ciphertext: Ciphertext, numCols: typing.SupportsInt, evalSumKeyMap: EvalKeyMap) -> Ciphertext:
        """EvalSumCols(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, numCols: typing.SupportsInt, evalSumKeyMap: openfhe.openfhe.EvalKeyMap) -> openfhe.openfhe.Ciphertext


        Sums all elements across each column in a packed-encoded matrix ciphertext.

        :param ciphertext: Input ciphertext.
        :type ciphertext: Ciphertext
        :param numCols: Number of columns in the matrix.
        :type numCols: int
        :param evalSumKeyMap: Map of evaluation keys generated for column summation.
        :type evalSumKeyMap: EvalKeyMap
        :return: Ciphertext: Ciphertext containing column-wise sums.
        :rtype: Ciphertext

        """
    def EvalSumColsKeyGen(self, privateKey: PrivateKey, publicKey: PublicKey = ...) -> EvalKeyMap:
        """EvalSumColsKeyGen(self: openfhe.openfhe.CryptoContext, privateKey: openfhe.openfhe.PrivateKey, publicKey: openfhe.openfhe.PublicKey = None) -> openfhe.openfhe.EvalKeyMap


        Generates automorphism keys for EvalSumCols (only for packed encoding).

        :param privateKey: Private key used for key generation.
        :type privateKey: PrivateKey
        :param publicKey: Public key (used in NTRU schemes; unused now).
        :type publicKey: PublicKey
        :return: Map of generated evaluation keys.
        :rtype: EvalKeyMap

        """
    def EvalSumKeyGen(self, privateKey: PrivateKey, publicKey: PublicKey = ...) -> None:
        """EvalSumKeyGen(self: openfhe.openfhe.CryptoContext, privateKey: openfhe.openfhe.PrivateKey, publicKey: openfhe.openfhe.PublicKey = None) -> None


        EvalSumKeyGen Generates the key map to be used by EvalSum

        :param privateKey: private key
        :type privateKey: PrivateKey
        :param publicKey: public key (used in NTRU schemes)
        :type publicKey: PublicKey
        :return: None

        """
    def EvalSumRows(
        self, ciphertext: Ciphertext, numRows: typing.SupportsInt, evalSumKeyMap: EvalKeyMap, subringDim: typing.SupportsInt = ...
    ) -> Ciphertext:
        """EvalSumRows(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, numRows: typing.SupportsInt, evalSumKeyMap: openfhe.openfhe.EvalKeyMap, subringDim: typing.SupportsInt = 0) -> openfhe.openfhe.Ciphertext


        Sums all elements across each row in a packed-encoded matrix ciphertext.

        :param ciphertext: Input ciphertext.
        :type ciphertext: Ciphertext
        :param numRows: Number of rows in the matrix.
        :type numRows: int
        :param evalSumKeyMap: Map of evaluation keys generated for row summation.
        :type evalSumKeyMap: EvalKeyMap
        :param subringDim: Subring dimension (use full cyclotomic order if 0).
        :type subringDim: int
        :return: Ciphertext: Ciphertext containing row-wise sums.
        :rtype: Ciphertext

        """
    def EvalSumRowsKeyGen(
        self, privateKey: PrivateKey, publicKey: PublicKey = ..., rowSize: typing.SupportsInt = ..., subringDim: typing.SupportsInt = ...
    ) -> EvalKeyMap:
        """EvalSumRowsKeyGen(self: openfhe.openfhe.CryptoContext, privateKey: openfhe.openfhe.PrivateKey, publicKey: openfhe.openfhe.PublicKey = None, rowSize: typing.SupportsInt = 0, subringDim: typing.SupportsInt = 0) -> openfhe.openfhe.EvalKeyMap


        Generates automorphism keys for EvalSumRows (only for packed encoding).

        :param privateKey: Private key used for key generation.
        :type privateKey: PrivateKey
        :param publicKey: Public key (used in NTRU schemes; unused now).
        :type publicKey: PublicKey
        :param rowSize: Number of slots per row in the packed matrix.
        :type rowSize: int
        :param subringDim: Subring dimension (use cyclotomic order if 0).
        :type subringDim: int
        :return: Map of generated evaluation keys.
        :rtype: EvalKeyMap

        """
    def FindAutomorphismIndex(self, idx: typing.SupportsInt) -> int:
        """FindAutomorphismIndex(self: openfhe.openfhe.CryptoContext, idx: typing.SupportsInt) -> int


        Finds an automorphism index for a given vector index using a scheme-specific algorithm

        :param idx: regular vector index
        :type idx: int
        :return: the automorphism index
        :rtype: int

        """
    def FindAutomorphismIndices(self, idxList: collections.abc.Sequence[typing.SupportsInt]) -> list[int]:
        """FindAutomorphismIndices(self: openfhe.openfhe.CryptoContext, idxList: collections.abc.Sequence[typing.SupportsInt]) -> list[int]


        Finds automorphism indices for a given list of vector indices using a scheme-specific algorithm

        :param idxList: list of indices
        :type idxList: List[int]
        :return: a list of automorphism indices
        :rtype: List[int]

        """
    def GetBatchSize(self) -> int:
        """GetBatchSize(self: openfhe.openfhe.CryptoContext) -> int"""
    def GetBinCCForSchemeSwitch(self) -> BinFHEContext:
        """GetBinCCForSchemeSwitch(self: openfhe.openfhe.CryptoContext) -> openfhe.openfhe.BinFHEContext"""
    def GetCKKSDataType(self) -> CKKSDataType:
        """GetCKKSDataType(self: openfhe.openfhe.CryptoContext) -> openfhe.openfhe.CKKSDataType"""
    def GetCompositeDegree(self) -> int:
        """GetCompositeDegree(self: openfhe.openfhe.CryptoContext) -> int"""
    def GetCyclotomicOrder(self) -> int:
        """GetCyclotomicOrder(self: openfhe.openfhe.CryptoContext) -> int


        Getter for cyclotomic order

        :return: cyclotomic order
        :rtype: int

        """
    def GetDigitSize(self) -> int:
        """GetDigitSize(self: openfhe.openfhe.CryptoContext) -> int"""
    def GetEvalAddCount(self) -> int:
        """GetEvalAddCount(self: openfhe.openfhe.CryptoContext) -> int"""
    @staticmethod
    def GetEvalAutomorphismKeyMap(keyTag: str = ...) -> EvalKeyMap:
        """GetEvalAutomorphismKeyMap(keyTag: str = '') -> openfhe.openfhe.EvalKeyMap


        Get automorphism keys for a specific secret key tag

        :param keyId: key identifier used for private key
        :type keyId: str
        :return: EvalKeyMap: map with all automorphism keys.
        :rtype: EvalKeyMap

        """
    @staticmethod
    def GetEvalMultKeyVector(keyTag: str = ...) -> list[EvalKey]:
        """GetEvalMultKeyVector(keyTag: str = '') -> list[openfhe.openfhe.EvalKey]


        Get relinearization keys for a specific secret key tag

        :param keyId: key identifier used for private key
        :type keyId: str
        :return: EvalKeyVector: vector with all relinearization keys.
        :rtype: EvalKeyVector

        """
    def GetEvalSumKeyMap(self, keyTag: str) -> EvalKeyMap:
        """GetEvalSumKeyMap(self: openfhe.openfhe.CryptoContext, keyTag: str) -> openfhe.openfhe.EvalKeyMap


        Get a map of summation keys (each is composed of several automorphism keys) for a specific secret key tag
        :return: EvalKeyMap: key map
        :rtype: EvalKeyMap

        """
    def GetKeyGenLevel(self) -> int:
        """GetKeyGenLevel(self: openfhe.openfhe.CryptoContext) -> int


        For future use: getter for the level at which evaluation keys should be generated

        :return: The level used for key generation
        :rtype: int

        """
    def GetKeySwitchCount(self) -> int:
        """GetKeySwitchCount(self: openfhe.openfhe.CryptoContext) -> int"""
    def GetModulus(self) -> float:
        """GetModulus(self: openfhe.openfhe.CryptoContext) -> float


        Getter for ciphertext modulus

        :return: modulus
        :rtype: int

        """
    def GetModulusCKKS(self) -> int:
        """GetModulusCKKS(self: openfhe.openfhe.CryptoContext) -> int"""
    def GetMultiplicativeDepth(self) -> int:
        """GetMultiplicativeDepth(self: openfhe.openfhe.CryptoContext) -> int"""
    def GetNoiseEstimate(self) -> float:
        """GetNoiseEstimate(self: openfhe.openfhe.CryptoContext) -> float"""
    def GetPRENumHops(self) -> int:
        """GetPRENumHops(self: openfhe.openfhe.CryptoContext) -> int"""
    def GetPlaintextModulus(self) -> int:
        """GetPlaintextModulus(self: openfhe.openfhe.CryptoContext) -> int


        Get the plaintext modulus used for this context

        :return: The plaintext modulus
        :rtype: int

        """
    def GetRegisterWordSize(self) -> int:
        """GetRegisterWordSize(self: openfhe.openfhe.CryptoContext) -> int"""
    def GetRingDimension(self) -> int:
        """GetRingDimension(self: openfhe.openfhe.CryptoContext) -> int


        Getter for ring dimension

        :return: The ring dimension
        :rtype: int

        """
    def GetScalingFactorReal(self, level: typing.SupportsInt) -> float:
        """GetScalingFactorReal(self: openfhe.openfhe.CryptoContext, level: typing.SupportsInt) -> float


        Method to retrieve the scaling factor of level l. For FIXEDMANUAL scaling technique method always returns 2^p, where p corresponds to plaintext modulus

        :param l:  For FLEXIBLEAUTO scaling technique the level whose scaling factor we want to learn. Levels start from 0 (no scaling done - all towers) and go up to K-1, where K is the number of towers supported.
        :type l: int
        :return: the scaling factor.
        :rtype: float

        """
    def GetScalingTechnique(self) -> ScalingTechnique:
        """GetScalingTechnique(self: openfhe.openfhe.CryptoContext) -> openfhe.openfhe.ScalingTechnique"""
    @staticmethod
    def InsertEvalAutomorphismKey(evalKeyMap: EvalKeyMap, keyTag: str = ...) -> None:
        """InsertEvalAutomorphismKey(evalKeyMap: openfhe.openfhe.EvalKeyMap, keyTag: str = '') -> None


        Add the given map of keys to the map, replacing the existing map if there is one

        :param evalKeyMap: map of keys to be inserted
        :type evalKeyMap: EvalKeyMap
        :param keyTag: key identifier for the given key map
        :type keyTag: str


        """
    @staticmethod
    def InsertEvalMultKey(evalKeyVec: collections.abc.Sequence[EvalKey], keyTag: str = ...) -> None:
        """InsertEvalMultKey(evalKeyVec: collections.abc.Sequence[openfhe.openfhe.EvalKey], keyTag: str = '') -> None


        Adds the given vector of keys to the map, replacing the existing vector if there

        :param evalKeyVec: vector of keys
        :type evalKeyVec: List[EvalKey]

        """
    @staticmethod
    def InsertEvalSumKey(evalKeyMap: EvalKeyMap, keyTag: str = ...) -> None:
        """InsertEvalSumKey(evalKeyMap: openfhe.openfhe.EvalKeyMap, keyTag: str = '') -> None


        InsertEvalSumKey - add the given map of keys to the map, replacing the existing map if there

        :param evalKeyMap: key map
        :type evalKeyMap: EvalKeyMap

        """
    def IntBootAdd(self, ciphertext1: Ciphertext, ciphertext2: Ciphertext) -> Ciphertext:
        """IntBootAdd(self: openfhe.openfhe.CryptoContext, ciphertext1: openfhe.openfhe.Ciphertext, ciphertext2: openfhe.openfhe.Ciphertext) -> openfhe.openfhe.Ciphertext


        Combines encrypted and unencrypted masked decryptions in 2-party interactive bootstrapping. It is the last step in the boostrapping.

        :param ciphertext1: Encrypted masked decryption
        :type ciphertext1: Ciphertext
        :param ciphertext2: Unencrypted masked decryption
        :type ciphertext2: Ciphertext
        :return: Refreshed ciphertext
        :rtype: Ciphertext

        """
    def IntBootAdjustScale(self, ciphertext: Ciphertext) -> Ciphertext:
        """IntBootAdjustScale(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext) -> openfhe.openfhe.Ciphertext


        Prepares a ciphertext for interactive bootstrapping.

        :param ciphertext: Input ciphertext
        :type ciphertext: Ciphertext
        :return: Adjusted ciphertext
        :rtype: Ciphertext

        """
    def IntBootDecrypt(self, privateKey: PrivateKey, ciphertext: Ciphertext) -> Ciphertext:
        """IntBootDecrypt(self: openfhe.openfhe.CryptoContext, privateKey: openfhe.openfhe.PrivateKey, ciphertext: openfhe.openfhe.Ciphertext) -> openfhe.openfhe.Ciphertext


        Performs masked decryption for interactive bootstrapping (2-party protocol).

        :param privateKey: Secret key share
        :type privateKey: PrivateKey
        :param ciphertext: Input Ciphertext
        :type ciphertext: Ciphertext
        :return: Resulting ciphertext
        :rtype: Ciphertext

        """
    def IntBootEncrypt(self, publicKey: PublicKey, ciphertext: Ciphertext) -> Ciphertext:
        """IntBootEncrypt(self: openfhe.openfhe.CryptoContext, publicKey: openfhe.openfhe.PublicKey, ciphertext: openfhe.openfhe.Ciphertext) -> openfhe.openfhe.Ciphertext


        Encrypts Client's masked decryption for interactive bootstrapping. Increases ciphertext modulus to allow further computation. Done by Client.

        :param publicKey: Joined public key (Threshold FHE)
        :type publicKey: PublicKey
        :param ciphertext: Input Ciphertext
        :type ciphertext: Ciphertext
        :return: Resulting ciphertext
        :rtype: Ciphertext

        """
    def IntMPBootAdd(self, sharePairVec: collections.abc.Sequence[collections.abc.Sequence[Ciphertext]]) -> list[Ciphertext]:
        """IntMPBootAdd(self: openfhe.openfhe.CryptoContext, sharePairVec: collections.abc.Sequence[collections.abc.Sequence[openfhe.openfhe.Ciphertext]]) -> list[openfhe.openfhe.Ciphertext]


        Threshold FHE: Aggregates a vector of masked decryptions and re-encryotion shares, which is the second step of the interactive multiparty bootstrapping procedure.

        :param sharesPairVec: vector of pair of ciphertexts, each element of this vector contains (h_0i, h_1i) - the masked-decryption and encryption shares ofparty i
        :type sharesPairVec: List[List[Ciphertext]]
        :return: aggregated pair of shares ((h_0, h_1)
        :rtype: List[Ciphertext]

        """
    def IntMPBootAdjustScale(self, ciphertext: Ciphertext) -> Ciphertext:
        """IntMPBootAdjustScale(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext) -> openfhe.openfhe.Ciphertext


        Threshold FHE: Prepare a ciphertext for Multi-Party Interactive Bootstrapping.

        :param ciphertext: Input Ciphertext
        :type ciphertext: Ciphertext
        :return: Resulting Ciphertext
        :rtype: Ciphertext

        """
    def IntMPBootDecrypt(self, privateKey: PrivateKey, ciphertext: Ciphertext, a: Ciphertext) -> list[Ciphertext]:
        """IntMPBootDecrypt(self: openfhe.openfhe.CryptoContext, privateKey: openfhe.openfhe.PrivateKey, ciphertext: openfhe.openfhe.Ciphertext, a: openfhe.openfhe.Ciphertext) -> list[openfhe.openfhe.Ciphertext]


        Threshold FHE: Does masked decryption as part of Multi-Party Interactive Bootstrapping. Each party calls this function as part of the protocol

        :param privateKey: secret key share for party i
        :type privateKey: PrivateKey
        :param ciphertext: input ciphertext
        :type ciphertext: Ciphertext
        :param a: input common random polynomial
        :type a: Ciphertext
        :return: Resulting masked decryption
        :rtype: Ciphertext

        """
    def IntMPBootEncrypt(
        self, publicKey: PublicKey, sharePair: collections.abc.Sequence[Ciphertext], a: Ciphertext, ciphertext: Ciphertext
    ) -> Ciphertext:
        """IntMPBootEncrypt(self: openfhe.openfhe.CryptoContext, publicKey: openfhe.openfhe.PublicKey, sharePair: collections.abc.Sequence[openfhe.openfhe.Ciphertext], a: openfhe.openfhe.Ciphertext, ciphertext: openfhe.openfhe.Ciphertext) -> openfhe.openfhe.Ciphertext


        Threshold FHE: Does public key encryption of lead party's masked decryption as part of interactive multi-party bootstrapping, which increases the ciphertext modulus and enables future computations. This operation is done by the lead party as the final step of interactive multi-party bootstrapping.

        :param publicKey: the lead party's public key
        :type publicKey: PublicKey
        :param sharesPair: aggregated decryption and re-encryption shares
        :type sharesPair: List[Ciphertext]
        :param a: common random ring element
        :type a: Ciphertext
        :param ciphertext: input ciphertext
        :type ciphertext: Ciphertext
        :return: Resulting encryption
        :rtype: Ciphertext

        """
    def IntMPBootRandomElementGen(self, publicKey: PublicKey) -> Ciphertext:
        """IntMPBootRandomElementGen(self: openfhe.openfhe.CryptoContext, publicKey: openfhe.openfhe.PublicKey) -> openfhe.openfhe.Ciphertext


        Threshold FHE: Generate a common random polynomial for Multi-Party Interactive Bootstrapping

        :param publicKey: the scheme public key (you can also provide the lead party's public-key)
        :type publicKey: PublicKey
        :return: Resulting ring element
        :rtype: Ciphertext

        """
    def KeyGen(self) -> KeyPair:
        """KeyGen(self: openfhe.openfhe.CryptoContext) -> openfhe.openfhe.KeyPair


        Generates a standard public/secret key pair.

        :return: a public/secret key pair
        :rtype: KeyPair

        """
    def KeySwitchGen(self, oldPrivateKey: PrivateKey, newPrivateKey: PrivateKey) -> EvalKey:
        """KeySwitchGen(self: openfhe.openfhe.CryptoContext, oldPrivateKey: openfhe.openfhe.PrivateKey, newPrivateKey: openfhe.openfhe.PrivateKey) -> openfhe.openfhe.EvalKey


        Generates a key switching key from one secret key to another.

        :param oldPrivateKey: Original secret key.
        :type oldPrivateKey: PrivateKey
        :param newPrivateKey: Target secret key.
        :type newPrivateKey: PrivateKey
        :return: New evaluation key for key switching.
        :rtype: EvalKey

        """
    @overload
    def MakeCKKSPackedPlaintext(
        self,
        value: collections.abc.Sequence[complex],
        noiseScaleDeg: typing.SupportsInt = ...,
        level: typing.SupportsInt = ...,
        params: ParmType = ...,
        slots: typing.SupportsInt = ...,
    ) -> Plaintext:
        """MakeCKKSPackedPlaintext(*args, **kwargs)
        Overloaded function.

        1. MakeCKKSPackedPlaintext(self: openfhe.openfhe.CryptoContext, value: collections.abc.Sequence[complex], noiseScaleDeg: typing.SupportsInt = 1, level: typing.SupportsInt = 0, params: openfhe.openfhe.ParmType = None, slots: typing.SupportsInt = 0) -> openfhe.openfhe.Plaintext


            COMPLEX ARITHMETIC IS NOT AVAILABLE, AND THIS METHOD BE DEPRECATED. USE THE REAL-NUMBER METHOD INSTEAD. MakeCKKSPackedPlaintext constructs a CKKSPackedEncoding in this context from a vector of complex numbers

            :param value: input vector of complex numbers
            :type value: List[complex]
            :param scaleDeg: degree of scaling factor used to encode the vector
            :type scaleDeg: int
            :param level: level at each the vector will get encrypted
            :type level: int
            :param params: parameters to be used for the ciphertext (Only accepting params = None in this version)
            :type params: openfhe.ParmType
            :param slots: number of slots
            :type slots: int
            :return: plaintext
            :rtype: Plaintext


        2. MakeCKKSPackedPlaintext(self: openfhe.openfhe.CryptoContext, value: collections.abc.Sequence[typing.SupportsFloat], noiseScaleDeg: typing.SupportsInt = 1, level: typing.SupportsInt = 0, params: openfhe.openfhe.ParmType = None, slots: typing.SupportsInt = 0) -> openfhe.openfhe.Plaintext


            MakeCKKSPlaintext constructs a CKKSPackedEncoding in this context from a vector of real numbers

            :param value: input vector (of floats)
            :type value: list
            :param scaleDeg: degree of scaling factor used to encode the vector
            :type scaleDeg: int
            :param level: level at each the vector will get encrypted
            :type level: int
            :param params: parameters to be used for the ciphertext (Only accepting params = None in this version)
            :type params: openfhe.ParmType
            :param slots: number of slots
            :type slots: int
            :return: plaintext
            :rtype: Plaintext

        """
    @overload
    def MakeCKKSPackedPlaintext(
        self,
        value: collections.abc.Sequence[typing.SupportsFloat],
        noiseScaleDeg: typing.SupportsInt = ...,
        level: typing.SupportsInt = ...,
        params: ParmType = ...,
        slots: typing.SupportsInt = ...,
    ) -> Plaintext:
        """MakeCKKSPackedPlaintext(*args, **kwargs)
        Overloaded function.

        1. MakeCKKSPackedPlaintext(self: openfhe.openfhe.CryptoContext, value: collections.abc.Sequence[complex], noiseScaleDeg: typing.SupportsInt = 1, level: typing.SupportsInt = 0, params: openfhe.openfhe.ParmType = None, slots: typing.SupportsInt = 0) -> openfhe.openfhe.Plaintext


            COMPLEX ARITHMETIC IS NOT AVAILABLE, AND THIS METHOD BE DEPRECATED. USE THE REAL-NUMBER METHOD INSTEAD. MakeCKKSPackedPlaintext constructs a CKKSPackedEncoding in this context from a vector of complex numbers

            :param value: input vector of complex numbers
            :type value: List[complex]
            :param scaleDeg: degree of scaling factor used to encode the vector
            :type scaleDeg: int
            :param level: level at each the vector will get encrypted
            :type level: int
            :param params: parameters to be used for the ciphertext (Only accepting params = None in this version)
            :type params: openfhe.ParmType
            :param slots: number of slots
            :type slots: int
            :return: plaintext
            :rtype: Plaintext


        2. MakeCKKSPackedPlaintext(self: openfhe.openfhe.CryptoContext, value: collections.abc.Sequence[typing.SupportsFloat], noiseScaleDeg: typing.SupportsInt = 1, level: typing.SupportsInt = 0, params: openfhe.openfhe.ParmType = None, slots: typing.SupportsInt = 0) -> openfhe.openfhe.Plaintext


            MakeCKKSPlaintext constructs a CKKSPackedEncoding in this context from a vector of real numbers

            :param value: input vector (of floats)
            :type value: list
            :param scaleDeg: degree of scaling factor used to encode the vector
            :type scaleDeg: int
            :param level: level at each the vector will get encrypted
            :type level: int
            :param params: parameters to be used for the ciphertext (Only accepting params = None in this version)
            :type params: openfhe.ParmType
            :param slots: number of slots
            :type slots: int
            :return: plaintext
            :rtype: Plaintext

        """
    def MakeCoefPackedPlaintext(
        self, value: collections.abc.Sequence[typing.SupportsInt], noiseScaleDeg: typing.SupportsInt = ..., level: typing.SupportsInt = ...
    ) -> Plaintext:
        """MakeCoefPackedPlaintext(self: openfhe.openfhe.CryptoContext, value: collections.abc.Sequence[typing.SupportsInt], noiseScaleDeg : typing.SupportsInt = 1, level: typing.SupportsInt = 0) -> openfhe.openfhe.Plaintext


        MakeCoefPackedPlaintext constructs a CoefPackedEncoding in this context

        :param value: vector of signed integers mod t
        :type value: List[int]
        :param noiseScaleDeg: is degree of the scaling factor to encode the plaintext at
        :type noiseScaleDeg: int
        :param level: is the level to encode the plaintext at
        :type level: int
        :return: plaintext
        :rtype: Plaintext


        """
    def MakePackedPlaintext(
        self, value: collections.abc.Sequence[typing.SupportsInt], noiseScaleDeg: typing.SupportsInt = ..., level: typing.SupportsInt = ...
    ) -> Plaintext:
        """MakePackedPlaintext(self: openfhe.openfhe.CryptoContext, value: collections.abc.Sequence[typing.SupportsInt], noiseScaleDeg: typing.SupportsInt = 1, level: typing.SupportsInt = 0) -> openfhe.openfhe.Plaintext


        MakePackedPlaintext constructs a PackedEncoding in this context

        :param value: vector of signed integers mod t
        :type value: List[int]
        :param noiseScaleDeg: is degree of the scaling factor to encode the plaintext at
        :type noiseScaleDeg: int
        :param level: is the level to encode the plaintext at
        :type level: int
        :return: plaintext
        :rtype: Plaintext

        """
    def MakeStringPlaintext(self, str: str) -> Plaintext:
        """MakeStringPlaintext(self: openfhe.openfhe.CryptoContext, str: str) -> openfhe.openfhe.Plaintext


        MakeStringPlaintext constructs a StringEncoding in this context.

        :param str: string to be encoded
        :type str: str
        :return: plaintext

        """
    def ModReduce(self, ciphertext: Ciphertext) -> Ciphertext:
        """ModReduce(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext) -> openfhe.openfhe.Ciphertext


        ModReduce - OpenFHE ModReduce method used only for BGV/CKKS.

        :param ciphertext: ciphertext
        :type ciphertext: Ciphertext
        :return: Ciphertext: mod reduced ciphertext
        :rtype: Ciphertext

        """
    def ModReduceInPlace(self, ciphertext: Ciphertext) -> None:
        """ModReduceInPlace(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext) -> None


        ModReduce - OpenFHE ModReduceInPlace method used only for BGV/CKKS.

        :param ciphertext: ciphertext to be mod-reduced in-place
        :type ciphertext: Ciphertext

        """
    def MultiAddEvalAutomorphismKeys(self, evalKeyMap1: EvalKeyMap, evalKeyMap2: EvalKeyMap, keyTag: str = ...) -> EvalKeyMap:
        """MultiAddEvalAutomorphismKeys(self: openfhe.openfhe.CryptoContext, evalKeyMap1: openfhe.openfhe.EvalKeyMap, evalKeyMap2: openfhe.openfhe.EvalKeyMap, keyTag: str = '') -> openfhe.openfhe.EvalKeyMap


        Threshold FHE: Adds two prior evaluation key sets for automorphisms

        :param evalKeyMap1: first automorphism key set
        :type evalKeyMap1: EvalKeyMap
        :param evalKeyMap2: second automorphism key set
        :type evalKeyMap2: EvalKeyMap
        :param keyId: new key identifier used for resulting evaluation key
        :type keyId: str
        :return: the new joined key set for summation
        :rtype: evalKeyMap

        """
    def MultiAddEvalKeys(self, evalKey1: EvalKey, evalKey2: EvalKey, keyTag: str = ...) -> EvalKey:
        """MultiAddEvalKeys(self: openfhe.openfhe.CryptoContext, evalKey1: openfhe.openfhe.EvalKey, evalKey2: openfhe.openfhe.EvalKey, keyTag: str = '') -> openfhe.openfhe.EvalKey


        Threshold FHE: Adds two prior evaluation keys

        :param evalKey1: first evaluation key
        :type evalKey1: EvalKey
        :param evalKey2: second evaluation key
        :type evalKey2: EvalKey
        :param keyId: new key identifier used for resulting evaluation key
        :type keyId: str
        :return: the new joined key
        :rtype: EvalKey

        """
    def MultiAddEvalMultKeys(self, evalKey1: EvalKey, evalKey2: EvalKey, keyTag: str = ...) -> EvalKey:
        """MultiAddEvalMultKeys(self: openfhe.openfhe.CryptoContext, evalKey1: openfhe.openfhe.EvalKey, evalKey2: openfhe.openfhe.EvalKey, keyTag: str = '') -> openfhe.openfhe.EvalKey


        Threshold FHE: Adds two prior evaluation key sets for summation

        :param evalKey1: first evaluation key
        :type evalKey1: EvalKey
        :param evalKey2: second evaluation key
        :type evalKey2: EvalKey
        :param keyId: new key identifier used for resulting evaluation key
        :type keyId: str
        :return: the new joined key
        :rtype: EvalKey

        """
    def MultiAddEvalSumKeys(self, evalKeyMap1: EvalKeyMap, evalKeyMap2: EvalKeyMap, keyTag: str = ...) -> EvalKeyMap:
        """MultiAddEvalSumKeys(self: openfhe.openfhe.CryptoContext, evalKeyMap1: openfhe.openfhe.EvalKeyMap, evalKeyMap2: openfhe.openfhe.EvalKeyMap, keyTag: str = '') -> openfhe.openfhe.EvalKeyMap


        Threshold FHE: Adds two prior evaluation key sets for summation

        :param evalKeyMap1: first summation key set
        :type evalKeyMap1: EvalKeyMap
        :param evalKeyMap2: second summation key set
        :type evalKeyMap2: EvalKeyMap
        :param keyId: new key identifier used for resulting evaluation key
        :type keyId: str
        :return: the neew joined key set for summation
        :rtype: EvalKeyMap

        """
    def MultiAddPubKeys(self, publicKey1: PublicKey, publicKey2: PublicKey, keyTag: str = ...) -> PublicKey:
        """MultiAddPubKeys(self: openfhe.openfhe.CryptoContext, publicKey1: openfhe.openfhe.PublicKey, publicKey2: openfhe.openfhe.PublicKey, keyTag: str = '') -> openfhe.openfhe.PublicKey


        Threshold FHE: Adds two prior public keys

        :param publicKey1: first public key
        :type publicKey1: PublicKey
        :param publicKey2: second public key
        :type publicKey2: PublicKey
        :param keyId: new key identifier used for the resulting key
        :type keyId: str
        :return: the new combined key
        :rtype: PublicKey

        """
    def MultiEvalAtIndexKeyGen(
        self, privateKey: PrivateKey, evalKeyMap: EvalKeyMap, indexList: collections.abc.Sequence[typing.SupportsInt], keyTag: str = ...
    ) -> EvalKeyMap:
        """MultiEvalAtIndexKeyGen(self: openfhe.openfhe.CryptoContext, privateKey: openfhe.openfhe.PrivateKey, evalKeyMap: openfhe.openfhe.EvalKeyMap, indexList: collections.abc.Sequence[typing.SupportsInt], keyTag: str = '') -> openfhe.openfhe.EvalKeyMap


        Threshold FHE: Generates joined rotation keys from the current secret key and prior joined rotation keys

        :param privateKey: secret key share
        :type privateKey: PrivateKey
        :param evalKeyMap: a map with prior joined rotation keys
        :type evalKeyMap: EvalKeyMap
        :param indexList: a vector of rotation indices
        :type indexList: List[int32]
        :param keyId: new key identifier used for resulting evaluation key
        :type keyId: str
        :return: EvalKeyMap: a map with new joined rotation keys
        :rtype: EvalKeyMap

        """
    def MultiEvalSumKeyGen(self, privateKey: PrivateKey, evalKeyMap: EvalKeyMap, keyTag: str = ...) -> EvalKeyMap:
        """MultiEvalSumKeyGen(self: openfhe.openfhe.CryptoContext, privateKey: openfhe.openfhe.PrivateKey, evalKeyMap: openfhe.openfhe.EvalKeyMap, keyTag: str = '') -> openfhe.openfhe.EvalKeyMap


        Threshold FHE: Generates joined summation evaluation keys from the current secret share and prior joined summation keys

        :param privateKey: secret key share
        :type privateKey: PrivateKey
        :param evalKeyMap: a map with prior joined summation keys
        :type evalKeyMap: EvalKeyMap
        :param keyId: new key identifier used for resulting evaluation key
        :type keyId: str
        :return: EvalKeyMap: new joined summation keys
        :rtype: EvalKeyMap

        """
    def MultiKeySwitchGen(self, originalPrivateKey: PrivateKey, newPrivateKey: PrivateKey, evalKey: EvalKey) -> EvalKey:
        """MultiKeySwitchGen(self: openfhe.openfhe.CryptoContext, originalPrivateKey: openfhe.openfhe.PrivateKey, newPrivateKey: openfhe.openfhe.PrivateKey, evalKey: openfhe.openfhe.EvalKey) -> openfhe.openfhe.EvalKey


        Threshold FHE: Generates a joined evaluation key from the current secret share and a prior joined evaluation key

        :param originalPrivateKey: secret key transformed from.
        :type originalPrivateKey: PrivateKey
        :param newPrivateKey: secret key transformed from.
        :type newPrivateKey: PrivateKey
        :param evalKey: the prior joined evaluation key.
        :type evalKey: EvalKey
        :return: EvalKey: the new joined evaluation key.
        :rtype: EvalKey

        """
    def MultiMultEvalKey(self, privateKey: PrivateKey, evalKey: EvalKey, keyTag: str = ...) -> EvalKey:
        """MultiMultEvalKey(self: openfhe.openfhe.CryptoContext, privateKey: openfhe.openfhe.PrivateKey, evalKey: openfhe.openfhe.EvalKey, keyTag: str = '') -> openfhe.openfhe.EvalKey


        Threshold FHE: Generates a partial evaluation key for homomorphic multiplication based on the current secret share and an existing partial evaluation key

        :param privateKey: current secret share
        :type privateKey: PrivateKey
        :param evalKey: prior evaluation key
        :type evalKey: EvalKey
        :param keyId: new key identifier used for resulting evaluation key
        :type keyId: str
        :return: the new joined key
        :rtype: EvalKey

        """
    def MultipartyDecryptFusion(self, partialCiphertextVec: collections.abc.Sequence[Ciphertext]) -> Plaintext:
        """MultipartyDecryptFusion(self: openfhe.openfhe.CryptoContext, partialCiphertextVec: collections.abc.Sequence[openfhe.openfhe.Ciphertext]) -> openfhe.openfhe.Plaintext


        Threshold FHE: Method for combining the partially decrypted ciphertexts and getting the final decryption in the clear.

        :param partialCiphertextVec: list of "partial" decryptions
        :type partialCiphertextVec: list
        :return: Plaintext: resulting plaintext
        :rtype: Plaintext

        """
    def MultipartyDecryptLead(self, ciphertextVec: collections.abc.Sequence[Ciphertext], privateKey: PrivateKey) -> list[Ciphertext]:
        """MultipartyDecryptLead(self: openfhe.openfhe.CryptoContext, ciphertextVec: collections.abc.Sequence[openfhe.openfhe.Ciphertext], privateKey: openfhe.openfhe.PrivateKey) -> list[openfhe.openfhe.Ciphertext]


        Threshold FHE: Method for decryption operation run by the lead decryption client

        :param ciphertextVec: a list of ciphertexts
        :type ciphertextVec: list
        :param privateKey:  secret key share used for decryption.
        :type privateKey: PrivateKey
        :return: list of partially decrypted ciphertexts.
        :rtype: List[Ciphertext]

        """
    def MultipartyDecryptMain(self, ciphertextVec: collections.abc.Sequence[Ciphertext], privateKey: PrivateKey) -> list[Ciphertext]:
        """MultipartyDecryptMain(self: openfhe.openfhe.CryptoContext, ciphertextVec: collections.abc.Sequence[openfhe.openfhe.Ciphertext], privateKey: openfhe.openfhe.PrivateKey) -> list[openfhe.openfhe.Ciphertext]


        Threshold FHE: "Partial" decryption computed by all parties except for the lead one

        :param ciphertextVec: a list of ciphertexts
        :type ciphertextVec: list
        :param privateKey:  secret key share used for decryption.
        :type privateKey: PrivateKey
        :return: list of partially decrypted ciphertexts.
        :rtype: List[Ciphertext]

        """
    @overload
    def MultipartyKeyGen(self, publicKey: PublicKey, makeSparse: bool = ..., fresh: bool = ...) -> KeyPair:
        """MultipartyKeyGen(*args, **kwargs)
        Overloaded function.

        1. MultipartyKeyGen(self: openfhe.openfhe.CryptoContext, publicKey: openfhe.openfhe.PublicKey, makeSparse: bool = False, fresh: bool = False) -> openfhe.openfhe.KeyPair


            Threshold FHE: Generation of a public key derived from a previous joined public key (for prior secret shares) and the secret key share of the current party.

            :param publicKey:  joined public key from prior parties.
            :type publicKey: PublicKey
            :param makeSparse: set to true if ring reduce by a factor of 2 is to be used. NOT SUPPORTED BY ANY SCHEME ANYMORE.
            :type makeSparse: bool
            :param fresh: set to true if proxy re-encryption is used in the multi-party protocol or star topology is used
            :type fresh: bool
            :return: KeyPair: key pair including the secret share for the current party and joined public key
            :rtype: KeyPair


        2. MultipartyKeyGen(self: openfhe.openfhe.CryptoContext, privateKeyVec: collections.abc.Sequence[openfhe.openfhe.PrivateKey]) -> openfhe.openfhe.KeyPair


            Threshold FHE: Generates a public key from a vector of secret shares. ONLY FOR DEBUGGIN PURPOSES. SHOULD NOT BE USED IN PRODUCTION.

            :param privateKeyVec: secret key shares.
            :type privateKeyVec: List[PrivateKey]
            :return KeyPair: key pair including the private for the current party and joined public key
            :rtype: KeyPair

        """
    @overload
    def MultipartyKeyGen(self, privateKeyVec: collections.abc.Sequence[PrivateKey]) -> KeyPair:
        """MultipartyKeyGen(*args, **kwargs)
        Overloaded function.

        1. MultipartyKeyGen(self: openfhe.openfhe.CryptoContext, publicKey: openfhe.openfhe.PublicKey, makeSparse: bool = False, fresh: bool = False) -> openfhe.openfhe.KeyPair


            Threshold FHE: Generation of a public key derived from a previous joined public key (for prior secret shares) and the secret key share of the current party.

            :param publicKey:  joined public key from prior parties.
            :type publicKey: PublicKey
            :param makeSparse: set to true if ring reduce by a factor of 2 is to be used. NOT SUPPORTED BY ANY SCHEME ANYMORE.
            :type makeSparse: bool
            :param fresh: set to true if proxy re-encryption is used in the multi-party protocol or star topology is used
            :type fresh: bool
            :return: KeyPair: key pair including the secret share for the current party and joined public key
            :rtype: KeyPair


        2. MultipartyKeyGen(self: openfhe.openfhe.CryptoContext, privateKeyVec: collections.abc.Sequence[openfhe.openfhe.PrivateKey]) -> openfhe.openfhe.KeyPair


            Threshold FHE: Generates a public key from a vector of secret shares. ONLY FOR DEBUGGIN PURPOSES. SHOULD NOT BE USED IN PRODUCTION.

            :param privateKeyVec: secret key shares.
            :type privateKeyVec: List[PrivateKey]
            :return KeyPair: key pair including the private for the current party and joined public key
            :rtype: KeyPair

        """
    def ReEncrypt(self, ciphertext: Ciphertext, evalKey: EvalKey, publicKey: PublicKey = ...) -> Ciphertext:
        """ReEncrypt(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext, evalKey: openfhe.openfhe.EvalKey, publicKey: openfhe.openfhe.PublicKey = None) -> openfhe.openfhe.Ciphertext


        ReEncrypt - Proxy Re-Encryption mechanism for OpenFHE

        :param ciphertext: input ciphertext
        :type ciphertext: Ciphertext
        :param evalKey: evaluation key for PRE keygen method
        :type evalKey: EvalKey
        :param publicKey: the public key of the recipient of the reencrypted ciphertext
        :type publicKey: PublicKey
        :return: the resulting ciphertext
        :rtype: Ciphertext

        """
    def ReKeyGen(self, oldPrivateKey: PrivateKey, newPublicKey: PublicKey) -> EvalKey:
        """ReKeyGen(self: openfhe.openfhe.CryptoContext, oldPrivateKey: openfhe.openfhe.PrivateKey, newPublicKey: openfhe.openfhe.PublicKey) -> openfhe.openfhe.EvalKey


        ReKeyGen produces an Eval Key that OpenFHE can use for Proxy Re-Encryption

        :param oldPrivateKey: original private key
        :type privateKey: PrivateKey
        :param newPublicKey: public key
        :type publicKey: PublicKey
        :return: new evaluation key
        :rtype: EvalKey

        """
    def Relinearize(self, ciphertext: Ciphertext) -> Ciphertext:
        """Relinearize(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext) -> openfhe.openfhe.Ciphertext


        Homomorphic multiplication of two ciphertexts withour relinearization

        :param ciphertext: input ciphertext
        :type ciphertext: Ciphertext
        :return: relinearized ciphertext
        :rtype: Ciphertext

        """
    def RelinearizeInPlace(self, ciphertext: Ciphertext) -> None:
        """RelinearizeInPlace(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext) -> None


        In-place relinearization of a ciphertext to the lowest level (with 2 polynomials per ciphertext).

        :param ciphertext: input ciphertext
        :type ciphertext: Ciphertext

        """
    def Rescale(self, ciphertext: Ciphertext) -> Ciphertext:
        """Rescale(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext) -> openfhe.openfhe.Ciphertext


        Rescale - An alias for OpenFHE ModReduce method. This is because ModReduce is called Rescale in CKKS.

        :param ciphertext: ciphertext
        :type ciphertext: Ciphertext
        :return: Ciphertext: rescaled ciphertext
        :rtype: Ciphertext

        """
    def RescaleInPlace(self, ciphertext: Ciphertext) -> None:
        """RescaleInPlace(self: openfhe.openfhe.CryptoContext, ciphertext: openfhe.openfhe.Ciphertext) -> None


        Rescale - An alias for OpenFHE ModReduceInPlace method. This is because ModReduceInPlace is called RescaleInPlace in CKKS.

        :param ciphertext:  ciphertext to be rescaled in-place
        :type ciphertext: Ciphertext

        """
    @overload
    @staticmethod
    def SerializeEvalAutomorphismKey(filename: str, sertype: SERBINARY, keyTag: str = ...) -> bool:
        """SerializeEvalAutomorphismKey(*args, **kwargs)
        Overloaded function.

        1. SerializeEvalAutomorphismKey(filename: str, sertype: openfhe.openfhe.SERBINARY, keyTag: str = '') -> bool


            SerializeEvalAutomorphismKey for a single EvalAuto key or all of the EvalAuto keys

            :param filename: output file
            :type filename: str
            :param sertype: serialization type
            :type sertype: SERJSON, SERBINARY
            :param id: key to serialize; empty string means all keys
            :type id: str
            :return: bool: true on success


        2. SerializeEvalAutomorphismKey(filename: str, sertype: openfhe.openfhe.SERJSON, keyTag: str = '') -> bool


            SerializeEvalAutomorphismKey for a single EvalAuto key or all of the EvalAuto keys

            :param filename: output file
            :type filename: str
            :param sertype: serialization type
            :type sertype: SERJSON, SERBINARY
            :param id: key to serialize; empty string means all keys
            :type id: str
            :return: bool: true on success

        """
    @overload
    @staticmethod
    def SerializeEvalAutomorphismKey(filename: str, sertype: SERJSON, keyTag: str = ...) -> bool:
        """SerializeEvalAutomorphismKey(*args, **kwargs)
        Overloaded function.

        1. SerializeEvalAutomorphismKey(filename: str, sertype: openfhe.openfhe.SERBINARY, keyTag: str = '') -> bool


            SerializeEvalAutomorphismKey for a single EvalAuto key or all of the EvalAuto keys

            :param filename: output file
            :type filename: str
            :param sertype: serialization type
            :type sertype: SERJSON, SERBINARY
            :param id: key to serialize; empty string means all keys
            :type id: str
            :return: bool: true on success


        2. SerializeEvalAutomorphismKey(filename: str, sertype: openfhe.openfhe.SERJSON, keyTag: str = '') -> bool


            SerializeEvalAutomorphismKey for a single EvalAuto key or all of the EvalAuto keys

            :param filename: output file
            :type filename: str
            :param sertype: serialization type
            :type sertype: SERJSON, SERBINARY
            :param id: key to serialize; empty string means all keys
            :type id: str
            :return: bool: true on success

        """
    @overload
    @staticmethod
    def SerializeEvalMultKey(filename: str, sertype: SERBINARY, keyTag: str = ...) -> bool:
        """SerializeEvalMultKey(*args, **kwargs)
        Overloaded function.

        1. SerializeEvalMultKey(filename: str, sertype: openfhe.openfhe.SERBINARY, keyTag: str = '') -> bool


            SerializeEvalMultKey for a single EvalMult key or all of the EvalMult keys

            :param filename: output file to serialize to
            :type filename: str
            :param sertype: type of serialization
            :type sertype: SERJSON, SERBINARY
            :param id: for key to serialize - if empty string, serialize them all
            :type id: str
            :return: bool: true on success (false on failure or no keys found)


        2. SerializeEvalMultKey(filename: str, sertype: openfhe.openfhe.SERJSON, keyTag: str = '') -> bool


            SerializeEvalMultKey for a single EvalMult key or all of the EvalMult keys

            :param filename: output file to serialize to
            :type filename: str
            :param sertype: type of serialization
            :type sertype: SERJSON, SERBINARY
            :param id: for key to serialize - if empty string, serialize them all
            :type id: str
            :return: bool: true on success (false on failure or no keys found)

        """
    @overload
    @staticmethod
    def SerializeEvalMultKey(filename: str, sertype: SERJSON, keyTag: str = ...) -> bool:
        """SerializeEvalMultKey(*args, **kwargs)
        Overloaded function.

        1. SerializeEvalMultKey(filename: str, sertype: openfhe.openfhe.SERBINARY, keyTag: str = '') -> bool


            SerializeEvalMultKey for a single EvalMult key or all of the EvalMult keys

            :param filename: output file to serialize to
            :type filename: str
            :param sertype: type of serialization
            :type sertype: SERJSON, SERBINARY
            :param id: for key to serialize - if empty string, serialize them all
            :type id: str
            :return: bool: true on success (false on failure or no keys found)


        2. SerializeEvalMultKey(filename: str, sertype: openfhe.openfhe.SERJSON, keyTag: str = '') -> bool


            SerializeEvalMultKey for a single EvalMult key or all of the EvalMult keys

            :param filename: output file to serialize to
            :type filename: str
            :param sertype: type of serialization
            :type sertype: SERJSON, SERBINARY
            :param id: for key to serialize - if empty string, serialize them all
            :type id: str
            :return: bool: true on success (false on failure or no keys found)

        """
    def SetEvalAddCount(self, evalAddCount: typing.SupportsInt) -> None:
        """SetEvalAddCount(self: openfhe.openfhe.CryptoContext, evalAddCount: typing.SupportsInt) -> None"""
    def SetKeyGenLevel(self, level: typing.SupportsInt) -> None:
        """SetKeyGenLevel(self: openfhe.openfhe.CryptoContext, level: typing.SupportsInt) -> None


        For future use: setter for the level at which evaluation keys should be generated

        :param level: the level to set the key generation to
        :type level: int

        """
    def SetKeySwitchCount(self, keySwitchCount: typing.SupportsInt) -> None:
        """SetKeySwitchCount(self: openfhe.openfhe.CryptoContext, keySwitchCount: typing.SupportsInt) -> None"""
    def SetMultiplicativeDepth(self, multiplicativeDepth: typing.SupportsInt) -> None:
        """SetMultiplicativeDepth(self: openfhe.openfhe.CryptoContext, multiplicativeDepth: typing.SupportsInt) -> None"""
    def SetNoiseEstimate(self, noiseEstimate: typing.SupportsFloat) -> None:
        """SetNoiseEstimate(self: openfhe.openfhe.CryptoContext, noiseEstimate: typing.SupportsFloat) -> None"""
    def SetPRENumHops(self, PRENumHops: typing.SupportsInt) -> None:
        """SetPRENumHops(self: openfhe.openfhe.CryptoContext, PRENumHops: typing.SupportsInt) -> None"""
    def get_ptr(self) -> None:
        """get_ptr(self: openfhe.openfhe.CryptoContext) -> None"""

class DCRTPoly:
    def __init__(self) -> None:
        """__init__(self: openfhe.openfhe.DCRTPoly) -> None"""

class DecryptionNoiseMode:
    """Members:

    FIXED_NOISE_DECRYPT

    NOISE_FLOODING_DECRYPT"""

    __members__: ClassVar[dict] = ...  # read-only
    FIXED_NOISE_DECRYPT: ClassVar[DecryptionNoiseMode] = ...
    NOISE_FLOODING_DECRYPT: ClassVar[DecryptionNoiseMode] = ...
    __entries: ClassVar[dict] = ...
    def __init__(self, value: typing.SupportsInt) -> None:
        """__init__(self: openfhe.openfhe.DecryptionNoiseMode, value: typing.SupportsInt) -> None"""
    def __eq__(self, other: object) -> bool:
        """__eq__(self: object, other: object, /) -> bool"""
    def __hash__(self) -> int:
        """__hash__(self: object, /) -> int"""
    def __index__(self) -> int:
        """__index__(self: openfhe.openfhe.DecryptionNoiseMode, /) -> int"""
    def __int__(self) -> int:
        """__int__(self: openfhe.openfhe.DecryptionNoiseMode, /) -> int"""
    def __ne__(self, other: object) -> bool:
        """__ne__(self: object, other: object, /) -> bool"""
    @property
    def name(self) -> str:
        """name(self: object, /) -> str

        name(self: object, /) -> str
        """
    @property
    def value(self) -> int:
        """(arg0: openfhe.openfhe.DecryptionNoiseMode) -> int"""

class EncryptionTechnique:
    """Members:

    STANDARD

    EXTENDED"""

    __members__: ClassVar[dict] = ...  # read-only
    EXTENDED: ClassVar[EncryptionTechnique] = ...
    STANDARD: ClassVar[EncryptionTechnique] = ...
    __entries: ClassVar[dict] = ...
    def __init__(self, value: typing.SupportsInt) -> None:
        """__init__(self: openfhe.openfhe.EncryptionTechnique, value: typing.SupportsInt) -> None"""
    def __eq__(self, other: object) -> bool:
        """__eq__(self: object, other: object, /) -> bool"""
    def __hash__(self) -> int:
        """__hash__(self: object, /) -> int"""
    def __index__(self) -> int:
        """__index__(self: openfhe.openfhe.EncryptionTechnique, /) -> int"""
    def __int__(self) -> int:
        """__int__(self: openfhe.openfhe.EncryptionTechnique, /) -> int"""
    def __ne__(self, other: object) -> bool:
        """__ne__(self: object, other: object, /) -> bool"""
    @property
    def name(self) -> str:
        """name(self: object, /) -> str

        name(self: object, /) -> str
        """
    @property
    def value(self) -> int:
        """(arg0: openfhe.openfhe.EncryptionTechnique) -> int"""

class EvalKey:
    def __init__(self) -> None:
        """__init__(self: openfhe.openfhe.EvalKey) -> None"""
    def GetKeyTag(self) -> str:
        """GetKeyTag(self: openfhe.openfhe.EvalKey) -> str"""
    def SetKeyTag(self, arg0: str) -> None:
        """SetKeyTag(self: openfhe.openfhe.EvalKey, arg0: str) -> None"""

class EvalKeyMap:
    def __init__(self) -> None:
        """__init__(self: openfhe.openfhe.EvalKeyMap) -> None"""

class ExecutionMode:
    """Members:

    EXEC_EVALUATION

    EXEC_NOISE_ESTIMATION"""

    __members__: ClassVar[dict] = ...  # read-only
    EXEC_EVALUATION: ClassVar[ExecutionMode] = ...
    EXEC_NOISE_ESTIMATION: ClassVar[ExecutionMode] = ...
    __entries: ClassVar[dict] = ...
    def __init__(self, value: typing.SupportsInt) -> None:
        """__init__(self: openfhe.openfhe.ExecutionMode, value: typing.SupportsInt) -> None"""
    def __eq__(self, other: object) -> bool:
        """__eq__(self: object, other: object, /) -> bool"""
    def __hash__(self) -> int:
        """__hash__(self: object, /) -> int"""
    def __index__(self) -> int:
        """__index__(self: openfhe.openfhe.ExecutionMode, /) -> int"""
    def __int__(self) -> int:
        """__int__(self: openfhe.openfhe.ExecutionMode, /) -> int"""
    def __ne__(self, other: object) -> bool:
        """__ne__(self: object, other: object, /) -> bool"""
    @property
    def name(self) -> str:
        """name(self: object, /) -> str

        name(self: object, /) -> str
        """
    @property
    def value(self) -> int:
        """(arg0: openfhe.openfhe.ExecutionMode) -> int"""

class FHECKKSRNS:
    def __init__(self) -> None:
        """__init__(self: openfhe.openfhe.FHECKKSRNS) -> None"""
    @overload
    @staticmethod
    def GetBootstrapDepth(
        depth: typing.SupportsInt, levelBudget: collections.abc.Sequence[typing.SupportsInt], keyDist: SecretKeyDist
    ) -> int:
        """GetBootstrapDepth(*args, **kwargs)
        Overloaded function.

        1. GetBootstrapDepth(depth: typing.SupportsInt, levelBudget: collections.abc.Sequence[typing.SupportsInt], keyDist: openfhe.openfhe.SecretKeyDist) -> int

        2. GetBootstrapDepth(levelBudget: collections.abc.Sequence[typing.SupportsInt], keyDist: openfhe.openfhe.SecretKeyDist) -> int
        """
    @overload
    @staticmethod
    def GetBootstrapDepth(levelBudget: collections.abc.Sequence[typing.SupportsInt], keyDist: SecretKeyDist) -> int:
        """GetBootstrapDepth(*args, **kwargs)
        Overloaded function.

        1. GetBootstrapDepth(depth: typing.SupportsInt, levelBudget: collections.abc.Sequence[typing.SupportsInt], keyDist: openfhe.openfhe.SecretKeyDist) -> int

        2. GetBootstrapDepth(levelBudget: collections.abc.Sequence[typing.SupportsInt], keyDist: openfhe.openfhe.SecretKeyDist) -> int
        """

class Format:
    """Members:

    EVALUATION

    COEFFICIENT"""

    __members__: ClassVar[dict] = ...  # read-only
    COEFFICIENT: ClassVar[Format] = ...
    EVALUATION: ClassVar[Format] = ...
    __entries: ClassVar[dict] = ...
    def __init__(self, value: typing.SupportsInt) -> None:
        """__init__(self: openfhe.openfhe.Format, value: typing.SupportsInt) -> None"""
    def __eq__(self, other: object) -> bool:
        """__eq__(self: object, other: object, /) -> bool"""
    def __hash__(self) -> int:
        """__hash__(self: object, /) -> int"""
    def __index__(self) -> int:
        """__index__(self: openfhe.openfhe.Format, /) -> int"""
    def __int__(self) -> int:
        """__int__(self: openfhe.openfhe.Format, /) -> int"""
    def __ne__(self, other: object) -> bool:
        """__ne__(self: object, other: object, /) -> bool"""
    @property
    def name(self) -> str:
        """name(self: object, /) -> str

        name(self: object, /) -> str
        """
    @property
    def value(self) -> int:
        """(arg0: openfhe.openfhe.Format) -> int"""

class KEYGEN_MODE:
    """Members:

    SYM_ENCRYPT

    PUB_ENCRYPT"""

    __members__: ClassVar[dict] = ...  # read-only
    PUB_ENCRYPT: ClassVar[KEYGEN_MODE] = ...
    SYM_ENCRYPT: ClassVar[KEYGEN_MODE] = ...
    __entries: ClassVar[dict] = ...
    def __init__(self, value: typing.SupportsInt) -> None:
        """__init__(self: openfhe.openfhe.KEYGEN_MODE, value: typing.SupportsInt) -> None"""
    def __eq__(self, other: object) -> bool:
        """__eq__(self: object, other: object, /) -> bool"""
    def __hash__(self) -> int:
        """__hash__(self: object, /) -> int"""
    def __index__(self) -> int:
        """__index__(self: openfhe.openfhe.KEYGEN_MODE, /) -> int"""
    def __int__(self) -> int:
        """__int__(self: openfhe.openfhe.KEYGEN_MODE, /) -> int"""
    def __ne__(self, other: object) -> bool:
        """__ne__(self: object, other: object, /) -> bool"""
    @property
    def name(self) -> str:
        """name(self: object, /) -> str

        name(self: object, /) -> str
        """
    @property
    def value(self) -> int:
        """(arg0: openfhe.openfhe.KEYGEN_MODE) -> int"""

class KeyPair:
    publicKey: PublicKey
    secretKey: PrivateKey
    def __init__(self, *args, **kwargs) -> None:
        """Initialize self.  See help(type(self)) for accurate signature."""
    def good(self) -> bool:
        """good(self: openfhe.openfhe.KeyPair) -> bool


        Checks whether both public key and secret key are non-null, or correctly initialized.

        :return: Result.
        :rtype: bool

        """

class KeySwitchTechnique:
    """Members:

    INVALID_KS_TECH

    BV

    HYBRID"""

    __members__: ClassVar[dict] = ...  # read-only
    BV: ClassVar[KeySwitchTechnique] = ...
    HYBRID: ClassVar[KeySwitchTechnique] = ...
    INVALID_KS_TECH: ClassVar[KeySwitchTechnique] = ...
    __entries: ClassVar[dict] = ...
    def __init__(self, value: typing.SupportsInt) -> None:
        """__init__(self: openfhe.openfhe.KeySwitchTechnique, value: typing.SupportsInt) -> None"""
    def __eq__(self, other: object) -> bool:
        """__eq__(self: object, other: object, /) -> bool"""
    def __hash__(self) -> int:
        """__hash__(self: object, /) -> int"""
    def __index__(self) -> int:
        """__index__(self: openfhe.openfhe.KeySwitchTechnique, /) -> int"""
    def __int__(self) -> int:
        """__int__(self: openfhe.openfhe.KeySwitchTechnique, /) -> int"""
    def __ne__(self, other: object) -> bool:
        """__ne__(self: object, other: object, /) -> bool"""
    @property
    def name(self) -> str:
        """name(self: object, /) -> str

        name(self: object, /) -> str
        """
    @property
    def value(self) -> int:
        """(arg0: openfhe.openfhe.KeySwitchTechnique) -> int"""

class LWECiphertext:
    def __init__(self) -> None:
        """__init__(self: openfhe.openfhe.LWECiphertext) -> None"""
    def GetLength(self) -> int:
        """GetLength(self: openfhe.openfhe.LWECiphertext) -> int"""
    def GetModulus(self) -> int:
        """GetModulus(self: openfhe.openfhe.LWECiphertext) -> int"""
    def __eq__(self, arg0: LWECiphertext) -> bool:
        """__eq__(self: openfhe.openfhe.LWECiphertext, arg0: openfhe.openfhe.LWECiphertext) -> bool"""
    def __ne__(self, arg0: LWECiphertext) -> bool:
        """__ne__(self: openfhe.openfhe.LWECiphertext, arg0: openfhe.openfhe.LWECiphertext) -> bool"""

class LWEPrivateKey:
    def __init__(self) -> None:
        """__init__(self: openfhe.openfhe.LWEPrivateKey) -> None"""
    def GetLength(self) -> int:
        """GetLength(self: openfhe.openfhe.LWEPrivateKey) -> int"""
    def __eq__(self, arg0: LWEPrivateKey) -> bool:
        """__eq__(self: openfhe.openfhe.LWEPrivateKey, arg0: openfhe.openfhe.LWEPrivateKey) -> bool"""
    def __ne__(self, arg0: LWEPrivateKey) -> bool:
        """__ne__(self: openfhe.openfhe.LWEPrivateKey, arg0: openfhe.openfhe.LWEPrivateKey) -> bool"""

class MultipartyMode:
    """Members:

    INVALID_MULTIPARTY_MODE

    FIXED_NOISE_MULTIPARTY

    NOISE_FLOODING_MULTIPARTY"""

    __members__: ClassVar[dict] = ...  # read-only
    FIXED_NOISE_MULTIPARTY: ClassVar[MultipartyMode] = ...
    INVALID_MULTIPARTY_MODE: ClassVar[MultipartyMode] = ...
    NOISE_FLOODING_MULTIPARTY: ClassVar[MultipartyMode] = ...
    __entries: ClassVar[dict] = ...
    def __init__(self, value: typing.SupportsInt) -> None:
        """__init__(self: openfhe.openfhe.MultipartyMode, value: typing.SupportsInt) -> None"""
    def __eq__(self, other: object) -> bool:
        """__eq__(self: object, other: object, /) -> bool"""
    def __hash__(self) -> int:
        """__hash__(self: object, /) -> int"""
    def __index__(self) -> int:
        """__index__(self: openfhe.openfhe.MultipartyMode, /) -> int"""
    def __int__(self) -> int:
        """__int__(self: openfhe.openfhe.MultipartyMode, /) -> int"""
    def __ne__(self, other: object) -> bool:
        """__ne__(self: object, other: object, /) -> bool"""
    @property
    def name(self) -> str:
        """name(self: object, /) -> str

        name(self: object, /) -> str
        """
    @property
    def value(self) -> int:
        """(arg0: openfhe.openfhe.MultipartyMode) -> int"""

class MultiplicationTechnique:
    """Members:

    BEHZ

    HPS

    HPSPOVERQ

    HPSPOVERQLEVELED"""

    __members__: ClassVar[dict] = ...  # read-only
    BEHZ: ClassVar[MultiplicationTechnique] = ...
    HPS: ClassVar[MultiplicationTechnique] = ...
    HPSPOVERQ: ClassVar[MultiplicationTechnique] = ...
    HPSPOVERQLEVELED: ClassVar[MultiplicationTechnique] = ...
    __entries: ClassVar[dict] = ...
    def __init__(self, value: typing.SupportsInt) -> None:
        """__init__(self: openfhe.openfhe.MultiplicationTechnique, value: typing.SupportsInt) -> None"""
    def __eq__(self, other: object) -> bool:
        """__eq__(self: object, other: object, /) -> bool"""
    def __hash__(self) -> int:
        """__hash__(self: object, /) -> int"""
    def __index__(self) -> int:
        """__index__(self: openfhe.openfhe.MultiplicationTechnique, /) -> int"""
    def __int__(self) -> int:
        """__int__(self: openfhe.openfhe.MultiplicationTechnique, /) -> int"""
    def __ne__(self, other: object) -> bool:
        """__ne__(self: object, other: object, /) -> bool"""
    @property
    def name(self) -> str:
        """name(self: object, /) -> str

        name(self: object, /) -> str
        """
    @property
    def value(self) -> int:
        """(arg0: openfhe.openfhe.MultiplicationTechnique) -> int"""

class PKESchemeFeature:
    """Members:

    PKE

    KEYSWITCH

    PRE

    LEVELEDSHE

    ADVANCEDSHE

    MULTIPARTY

    FHE

    SCHEMESWITCH"""

    __members__: ClassVar[dict] = ...  # read-only
    ADVANCEDSHE: ClassVar[PKESchemeFeature] = ...
    FHE: ClassVar[PKESchemeFeature] = ...
    KEYSWITCH: ClassVar[PKESchemeFeature] = ...
    LEVELEDSHE: ClassVar[PKESchemeFeature] = ...
    MULTIPARTY: ClassVar[PKESchemeFeature] = ...
    PKE: ClassVar[PKESchemeFeature] = ...
    PRE: ClassVar[PKESchemeFeature] = ...
    SCHEMESWITCH: ClassVar[PKESchemeFeature] = ...
    __entries: ClassVar[dict] = ...
    def __init__(self, value: typing.SupportsInt) -> None:
        """__init__(self: openfhe.openfhe.PKESchemeFeature, value: typing.SupportsInt) -> None"""
    def __eq__(self, other: object) -> bool:
        """__eq__(self: object, other: object, /) -> bool"""
    def __hash__(self) -> int:
        """__hash__(self: object, /) -> int"""
    def __index__(self) -> int:
        """__index__(self: openfhe.openfhe.PKESchemeFeature, /) -> int"""
    def __int__(self) -> int:
        """__int__(self: openfhe.openfhe.PKESchemeFeature, /) -> int"""
    def __ne__(self, other: object) -> bool:
        """__ne__(self: object, other: object, /) -> bool"""
    @property
    def name(self) -> str:
        """name(self: object, /) -> str

        name(self: object, /) -> str
        """
    @property
    def value(self) -> int:
        """(arg0: openfhe.openfhe.PKESchemeFeature) -> int"""

class ParmType:
    def __init__(self, *args, **kwargs) -> None:
        """Initialize self.  See help(type(self)) for accurate signature."""

class Plaintext:
    def __init__(self, *args, **kwargs) -> None:
        """Initialize self.  See help(type(self)) for accurate signature."""
    @overload
    def Decode(self) -> bool:
        """Decode(*args, **kwargs)
        Overloaded function.

        1. Decode(self: openfhe.openfhe.Plaintext) -> bool


            Decode the polynomial into a plaintext.


        2. Decode(self: openfhe.openfhe.Plaintext, arg0: typing.SupportsInt, arg1: typing.SupportsFloat, arg2: openfhe.openfhe.ScalingTechnique, arg3: openfhe.openfhe.ExecutionMode) -> bool


            Decode the polynomial into a plaintext.

        """
    @overload
    def Decode(self, arg0: typing.SupportsInt, arg1: typing.SupportsFloat, arg2: ScalingTechnique, arg3: ExecutionMode) -> bool:
        """Decode(*args, **kwargs)
        Overloaded function.

        1. Decode(self: openfhe.openfhe.Plaintext) -> bool


            Decode the polynomial into a plaintext.


        2. Decode(self: openfhe.openfhe.Plaintext, arg0: typing.SupportsInt, arg1: typing.SupportsFloat, arg2: openfhe.openfhe.ScalingTechnique, arg3: openfhe.openfhe.ExecutionMode) -> bool


            Decode the polynomial into a plaintext.

        """
    def Encode(self) -> bool:
        """Encode(self: openfhe.openfhe.Plaintext) -> bool


        Encode the plaintext into a polynomial.

        """
    def GetCKKSPackedValue(self) -> list[complex]:
        """GetCKKSPackedValue(self: openfhe.openfhe.Plaintext) -> list[complex]


        Get the packed value of the plaintext for CKKS-based plaintexts.

        :return: The packed value of the plaintext.
        :rtype: List[complex]

        """
    def GetCoefPackedValue(self) -> list[int]:
        """GetCoefPackedValue(self: openfhe.openfhe.Plaintext) -> list[int]"""
    def GetFormattedValues(self, arg0: typing.SupportsInt) -> str:
        """GetFormattedValues(self: openfhe.openfhe.Plaintext, arg0: typing.SupportsInt) -> str"""
    def GetLength(self) -> int:
        """GetLength(self: openfhe.openfhe.Plaintext) -> int


        Get method to return the length of the plaintext.

        :return: The length of the plaintext in terms of the number of bits.
        :rtype: int

        """
    def GetLevel(self) -> int:
        """GetLevel(self: openfhe.openfhe.Plaintext) -> int"""
    def GetLogError(self) -> float:
        """GetLogError(self: openfhe.openfhe.Plaintext) -> float"""
    @overload
    def GetLogPrecision(self) -> float:
        """GetLogPrecision(*args, **kwargs)
        Overloaded function.

        1. GetLogPrecision(self: openfhe.openfhe.Plaintext) -> float


            Get the log of the plaintext precision.

            :return: The log of the plaintext precision.
            :rtype: float


        2. GetLogPrecision(self: openfhe.openfhe.Plaintext) -> float
        """
    @overload
    def GetLogPrecision(self) -> float:
        """GetLogPrecision(*args, **kwargs)
        Overloaded function.

        1. GetLogPrecision(self: openfhe.openfhe.Plaintext) -> float


            Get the log of the plaintext precision.

            :return: The log of the plaintext precision.
            :rtype: float


        2. GetLogPrecision(self: openfhe.openfhe.Plaintext) -> float
        """
    def GetNoiseScaleDeg(self) -> int:
        """GetNoiseScaleDeg(self: openfhe.openfhe.Plaintext) -> int"""
    def GetPackedValue(self) -> list[int]:
        """GetPackedValue(self: openfhe.openfhe.Plaintext) -> list[int]"""
    def GetRealPackedValue(self) -> list[float]:
        """GetRealPackedValue(self: openfhe.openfhe.Plaintext) -> list[float]


        Get the real component of the packed value of the plaintext for CKKS-based plaintexts.

        :return: The real-component of the packed value of the plaintext.
        :rtype: List[double]

        """
    def GetScalingFactor(self) -> float:
        """GetScalingFactor(self: openfhe.openfhe.Plaintext) -> float


        Get the scaling factor of the plaintext for CKKS-based plaintexts.

        :return: The scaling factor of the plaintext.
        :rtype: float

        """
    def GetSchemeID(self) -> SCHEME:
        """GetSchemeID(self: openfhe.openfhe.Plaintext) -> openfhe.openfhe.SCHEME


        Get the encryption technique of the plaintext for BFV-based plaintexts.

        :return: The scheme ID of the plaintext.
        :rtype: SCHEME

        """
    def GetSlots(self) -> int:
        """GetSlots(self: openfhe.openfhe.Plaintext) -> int"""
    def GetStringValue(self) -> str:
        """GetStringValue(self: openfhe.openfhe.Plaintext) -> str"""
    def HighBound(self) -> int:
        """HighBound(self: openfhe.openfhe.Plaintext) -> int


        Calculate and return upper bound that can be encoded with the plaintext modulus the number to encode MUST be less than this value

        :return: floor(p/2)
        :rtype: int

        """
    def IsEncoded(self) -> bool:
        """IsEncoded(self: openfhe.openfhe.Plaintext) -> bool


        Check if the plaintext is encoded.

        :return: True if the plaintext is encoded, False otherwise.
        :rtype: bool

        """
    def LowBound(self) -> int:
        """LowBound(self: openfhe.openfhe.Plaintext) -> int


        Calculate and return lower bound that can be encoded with the plaintext modulus the number to encode MUST be greater than this value

        :return: floor(-p/2)
        :rtype: int

        """
    def SetFormat(self, fmt: Format) -> None:
        """SetFormat(self: openfhe.openfhe.Plaintext, fmt: openfhe.openfhe.Format) -> None


        SetFormat - allows format to be changed for openfhe.Plaintext evaluations

        :param fmt:
        :type format: Format

        """
    def SetIntVectorValue(self, arg0: collections.abc.Sequence[typing.SupportsInt]) -> None:
        """SetIntVectorValue(self: openfhe.openfhe.Plaintext, arg0: collections.abc.Sequence[typing.SupportsInt]) -> None"""
    def SetLength(self, newSize: typing.SupportsInt) -> None:
        """SetLength(self: openfhe.openfhe.Plaintext, newSize: typing.SupportsInt) -> None


        Resize the plaintext; only works for plaintexts that support a resizable vector (coefpacked).

        :param newSize: The new size of the plaintext.
        :type newSize: int

        """
    def SetLevel(self, arg0: typing.SupportsInt) -> None:
        """SetLevel(self: openfhe.openfhe.Plaintext, arg0: typing.SupportsInt) -> None"""
    def SetNoiseScaleDeg(self, arg0: typing.SupportsInt) -> None:
        """SetNoiseScaleDeg(self: openfhe.openfhe.Plaintext, arg0: typing.SupportsInt) -> None"""
    def SetScalingFactor(self, sf: typing.SupportsFloat) -> None:
        """SetScalingFactor(self: openfhe.openfhe.Plaintext, sf: typing.SupportsFloat) -> None


        Set the scaling factor of the plaintext for CKKS-based plaintexts.

        :param sf: The scaling factor to set.
        :type sf: float

        """
    def SetSlots(self, arg0: typing.SupportsInt) -> None:
        """SetSlots(self: openfhe.openfhe.Plaintext, arg0: typing.SupportsInt) -> None"""
    def SetStringValue(self, arg0: str) -> None:
        """SetStringValue(self: openfhe.openfhe.Plaintext, arg0: str) -> None"""

class PrivateKey:
    def __init__(self) -> None:
        """__init__(self: openfhe.openfhe.PrivateKey) -> None"""
    def GetCryptoContext(self, *args, **kwargs):
        """GetCryptoContext(self: openfhe.openfhe.PrivateKey) -> lbcrypto::CryptoContextImpl<lbcrypto::DCRTPolyImpl<bigintdyn::mubintvec<bigintdyn::ubint<unsigned long> > > >"""
    def GetKeyTag(self) -> str:
        """GetKeyTag(self: openfhe.openfhe.PrivateKey) -> str"""
    def SetKeyTag(self, arg0: str) -> None:
        """SetKeyTag(self: openfhe.openfhe.PrivateKey, arg0: str) -> None"""

class ProxyReEncryptionMode:
    """Members:

    NOT_SET

    INDCPA

    FIXED_NOISE_HRA

    NOISE_FLOODING_HRA"""

    __members__: ClassVar[dict] = ...  # read-only
    FIXED_NOISE_HRA: ClassVar[ProxyReEncryptionMode] = ...
    INDCPA: ClassVar[ProxyReEncryptionMode] = ...
    NOISE_FLOODING_HRA: ClassVar[ProxyReEncryptionMode] = ...
    NOT_SET: ClassVar[ProxyReEncryptionMode] = ...
    __entries: ClassVar[dict] = ...
    def __init__(self, value: typing.SupportsInt) -> None:
        """__init__(self: openfhe.openfhe.ProxyReEncryptionMode, value: typing.SupportsInt) -> None"""
    def __eq__(self, other: object) -> bool:
        """__eq__(self: object, other: object, /) -> bool"""
    def __hash__(self) -> int:
        """__hash__(self: object, /) -> int"""
    def __index__(self) -> int:
        """__index__(self: openfhe.openfhe.ProxyReEncryptionMode, /) -> int"""
    def __int__(self) -> int:
        """__int__(self: openfhe.openfhe.ProxyReEncryptionMode, /) -> int"""
    def __ne__(self, other: object) -> bool:
        """__ne__(self: object, other: object, /) -> bool"""
    @property
    def name(self) -> str:
        """name(self: object, /) -> str

        name(self: object, /) -> str
        """
    @property
    def value(self) -> int:
        """(arg0: openfhe.openfhe.ProxyReEncryptionMode) -> int"""

class PublicKey:
    def __init__(self) -> None:
        """__init__(self: openfhe.openfhe.PublicKey) -> None"""
    def GetKeyTag(self) -> str:
        """GetKeyTag(self: openfhe.openfhe.PublicKey) -> str"""
    def SetKeyTag(self, arg0: str) -> None:
        """SetKeyTag(self: openfhe.openfhe.PublicKey, arg0: str) -> None"""

class SCHEME:
    """Members:

    INVALID_SCHEME

    CKKSRNS_SCHEME

    BFVRNS_SCHEME

    BGVRNS_SCHEME"""

    __members__: ClassVar[dict] = ...  # read-only
    BFVRNS_SCHEME: ClassVar[SCHEME] = ...
    BGVRNS_SCHEME: ClassVar[SCHEME] = ...
    CKKSRNS_SCHEME: ClassVar[SCHEME] = ...
    INVALID_SCHEME: ClassVar[SCHEME] = ...
    __entries: ClassVar[dict] = ...
    def __init__(self, value: typing.SupportsInt) -> None:
        """__init__(self: openfhe.openfhe.SCHEME, value: typing.SupportsInt) -> None"""
    def __eq__(self, other: object) -> bool:
        """__eq__(self: object, other: object, /) -> bool"""
    def __hash__(self) -> int:
        """__hash__(self: object, /) -> int"""
    def __index__(self) -> int:
        """__index__(self: openfhe.openfhe.SCHEME, /) -> int"""
    def __int__(self) -> int:
        """__int__(self: openfhe.openfhe.SCHEME, /) -> int"""
    def __ne__(self, other: object) -> bool:
        """__ne__(self: object, other: object, /) -> bool"""
    @property
    def name(self) -> str:
        """name(self: object, /) -> str

        name(self: object, /) -> str
        """
    @property
    def value(self) -> int:
        """(arg0: openfhe.openfhe.SCHEME) -> int"""

class SERBINARY:
    def __init__(self, *args, **kwargs) -> None:
        """Initialize self.  See help(type(self)) for accurate signature."""

class SERJSON:
    def __init__(self, *args, **kwargs) -> None:
        """Initialize self.  See help(type(self)) for accurate signature."""

class ScalingTechnique:
    """Members:

    FIXEDMANUAL

    FIXEDAUTO

    FLEXIBLEAUTO

    FLEXIBLEAUTOEXT

    NORESCALE

    COMPOSITESCALINGAUTO

    COMPOSITESCALINGMANUAL

    INVALID_RS_TECHNIQUE"""

    __members__: ClassVar[dict] = ...  # read-only
    COMPOSITESCALINGAUTO: ClassVar[ScalingTechnique] = ...
    COMPOSITESCALINGMANUAL: ClassVar[ScalingTechnique] = ...
    FIXEDAUTO: ClassVar[ScalingTechnique] = ...
    FIXEDMANUAL: ClassVar[ScalingTechnique] = ...
    FLEXIBLEAUTO: ClassVar[ScalingTechnique] = ...
    FLEXIBLEAUTOEXT: ClassVar[ScalingTechnique] = ...
    INVALID_RS_TECHNIQUE: ClassVar[ScalingTechnique] = ...
    NORESCALE: ClassVar[ScalingTechnique] = ...
    __entries: ClassVar[dict] = ...
    def __init__(self, value: typing.SupportsInt) -> None:
        """__init__(self: openfhe.openfhe.ScalingTechnique, value: typing.SupportsInt) -> None"""
    def __eq__(self, other: object) -> bool:
        """__eq__(self: object, other: object, /) -> bool"""
    def __hash__(self) -> int:
        """__hash__(self: object, /) -> int"""
    def __index__(self) -> int:
        """__index__(self: openfhe.openfhe.ScalingTechnique, /) -> int"""
    def __int__(self) -> int:
        """__int__(self: openfhe.openfhe.ScalingTechnique, /) -> int"""
    def __ne__(self, other: object) -> bool:
        """__ne__(self: object, other: object, /) -> bool"""
    @property
    def name(self) -> str:
        """name(self: object, /) -> str

        name(self: object, /) -> str
        """
    @property
    def value(self) -> int:
        """(arg0: openfhe.openfhe.ScalingTechnique) -> int"""

class SchSwchParams:
    def __init__(self) -> None:
        """__init__(self: openfhe.openfhe.SchSwchParams) -> None"""
    def GetArbitraryFunctionEvaluation(self) -> bool:
        """GetArbitraryFunctionEvaluation(self: openfhe.openfhe.SchSwchParams) -> bool"""
    def GetBStepLTrCKKStoFHEW(self) -> int:
        """GetBStepLTrCKKStoFHEW(self: openfhe.openfhe.SchSwchParams) -> int"""
    def GetBStepLTrFHEWtoCKKS(self) -> int:
        """GetBStepLTrFHEWtoCKKS(self: openfhe.openfhe.SchSwchParams) -> int"""
    def GetBatchSize(self) -> int:
        """GetBatchSize(self: openfhe.openfhe.SchSwchParams) -> int"""
    def GetComputeArgmin(self) -> bool:
        """GetComputeArgmin(self: openfhe.openfhe.SchSwchParams) -> bool"""
    def GetCtxtModSizeFHEWIntermedSwch(self) -> int:
        """GetCtxtModSizeFHEWIntermedSwch(self: openfhe.openfhe.SchSwchParams) -> int"""
    def GetCtxtModSizeFHEWLargePrec(self) -> int:
        """GetCtxtModSizeFHEWLargePrec(self: openfhe.openfhe.SchSwchParams) -> int"""
    def GetInitialCKKSModulus(self, *args, **kwargs):
        """GetInitialCKKSModulus(self: openfhe.openfhe.SchSwchParams) -> intnat::NativeIntegerT<unsigned long>"""
    def GetLevelLTrCKKStoFHEW(self) -> int:
        """GetLevelLTrCKKStoFHEW(self: openfhe.openfhe.SchSwchParams) -> int"""
    def GetLevelLTrFHEWtoCKKS(self) -> int:
        """GetLevelLTrFHEWtoCKKS(self: openfhe.openfhe.SchSwchParams) -> int"""
    def GetNumSlotsCKKS(self) -> int:
        """GetNumSlotsCKKS(self: openfhe.openfhe.SchSwchParams) -> int"""
    def GetNumValues(self) -> int:
        """GetNumValues(self: openfhe.openfhe.SchSwchParams) -> int"""
    def GetOneHotEncoding(self) -> bool:
        """GetOneHotEncoding(self: openfhe.openfhe.SchSwchParams) -> bool"""
    def GetRingDimension(self) -> int:
        """GetRingDimension(self: openfhe.openfhe.SchSwchParams) -> int"""
    def GetScalingModSize(self) -> int:
        """GetScalingModSize(self: openfhe.openfhe.SchSwchParams) -> int"""
    def GetSecurityLevelCKKS(self) -> SecurityLevel:
        """GetSecurityLevelCKKS(self: openfhe.openfhe.SchSwchParams) -> openfhe.openfhe.SecurityLevel"""
    def GetSecurityLevelFHEW(self) -> BINFHE_PARAMSET:
        """GetSecurityLevelFHEW(self: openfhe.openfhe.SchSwchParams) -> openfhe.openfhe.BINFHE_PARAMSET"""
    def GetUseAltArgmin(self) -> bool:
        """GetUseAltArgmin(self: openfhe.openfhe.SchSwchParams) -> bool"""
    def GetUseDynamicModeFHEW(self) -> bool:
        """GetUseDynamicModeFHEW(self: openfhe.openfhe.SchSwchParams) -> bool"""
    def SetArbitraryFunctionEvaluation(self, arg0: bool) -> None:
        """SetArbitraryFunctionEvaluation(self: openfhe.openfhe.SchSwchParams, arg0: bool) -> None"""
    def SetBStepLTrCKKStoFHEW(self, arg0: typing.SupportsInt) -> None:
        """SetBStepLTrCKKStoFHEW(self: openfhe.openfhe.SchSwchParams, arg0: typing.SupportsInt) -> None"""
    def SetBStepLTrFHEWtoCKKS(self, arg0: typing.SupportsInt) -> None:
        """SetBStepLTrFHEWtoCKKS(self: openfhe.openfhe.SchSwchParams, arg0: typing.SupportsInt) -> None"""
    def SetBatchSize(self, arg0: typing.SupportsInt) -> None:
        """SetBatchSize(self: openfhe.openfhe.SchSwchParams, arg0: typing.SupportsInt) -> None"""
    def SetComputeArgmin(self, arg0: bool) -> None:
        """SetComputeArgmin(self: openfhe.openfhe.SchSwchParams, arg0: bool) -> None"""
    def SetCtxtModSizeFHEWIntermedSwch(self, arg0: typing.SupportsInt) -> None:
        """SetCtxtModSizeFHEWIntermedSwch(self: openfhe.openfhe.SchSwchParams, arg0: typing.SupportsInt) -> None"""
    def SetCtxtModSizeFHEWLargePrec(self, arg0: typing.SupportsInt) -> None:
        """SetCtxtModSizeFHEWLargePrec(self: openfhe.openfhe.SchSwchParams, arg0: typing.SupportsInt) -> None"""
    def SetInitialCKKSModulus(self, arg0) -> None:
        """SetInitialCKKSModulus(self: openfhe.openfhe.SchSwchParams, arg0: intnat::NativeIntegerT<unsigned long>) -> None"""
    def SetLevelLTrCKKStoFHEW(self, arg0: typing.SupportsInt) -> None:
        """SetLevelLTrCKKStoFHEW(self: openfhe.openfhe.SchSwchParams, arg0: typing.SupportsInt) -> None"""
    def SetLevelLTrFHEWtoCKKS(self, arg0: typing.SupportsInt) -> None:
        """SetLevelLTrFHEWtoCKKS(self: openfhe.openfhe.SchSwchParams, arg0: typing.SupportsInt) -> None"""
    def SetNumSlotsCKKS(self, arg0: typing.SupportsInt) -> None:
        """SetNumSlotsCKKS(self: openfhe.openfhe.SchSwchParams, arg0: typing.SupportsInt) -> None"""
    def SetNumValues(self, arg0: typing.SupportsInt) -> None:
        """SetNumValues(self: openfhe.openfhe.SchSwchParams, arg0: typing.SupportsInt) -> None"""
    def SetOneHotEncoding(self, arg0: bool) -> None:
        """SetOneHotEncoding(self: openfhe.openfhe.SchSwchParams, arg0: bool) -> None"""
    def SetRingDimension(self, arg0: typing.SupportsInt) -> None:
        """SetRingDimension(self: openfhe.openfhe.SchSwchParams, arg0: typing.SupportsInt) -> None"""
    def SetScalingModSize(self, arg0: typing.SupportsInt) -> None:
        """SetScalingModSize(self: openfhe.openfhe.SchSwchParams, arg0: typing.SupportsInt) -> None"""
    def SetSecurityLevelCKKS(self, arg0: SecurityLevel) -> None:
        """SetSecurityLevelCKKS(self: openfhe.openfhe.SchSwchParams, arg0: openfhe.openfhe.SecurityLevel) -> None"""
    def SetSecurityLevelFHEW(self, arg0: BINFHE_PARAMSET) -> None:
        """SetSecurityLevelFHEW(self: openfhe.openfhe.SchSwchParams, arg0: openfhe.openfhe.BINFHE_PARAMSET) -> None"""
    def SetUseAltArgmin(self, arg0: bool) -> None:
        """SetUseAltArgmin(self: openfhe.openfhe.SchSwchParams, arg0: bool) -> None"""
    def SetUseDynamicModeFHEW(self, arg0: bool) -> None:
        """SetUseDynamicModeFHEW(self: openfhe.openfhe.SchSwchParams, arg0: bool) -> None"""

class SecretKeyDist:
    """Members:

    GAUSSIAN

    UNIFORM_TERNARY

    SPARSE_TERNARY"""

    __members__: ClassVar[dict] = ...  # read-only
    GAUSSIAN: ClassVar[SecretKeyDist] = ...
    SPARSE_TERNARY: ClassVar[SecretKeyDist] = ...
    UNIFORM_TERNARY: ClassVar[SecretKeyDist] = ...
    __entries: ClassVar[dict] = ...
    def __init__(self, value: typing.SupportsInt) -> None:
        """__init__(self: openfhe.openfhe.SecretKeyDist, value: typing.SupportsInt) -> None"""
    def __eq__(self, other: object) -> bool:
        """__eq__(self: object, other: object, /) -> bool"""
    def __hash__(self) -> int:
        """__hash__(self: object, /) -> int"""
    def __index__(self) -> int:
        """__index__(self: openfhe.openfhe.SecretKeyDist, /) -> int"""
    def __int__(self) -> int:
        """__int__(self: openfhe.openfhe.SecretKeyDist, /) -> int"""
    def __ne__(self, other: object) -> bool:
        """__ne__(self: object, other: object, /) -> bool"""
    @property
    def name(self) -> str:
        """name(self: object, /) -> str

        name(self: object, /) -> str
        """
    @property
    def value(self) -> int:
        """(arg0: openfhe.openfhe.SecretKeyDist) -> int"""

class SecurityLevel:
    """Members:

    HEStd_128_classic

    HEStd_192_classic

    HEStd_256_classic

    HEStd_NotSet"""

    __members__: ClassVar[dict] = ...  # read-only
    HEStd_128_classic: ClassVar[SecurityLevel] = ...
    HEStd_192_classic: ClassVar[SecurityLevel] = ...
    HEStd_256_classic: ClassVar[SecurityLevel] = ...
    HEStd_NotSet: ClassVar[SecurityLevel] = ...
    __entries: ClassVar[dict] = ...
    def __init__(self, value: typing.SupportsInt) -> None:
        """__init__(self: openfhe.openfhe.SecurityLevel, value: typing.SupportsInt) -> None"""
    def __eq__(self, other: object) -> bool:
        """__eq__(self: object, other: object, /) -> bool"""
    def __hash__(self) -> int:
        """__hash__(self: object, /) -> int"""
    def __index__(self) -> int:
        """__index__(self: openfhe.openfhe.SecurityLevel, /) -> int"""
    def __int__(self) -> int:
        """__int__(self: openfhe.openfhe.SecurityLevel, /) -> int"""
    def __ne__(self, other: object) -> bool:
        """__ne__(self: object, other: object, /) -> bool"""
    @property
    def name(self) -> str:
        """name(self: object, /) -> str

        name(self: object, /) -> str
        """
    @property
    def value(self) -> int:
        """(arg0: openfhe.openfhe.SecurityLevel) -> int"""

def ClearEvalMultKeys() -> None:
    """ClearEvalMultKeys() -> None"""

@overload
def DeserializeCiphertext(filename: str, sertype: SERJSON) -> tuple[Ciphertext, bool]:
    """DeserializeCiphertext(*args, **kwargs)
    Overloaded function.

    1. DeserializeCiphertext(filename: str, sertype: openfhe.openfhe.SERJSON) -> tuple[openfhe.openfhe.Ciphertext, bool]

    2. DeserializeCiphertext(filename: str, sertype: openfhe.openfhe.SERBINARY) -> tuple[openfhe.openfhe.Ciphertext, bool]
    """

@overload
def DeserializeCiphertext(filename: str, sertype: SERBINARY) -> tuple[Ciphertext, bool]:
    """DeserializeCiphertext(*args, **kwargs)
    Overloaded function.

    1. DeserializeCiphertext(filename: str, sertype: openfhe.openfhe.SERJSON) -> tuple[openfhe.openfhe.Ciphertext, bool]

    2. DeserializeCiphertext(filename: str, sertype: openfhe.openfhe.SERBINARY) -> tuple[openfhe.openfhe.Ciphertext, bool]
    """

@overload
def DeserializeCiphertextString(str: str, sertype: SERJSON) -> Ciphertext:
    """DeserializeCiphertextString(*args, **kwargs)
    Overloaded function.

    1. DeserializeCiphertextString(str: str, sertype: openfhe.openfhe.SERJSON) -> openfhe.openfhe.Ciphertext

    2. DeserializeCiphertextString(str: bytes, sertype: openfhe.openfhe.SERBINARY) -> openfhe.openfhe.Ciphertext
    """

@overload
def DeserializeCiphertextString(str: bytes, sertype: SERBINARY) -> Ciphertext:
    """DeserializeCiphertextString(*args, **kwargs)
    Overloaded function.

    1. DeserializeCiphertextString(str: str, sertype: openfhe.openfhe.SERJSON) -> openfhe.openfhe.Ciphertext

    2. DeserializeCiphertextString(str: bytes, sertype: openfhe.openfhe.SERBINARY) -> openfhe.openfhe.Ciphertext
    """

@overload
def DeserializeCryptoContext(filename: str, sertype: SERJSON) -> tuple[CryptoContext, bool]:
    """DeserializeCryptoContext(*args, **kwargs)
    Overloaded function.

    1. DeserializeCryptoContext(filename: str, sertype: openfhe.openfhe.SERJSON) -> tuple[openfhe.openfhe.CryptoContext, bool]

    2. DeserializeCryptoContext(filename: str, sertype: openfhe.openfhe.SERBINARY) -> tuple[openfhe.openfhe.CryptoContext, bool]
    """

@overload
def DeserializeCryptoContext(filename: str, sertype: SERBINARY) -> tuple[CryptoContext, bool]:
    """DeserializeCryptoContext(*args, **kwargs)
    Overloaded function.

    1. DeserializeCryptoContext(filename: str, sertype: openfhe.openfhe.SERJSON) -> tuple[openfhe.openfhe.CryptoContext, bool]

    2. DeserializeCryptoContext(filename: str, sertype: openfhe.openfhe.SERBINARY) -> tuple[openfhe.openfhe.CryptoContext, bool]
    """

@overload
def DeserializeCryptoContextString(str: str, sertype: SERJSON) -> CryptoContext:
    """DeserializeCryptoContextString(*args, **kwargs)
    Overloaded function.

    1. DeserializeCryptoContextString(str: str, sertype: openfhe.openfhe.SERJSON) -> openfhe.openfhe.CryptoContext

    2. DeserializeCryptoContextString(str: bytes, sertype: openfhe.openfhe.SERBINARY) -> openfhe.openfhe.CryptoContext
    """

@overload
def DeserializeCryptoContextString(str: bytes, sertype: SERBINARY) -> CryptoContext:
    """DeserializeCryptoContextString(*args, **kwargs)
    Overloaded function.

    1. DeserializeCryptoContextString(str: str, sertype: openfhe.openfhe.SERJSON) -> openfhe.openfhe.CryptoContext

    2. DeserializeCryptoContextString(str: bytes, sertype: openfhe.openfhe.SERBINARY) -> openfhe.openfhe.CryptoContext
    """

@overload
def DeserializeEvalAutomorphismKeyString(data: str, sertype: SERJSON) -> None:
    """DeserializeEvalAutomorphismKeyString(*args, **kwargs)
    Overloaded function.

    1. DeserializeEvalAutomorphismKeyString(data: str, sertype: openfhe.openfhe.SERJSON) -> None

    2. DeserializeEvalAutomorphismKeyString(bytes: bytes, sertype: openfhe.openfhe.SERBINARY) -> None
    """

@overload
def DeserializeEvalAutomorphismKeyString(bytes: bytes, sertype: SERBINARY) -> None:
    """DeserializeEvalAutomorphismKeyString(*args, **kwargs)
    Overloaded function.

    1. DeserializeEvalAutomorphismKeyString(data: str, sertype: openfhe.openfhe.SERJSON) -> None

    2. DeserializeEvalAutomorphismKeyString(bytes: bytes, sertype: openfhe.openfhe.SERBINARY) -> None
    """

@overload
def DeserializeEvalKey(filename: str, sertype: SERJSON) -> tuple[EvalKey, bool]:
    """DeserializeEvalKey(*args, **kwargs)
    Overloaded function.

    1. DeserializeEvalKey(filename: str, sertype: openfhe.openfhe.SERJSON) -> tuple[openfhe.openfhe.EvalKey, bool]

    2. DeserializeEvalKey(filename: str, sertype: openfhe.openfhe.SERBINARY) -> tuple[openfhe.openfhe.EvalKey, bool]
    """

@overload
def DeserializeEvalKey(filename: str, sertype: SERBINARY) -> tuple[EvalKey, bool]:
    """DeserializeEvalKey(*args, **kwargs)
    Overloaded function.

    1. DeserializeEvalKey(filename: str, sertype: openfhe.openfhe.SERJSON) -> tuple[openfhe.openfhe.EvalKey, bool]

    2. DeserializeEvalKey(filename: str, sertype: openfhe.openfhe.SERBINARY) -> tuple[openfhe.openfhe.EvalKey, bool]
    """

@overload
def DeserializeEvalKeyMap(filename: str, sertype: SERJSON) -> tuple[EvalKeyMap, bool]:
    """DeserializeEvalKeyMap(*args, **kwargs)
    Overloaded function.

    1. DeserializeEvalKeyMap(filename: str, sertype: openfhe.openfhe.SERJSON) -> tuple[openfhe.openfhe.EvalKeyMap, bool]

    2. DeserializeEvalKeyMap(filename: str, sertype: openfhe.openfhe.SERBINARY) -> tuple[openfhe.openfhe.EvalKeyMap, bool]
    """

@overload
def DeserializeEvalKeyMap(filename: str, sertype: SERBINARY) -> tuple[EvalKeyMap, bool]:
    """DeserializeEvalKeyMap(*args, **kwargs)
    Overloaded function.

    1. DeserializeEvalKeyMap(filename: str, sertype: openfhe.openfhe.SERJSON) -> tuple[openfhe.openfhe.EvalKeyMap, bool]

    2. DeserializeEvalKeyMap(filename: str, sertype: openfhe.openfhe.SERBINARY) -> tuple[openfhe.openfhe.EvalKeyMap, bool]
    """

@overload
def DeserializeEvalKeyMapString(str: bytes, sertype: SERJSON) -> EvalKeyMap:
    """DeserializeEvalKeyMapString(*args, **kwargs)
    Overloaded function.

    1. DeserializeEvalKeyMapString(str: bytes, sertype: openfhe.openfhe.SERJSON) -> openfhe.openfhe.EvalKeyMap

    2. DeserializeEvalKeyMapString(str: bytes, sertype: openfhe.openfhe.SERBINARY) -> openfhe.openfhe.EvalKeyMap
    """

@overload
def DeserializeEvalKeyMapString(str: bytes, sertype: SERBINARY) -> EvalKeyMap:
    """DeserializeEvalKeyMapString(*args, **kwargs)
    Overloaded function.

    1. DeserializeEvalKeyMapString(str: bytes, sertype: openfhe.openfhe.SERJSON) -> openfhe.openfhe.EvalKeyMap

    2. DeserializeEvalKeyMapString(str: bytes, sertype: openfhe.openfhe.SERBINARY) -> openfhe.openfhe.EvalKeyMap
    """

def DeserializeEvalKeyMapVectorString(str: bytes, sertype: SERBINARY) -> list[EvalKey]:
    """DeserializeEvalKeyMapVectorString(str: bytes, sertype: openfhe.openfhe.SERBINARY) -> list[openfhe.openfhe.EvalKey]"""

@overload
def DeserializeEvalKeyString(str: str, sertype: SERJSON) -> EvalKey:
    """DeserializeEvalKeyString(*args, **kwargs)
    Overloaded function.

    1. DeserializeEvalKeyString(str: str, sertype: openfhe.openfhe.SERJSON) -> openfhe.openfhe.EvalKey

    2. DeserializeEvalKeyString(str: bytes, sertype: openfhe.openfhe.SERBINARY) -> openfhe.openfhe.EvalKey
    """

@overload
def DeserializeEvalKeyString(str: bytes, sertype: SERBINARY) -> EvalKey:
    """DeserializeEvalKeyString(*args, **kwargs)
    Overloaded function.

    1. DeserializeEvalKeyString(str: str, sertype: openfhe.openfhe.SERJSON) -> openfhe.openfhe.EvalKey

    2. DeserializeEvalKeyString(str: bytes, sertype: openfhe.openfhe.SERBINARY) -> openfhe.openfhe.EvalKey
    """

@overload
def DeserializeEvalMultKeyString(data: str, sertype: SERJSON) -> None:
    """DeserializeEvalMultKeyString(*args, **kwargs)
    Overloaded function.

    1. DeserializeEvalMultKeyString(data: str, sertype: openfhe.openfhe.SERJSON) -> None

    2. DeserializeEvalMultKeyString(bytes: bytes, sertype: openfhe.openfhe.SERBINARY) -> None
    """

@overload
def DeserializeEvalMultKeyString(bytes: bytes, sertype: SERBINARY) -> None:
    """DeserializeEvalMultKeyString(*args, **kwargs)
    Overloaded function.

    1. DeserializeEvalMultKeyString(data: str, sertype: openfhe.openfhe.SERJSON) -> None

    2. DeserializeEvalMultKeyString(bytes: bytes, sertype: openfhe.openfhe.SERBINARY) -> None
    """

@overload
def DeserializePrivateKey(filename: str, sertype: SERJSON) -> tuple[PrivateKey, bool]:
    """DeserializePrivateKey(*args, **kwargs)
    Overloaded function.

    1. DeserializePrivateKey(filename: str, sertype: openfhe.openfhe.SERJSON) -> tuple[openfhe.openfhe.PrivateKey, bool]

    2. DeserializePrivateKey(filename: str, sertype: openfhe.openfhe.SERBINARY) -> tuple[openfhe.openfhe.PrivateKey, bool]
    """

@overload
def DeserializePrivateKey(filename: str, sertype: SERBINARY) -> tuple[PrivateKey, bool]:
    """DeserializePrivateKey(*args, **kwargs)
    Overloaded function.

    1. DeserializePrivateKey(filename: str, sertype: openfhe.openfhe.SERJSON) -> tuple[openfhe.openfhe.PrivateKey, bool]

    2. DeserializePrivateKey(filename: str, sertype: openfhe.openfhe.SERBINARY) -> tuple[openfhe.openfhe.PrivateKey, bool]
    """

@overload
def DeserializePrivateKeyString(str: str, sertype: SERJSON) -> PrivateKey:
    """DeserializePrivateKeyString(*args, **kwargs)
    Overloaded function.

    1. DeserializePrivateKeyString(str: str, sertype: openfhe.openfhe.SERJSON) -> openfhe.openfhe.PrivateKey

    2. DeserializePrivateKeyString(str: bytes, sertype: openfhe.openfhe.SERBINARY) -> openfhe.openfhe.PrivateKey
    """

@overload
def DeserializePrivateKeyString(str: bytes, sertype: SERBINARY) -> PrivateKey:
    """DeserializePrivateKeyString(*args, **kwargs)
    Overloaded function.

    1. DeserializePrivateKeyString(str: str, sertype: openfhe.openfhe.SERJSON) -> openfhe.openfhe.PrivateKey

    2. DeserializePrivateKeyString(str: bytes, sertype: openfhe.openfhe.SERBINARY) -> openfhe.openfhe.PrivateKey
    """

@overload
def DeserializePublicKey(filename: str, sertype: SERJSON) -> tuple[PublicKey, bool]:
    """DeserializePublicKey(*args, **kwargs)
    Overloaded function.

    1. DeserializePublicKey(filename: str, sertype: openfhe.openfhe.SERJSON) -> tuple[openfhe.openfhe.PublicKey, bool]

    2. DeserializePublicKey(filename: str, sertype: openfhe.openfhe.SERBINARY) -> tuple[openfhe.openfhe.PublicKey, bool]
    """

@overload
def DeserializePublicKey(filename: str, sertype: SERBINARY) -> tuple[PublicKey, bool]:
    """DeserializePublicKey(*args, **kwargs)
    Overloaded function.

    1. DeserializePublicKey(filename: str, sertype: openfhe.openfhe.SERJSON) -> tuple[openfhe.openfhe.PublicKey, bool]

    2. DeserializePublicKey(filename: str, sertype: openfhe.openfhe.SERBINARY) -> tuple[openfhe.openfhe.PublicKey, bool]
    """

@overload
def DeserializePublicKeyString(str: str, sertype: SERJSON) -> PublicKey:
    """DeserializePublicKeyString(*args, **kwargs)
    Overloaded function.

    1. DeserializePublicKeyString(str: str, sertype: openfhe.openfhe.SERJSON) -> openfhe.openfhe.PublicKey

    2. DeserializePublicKeyString(str: bytes, sertype: openfhe.openfhe.SERBINARY) -> openfhe.openfhe.PublicKey
    """

@overload
def DeserializePublicKeyString(str: bytes, sertype: SERBINARY) -> PublicKey:
    """DeserializePublicKeyString(*args, **kwargs)
    Overloaded function.

    1. DeserializePublicKeyString(str: str, sertype: openfhe.openfhe.SERJSON) -> openfhe.openfhe.PublicKey

    2. DeserializePublicKeyString(str: bytes, sertype: openfhe.openfhe.SERBINARY) -> openfhe.openfhe.PublicKey
    """

def DisablePrecomputeCRTTablesAfterDeserializaton() -> None:
    """DisablePrecomputeCRTTablesAfterDeserializaton() -> None

    Disable CRT precomputation after deserialization
    """

def EnablePrecomputeCRTTablesAfterDeserializaton() -> None:
    """EnablePrecomputeCRTTablesAfterDeserializaton() -> None

    Enable CRT precomputation after deserialization
    """

@overload
def GenCryptoContext(params: CCParamsBFVRNS) -> CryptoContext:
    """GenCryptoContext(*args, **kwargs)
    Overloaded function.

    1. GenCryptoContext(params: openfhe.openfhe.CCParamsBFVRNS) -> openfhe.openfhe.CryptoContext

    2. GenCryptoContext(params: openfhe.openfhe.CCParamsBGVRNS) -> openfhe.openfhe.CryptoContext

    3. GenCryptoContext(params: openfhe.openfhe.CCParamsCKKSRNS) -> openfhe.openfhe.CryptoContext
    """

@overload
def GenCryptoContext(params: CCParamsBGVRNS) -> CryptoContext:
    """GenCryptoContext(*args, **kwargs)
    Overloaded function.

    1. GenCryptoContext(params: openfhe.openfhe.CCParamsBFVRNS) -> openfhe.openfhe.CryptoContext

    2. GenCryptoContext(params: openfhe.openfhe.CCParamsBGVRNS) -> openfhe.openfhe.CryptoContext

    3. GenCryptoContext(params: openfhe.openfhe.CCParamsCKKSRNS) -> openfhe.openfhe.CryptoContext
    """

@overload
def GenCryptoContext(params: CCParamsCKKSRNS) -> CryptoContext:
    """GenCryptoContext(*args, **kwargs)
    Overloaded function.

    1. GenCryptoContext(params: openfhe.openfhe.CCParamsBFVRNS) -> openfhe.openfhe.CryptoContext

    2. GenCryptoContext(params: openfhe.openfhe.CCParamsBGVRNS) -> openfhe.openfhe.CryptoContext

    3. GenCryptoContext(params: openfhe.openfhe.CCParamsCKKSRNS) -> openfhe.openfhe.CryptoContext
    """

def GetAllContexts() -> list[CryptoContext]:
    """GetAllContexts() -> list[openfhe.openfhe.CryptoContext]"""

def ReleaseAllContexts() -> None:
    """ReleaseAllContexts() -> None"""

@overload
def Serialize(obj: CryptoContext, sertype: SERJSON) -> str:
    """Serialize(*args, **kwargs)
    Overloaded function.

    1. Serialize(obj: openfhe.openfhe.CryptoContext, sertype: openfhe.openfhe.SERJSON) -> str

    2. Serialize(obj: openfhe.openfhe.PublicKey, sertype: openfhe.openfhe.SERJSON) -> str

    3. Serialize(obj: openfhe.openfhe.PrivateKey, sertype: openfhe.openfhe.SERJSON) -> str

    4. Serialize(obj: openfhe.openfhe.Ciphertext, sertype: openfhe.openfhe.SERJSON) -> str

    5. Serialize(obj: openfhe.openfhe.EvalKey, sertype: openfhe.openfhe.SERJSON) -> str

    6. Serialize(obj: openfhe.openfhe.EvalKeyMap, sertype: openfhe.openfhe.SERJSON) -> bytes

    7. Serialize(obj: openfhe.openfhe.CryptoContext, sertype: openfhe.openfhe.SERBINARY) -> bytes

    8. Serialize(obj: openfhe.openfhe.PublicKey, sertype: openfhe.openfhe.SERBINARY) -> bytes

    9. Serialize(obj: openfhe.openfhe.PrivateKey, sertype: openfhe.openfhe.SERBINARY) -> bytes

    10. Serialize(obj: openfhe.openfhe.Ciphertext, sertype: openfhe.openfhe.SERBINARY) -> bytes

    11. Serialize(obj: openfhe.openfhe.EvalKey, sertype: openfhe.openfhe.SERBINARY) -> bytes

    12. Serialize(obj: openfhe.openfhe.EvalKeyMap, sertype: openfhe.openfhe.SERBINARY) -> bytes

    13. Serialize(obj: collections.abc.Sequence[openfhe.openfhe.EvalKey], sertype: openfhe.openfhe.SERBINARY) -> bytes
    """

@overload
def Serialize(obj: PublicKey, sertype: SERJSON) -> str:
    """Serialize(*args, **kwargs)
    Overloaded function.

    1. Serialize(obj: openfhe.openfhe.CryptoContext, sertype: openfhe.openfhe.SERJSON) -> str

    2. Serialize(obj: openfhe.openfhe.PublicKey, sertype: openfhe.openfhe.SERJSON) -> str

    3. Serialize(obj: openfhe.openfhe.PrivateKey, sertype: openfhe.openfhe.SERJSON) -> str

    4. Serialize(obj: openfhe.openfhe.Ciphertext, sertype: openfhe.openfhe.SERJSON) -> str

    5. Serialize(obj: openfhe.openfhe.EvalKey, sertype: openfhe.openfhe.SERJSON) -> str

    6. Serialize(obj: openfhe.openfhe.EvalKeyMap, sertype: openfhe.openfhe.SERJSON) -> bytes

    7. Serialize(obj: openfhe.openfhe.CryptoContext, sertype: openfhe.openfhe.SERBINARY) -> bytes

    8. Serialize(obj: openfhe.openfhe.PublicKey, sertype: openfhe.openfhe.SERBINARY) -> bytes

    9. Serialize(obj: openfhe.openfhe.PrivateKey, sertype: openfhe.openfhe.SERBINARY) -> bytes

    10. Serialize(obj: openfhe.openfhe.Ciphertext, sertype: openfhe.openfhe.SERBINARY) -> bytes

    11. Serialize(obj: openfhe.openfhe.EvalKey, sertype: openfhe.openfhe.SERBINARY) -> bytes

    12. Serialize(obj: openfhe.openfhe.EvalKeyMap, sertype: openfhe.openfhe.SERBINARY) -> bytes

    13. Serialize(obj: collections.abc.Sequence[openfhe.openfhe.EvalKey], sertype: openfhe.openfhe.SERBINARY) -> bytes
    """

@overload
def Serialize(obj: PrivateKey, sertype: SERJSON) -> str:
    """Serialize(*args, **kwargs)
    Overloaded function.

    1. Serialize(obj: openfhe.openfhe.CryptoContext, sertype: openfhe.openfhe.SERJSON) -> str

    2. Serialize(obj: openfhe.openfhe.PublicKey, sertype: openfhe.openfhe.SERJSON) -> str

    3. Serialize(obj: openfhe.openfhe.PrivateKey, sertype: openfhe.openfhe.SERJSON) -> str

    4. Serialize(obj: openfhe.openfhe.Ciphertext, sertype: openfhe.openfhe.SERJSON) -> str

    5. Serialize(obj: openfhe.openfhe.EvalKey, sertype: openfhe.openfhe.SERJSON) -> str

    6. Serialize(obj: openfhe.openfhe.EvalKeyMap, sertype: openfhe.openfhe.SERJSON) -> bytes

    7. Serialize(obj: openfhe.openfhe.CryptoContext, sertype: openfhe.openfhe.SERBINARY) -> bytes

    8. Serialize(obj: openfhe.openfhe.PublicKey, sertype: openfhe.openfhe.SERBINARY) -> bytes

    9. Serialize(obj: openfhe.openfhe.PrivateKey, sertype: openfhe.openfhe.SERBINARY) -> bytes

    10. Serialize(obj: openfhe.openfhe.Ciphertext, sertype: openfhe.openfhe.SERBINARY) -> bytes

    11. Serialize(obj: openfhe.openfhe.EvalKey, sertype: openfhe.openfhe.SERBINARY) -> bytes

    12. Serialize(obj: openfhe.openfhe.EvalKeyMap, sertype: openfhe.openfhe.SERBINARY) -> bytes

    13. Serialize(obj: collections.abc.Sequence[openfhe.openfhe.EvalKey], sertype: openfhe.openfhe.SERBINARY) -> bytes
    """

@overload
def Serialize(obj: Ciphertext, sertype: SERJSON) -> str:
    """Serialize(*args, **kwargs)
    Overloaded function.

    1. Serialize(obj: openfhe.openfhe.CryptoContext, sertype: openfhe.openfhe.SERJSON) -> str

    2. Serialize(obj: openfhe.openfhe.PublicKey, sertype: openfhe.openfhe.SERJSON) -> str

    3. Serialize(obj: openfhe.openfhe.PrivateKey, sertype: openfhe.openfhe.SERJSON) -> str

    4. Serialize(obj: openfhe.openfhe.Ciphertext, sertype: openfhe.openfhe.SERJSON) -> str

    5. Serialize(obj: openfhe.openfhe.EvalKey, sertype: openfhe.openfhe.SERJSON) -> str

    6. Serialize(obj: openfhe.openfhe.EvalKeyMap, sertype: openfhe.openfhe.SERJSON) -> bytes

    7. Serialize(obj: openfhe.openfhe.CryptoContext, sertype: openfhe.openfhe.SERBINARY) -> bytes

    8. Serialize(obj: openfhe.openfhe.PublicKey, sertype: openfhe.openfhe.SERBINARY) -> bytes

    9. Serialize(obj: openfhe.openfhe.PrivateKey, sertype: openfhe.openfhe.SERBINARY) -> bytes

    10. Serialize(obj: openfhe.openfhe.Ciphertext, sertype: openfhe.openfhe.SERBINARY) -> bytes

    11. Serialize(obj: openfhe.openfhe.EvalKey, sertype: openfhe.openfhe.SERBINARY) -> bytes

    12. Serialize(obj: openfhe.openfhe.EvalKeyMap, sertype: openfhe.openfhe.SERBINARY) -> bytes

    13. Serialize(obj: collections.abc.Sequence[openfhe.openfhe.EvalKey], sertype: openfhe.openfhe.SERBINARY) -> bytes
    """

@overload
def Serialize(obj: EvalKey, sertype: SERJSON) -> str:
    """Serialize(*args, **kwargs)
    Overloaded function.

    1. Serialize(obj: openfhe.openfhe.CryptoContext, sertype: openfhe.openfhe.SERJSON) -> str

    2. Serialize(obj: openfhe.openfhe.PublicKey, sertype: openfhe.openfhe.SERJSON) -> str

    3. Serialize(obj: openfhe.openfhe.PrivateKey, sertype: openfhe.openfhe.SERJSON) -> str

    4. Serialize(obj: openfhe.openfhe.Ciphertext, sertype: openfhe.openfhe.SERJSON) -> str

    5. Serialize(obj: openfhe.openfhe.EvalKey, sertype: openfhe.openfhe.SERJSON) -> str

    6. Serialize(obj: openfhe.openfhe.EvalKeyMap, sertype: openfhe.openfhe.SERJSON) -> bytes

    7. Serialize(obj: openfhe.openfhe.CryptoContext, sertype: openfhe.openfhe.SERBINARY) -> bytes

    8. Serialize(obj: openfhe.openfhe.PublicKey, sertype: openfhe.openfhe.SERBINARY) -> bytes

    9. Serialize(obj: openfhe.openfhe.PrivateKey, sertype: openfhe.openfhe.SERBINARY) -> bytes

    10. Serialize(obj: openfhe.openfhe.Ciphertext, sertype: openfhe.openfhe.SERBINARY) -> bytes

    11. Serialize(obj: openfhe.openfhe.EvalKey, sertype: openfhe.openfhe.SERBINARY) -> bytes

    12. Serialize(obj: openfhe.openfhe.EvalKeyMap, sertype: openfhe.openfhe.SERBINARY) -> bytes

    13. Serialize(obj: collections.abc.Sequence[openfhe.openfhe.EvalKey], sertype: openfhe.openfhe.SERBINARY) -> bytes
    """

@overload
def Serialize(obj: EvalKeyMap, sertype: SERJSON) -> bytes:
    """Serialize(*args, **kwargs)
    Overloaded function.

    1. Serialize(obj: openfhe.openfhe.CryptoContext, sertype: openfhe.openfhe.SERJSON) -> str

    2. Serialize(obj: openfhe.openfhe.PublicKey, sertype: openfhe.openfhe.SERJSON) -> str

    3. Serialize(obj: openfhe.openfhe.PrivateKey, sertype: openfhe.openfhe.SERJSON) -> str

    4. Serialize(obj: openfhe.openfhe.Ciphertext, sertype: openfhe.openfhe.SERJSON) -> str

    5. Serialize(obj: openfhe.openfhe.EvalKey, sertype: openfhe.openfhe.SERJSON) -> str

    6. Serialize(obj: openfhe.openfhe.EvalKeyMap, sertype: openfhe.openfhe.SERJSON) -> bytes

    7. Serialize(obj: openfhe.openfhe.CryptoContext, sertype: openfhe.openfhe.SERBINARY) -> bytes

    8. Serialize(obj: openfhe.openfhe.PublicKey, sertype: openfhe.openfhe.SERBINARY) -> bytes

    9. Serialize(obj: openfhe.openfhe.PrivateKey, sertype: openfhe.openfhe.SERBINARY) -> bytes

    10. Serialize(obj: openfhe.openfhe.Ciphertext, sertype: openfhe.openfhe.SERBINARY) -> bytes

    11. Serialize(obj: openfhe.openfhe.EvalKey, sertype: openfhe.openfhe.SERBINARY) -> bytes

    12. Serialize(obj: openfhe.openfhe.EvalKeyMap, sertype: openfhe.openfhe.SERBINARY) -> bytes

    13. Serialize(obj: collections.abc.Sequence[openfhe.openfhe.EvalKey], sertype: openfhe.openfhe.SERBINARY) -> bytes
    """

@overload
def Serialize(obj: CryptoContext, sertype: SERBINARY) -> bytes:
    """Serialize(*args, **kwargs)
    Overloaded function.

    1. Serialize(obj: openfhe.openfhe.CryptoContext, sertype: openfhe.openfhe.SERJSON) -> str

    2. Serialize(obj: openfhe.openfhe.PublicKey, sertype: openfhe.openfhe.SERJSON) -> str

    3. Serialize(obj: openfhe.openfhe.PrivateKey, sertype: openfhe.openfhe.SERJSON) -> str

    4. Serialize(obj: openfhe.openfhe.Ciphertext, sertype: openfhe.openfhe.SERJSON) -> str

    5. Serialize(obj: openfhe.openfhe.EvalKey, sertype: openfhe.openfhe.SERJSON) -> str

    6. Serialize(obj: openfhe.openfhe.EvalKeyMap, sertype: openfhe.openfhe.SERJSON) -> bytes

    7. Serialize(obj: openfhe.openfhe.CryptoContext, sertype: openfhe.openfhe.SERBINARY) -> bytes

    8. Serialize(obj: openfhe.openfhe.PublicKey, sertype: openfhe.openfhe.SERBINARY) -> bytes

    9. Serialize(obj: openfhe.openfhe.PrivateKey, sertype: openfhe.openfhe.SERBINARY) -> bytes

    10. Serialize(obj: openfhe.openfhe.Ciphertext, sertype: openfhe.openfhe.SERBINARY) -> bytes

    11. Serialize(obj: openfhe.openfhe.EvalKey, sertype: openfhe.openfhe.SERBINARY) -> bytes

    12. Serialize(obj: openfhe.openfhe.EvalKeyMap, sertype: openfhe.openfhe.SERBINARY) -> bytes

    13. Serialize(obj: collections.abc.Sequence[openfhe.openfhe.EvalKey], sertype: openfhe.openfhe.SERBINARY) -> bytes
    """

@overload
def Serialize(obj: PublicKey, sertype: SERBINARY) -> bytes:
    """Serialize(*args, **kwargs)
    Overloaded function.

    1. Serialize(obj: openfhe.openfhe.CryptoContext, sertype: openfhe.openfhe.SERJSON) -> str

    2. Serialize(obj: openfhe.openfhe.PublicKey, sertype: openfhe.openfhe.SERJSON) -> str

    3. Serialize(obj: openfhe.openfhe.PrivateKey, sertype: openfhe.openfhe.SERJSON) -> str

    4. Serialize(obj: openfhe.openfhe.Ciphertext, sertype: openfhe.openfhe.SERJSON) -> str

    5. Serialize(obj: openfhe.openfhe.EvalKey, sertype: openfhe.openfhe.SERJSON) -> str

    6. Serialize(obj: openfhe.openfhe.EvalKeyMap, sertype: openfhe.openfhe.SERJSON) -> bytes

    7. Serialize(obj: openfhe.openfhe.CryptoContext, sertype: openfhe.openfhe.SERBINARY) -> bytes

    8. Serialize(obj: openfhe.openfhe.PublicKey, sertype: openfhe.openfhe.SERBINARY) -> bytes

    9. Serialize(obj: openfhe.openfhe.PrivateKey, sertype: openfhe.openfhe.SERBINARY) -> bytes

    10. Serialize(obj: openfhe.openfhe.Ciphertext, sertype: openfhe.openfhe.SERBINARY) -> bytes

    11. Serialize(obj: openfhe.openfhe.EvalKey, sertype: openfhe.openfhe.SERBINARY) -> bytes

    12. Serialize(obj: openfhe.openfhe.EvalKeyMap, sertype: openfhe.openfhe.SERBINARY) -> bytes

    13. Serialize(obj: collections.abc.Sequence[openfhe.openfhe.EvalKey], sertype: openfhe.openfhe.SERBINARY) -> bytes
    """

@overload
def Serialize(obj: PrivateKey, sertype: SERBINARY) -> bytes:
    """Serialize(*args, **kwargs)
    Overloaded function.

    1. Serialize(obj: openfhe.openfhe.CryptoContext, sertype: openfhe.openfhe.SERJSON) -> str

    2. Serialize(obj: openfhe.openfhe.PublicKey, sertype: openfhe.openfhe.SERJSON) -> str

    3. Serialize(obj: openfhe.openfhe.PrivateKey, sertype: openfhe.openfhe.SERJSON) -> str

    4. Serialize(obj: openfhe.openfhe.Ciphertext, sertype: openfhe.openfhe.SERJSON) -> str

    5. Serialize(obj: openfhe.openfhe.EvalKey, sertype: openfhe.openfhe.SERJSON) -> str

    6. Serialize(obj: openfhe.openfhe.EvalKeyMap, sertype: openfhe.openfhe.SERJSON) -> bytes

    7. Serialize(obj: openfhe.openfhe.CryptoContext, sertype: openfhe.openfhe.SERBINARY) -> bytes

    8. Serialize(obj: openfhe.openfhe.PublicKey, sertype: openfhe.openfhe.SERBINARY) -> bytes

    9. Serialize(obj: openfhe.openfhe.PrivateKey, sertype: openfhe.openfhe.SERBINARY) -> bytes

    10. Serialize(obj: openfhe.openfhe.Ciphertext, sertype: openfhe.openfhe.SERBINARY) -> bytes

    11. Serialize(obj: openfhe.openfhe.EvalKey, sertype: openfhe.openfhe.SERBINARY) -> bytes

    12. Serialize(obj: openfhe.openfhe.EvalKeyMap, sertype: openfhe.openfhe.SERBINARY) -> bytes

    13. Serialize(obj: collections.abc.Sequence[openfhe.openfhe.EvalKey], sertype: openfhe.openfhe.SERBINARY) -> bytes
    """

@overload
def Serialize(obj: Ciphertext, sertype: SERBINARY) -> bytes:
    """Serialize(*args, **kwargs)
    Overloaded function.

    1. Serialize(obj: openfhe.openfhe.CryptoContext, sertype: openfhe.openfhe.SERJSON) -> str

    2. Serialize(obj: openfhe.openfhe.PublicKey, sertype: openfhe.openfhe.SERJSON) -> str

    3. Serialize(obj: openfhe.openfhe.PrivateKey, sertype: openfhe.openfhe.SERJSON) -> str

    4. Serialize(obj: openfhe.openfhe.Ciphertext, sertype: openfhe.openfhe.SERJSON) -> str

    5. Serialize(obj: openfhe.openfhe.EvalKey, sertype: openfhe.openfhe.SERJSON) -> str

    6. Serialize(obj: openfhe.openfhe.EvalKeyMap, sertype: openfhe.openfhe.SERJSON) -> bytes

    7. Serialize(obj: openfhe.openfhe.CryptoContext, sertype: openfhe.openfhe.SERBINARY) -> bytes

    8. Serialize(obj: openfhe.openfhe.PublicKey, sertype: openfhe.openfhe.SERBINARY) -> bytes

    9. Serialize(obj: openfhe.openfhe.PrivateKey, sertype: openfhe.openfhe.SERBINARY) -> bytes

    10. Serialize(obj: openfhe.openfhe.Ciphertext, sertype: openfhe.openfhe.SERBINARY) -> bytes

    11. Serialize(obj: openfhe.openfhe.EvalKey, sertype: openfhe.openfhe.SERBINARY) -> bytes

    12. Serialize(obj: openfhe.openfhe.EvalKeyMap, sertype: openfhe.openfhe.SERBINARY) -> bytes

    13. Serialize(obj: collections.abc.Sequence[openfhe.openfhe.EvalKey], sertype: openfhe.openfhe.SERBINARY) -> bytes
    """

@overload
def Serialize(obj: EvalKey, sertype: SERBINARY) -> bytes:
    """Serialize(*args, **kwargs)
    Overloaded function.

    1. Serialize(obj: openfhe.openfhe.CryptoContext, sertype: openfhe.openfhe.SERJSON) -> str

    2. Serialize(obj: openfhe.openfhe.PublicKey, sertype: openfhe.openfhe.SERJSON) -> str

    3. Serialize(obj: openfhe.openfhe.PrivateKey, sertype: openfhe.openfhe.SERJSON) -> str

    4. Serialize(obj: openfhe.openfhe.Ciphertext, sertype: openfhe.openfhe.SERJSON) -> str

    5. Serialize(obj: openfhe.openfhe.EvalKey, sertype: openfhe.openfhe.SERJSON) -> str

    6. Serialize(obj: openfhe.openfhe.EvalKeyMap, sertype: openfhe.openfhe.SERJSON) -> bytes

    7. Serialize(obj: openfhe.openfhe.CryptoContext, sertype: openfhe.openfhe.SERBINARY) -> bytes

    8. Serialize(obj: openfhe.openfhe.PublicKey, sertype: openfhe.openfhe.SERBINARY) -> bytes

    9. Serialize(obj: openfhe.openfhe.PrivateKey, sertype: openfhe.openfhe.SERBINARY) -> bytes

    10. Serialize(obj: openfhe.openfhe.Ciphertext, sertype: openfhe.openfhe.SERBINARY) -> bytes

    11. Serialize(obj: openfhe.openfhe.EvalKey, sertype: openfhe.openfhe.SERBINARY) -> bytes

    12. Serialize(obj: openfhe.openfhe.EvalKeyMap, sertype: openfhe.openfhe.SERBINARY) -> bytes

    13. Serialize(obj: collections.abc.Sequence[openfhe.openfhe.EvalKey], sertype: openfhe.openfhe.SERBINARY) -> bytes
    """

@overload
def Serialize(obj: EvalKeyMap, sertype: SERBINARY) -> bytes:
    """Serialize(*args, **kwargs)
    Overloaded function.

    1. Serialize(obj: openfhe.openfhe.CryptoContext, sertype: openfhe.openfhe.SERJSON) -> str

    2. Serialize(obj: openfhe.openfhe.PublicKey, sertype: openfhe.openfhe.SERJSON) -> str

    3. Serialize(obj: openfhe.openfhe.PrivateKey, sertype: openfhe.openfhe.SERJSON) -> str

    4. Serialize(obj: openfhe.openfhe.Ciphertext, sertype: openfhe.openfhe.SERJSON) -> str

    5. Serialize(obj: openfhe.openfhe.EvalKey, sertype: openfhe.openfhe.SERJSON) -> str

    6. Serialize(obj: openfhe.openfhe.EvalKeyMap, sertype: openfhe.openfhe.SERJSON) -> bytes

    7. Serialize(obj: openfhe.openfhe.CryptoContext, sertype: openfhe.openfhe.SERBINARY) -> bytes

    8. Serialize(obj: openfhe.openfhe.PublicKey, sertype: openfhe.openfhe.SERBINARY) -> bytes

    9. Serialize(obj: openfhe.openfhe.PrivateKey, sertype: openfhe.openfhe.SERBINARY) -> bytes

    10. Serialize(obj: openfhe.openfhe.Ciphertext, sertype: openfhe.openfhe.SERBINARY) -> bytes

    11. Serialize(obj: openfhe.openfhe.EvalKey, sertype: openfhe.openfhe.SERBINARY) -> bytes

    12. Serialize(obj: openfhe.openfhe.EvalKeyMap, sertype: openfhe.openfhe.SERBINARY) -> bytes

    13. Serialize(obj: collections.abc.Sequence[openfhe.openfhe.EvalKey], sertype: openfhe.openfhe.SERBINARY) -> bytes
    """

@overload
def Serialize(obj: collections.abc.Sequence[EvalKey], sertype: SERBINARY) -> bytes:
    """Serialize(*args, **kwargs)
    Overloaded function.

    1. Serialize(obj: openfhe.openfhe.CryptoContext, sertype: openfhe.openfhe.SERJSON) -> str

    2. Serialize(obj: openfhe.openfhe.PublicKey, sertype: openfhe.openfhe.SERJSON) -> str

    3. Serialize(obj: openfhe.openfhe.PrivateKey, sertype: openfhe.openfhe.SERJSON) -> str

    4. Serialize(obj: openfhe.openfhe.Ciphertext, sertype: openfhe.openfhe.SERJSON) -> str

    5. Serialize(obj: openfhe.openfhe.EvalKey, sertype: openfhe.openfhe.SERJSON) -> str

    6. Serialize(obj: openfhe.openfhe.EvalKeyMap, sertype: openfhe.openfhe.SERJSON) -> bytes

    7. Serialize(obj: openfhe.openfhe.CryptoContext, sertype: openfhe.openfhe.SERBINARY) -> bytes

    8. Serialize(obj: openfhe.openfhe.PublicKey, sertype: openfhe.openfhe.SERBINARY) -> bytes

    9. Serialize(obj: openfhe.openfhe.PrivateKey, sertype: openfhe.openfhe.SERBINARY) -> bytes

    10. Serialize(obj: openfhe.openfhe.Ciphertext, sertype: openfhe.openfhe.SERBINARY) -> bytes

    11. Serialize(obj: openfhe.openfhe.EvalKey, sertype: openfhe.openfhe.SERBINARY) -> bytes

    12. Serialize(obj: openfhe.openfhe.EvalKeyMap, sertype: openfhe.openfhe.SERBINARY) -> bytes

    13. Serialize(obj: collections.abc.Sequence[openfhe.openfhe.EvalKey], sertype: openfhe.openfhe.SERBINARY) -> bytes
    """

@overload
def SerializeEvalAutomorphismKeyString(sertype: SERJSON, keyTag: str = ...) -> str:
    """SerializeEvalAutomorphismKeyString(*args, **kwargs)
    Overloaded function.

    1. SerializeEvalAutomorphismKeyString(sertype: openfhe.openfhe.SERJSON, keyTag: str = '') -> str

    2. SerializeEvalAutomorphismKeyString(sertype: openfhe.openfhe.SERBINARY, keyTag: str = '') -> bytes
    """

@overload
def SerializeEvalAutomorphismKeyString(sertype: SERBINARY, keyTag: str = ...) -> bytes:
    """SerializeEvalAutomorphismKeyString(*args, **kwargs)
    Overloaded function.

    1. SerializeEvalAutomorphismKeyString(sertype: openfhe.openfhe.SERJSON, keyTag: str = '') -> str

    2. SerializeEvalAutomorphismKeyString(sertype: openfhe.openfhe.SERBINARY, keyTag: str = '') -> bytes
    """

@overload
def SerializeEvalMultKeyString(sertype: SERJSON, keyTag: str = ...) -> str:
    """SerializeEvalMultKeyString(*args, **kwargs)
    Overloaded function.

    1. SerializeEvalMultKeyString(sertype: openfhe.openfhe.SERJSON, keyTag: str = '') -> str

    2. SerializeEvalMultKeyString(sertype: openfhe.openfhe.SERBINARY, keyTag: str = '') -> bytes
    """

@overload
def SerializeEvalMultKeyString(sertype: SERBINARY, keyTag: str = ...) -> bytes:
    """SerializeEvalMultKeyString(*args, **kwargs)
    Overloaded function.

    1. SerializeEvalMultKeyString(sertype: openfhe.openfhe.SERJSON, keyTag: str = '') -> str

    2. SerializeEvalMultKeyString(sertype: openfhe.openfhe.SERBINARY, keyTag: str = '') -> bytes
    """

@overload
def SerializeToFile(filename: str, obj: CryptoContext, sertype: SERJSON) -> bool:
    """SerializeToFile(*args, **kwargs)
    Overloaded function.

    1. SerializeToFile(filename: str, obj: openfhe.openfhe.CryptoContext, sertype: openfhe.openfhe.SERJSON) -> bool

    2. SerializeToFile(filename: str, obj: openfhe.openfhe.PublicKey, sertype: openfhe.openfhe.SERJSON) -> bool

    3. SerializeToFile(filename: str, obj: openfhe.openfhe.PrivateKey, sertype: openfhe.openfhe.SERJSON) -> bool

    4. SerializeToFile(filename: str, obj: openfhe.openfhe.Ciphertext, sertype: openfhe.openfhe.SERJSON) -> bool

    5. SerializeToFile(filename: str, obj: openfhe.openfhe.EvalKey, sertype: openfhe.openfhe.SERJSON) -> bool

    6. SerializeToFile(filename: str, obj: openfhe.openfhe.EvalKeyMap, sertype: openfhe.openfhe.SERJSON) -> bool

    7. SerializeToFile(filename: str, obj: openfhe.openfhe.CryptoContext, sertype: openfhe.openfhe.SERBINARY) -> bool

    8. SerializeToFile(filename: str, obj: openfhe.openfhe.PublicKey, sertype: openfhe.openfhe.SERBINARY) -> bool

    9. SerializeToFile(filename: str, obj: openfhe.openfhe.PrivateKey, sertype: openfhe.openfhe.SERBINARY) -> bool

    10. SerializeToFile(filename: str, obj: openfhe.openfhe.Ciphertext, sertype: openfhe.openfhe.SERBINARY) -> bool

    11. SerializeToFile(filename: str, obj: openfhe.openfhe.EvalKey, sertype: openfhe.openfhe.SERBINARY) -> bool

    12. SerializeToFile(filename: str, obj: openfhe.openfhe.EvalKeyMap, sertype: openfhe.openfhe.SERBINARY) -> bool
    """

@overload
def SerializeToFile(filename: str, obj: PublicKey, sertype: SERJSON) -> bool:
    """SerializeToFile(*args, **kwargs)
    Overloaded function.

    1. SerializeToFile(filename: str, obj: openfhe.openfhe.CryptoContext, sertype: openfhe.openfhe.SERJSON) -> bool

    2. SerializeToFile(filename: str, obj: openfhe.openfhe.PublicKey, sertype: openfhe.openfhe.SERJSON) -> bool

    3. SerializeToFile(filename: str, obj: openfhe.openfhe.PrivateKey, sertype: openfhe.openfhe.SERJSON) -> bool

    4. SerializeToFile(filename: str, obj: openfhe.openfhe.Ciphertext, sertype: openfhe.openfhe.SERJSON) -> bool

    5. SerializeToFile(filename: str, obj: openfhe.openfhe.EvalKey, sertype: openfhe.openfhe.SERJSON) -> bool

    6. SerializeToFile(filename: str, obj: openfhe.openfhe.EvalKeyMap, sertype: openfhe.openfhe.SERJSON) -> bool

    7. SerializeToFile(filename: str, obj: openfhe.openfhe.CryptoContext, sertype: openfhe.openfhe.SERBINARY) -> bool

    8. SerializeToFile(filename: str, obj: openfhe.openfhe.PublicKey, sertype: openfhe.openfhe.SERBINARY) -> bool

    9. SerializeToFile(filename: str, obj: openfhe.openfhe.PrivateKey, sertype: openfhe.openfhe.SERBINARY) -> bool

    10. SerializeToFile(filename: str, obj: openfhe.openfhe.Ciphertext, sertype: openfhe.openfhe.SERBINARY) -> bool

    11. SerializeToFile(filename: str, obj: openfhe.openfhe.EvalKey, sertype: openfhe.openfhe.SERBINARY) -> bool

    12. SerializeToFile(filename: str, obj: openfhe.openfhe.EvalKeyMap, sertype: openfhe.openfhe.SERBINARY) -> bool
    """

@overload
def SerializeToFile(filename: str, obj: PrivateKey, sertype: SERJSON) -> bool:
    """SerializeToFile(*args, **kwargs)
    Overloaded function.

    1. SerializeToFile(filename: str, obj: openfhe.openfhe.CryptoContext, sertype: openfhe.openfhe.SERJSON) -> bool

    2. SerializeToFile(filename: str, obj: openfhe.openfhe.PublicKey, sertype: openfhe.openfhe.SERJSON) -> bool

    3. SerializeToFile(filename: str, obj: openfhe.openfhe.PrivateKey, sertype: openfhe.openfhe.SERJSON) -> bool

    4. SerializeToFile(filename: str, obj: openfhe.openfhe.Ciphertext, sertype: openfhe.openfhe.SERJSON) -> bool

    5. SerializeToFile(filename: str, obj: openfhe.openfhe.EvalKey, sertype: openfhe.openfhe.SERJSON) -> bool

    6. SerializeToFile(filename: str, obj: openfhe.openfhe.EvalKeyMap, sertype: openfhe.openfhe.SERJSON) -> bool

    7. SerializeToFile(filename: str, obj: openfhe.openfhe.CryptoContext, sertype: openfhe.openfhe.SERBINARY) -> bool

    8. SerializeToFile(filename: str, obj: openfhe.openfhe.PublicKey, sertype: openfhe.openfhe.SERBINARY) -> bool

    9. SerializeToFile(filename: str, obj: openfhe.openfhe.PrivateKey, sertype: openfhe.openfhe.SERBINARY) -> bool

    10. SerializeToFile(filename: str, obj: openfhe.openfhe.Ciphertext, sertype: openfhe.openfhe.SERBINARY) -> bool

    11. SerializeToFile(filename: str, obj: openfhe.openfhe.EvalKey, sertype: openfhe.openfhe.SERBINARY) -> bool

    12. SerializeToFile(filename: str, obj: openfhe.openfhe.EvalKeyMap, sertype: openfhe.openfhe.SERBINARY) -> bool
    """

@overload
def SerializeToFile(filename: str, obj: Ciphertext, sertype: SERJSON) -> bool:
    """SerializeToFile(*args, **kwargs)
    Overloaded function.

    1. SerializeToFile(filename: str, obj: openfhe.openfhe.CryptoContext, sertype: openfhe.openfhe.SERJSON) -> bool

    2. SerializeToFile(filename: str, obj: openfhe.openfhe.PublicKey, sertype: openfhe.openfhe.SERJSON) -> bool

    3. SerializeToFile(filename: str, obj: openfhe.openfhe.PrivateKey, sertype: openfhe.openfhe.SERJSON) -> bool

    4. SerializeToFile(filename: str, obj: openfhe.openfhe.Ciphertext, sertype: openfhe.openfhe.SERJSON) -> bool

    5. SerializeToFile(filename: str, obj: openfhe.openfhe.EvalKey, sertype: openfhe.openfhe.SERJSON) -> bool

    6. SerializeToFile(filename: str, obj: openfhe.openfhe.EvalKeyMap, sertype: openfhe.openfhe.SERJSON) -> bool

    7. SerializeToFile(filename: str, obj: openfhe.openfhe.CryptoContext, sertype: openfhe.openfhe.SERBINARY) -> bool

    8. SerializeToFile(filename: str, obj: openfhe.openfhe.PublicKey, sertype: openfhe.openfhe.SERBINARY) -> bool

    9. SerializeToFile(filename: str, obj: openfhe.openfhe.PrivateKey, sertype: openfhe.openfhe.SERBINARY) -> bool

    10. SerializeToFile(filename: str, obj: openfhe.openfhe.Ciphertext, sertype: openfhe.openfhe.SERBINARY) -> bool

    11. SerializeToFile(filename: str, obj: openfhe.openfhe.EvalKey, sertype: openfhe.openfhe.SERBINARY) -> bool

    12. SerializeToFile(filename: str, obj: openfhe.openfhe.EvalKeyMap, sertype: openfhe.openfhe.SERBINARY) -> bool
    """

@overload
def SerializeToFile(filename: str, obj: EvalKey, sertype: SERJSON) -> bool:
    """SerializeToFile(*args, **kwargs)
    Overloaded function.

    1. SerializeToFile(filename: str, obj: openfhe.openfhe.CryptoContext, sertype: openfhe.openfhe.SERJSON) -> bool

    2. SerializeToFile(filename: str, obj: openfhe.openfhe.PublicKey, sertype: openfhe.openfhe.SERJSON) -> bool

    3. SerializeToFile(filename: str, obj: openfhe.openfhe.PrivateKey, sertype: openfhe.openfhe.SERJSON) -> bool

    4. SerializeToFile(filename: str, obj: openfhe.openfhe.Ciphertext, sertype: openfhe.openfhe.SERJSON) -> bool

    5. SerializeToFile(filename: str, obj: openfhe.openfhe.EvalKey, sertype: openfhe.openfhe.SERJSON) -> bool

    6. SerializeToFile(filename: str, obj: openfhe.openfhe.EvalKeyMap, sertype: openfhe.openfhe.SERJSON) -> bool

    7. SerializeToFile(filename: str, obj: openfhe.openfhe.CryptoContext, sertype: openfhe.openfhe.SERBINARY) -> bool

    8. SerializeToFile(filename: str, obj: openfhe.openfhe.PublicKey, sertype: openfhe.openfhe.SERBINARY) -> bool

    9. SerializeToFile(filename: str, obj: openfhe.openfhe.PrivateKey, sertype: openfhe.openfhe.SERBINARY) -> bool

    10. SerializeToFile(filename: str, obj: openfhe.openfhe.Ciphertext, sertype: openfhe.openfhe.SERBINARY) -> bool

    11. SerializeToFile(filename: str, obj: openfhe.openfhe.EvalKey, sertype: openfhe.openfhe.SERBINARY) -> bool

    12. SerializeToFile(filename: str, obj: openfhe.openfhe.EvalKeyMap, sertype: openfhe.openfhe.SERBINARY) -> bool
    """

@overload
def SerializeToFile(filename: str, obj: EvalKeyMap, sertype: SERJSON) -> bool:
    """SerializeToFile(*args, **kwargs)
    Overloaded function.

    1. SerializeToFile(filename: str, obj: openfhe.openfhe.CryptoContext, sertype: openfhe.openfhe.SERJSON) -> bool

    2. SerializeToFile(filename: str, obj: openfhe.openfhe.PublicKey, sertype: openfhe.openfhe.SERJSON) -> bool

    3. SerializeToFile(filename: str, obj: openfhe.openfhe.PrivateKey, sertype: openfhe.openfhe.SERJSON) -> bool

    4. SerializeToFile(filename: str, obj: openfhe.openfhe.Ciphertext, sertype: openfhe.openfhe.SERJSON) -> bool

    5. SerializeToFile(filename: str, obj: openfhe.openfhe.EvalKey, sertype: openfhe.openfhe.SERJSON) -> bool

    6. SerializeToFile(filename: str, obj: openfhe.openfhe.EvalKeyMap, sertype: openfhe.openfhe.SERJSON) -> bool

    7. SerializeToFile(filename: str, obj: openfhe.openfhe.CryptoContext, sertype: openfhe.openfhe.SERBINARY) -> bool

    8. SerializeToFile(filename: str, obj: openfhe.openfhe.PublicKey, sertype: openfhe.openfhe.SERBINARY) -> bool

    9. SerializeToFile(filename: str, obj: openfhe.openfhe.PrivateKey, sertype: openfhe.openfhe.SERBINARY) -> bool

    10. SerializeToFile(filename: str, obj: openfhe.openfhe.Ciphertext, sertype: openfhe.openfhe.SERBINARY) -> bool

    11. SerializeToFile(filename: str, obj: openfhe.openfhe.EvalKey, sertype: openfhe.openfhe.SERBINARY) -> bool

    12. SerializeToFile(filename: str, obj: openfhe.openfhe.EvalKeyMap, sertype: openfhe.openfhe.SERBINARY) -> bool
    """

@overload
def SerializeToFile(filename: str, obj: CryptoContext, sertype: SERBINARY) -> bool:
    """SerializeToFile(*args, **kwargs)
    Overloaded function.

    1. SerializeToFile(filename: str, obj: openfhe.openfhe.CryptoContext, sertype: openfhe.openfhe.SERJSON) -> bool

    2. SerializeToFile(filename: str, obj: openfhe.openfhe.PublicKey, sertype: openfhe.openfhe.SERJSON) -> bool

    3. SerializeToFile(filename: str, obj: openfhe.openfhe.PrivateKey, sertype: openfhe.openfhe.SERJSON) -> bool

    4. SerializeToFile(filename: str, obj: openfhe.openfhe.Ciphertext, sertype: openfhe.openfhe.SERJSON) -> bool

    5. SerializeToFile(filename: str, obj: openfhe.openfhe.EvalKey, sertype: openfhe.openfhe.SERJSON) -> bool

    6. SerializeToFile(filename: str, obj: openfhe.openfhe.EvalKeyMap, sertype: openfhe.openfhe.SERJSON) -> bool

    7. SerializeToFile(filename: str, obj: openfhe.openfhe.CryptoContext, sertype: openfhe.openfhe.SERBINARY) -> bool

    8. SerializeToFile(filename: str, obj: openfhe.openfhe.PublicKey, sertype: openfhe.openfhe.SERBINARY) -> bool

    9. SerializeToFile(filename: str, obj: openfhe.openfhe.PrivateKey, sertype: openfhe.openfhe.SERBINARY) -> bool

    10. SerializeToFile(filename: str, obj: openfhe.openfhe.Ciphertext, sertype: openfhe.openfhe.SERBINARY) -> bool

    11. SerializeToFile(filename: str, obj: openfhe.openfhe.EvalKey, sertype: openfhe.openfhe.SERBINARY) -> bool

    12. SerializeToFile(filename: str, obj: openfhe.openfhe.EvalKeyMap, sertype: openfhe.openfhe.SERBINARY) -> bool
    """

@overload
def SerializeToFile(filename: str, obj: PublicKey, sertype: SERBINARY) -> bool:
    """SerializeToFile(*args, **kwargs)
    Overloaded function.

    1. SerializeToFile(filename: str, obj: openfhe.openfhe.CryptoContext, sertype: openfhe.openfhe.SERJSON) -> bool

    2. SerializeToFile(filename: str, obj: openfhe.openfhe.PublicKey, sertype: openfhe.openfhe.SERJSON) -> bool

    3. SerializeToFile(filename: str, obj: openfhe.openfhe.PrivateKey, sertype: openfhe.openfhe.SERJSON) -> bool

    4. SerializeToFile(filename: str, obj: openfhe.openfhe.Ciphertext, sertype: openfhe.openfhe.SERJSON) -> bool

    5. SerializeToFile(filename: str, obj: openfhe.openfhe.EvalKey, sertype: openfhe.openfhe.SERJSON) -> bool

    6. SerializeToFile(filename: str, obj: openfhe.openfhe.EvalKeyMap, sertype: openfhe.openfhe.SERJSON) -> bool

    7. SerializeToFile(filename: str, obj: openfhe.openfhe.CryptoContext, sertype: openfhe.openfhe.SERBINARY) -> bool

    8. SerializeToFile(filename: str, obj: openfhe.openfhe.PublicKey, sertype: openfhe.openfhe.SERBINARY) -> bool

    9. SerializeToFile(filename: str, obj: openfhe.openfhe.PrivateKey, sertype: openfhe.openfhe.SERBINARY) -> bool

    10. SerializeToFile(filename: str, obj: openfhe.openfhe.Ciphertext, sertype: openfhe.openfhe.SERBINARY) -> bool

    11. SerializeToFile(filename: str, obj: openfhe.openfhe.EvalKey, sertype: openfhe.openfhe.SERBINARY) -> bool

    12. SerializeToFile(filename: str, obj: openfhe.openfhe.EvalKeyMap, sertype: openfhe.openfhe.SERBINARY) -> bool
    """

@overload
def SerializeToFile(filename: str, obj: PrivateKey, sertype: SERBINARY) -> bool:
    """SerializeToFile(*args, **kwargs)
    Overloaded function.

    1. SerializeToFile(filename: str, obj: openfhe.openfhe.CryptoContext, sertype: openfhe.openfhe.SERJSON) -> bool

    2. SerializeToFile(filename: str, obj: openfhe.openfhe.PublicKey, sertype: openfhe.openfhe.SERJSON) -> bool

    3. SerializeToFile(filename: str, obj: openfhe.openfhe.PrivateKey, sertype: openfhe.openfhe.SERJSON) -> bool

    4. SerializeToFile(filename: str, obj: openfhe.openfhe.Ciphertext, sertype: openfhe.openfhe.SERJSON) -> bool

    5. SerializeToFile(filename: str, obj: openfhe.openfhe.EvalKey, sertype: openfhe.openfhe.SERJSON) -> bool

    6. SerializeToFile(filename: str, obj: openfhe.openfhe.EvalKeyMap, sertype: openfhe.openfhe.SERJSON) -> bool

    7. SerializeToFile(filename: str, obj: openfhe.openfhe.CryptoContext, sertype: openfhe.openfhe.SERBINARY) -> bool

    8. SerializeToFile(filename: str, obj: openfhe.openfhe.PublicKey, sertype: openfhe.openfhe.SERBINARY) -> bool

    9. SerializeToFile(filename: str, obj: openfhe.openfhe.PrivateKey, sertype: openfhe.openfhe.SERBINARY) -> bool

    10. SerializeToFile(filename: str, obj: openfhe.openfhe.Ciphertext, sertype: openfhe.openfhe.SERBINARY) -> bool

    11. SerializeToFile(filename: str, obj: openfhe.openfhe.EvalKey, sertype: openfhe.openfhe.SERBINARY) -> bool

    12. SerializeToFile(filename: str, obj: openfhe.openfhe.EvalKeyMap, sertype: openfhe.openfhe.SERBINARY) -> bool
    """

@overload
def SerializeToFile(filename: str, obj: Ciphertext, sertype: SERBINARY) -> bool:
    """SerializeToFile(*args, **kwargs)
    Overloaded function.

    1. SerializeToFile(filename: str, obj: openfhe.openfhe.CryptoContext, sertype: openfhe.openfhe.SERJSON) -> bool

    2. SerializeToFile(filename: str, obj: openfhe.openfhe.PublicKey, sertype: openfhe.openfhe.SERJSON) -> bool

    3. SerializeToFile(filename: str, obj: openfhe.openfhe.PrivateKey, sertype: openfhe.openfhe.SERJSON) -> bool

    4. SerializeToFile(filename: str, obj: openfhe.openfhe.Ciphertext, sertype: openfhe.openfhe.SERJSON) -> bool

    5. SerializeToFile(filename: str, obj: openfhe.openfhe.EvalKey, sertype: openfhe.openfhe.SERJSON) -> bool

    6. SerializeToFile(filename: str, obj: openfhe.openfhe.EvalKeyMap, sertype: openfhe.openfhe.SERJSON) -> bool

    7. SerializeToFile(filename: str, obj: openfhe.openfhe.CryptoContext, sertype: openfhe.openfhe.SERBINARY) -> bool

    8. SerializeToFile(filename: str, obj: openfhe.openfhe.PublicKey, sertype: openfhe.openfhe.SERBINARY) -> bool

    9. SerializeToFile(filename: str, obj: openfhe.openfhe.PrivateKey, sertype: openfhe.openfhe.SERBINARY) -> bool

    10. SerializeToFile(filename: str, obj: openfhe.openfhe.Ciphertext, sertype: openfhe.openfhe.SERBINARY) -> bool

    11. SerializeToFile(filename: str, obj: openfhe.openfhe.EvalKey, sertype: openfhe.openfhe.SERBINARY) -> bool

    12. SerializeToFile(filename: str, obj: openfhe.openfhe.EvalKeyMap, sertype: openfhe.openfhe.SERBINARY) -> bool
    """

@overload
def SerializeToFile(filename: str, obj: EvalKey, sertype: SERBINARY) -> bool:
    """SerializeToFile(*args, **kwargs)
    Overloaded function.

    1. SerializeToFile(filename: str, obj: openfhe.openfhe.CryptoContext, sertype: openfhe.openfhe.SERJSON) -> bool

    2. SerializeToFile(filename: str, obj: openfhe.openfhe.PublicKey, sertype: openfhe.openfhe.SERJSON) -> bool

    3. SerializeToFile(filename: str, obj: openfhe.openfhe.PrivateKey, sertype: openfhe.openfhe.SERJSON) -> bool

    4. SerializeToFile(filename: str, obj: openfhe.openfhe.Ciphertext, sertype: openfhe.openfhe.SERJSON) -> bool

    5. SerializeToFile(filename: str, obj: openfhe.openfhe.EvalKey, sertype: openfhe.openfhe.SERJSON) -> bool

    6. SerializeToFile(filename: str, obj: openfhe.openfhe.EvalKeyMap, sertype: openfhe.openfhe.SERJSON) -> bool

    7. SerializeToFile(filename: str, obj: openfhe.openfhe.CryptoContext, sertype: openfhe.openfhe.SERBINARY) -> bool

    8. SerializeToFile(filename: str, obj: openfhe.openfhe.PublicKey, sertype: openfhe.openfhe.SERBINARY) -> bool

    9. SerializeToFile(filename: str, obj: openfhe.openfhe.PrivateKey, sertype: openfhe.openfhe.SERBINARY) -> bool

    10. SerializeToFile(filename: str, obj: openfhe.openfhe.Ciphertext, sertype: openfhe.openfhe.SERBINARY) -> bool

    11. SerializeToFile(filename: str, obj: openfhe.openfhe.EvalKey, sertype: openfhe.openfhe.SERBINARY) -> bool

    12. SerializeToFile(filename: str, obj: openfhe.openfhe.EvalKeyMap, sertype: openfhe.openfhe.SERBINARY) -> bool
    """

@overload
def SerializeToFile(filename: str, obj: EvalKeyMap, sertype: SERBINARY) -> bool:
    """SerializeToFile(*args, **kwargs)
    Overloaded function.

    1. SerializeToFile(filename: str, obj: openfhe.openfhe.CryptoContext, sertype: openfhe.openfhe.SERJSON) -> bool

    2. SerializeToFile(filename: str, obj: openfhe.openfhe.PublicKey, sertype: openfhe.openfhe.SERJSON) -> bool

    3. SerializeToFile(filename: str, obj: openfhe.openfhe.PrivateKey, sertype: openfhe.openfhe.SERJSON) -> bool

    4. SerializeToFile(filename: str, obj: openfhe.openfhe.Ciphertext, sertype: openfhe.openfhe.SERJSON) -> bool

    5. SerializeToFile(filename: str, obj: openfhe.openfhe.EvalKey, sertype: openfhe.openfhe.SERJSON) -> bool

    6. SerializeToFile(filename: str, obj: openfhe.openfhe.EvalKeyMap, sertype: openfhe.openfhe.SERJSON) -> bool

    7. SerializeToFile(filename: str, obj: openfhe.openfhe.CryptoContext, sertype: openfhe.openfhe.SERBINARY) -> bool

    8. SerializeToFile(filename: str, obj: openfhe.openfhe.PublicKey, sertype: openfhe.openfhe.SERBINARY) -> bool

    9. SerializeToFile(filename: str, obj: openfhe.openfhe.PrivateKey, sertype: openfhe.openfhe.SERBINARY) -> bool

    10. SerializeToFile(filename: str, obj: openfhe.openfhe.Ciphertext, sertype: openfhe.openfhe.SERBINARY) -> bool

    11. SerializeToFile(filename: str, obj: openfhe.openfhe.EvalKey, sertype: openfhe.openfhe.SERBINARY) -> bool

    12. SerializeToFile(filename: str, obj: openfhe.openfhe.EvalKeyMap, sertype: openfhe.openfhe.SERBINARY) -> bool
    """

def get_native_int() -> int:
    """get_native_int() -> int"""
