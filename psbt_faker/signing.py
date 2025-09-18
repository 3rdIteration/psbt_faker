"""Utilities for signing and finalizing PSBTs produced by psbt_faker."""

from __future__ import annotations

import hashlib
import io
import struct
import unicodedata
from dataclasses import dataclass
from typing import Iterable, List, Optional, Tuple

from ecdsa import SECP256k1, SigningKey
from ecdsa.util import sigencode_der_canonize

from .bip32 import BIP32Node, HARDENED
from .ctransaction import (
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
    hash256,
)
from .psbt import (
    BasicPSBT,
    BasicPSBTInput,
    PSBT_IN_FINAL_SCRIPTSIG,
    PSBT_IN_FINAL_SCRIPTWITNESS,
)
from .serialize import ser_string, ser_string_vector, uint256_from_str

SIGHASH_ALL = 0x01


class SigningError(Exception):
    """Raised when a PSBT cannot be signed with the provided material."""


@dataclass
class _InputSigningInfo:
    """Book-keeping for each input that is signed."""

    pubkey: bytes
    script_type: str
    redeem_script: Optional[bytes]
    signature: bytes


def mnemonic_to_seed(mnemonic: str, passphrase: str = "") -> bytes:
    """Convert a BIP39 mnemonic into a binary seed."""

    normalized_mnemonic = unicodedata.normalize("NFKD", " ".join(mnemonic.strip().split()))
    normalized_passphrase = unicodedata.normalize("NFKD", passphrase or "")
    salt = "mnemonic" + normalized_passphrase
    return hashlib.pbkdf2_hmac(
        "sha512",
        normalized_mnemonic.encode("utf-8"),
        salt.encode("utf-8"),
        2048,
    )


def derive_signing_node(
    *,
    mnemonic: Optional[str] = None,
    passphrase: str = "",
    xprv: Optional[str] = None,
    netcode: str = "XTN",
    root_path: Optional[str] = None,
) -> BIP32Node:
    """Create a ``BIP32Node`` suitable for signing."""

    if mnemonic and xprv:
        raise SigningError("Provide either a mnemonic or an extended private key, not both.")
    if not mnemonic and not xprv:
        raise SigningError("Signing requires a mnemonic or an extended private key.")

    if mnemonic:
        seed = mnemonic_to_seed(mnemonic, passphrase)
        node = BIP32Node.from_master_secret(seed, netcode=netcode)
    else:
        node = BIP32Node.from_wallet_key(xprv)  # type: ignore[arg-type]

    if root_path:
        trimmed = root_path.strip()
        if trimmed.startswith("m/"):
            trimmed = trimmed[2:]
        trimmed = trimmed.strip("/")
        if trimmed:
            node = node.subkey_for_path(trimmed)
    return node


def sign_psbt(psbt: BasicPSBT, signing_root: BIP32Node, *, finalize: bool = True) -> Tuple[BasicPSBT, Optional[CTransaction]]:
    """Add signatures to a :class:`BasicPSBT` using the provided signing root."""

    tx = _psbt_to_transaction(psbt)
    if len(tx.vin) != len(psbt.inputs):
        raise SigningError("Mismatch between transaction inputs and PSBT inputs")

    hash_prevouts = _hash_prevouts(tx)
    hash_sequence = _hash_sequence(tx)
    hash_outputs = _hash_outputs(tx)

    input_infos: List[_InputSigningInfo] = []

    for idx, (psbt_input, txin) in enumerate(zip(psbt.inputs, tx.vin)):
        pubkey, path_bytes = _extract_bip32_path(psbt_input)
        fingerprint, path = _parse_derivation(path_bytes)
        if fingerprint != signing_root.node.fingerprint():
            raise SigningError(
                f"Signing key fingerprint {signing_root.node.fingerprint().hex()} does not match input {idx}"
            )

        derived = _derive_from_path(signing_root, path)
        derived_pubkey = derived.sec()
        if derived_pubkey != pubkey:
            raise SigningError(f"Derived pubkey does not match PSBT key for input {idx}")

        utxo = _extract_prev_output(psbt_input, txin)
        script_type, script_code, redeem_script = _classify_input(psbt_input, utxo.scriptPubKey)

        if script_type in {"p2wpkh", "p2wpkh-p2sh"}:
            sighash = _calc_bip143_sighash(
                tx,
                idx,
                script_code,
                utxo.nValue,
                hash_prevouts,
                hash_sequence,
                hash_outputs,
            )
        elif script_type == "p2pkh":
            sighash = _calc_legacy_sighash(tx, idx, script_code)
        else:
            raise SigningError(f"Unsupported script type for signing: {script_type}")

        signature = _sign_digest(derived.privkey(), sighash)
        psbt_input.part_sigs[pubkey] = signature
        psbt_input.sighash = SIGHASH_ALL
        input_infos.append(_InputSigningInfo(pubkey, script_type, redeem_script, signature))

    final_tx: Optional[CTransaction] = None
    if finalize:
        final_tx = _finalize_inputs(psbt, tx, input_infos)

    psbt.parsed_txn = tx
    return psbt, final_tx


def _psbt_to_transaction(psbt: BasicPSBT) -> CTransaction:
    if psbt.parsed_txn is not None:
        return CTransaction(psbt.parsed_txn)

    tx = CTransaction()
    tx.nVersion = psbt.txn_version or 2
    tx.nLockTime = psbt.fallback_locktime or 0
    tx.vin = []
    for psbt_input in psbt.inputs:
        prev_hash = uint256_from_str(psbt_input.previous_txid) if psbt_input.previous_txid else 0
        prev_index = psbt_input.prevout_idx if psbt_input.prevout_idx is not None else 0
        outpoint = COutPoint(prev_hash, prev_index)
        sequence = psbt_input.sequence if psbt_input.sequence is not None else 0xFFFFFFFF
        tx.vin.append(CTxIn(outpoint, nSequence=sequence))
    tx.vout = []
    for psbt_output in psbt.outputs:
        amount = psbt_output.amount if psbt_output.amount is not None else 0
        script = psbt_output.script if psbt_output.script is not None else b""
        tx.vout.append(CTxOut(amount, script))
    tx.wit.vtxinwit = [CTxInWitness() for _ in tx.vin]
    return tx


def _extract_prev_output(psbt_input: BasicPSBTInput, txin: CTxIn) -> CTxOut:
    if psbt_input.witness_utxo:
        fd = io.BytesIO(psbt_input.witness_utxo)
        out = CTxOut()
        out.deserialize(fd)
        return out
    if psbt_input.utxo:
        prev_tx = CTransaction()
        prev_tx.deserialize(io.BytesIO(psbt_input.utxo))
        return prev_tx.vout[txin.prevout.n]
    raise SigningError("Missing UTXO data for PSBT input")


def _extract_bip32_path(psbt_input: BasicPSBTInput) -> Tuple[bytes, bytes]:
    if not psbt_input.bip32_paths:
        raise SigningError("PSBT input is missing BIP32 derivation data")
    pubkey, path = next(iter(psbt_input.bip32_paths.items()))
    return pubkey, path


def _parse_derivation(data: bytes) -> Tuple[bytes, List[int]]:
    if len(data) < 4 or (len(data) - 4) % 4:
        raise SigningError("Invalid BIP32 derivation path encoding")
    fingerprint = data[:4]
    path: List[int] = []
    if len(data) > 4:
        count = (len(data) - 4) // 4
        path = list(struct.unpack(f"<{count}I", data[4:]))
    return fingerprint, path


def _derive_from_path(node: BIP32Node, path: Iterable[int]) -> BIP32Node:
    current = node
    for index in path:
        if index & HARDENED:
            current = current.subkey_for_path(f"{index - HARDENED}h")
        else:
            current = current.subkey_for_path(str(index))
    return current


def _classify_input(psbt_input: BasicPSBTInput, script_pubkey: bytes) -> Tuple[str, bytes, Optional[bytes]]:
    if psbt_input.redeem_script and psbt_input.redeem_script.startswith(b"\x00\x14"):
        redeem = psbt_input.redeem_script
        return "p2wpkh-p2sh", _script_code_for_p2wpkh(redeem), redeem

    if script_pubkey.startswith(b"\x00\x14"):
        return "p2wpkh", _script_code_for_p2wpkh(script_pubkey), None

    if script_pubkey.startswith(b"\x76\xa9\x14") and script_pubkey.endswith(b"\x88\xac"):
        return "p2pkh", script_pubkey, None

    raise SigningError("Unsupported script type in UTXO")


def _script_code_for_p2wpkh(program: bytes) -> bytes:
    if len(program) != 22:
        raise SigningError("Unexpected witness program length for p2wpkh")
    return b"\x19\x76\xa9\x14" + program[2:] + b"\x88\xac"


def _hash_prevouts(tx: CTransaction) -> bytes:
    data = b"".join(inp.prevout.serialize() for inp in tx.vin)
    return hash256(data)


def _hash_sequence(tx: CTransaction) -> bytes:
    data = b"".join(struct.pack("<I", inp.nSequence) for inp in tx.vin)
    return hash256(data)


def _hash_outputs(tx: CTransaction) -> bytes:
    data = b"".join(out.serialize() for out in tx.vout)
    return hash256(data)


def _calc_bip143_sighash(
    tx: CTransaction,
    input_index: int,
    script_code: bytes,
    amount: int,
    hash_prevouts: bytes,
    hash_sequence: bytes,
    hash_outputs: bytes,
) -> bytes:
    txin = tx.vin[input_index]
    preimage = (
        struct.pack("<I", tx.nVersion)
        + hash_prevouts
        + hash_sequence
        + txin.prevout.serialize()
        + ser_string(script_code)
        + struct.pack("<q", amount)
        + struct.pack("<I", txin.nSequence)
        + hash_outputs
        + struct.pack("<I", tx.nLockTime)
        + struct.pack("<I", SIGHASH_ALL)
    )
    return hash256(preimage)


def _calc_legacy_sighash(tx: CTransaction, input_index: int, script_code: bytes) -> bytes:
    tx_copy = CTransaction(tx)
    for i, txin in enumerate(tx_copy.vin):
        txin.scriptSig = script_code if i == input_index else b""
    serialized = tx_copy.serialize() + struct.pack("<I", SIGHASH_ALL)
    return hash256(serialized)


def _sign_digest(privkey_bytes: bytes, digest: bytes) -> bytes:
    sk = SigningKey.from_string(privkey_bytes, curve=SECP256k1)
    signature = sk.sign_digest(digest, sigencode=sigencode_der_canonize)
    return signature + bytes([SIGHASH_ALL])


def _push_data(data: bytes) -> bytes:
    length = len(data)
    if length < 0x4C:
        return bytes([length]) + data
    if length <= 0xFF:
        return b"\x4c" + bytes([length]) + data
    if length <= 0xFFFF:
        return b"\x4d" + struct.pack("<H", length) + data
    return b"\x4e" + struct.pack("<I", length) + data


def _finalize_inputs(
    psbt: BasicPSBT,
    tx: CTransaction,
    input_infos: List[_InputSigningInfo],
) -> CTransaction:
    if len(tx.wit.vtxinwit) != len(tx.vin):
        tx.wit.vtxinwit = [CTxInWitness() for _ in tx.vin]

    for idx, (psbt_input, info) in enumerate(zip(psbt.inputs, input_infos)):
        if info.script_type == "p2pkh":
            script_sig = _push_data(info.signature) + _push_data(info.pubkey)
            tx.vin[idx].scriptSig = script_sig
            psbt_input.others[PSBT_IN_FINAL_SCRIPTSIG] = script_sig
        else:
            witness = [info.signature, info.pubkey]
            tx.wit.vtxinwit[idx].scriptWitness.stack = witness
            psbt_input.others[PSBT_IN_FINAL_SCRIPTWITNESS] = ser_string_vector(witness)
            if info.script_type == "p2wpkh-p2sh":
                assert info.redeem_script is not None
                script_sig = _push_data(info.redeem_script)
                tx.vin[idx].scriptSig = script_sig
                psbt_input.others[PSBT_IN_FINAL_SCRIPTSIG] = script_sig
            else:
                tx.vin[idx].scriptSig = b""

    return tx


__all__ = [
    "SigningError",
    "SIGHASH_ALL",
    "derive_signing_node",
    "mnemonic_to_seed",
    "sign_psbt",
]
