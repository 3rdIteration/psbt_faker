#!/usr/bin/env python3
#
# To use this, install with:
#
#   pip install --editable .
#
# That will create the command "psbt_faker" in your path... or just use "./main.py ..." here
#
#
import click
from binascii import b2a_hex as _b2a_hex
from base64 import b64encode
from decimal import Decimal
from .txn import fake_ms_txn, fake_txn, ADDR_STYLES
from .multisig import from_simple_text
from .psbt import BasicPSBT
from .signing import derive_signing_node, sign_psbt, SigningError

b2a_hex = lambda a: str(_b2a_hex(a), 'ascii')
#xfp2hex = lambda a: b2a_hex(a[::-1]).upper()

SIM_XPUB = 'tpubD6NzVbkrYhZ4XzL5Dhayo67Gorv1YMS7j8pRUvVMd5odC2LBPLAygka9p7748JtSq82FNGPppFEz5xxZUdasBRCqJqXvUHq6xpnsMcYJzeh'


@click.command()
@click.argument('out_psbt', type=click.File('wb'), metavar="OUTPUT.PSBT")
@click.argument('xpub', type=str, default=SIM_XPUB)
@click.option('--num-ins', '-i', help="Number of inputs (default 1)", default=1)
@click.option('--num-outs', '-o', help="Number of all txn outputs (default 2)", default=2)
@click.option('--num-change', '-c', help="Number of change outputs (default 1) from num-outs", default=1)
@click.option('--fee', '-f', help="Miner's fee in Satoshis", default=1000)
@click.option('--psbt2', '-2', help="Make PSBTv2", is_flag=True, default=False)
@click.option('--segwit', '-s', help="[SS] Make inputs be segwit style", is_flag=True, default=False)
@click.option('--wrapped', '-w', help="[SS] Make inputs be wrapped segwit style (requires --segwit flag)", is_flag=True, default=False)
@click.option('--styles', '-a',  help="Output address style (multiple ok). If multisig only applies to non-change addresses.", multiple=True, default=None, type=click.Choice(ADDR_STYLES))
@click.option('--base64', '-6', help="Output base64 (default binary)", is_flag=True, default=False)
@click.option('--testnet', '-t', help="Assume testnet4 addresses (default mainnet)", is_flag=True, default=False)
@click.option('--partial', '-p', help="[SS] Change first input so its different XPUB and result cannot be finalized", is_flag=True, default=False)
@click.option('--zero-xfp', '-z', help="[SS] Provide zero XFP and junk XPUB (cannot be signed, but should be decodable)", is_flag=True, default=False)
@click.option('--multisig', '-m', type=click.File('rt'), metavar="config.txt", help="[MS] CC Multisig config file (text)", default=None)
@click.option('--locktime', '-l', help="nLocktime value (default 0), use 'current' to fetch best block height from mempool.space", default="0")
@click.option('--input-amount', '-n', help="Size of each input in sats (default 100k sats each input)", default=100000)
@click.option('--incl-xpubs', '-I',  help="[MS] Include XPUBs in PSBT global section", is_flag=True, default=False)
@click.option('--signing-mnemonic', help="BIP39 mnemonic used to derive signing keys", default=None)
@click.option('--signing-passphrase', help="Optional BIP39 passphrase", default="", show_default=True)
@click.option('--signing-xprv', help="Extended private key used for signing", default=None)
@click.option('--signing-root-path', help="Derivation path applied to the signing key before matching fingerprints", default=None)
@click.option('--signed-psbt', type=click.File('wb'), metavar="SIGNED.PSBT", help="Write the signed PSBT to a separate file", default=None)
@click.option('--final-txn', type=click.File('wb'), metavar="SIGNED.TXN", help="Write the fully signed transaction to this file", default=None)
@click.option('--no-finalize', is_flag=True, help="Add partial signatures without finalizing scripts/witnesses", default=False)
def main(num_ins, num_change, num_outs, out_psbt, testnet, xpub, segwit, fee, styles, base64,
         partial, zero_xfp, multisig, locktime, input_amount, psbt2, incl_xpubs, wrapped,
         signing_mnemonic, signing_passphrase, signing_xprv, signing_root_path,
         signed_psbt, final_txn, no_finalize):
    '''Construct a valid PSBT which spends non-existant BTC to random addresses!'''

    if locktime == "current":
        try:
            import urllib.request
            u = urllib.request.urlopen("https://mempool.space/api/blocks/tip/height")
            locktime = int(u.read().decode())
        except:
            locktime = 0
    else:
        locktime = int(locktime)

    if multisig:
        ms_config = multisig.read()
        name, af, keys, M, N = from_simple_text(ms_config.split("\n"))
        psbt, outs = fake_ms_txn(num_ins, num_outs, M, keys, fee=fee, locktime=locktime,
                                 change_outputs=list(range(num_change)), outstyles=styles,
                                 input_amount=input_amount, psbt_v2=psbt2, change_af=af,
                                 incl_xpubs=incl_xpubs, is_testnet=testnet)
    else:
        if zero_xfp:
            xpub = None

        psbt, outs = fake_txn(num_ins, num_outs, master_xpub=xpub, fee=fee,
                              segwit_in=segwit, outstyles=styles, locktime=locktime,
                              partial=partial, is_testnet=testnet, wrapped=wrapped,
                              change_outputs=list(range(num_change)),
                              psbt_v2=psbt2, input_amount=input_amount)

    signing_requested = bool(signing_mnemonic or signing_xprv)
    if signing_root_path and not signing_requested:
        raise click.UsageError('--signing-root-path requires signing credentials')
    if signed_psbt and not signing_requested:
        raise click.UsageError('--signed-psbt requires signing credentials')
    if final_txn and not signing_requested:
        raise click.UsageError('--final-txn requires signing credentials')
    if no_finalize and not signing_requested:
        raise click.UsageError('--no-finalize is only applicable when signing')
    if signing_mnemonic and signing_xprv:
        raise click.UsageError('Provide either --signing-mnemonic or --signing-xprv, not both')
    if final_txn and no_finalize:
        raise click.UsageError('--final-txn cannot be used together with --no-finalize')

    signed_bytes = None
    final_tx_bytes = None
    final_tx_obj = None

    if signing_requested:
        netcode = 'XTN' if testnet else 'BTC'
        try:
            signing_node = derive_signing_node(
                mnemonic=signing_mnemonic,
                passphrase=signing_passphrase,
                xprv=signing_xprv,
                netcode=netcode,
                root_path=signing_root_path,
            )
        except SigningError as exc:
            raise click.ClickException(str(exc)) from exc

        psbt_obj = BasicPSBT()
        psbt_obj.parse(psbt)
        try:
            psbt_obj, final_tx_obj = sign_psbt(psbt_obj, signing_node, finalize=not no_finalize)
        except SigningError as exc:
            raise click.ClickException(str(exc)) from exc
        signed_bytes = psbt_obj.as_bytes()
        if final_tx_obj is not None:
            final_tx_bytes = final_tx_obj.serialize_with_witness()

    def _write_psbt(handle, payload):
        handle.write(b64encode(payload) if base64 else payload)

    if signing_requested:
        if signed_psbt:
            _write_psbt(out_psbt, psbt)
            _write_psbt(signed_psbt, signed_bytes)
        else:
            _write_psbt(out_psbt, signed_bytes)
    else:
        _write_psbt(out_psbt, psbt)

    if signing_requested and final_txn and final_tx_bytes is not None:
        final_txn.write(final_tx_bytes)

    print(f"\nFake PSBT would send {((num_ins*input_amount)/Decimal(1E8))} BTC to: ")
    print('\n'.join(" %.8f => %s %s" % (Decimal(amt)/Decimal(1E8),dest, ' (change back)' if chg else '')
                                                                for amt,dest,chg in outs))
    if fee:
        print(" %.8f => miners fee" % (Decimal(fee)/Decimal(1E8)))

    if signing_requested:
        if signed_psbt:
            print(f"\nUnsigned PSBT written to {out_psbt.name}")
            print(f"Signed PSBT written to {signed_psbt.name}")
        else:
            print(f"\nSigned PSBT written to {out_psbt.name}")
        if final_txn and final_tx_bytes is not None:
            print(f"Final transaction written to {final_txn.name}")
        elif final_tx_obj is not None:
            txid = final_tx_obj.calc_sha256(with_witness=True)
            if txid is not None:
                print(f"Final transaction txid: {txid:064x}")
        print()
    else:
        print("\nPSBT to be signed: " + out_psbt.name, end='\n\n')


if __name__ == '__main__':
    main()

# EOF
