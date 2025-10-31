# (c) Copyright 2025 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Key Teleport protocol re-implementation: CLI for humans (testing purposes only).
#
import click, pyqrcode, json
from bbqr import split_qrs
from pysecp256k1.extrakeys import keypair_create, keypair_sec
from teleport_protocol import (receiver_step1, sender_step1, txt_grouper, stash_encode_secret,
                               stash_decode_secret, receiver_step2)


def show_payload(payload, type_code, title, msg):
    vers, parts = split_qrs(payload, type_code, max_version=5)
    qs = [pyqrcode.create(part, error='L', version=vers, mode='alphanumeric')
          for part in parts]

    for q in qs:
        click.echo(q.terminal())

    click.echo("\nBBQr payload:")
    for p in parts:
        click.echo(p)

    click.echo()
    click.echo(title)
    click.echo(msg)

def show_received(dtype, data):
    if dtype == 's':
        # words / bip 32 master / xprv, etc
        noun, decoded = stash_decode_secret(data)
        print(f"Received {noun} via teleport:\n", decoded)

    elif dtype == 'x':
        # TODO seems can be removed
        # it's an XPRV, but in binary.. some extra data we throw away here; sigh
        # XXX no way to send this .. but was thinking of address explorer
        raise NotImplementedError

    elif dtype == 'p':
        # raw PSBT -- much bigger more complex
        raise NotImplementedError

    elif dtype == 'b':
        # full system backup, including master: text lines
        print("Received backup via Teleport:\n")
        for ln in data.decode().split('\n'):
            if not ln: continue
            print(ln)

    elif dtype == 'v':
        # one key export from a seed vault
        # - watch for incompatibility here if we ever change VaultEntry
        print("Received Seed Vault entry via Teleport:\n", json.loads(data))
    elif dtype == 'n':
        # import secure note(s)
        print("Received secure note(s) via Teleport:\n", json.loads(data))
    else:
        raise ValueError("Unknown type", dtype)

@click.group()
def main():
    pass

@main.command('recv_init')
@click.option('--secret', '-k', type=str, default=None,
              help='Ephemeral private key used to create shared ECDH key')
def recv_init(secret):
    number_pass, enc_pubkey, kp_receiver = receiver_step1(secret=secret)
    msg = (f'To receive sensitive data from another COLDCARD,'
           f'share this Receiver Password with sender:\n\t{number_pass}'
           f'  =  {txt_grouper(number_pass)}')

    show_payload(enc_pubkey, "R", 'Key Teleport: Receive', msg)
    if secret is None:
        # if user haven't specified secret for ECDH keypair dump it to stdout
        # it is needed as second arguemnt to "recv" cmd
        click.echo("Picked ephemeral ECDH key: " + keypair_sec(kp_receiver).hex())

    click.echo()
    # encrypted pubkey payload is first argument to "send" cmd
    click.echo("Encrypted pubkey (payload): " + enc_pubkey.hex())


@main.command('send')
@click.argument('payload', type=str)
@click.option('--secret', '-k', type=str, default=None,
              help='Ephemeral private key used to create shared ECDH key')
@click.option('--password', prompt=True, required=True)
@click.option('--mnemonic', type=str, default=None)
@click.option('--xprv', type=str, default=None)
@click.option('--text', type=str, default=None)
@click.option('--backup', type=click.Path(exists=True), default=None)
def send(payload, secret, password, mnemonic, xprv, text, backup):
    if mnemonic:
        cleartext = b"s" + stash_encode_secret(words=mnemonic)
    elif xprv:
        cleartext = b"s" + stash_encode_secret(xprv=xprv)
    elif text:
        cleartext = b"n" + json.dumps([{"title": "Quick Note", "misc":text}]).encode()
    else:
        assert backup
        out = []
        with open(backup, "r") as f:  # this needs to be cleartext backup
            for ln in f.readlines():
                if not ln: continue
                if ln[0] == '#': continue
                out.append(ln.encode())

        cleartext = b"b" + b'\n'.join(ln for ln in out)

    noid_txt, encrypted_payload, kp_sender, pk_rec = sender_step1(
        password, bytes.fromhex(payload), cleartext, secret=secret
    )
    msg = ("Share this password with the receiver, via some different channel:"
           "\n\n\t%s  =  %s" % (noid_txt, txt_grouper(noid_txt)))
    show_payload(encrypted_payload, "S", 'Teleport Password', msg)

    click.echo()
    # encrypted payload is first arguemnt to "recv" cmd
    click.echo("Encrypted payload: " + encrypted_payload.hex())


@main.command('recv')
@click.argument('payload', type=str)
@click.argument('secret', type=str)
@click.option('--password', prompt=True, required=True)
def recv(payload, secret, password):
    dtype, received = receiver_step2(password.upper(), bytes.fromhex(payload),
                                     keypair_create(bytes.fromhex(secret)))
    click.echo()
    show_received(dtype, received)


if __name__ == "__main__":
    main()

# EOF
