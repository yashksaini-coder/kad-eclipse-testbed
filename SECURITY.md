# Security policy

## This repository contains attack tooling

`src/attack.rs` grinds peer IDs toward a chosen Kademlia key. That is offensive
capability, and it is here on purpose: the defence cannot be evaluated without
it.

This is not a disclosure of anything novel. Eclipse and Sybil attacks on
Kademlia have been public since at least S/Kademlia (Baumgart & Mies, 2007), and
the specific weakness — that libp2p peer IDs are unconstrained hashes of a
public key, so targeted placement costs only keypair generation — is documented
in the libp2p specifications and analysed in the published literature. Nothing
here tells an attacker something they could not read in a paper.

Do not point this at a network you do not operate or have written permission to
test.

## Reporting a vulnerability in this repository

Open a private security advisory through GitHub's advisory workflow on this
repository. Do not open a public issue for anything you believe to be
exploitable.

## Reporting a vulnerability in libp2p

If the testbed surfaces something that looks like a genuine, previously unknown
weakness in libp2p itself — as opposed to the known class of attack this
repository studies — **it does not get published here first.** Report it through
libp2p's own disclosure process and give maintainers time to respond before any
public writeup.

The distinction that matters: measuring a known attack is research and belongs
in the open. Finding a new one is a disclosure and belongs in a private channel
until it isn't.
