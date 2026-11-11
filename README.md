# Blit attested worker: image sources

This repository holds the source of the machine image that Blit's
zero-knowledge projects run on. It covers every program on those machines that
ever handles a project key or decrypted project data. Use it to check the
machines yourself.

Each commit here matches one published image. The commit's date is the build
date the image was made with, and the tag names the release.

## What your browser checks before it releases a project key

A zero-knowledge run starts on an AWS EC2 instance with NitroTPM. Before your
browser hands over a project key, it asks the machine for a TPM attestation
document that AWS's Nitro hardware has signed. The browser accepts the machine
only if the document shows all of the following.

* **PCR4** equals a published image measurement. PCR4 covers the kernel, the
  initrd and the read-only root of the boot volume. That root holds
  `blit-worker-boot`, the worker, the broker, the job sandbox and the
  processing service (`attested/`, `blitcrypto/`, `utils/run_creds.py`).
* **PCR15** is either untouched or equals a published *engine root*, the
  solver's userspace. The machine measures the engine root before it mounts
  it, and the engine root only ever runs inside the sandbox described below.
* **PCR12** and **PCR13** are untouched. PCR14 names a published commit of
  the solver code.

The published values are in
[`attested-releases.json`](https://www.blit.ai/attested-releases.json). Each
one is also recorded in Sigstore's public transparency log. To check the log
entries, use [`verify.js`](https://www.blit.ai/attested-log/verify.js).

One input isn't measured: the launch settings in the instance's user data.
They name the storage bucket for the machine's encrypted files and the two
secrets it reads (the key that fetches the solver commit, and the AI model
provider's API key). The boot script accepts only plain names and runs
nothing from them (`blit-worker-boot`). They decide where encrypted files go,
not what the machine trusts: the project key is still sealed to the measured
machine, and the solver commit is still measured into PCR14.

## What runs with your key, and what doesn't

The worker, the broker and the processing service hold the key. Their code is
in this repository and is measured into PCR4.

The solver code (the engine root plus the solver commit) is **not** published
here, and it never holds the key:

* it runs as an unprivileged user in its own PID, mount and network
  namespaces, under a seccomp filter;
* it sees no network interface and no TPM;
* its only way out is a Unix socket to the broker, which decrypts what the job
  may read, encrypts everything it writes, and accepts only a fixed set of
  object names inside the project's own folder (`attested/broker.py`).

The processing service runs its functions in containers the same way: no
network, no capabilities, and a read-only root (`attested/sandboxes.py`).

What these machines can't vouch for:

* **The AI Agent.** Messages and attachments you send the AI Agent go to the
  AI model provider so it can answer them (`attested/ai.py`). Using the AI
  Agent is entirely optional: nothing reaches the provider unless you send it.
* **File sizes and timing.** Blit can see how large your encrypted files are
  and when they change, but not what they contain.

## Rebuilding an image

You need an Amazon Linux 2023 x86_64 machine (an EC2 c6i.4xlarge with a
120 GB disk takes about 45 minutes), plus root:

```
dnf install -y kiwi-cli python3-kiwi kiwi-systemdeps-core python3-poetry-core qemu-img \
  veritysetup erofs-utils git aws-nitro-tpm-tools kiwi-image-descriptions-examples rsync
dnf install -y nvidia-release
git clone <this repository> src && cd src && git checkout <release tag>
mkdir -p /root/empty/home/ubuntu
VERIFY=1 bash attested-worker/build.sh check /root/empty
```

The build prints `PCR4: …`. Compare it with the release's `pcr4` in
`attested-releases.json`. The boot volume doesn't depend on the engine root,
so an empty folder in its place leaves PCR4 unchanged. The `engine root:` line
it prints will not match, because it describes the empty folder.

The package repositories are pinned to fixed snapshots
(`attested-worker/image/appliance.kiwi`). The one binary the image carries that
isn't a package is pinned by digest (`attested-worker/image/fetch-assets.sh`).
Every timestamp and every identifier the tools would otherwise draw at random
is derived from the commit date (see the header of `attested-worker/build.sh`).

## Licence

The image description in `attested-worker/image/` is adapted from Amazon
Linux's attestable-image example, under the Apache License 2.0. The rest is
published for review only: copyright Blit, all rights reserved.
