# Getting started with AE-OS Receipts

This guide is for anyone who wants to try AE-OS Receipts, including people who do not write code. It takes about ten minutes and uses copy-and-paste commands.

AE-OS Receipts keeps a tamper-evident record of what an AI agent does: each tool it uses, who it acted for, and what came back. The record is signed, so an auditor can later check any entry with a public key and confirm nothing was changed.

## 1. Install

You need Python 3.10 or later, which most Linux and macOS systems already have. On Windows, install Python from [python.org](https://www.python.org/downloads/) and tick "Add Python to PATH" during installation.

The simplest way to install a command-line tool is `pipx`, which keeps it separate from the rest of your system. The install fetches the code from GitHub, so it also needs `git`.

**Ubuntu or Debian**

```
sudo apt install pipx git
pipx ensurepath
pipx install "git+https://github.com/Daz-za/ae-os#subdirectory=python"
```

**macOS** (with [Homebrew](https://brew.sh))

```
brew install pipx
pipx ensurepath
pipx install "git+https://github.com/Daz-za/ae-os#subdirectory=python"
```

**Windows** (in PowerShell, after installing [Git for Windows](https://git-scm.com/download/win))

```
py -m pip install --user pipx
py -m pipx ensurepath
pipx install "git+https://github.com/Daz-za/ae-os#subdirectory=python"
```

On every system, close and reopen the terminal after `pipx ensurepath` so it can find the new command. Then check that it worked:

```
aeos-receipts --version
```

To update later, run `pipx upgrade aeos-receipts`.

## 2. Work in your web browser

```
aeos-receipts ui
```

This opens a page in your web browser where you can run the example, create a log, look through its records and check receipts, without typing further commands. The page runs on your computer only. Close it by pressing Ctrl+C in the terminal.

The rest of this guide does the same things with commands.

## 3. See an example

```
aeos-receipts demo
```

The demo follows an AI agent that pays a supplier invoice. The payment needs a person's approval because it is above the agent's limit. You then see an auditor check the evidence, and see what happens when someone edits a record afterwards. The example files stay in a folder called `aeos-demo` so you can try the other commands on them:

```
aeos-receipts status aeos-demo/log
aeos-receipts verify-receipt aeos-demo/payment-receipt.json --public-key aeos-demo/public-key.txt
```

## 4. Create your own log

```
aeos-receipts setup
```

Setup asks a few questions, each with a suggested answer you can accept by pressing Enter:

| Question | What it is for |
|---|---|
| A short name for the log | Identifies the log in receipts, for example `acme-accounts-payable` |
| Folder for the log | Where the records are kept |
| Where to keep the signing key | The key that signs the log. Keep it somewhere agents cannot read, and back it up |
| The agent's identity | The name recorded for the agent's actions, written like a web address |
| How tool calls reach the log | How your agent connects to its tools. Choose "decide later" if you are unsure |

Setup then prints the exact commands for your choice and saves them in `NEXT-STEPS.txt` in the log folder.

## 5. Check on the log

```
aeos-receipts status ./acme-accounts-payable-log
```

The summary shows how many tool calls were recorded, how many were refused by policy or ended in an error, and whether every record is covered by a signed checkpoint. A checkpoint is a signed statement of how many records the log held at a moment, and their exact content. Once a record is covered by one, any later change to it is detected.

## 6. Give an auditor evidence

Send the auditor the public key from `public-key.txt` in the log folder, through a channel they trust. For any record, create a receipt and send it to them:

```
aeos-receipts receipt ./acme-accounts-payable-log 12 -o receipt-12.json --key <signing key file>
```

Here `12` is the record number, as listed by `aeos-receipts show ./acme-accounts-payable-log`. The signing key file is the one you chose during setup, by default `~/.config/aeos-receipts/keys/acme-accounts-payable.key`. The auditor checks the receipt with:

```
aeos-receipts verify-receipt receipt-12.json --public-key public-key.txt
```

Each check ends with a line that explains the result: what a valid result means, or what to do when a check fails.

Auditors can also check a receipt in their web browser, with nothing to install, at [ae-os.org/verify](https://ae-os.org/verify). The files stay on their device.

## Getting help

Run `aeos-receipts --help`, or `aeos-receipts <command> --help` for any command. Questions and problems are welcome as [GitHub issues](https://github.com/Daz-za/ae-os/issues).
