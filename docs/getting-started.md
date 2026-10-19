# Getting started with AE-OS

This guide is for anyone who wants to try the AE-OS software, including people who do not write code. It takes about ten minutes and uses copy-and-paste commands.

The `aeos` command records what an AI agent does in a tamper-evident log: each tool it uses, who it acted for, and what came back. The record is signed, so an auditor can later check any entry with a public key and confirm nothing was changed.

## 1. Install

You need Python 3.10 or later, which most Linux and macOS systems already have. Windows needs it installed first, as shown below.

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

**Windows** (in PowerShell)

First install Python and Git, then close PowerShell and open a new window:

```
winget install Python.Python.3.12
winget install Git.Git
```

If `winget` is not available, install [Python](https://www.python.org/downloads/) (tick "Add python.exe to PATH") and [Git for Windows](https://git-scm.com/download/win) from their websites. Then:

```
py -m pip install --user pipx
py -m pipx ensurepath
pipx install "git+https://github.com/Daz-za/ae-os#subdirectory=python"
```

If PowerShell says `py` is not recognized, Python is not installed yet, or PowerShell was opened before it was installed.

On every system, close and reopen the terminal after `pipx ensurepath` so it can find the new command. Then check that it worked:

```
aeos --version
```

To update later, run the install command above again with `--force` at the end. `pipx upgrade` does not fetch new code for a tool installed from GitHub.

## 2. Work in your web browser

```
aeos ui
```

This opens a page in your web browser. Choose **Create the workspace** to start from Kestrel Foods, the company in the film on ae-os.org. **Set up** builds the company one part at a time: its certificate authority, its people, its AI agents and their identities, the books, the rules, the systems and the authority the CFO signs. **Architecture** draws every part and shows each call travelling through it. **Run the close** plays the film's quarter-end close as real calls, and **Try a call** lets you act as any agent. Everything is filled in, and you can change any of it. The page can also run the examples and open any log. It runs on your computer only. Close it by pressing Ctrl+C in the terminal.

When you are ready to connect your own tools, rules or agents, read [building.md](building.md). The rest of this guide covers the commands for recording and checking a log.

## 3. See an example

```
aeos demo
```

The demo follows an AI agent that pays a supplier invoice. The payment needs a person's approval because it is above the agent's limit. You then see an auditor check the evidence, and see what happens when someone edits a record afterwards. The example files stay in a folder called `aeos-demo` so you can try the other commands on them:

```
aeos status aeos-demo/log
aeos verify-receipt aeos-demo/payment-receipt.json --public-key aeos-demo/public-key.txt
```

## 4. Create your own log

```
aeos setup
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
aeos status ./acme-accounts-payable-log
```

The summary shows how many tool calls were recorded, how many were refused by policy or ended in an error, and whether every record is covered by a signed checkpoint. A checkpoint is a signed statement of how many records the log held at a moment, and their exact content. Once a record is covered by one, any later change to it is detected.

## 6. Give an auditor evidence

Send the auditor the public key from `public-key.txt` in the log folder, through a channel they trust. For any record, create a receipt and send it to them:

```
aeos receipt ./acme-accounts-payable-log 12 -o receipt-12.json --key <signing key file>
```

Here `12` is the record number, as listed by `aeos show ./acme-accounts-payable-log`. The signing key file is the one you chose during setup, by default `~/.config/aeos/keys/acme-accounts-payable.key`. The auditor checks the receipt with:

```
aeos verify-receipt receipt-12.json --public-key public-key.txt
```

Each check ends with a line that explains the result: what a valid result means, or what to do when a check fails.

Auditors can also check a receipt in their web browser, with nothing to install, at [ae-os.org/verify](https://ae-os.org/verify). The files stay on their device.

## Getting help

Run `aeos --help`, or `aeos <command> --help` for any command. Questions and problems are welcome as [GitHub issues](https://github.com/Daz-za/ae-os/issues).
