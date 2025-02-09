# Recce Mission

A simple, portable TCP scanner for Windows.

[Midnight Salmon](https://midnightsalmon.boo)

## Why another port scanner?

This is mostly a toy. It has, however, a couple of redeeming features:
* Portability: Recce Mission does not require a custom network driver, 
administrative rights, or anything other than the executable.
* Ease of use: Recce Mission does one thing and one thing only. There's even an
interactive mode.

## Usage

Try the interactive mode. There's a cool banner! That's an important feature.

`reccem -i`

You can also specify scan parameters on the command line.

`reccem -t target -p ports`

The ports list is a string made up of individual ports or port ranges separated
by spaces. Like so: `-p "1-1024 443 3389"`

## Compiling

`build.sh` is the script used to compile the available builds. It's intended to
be used with the MSYS2 UCRT64 toolchain. Compile otherwise at your own risk.

## Future possibilities

I plan to add an "auto" mode for automatically mapping out a network. Other
potential improvements include:
* Speed. It's multithreaded currently, but the thread allocation is simplistic.
* Specifying multiple targets with CIDR notation.
* Improved interactive mode. It would be nice for this to be more like a proper
shell than a series of fixed prompts.

## Legal bits

Firstly, port scanning is a legal grey area at best. If you use Recce Mission
to do crimes and you end up in the clink that's on you, not me. The terms of
the license can be found in `LICENSE`. Here's the copyright notice:


Copyright (C) 2025 Midnight Salmon.

This program is free software: you can redistribute it and/or modify it
under the terms of the GNU General Public License version 3 as published by
the Free Software Foundation.

This program is distributed without any warranty; without even the implied
warranty of merchantability or fitness for a particular purpose. See the GNU
General Public License for more details. 
