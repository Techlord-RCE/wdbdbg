# Python WDB RPC monitor for VxWorks 5.x and 6.x
Author: Yannick Formaggio

## Description
This python 2 framework is meant to monitor a x86 (32bits only) VxWorks target while fuzzing it.
It uses the WDB RPC protocol in order to know whether the target has crashed, then try to get more
information on the crash context:
* registers state
* disassembly of the memory dump around the PC register when crash occurs if possible.

## Requirements
* capstone 3.0.4
* enum34

Install the required packages as follows: `pip install -r requirements`

## Usage
This is not meant to use as a standalone. Try the Sulley process monitor example in the example folder instead.

## Installation
I suggest you install dependencies and this guy in a virtual environment.
```bash
python setup.py install
```
## Contributing
Feel free to open issues or make pull requests :)
