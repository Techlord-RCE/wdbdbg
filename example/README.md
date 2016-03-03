# README
This folder contains examples WdbDBG usage.

## Sulley process monitor
[vxworks_process_monitor.py](./vxworks_process_monitor.py)

### Requirements
You must have installed the sulley fuzzing framework in your path.

### Usage
```bash
usage: vxworks_procmon -c CRASHBIN -t TARGET -v VERSION [-l {10,20,30,40,50}]
                       [-p PORT]
```

Where:
* CRASHBIN is the path to the file to store the crashes details
* TARGET is the target IP address
* VERSION is the major version of VxWorks (5 and 6 are the supported versions)
* PORT is the port on which the process monitor server will listen to
* -l is for the verbosity of the process monitor
