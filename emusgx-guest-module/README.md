# vSGX AVM Module

## About the Project

This is a research project aims to enable binary compatibility execution of Intel SGX enclaves on AMD SEV machines. The paper is accepted to 2022 IEEE Symposium on Security and Privacy. You can download the paper [here](https://www.computer.org/csdl/proceedings-article/sp/2022/131600a687/1A4Q3q3W28E).

All implementations except for existing code bases (Linux, Intel SGX SDK, etc.) were written and debugged by NSKernel.  

## License

This project is opensourced under GPLv2.  See [`../LICENSE.txt`](../LICENSE.txt).

Copyright (C) 2022 [NSKernel](https://u.osu.edu/zhao-3289/) and [OSU SecLab](https://seclab.engineering.osu.edu).

## Build and Install

You can build the module by `make`. You can install the module by `make install` and then type your password for `sudo`. Alternatively you can manually `insmod`.