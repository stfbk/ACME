# Replication Package for "A Simulation Framework for the Experimental Evaluation of Access Control Enforcement Mechanisms based on Business Processes"

While the security analysis of Access Control (AC) policies has received a lot of attention, the same cannot be said for their **enforcement**. As systems become more distributed (e.g., centralized services may become a *bottleneck*) and legal compliance constraints stricter (e.g., the problem of *honest but curious* Cloud providers in the light of privacy regulations), the **fine-tuning of AC enforcement mechanisms** is likely to become more and more important. This is especially true in scenarios where the quality of service may suffer from **computationally heavy security mechanisms** and low latency is a prominent requirement. 

As a first step towards a principled approach to fine-tune AC enforcement, we wrote a scientific article entitled "*A Simulation Framework for the Experimental Evaluation of Access Control Enforcement Mechanisms based on Business Processes*"; the article proposes a methodology providing the means to **measure the performance of AC enforcement mechanisms through the simulation of realistic deployment scenarios.** To do so, we base our methodology on Business Process Model and Notation (BPMN) workflows—that provide for an appropriate abstraction of the sequence of requests toward AC enforcement mechanisms performed by applications—to derive lists of AC operations (e.g., access a resource, revoke a permission) and execute them to evaluate and compare the performance of different mechanisms. 

This repository contains the implementation of such a methodology. Please refer to the article for more details:
* [workflows](./workflows/) - the [XML files](./workflows/xml) of the BPMN workflows discussed in the article along with the [lists of access control operations](./workflows/operations/) obtained with the workflow extraction procedure; 
* [wep](./wep/) - the implementation of the workflow extraction procedure. Please run the helper (`./launchHelpWEP.sh`) to obtain more information and the scripts (`./launchers/launchWEPOn*.sh`) to launch the procedure on a workflow ([python3](https://www.python.org/downloads/), version 3.8 or later, is required);
* [microbenchmark](./microbenchmark/) - the AC operations for launching micro-benchmarks using the simulator tool;
* [simulator](./simulator/) - the implementation of the simulator tool. Please run the helper (`./launchHelpSimulator.sh`) to obtain more information. To run the simulator tool, refer to the section below. Please check all files in order to update, e.g., file system paths and URLs;
* [launchers](./launchers/) - the folder collecting all launchers.


## The Simulator Tool

As described in the article, the simulator tool is composed of two modules, i.e., the initializer and the engine. The engine uses Locust as load generator. When running [distributed](https://docs.locust.io/en/stable/running-distributed.html), Locust expects a single instance coordinating the evaluation (called `master`) and many instances sending requests to the access control enforcement mechanism (called `workers`).

The engine allows a fine-grained customization of several parameters (run the helper `./launchHelpSimulator.sh` for more details). In particular, we implement a dedicated request/response protocol to synchronize the usage of users (of the AC policy) across instances of the engine and the state of the access control policy, as described in Section 6 in the article. This helps in simulating a realistic environment in which each user carries out a single activity at a given time, but can take part in more than one instances of different workflows simultaneously (even on different clients). If no user is available to execute an activity in a specific worker (because, e.g., all users are already busy), the worker goes into an "idling" state until notified by the master that a user with the required role assignment is available. The idling time is measured separately from the workflow execution time and can be useful to identify bottlenecks in the access control policy, i.e., important roles with too few users assigned.

Our simulator tool can currently be used to evaluate the performance of CryptoAC, OPA and the AuthzForce Server implementation of XACML. To use our simulator tool with other access control enforcement mechanisms, please refer to the [dedicated instructions](simulator/BaseRBAC.py).


## How to use the Simulator Tool

To use the simulator tool, the following is required:
* 1 device to run the AC enforcement mechanism (e.g., OPA, the AuthzForce Server for XACML or the centralized services of CryptoAC);
* 1 device to run the master instance of Locust (called "master" hereafter);
* 1 or more devices, one for each client (called "worker" hereafter).

As operating system, all devices must have a linux-based distribution (e.g., Ubuntu 22.04). Moreover, the following packages must be installed:
* [docker](https://docs.docker.com/get-docker/);
* [docker-compose](https://docs.docker.com/compose/install/);
* [python3](https://www.python.org/downloads/) (version 3.8 or later);

Finally, the following Python3 packages must be installed thorugh, e.g., pip3:
* [locust](https://docs.locust.io/en/stable/installation.html);
* [names](https://pypi.org/project/names/);
* [websocket-client](https://github.com/websocket-client/websocket-client);


### Setup

Download the content of this folder inside a newly created folder `~/policySimulator/` in the mechanism, the master and the worker devices. Then, download the [repository](https://github.com/stfbk/CryptoAC/) of CryptoAC in the mechanism and in all the workers. Finally, unzip the repository inside the `~/policySimulator/` folder (in the mechanism and the workers as well).


### Launch the Initializer for OPA

On the mechanism:
1. open a terminal at `~/policySimulator/CryptoAC/docs/source/gettingstarted/installation/`;
2. run `./cleanAll.sh && ./build.sh "CryptoAC/ OPAInterface/" && clear && ./startCryptoAC_ALL.sh "cryptoac_opa cryptoac_dm"` and wait for Docker containers to start;
3. open another terminal at `~/policySimulator/`;
4. run the file `./launchers/launchInitializerOPAWithDMHealthcareAllWorkflows.sh`;


### Launch the Initializer for XACML

On the mechanism:
1. open a terminal at `~/policySimulator/CryptoAC/docs/source/gettingstarted/installation/`;
2. run `./cleanAll.sh && ./build.sh "CryptoAC/ XACMLInterface/" && clear && ./startCryptoAC_ALL.sh "cryptoac_xacml cryptoac_dm"` and wait for Docker containers to start;
3. open another terminal at `~/policySimulator/`;
4. run the file `./launchers/launchInitializerXACMLWithDMHealthcareAllWorkflows.sh`;


### Launch the Initializer for CryptoAC

On the mechanism:
1. open a terminal at `~/policySimulator/CryptoAC/docs/source/gettingstarted/installation/`;
2. run `./cleanAll.sh && ./build.sh "CryptoAC/ MMInterfaceRedis/" && clear && ./startCryptoAC_ALL.sh "cryptoac_redis cryptoac_dm cryptoac_rm cryptoac_proxy"` and wait for Docker containers to start. As you can note, we launch CryptoAC in this device as well, but only for initializing the AC policy (and not for the experimentation);
3. open another terminal at `~/policySimulator/`;
4. run the file `./launchers/launchInitializerCryptoACHealthcareAllWorkflows.sh`;



### Launch the Engine for OPA

Assuming that OPA was already initialized as described above:
1. On the master:
    
    1. open a terminal at `~/policySimulator/`;
    2. in the file `./launchers/launchMasterEngineOPAWithDMAllWorkflows.sh` modify:
        * the number of workers for the current evaluation (set the `-expect-workers`, `numberOfWorkers` and `-u` options to the same value);
        * the `--host` option, replacing it with the URL (or IP address) of the mechanism;
    3. run the file `./launchers/launchMasterEngineOPAWithDMAllWorkflows.sh`;
    4. open the UI in the browser, following the link contained in the output of the terminal;
2. On all workers:

    1. open a terminal at `~/policySimulator/`;
    2. in the file `./launchers/launchWorkerEngineOPAWithDMAllWorkflows.sh` modify:
        * the `--host` option, replacing it with the URL (or IP address) of the mechanism;
    3. run the file `./launchers/launchWorkerEngineOPAWithDMAllWorkflows.sh`;

3. Once all workers started, the experimentation starts automatically;
4. Once the experimentation finished (in 20 minutes), collect the results from the UI in the browser of the master.



### Launch the Engine for XACML

Assuming that XACML was already initialized as described above:
1. On the master:
    
    1. open a terminal at `~/policySimulator/`;
    2. in the file `./launchers/launchMasterEngineXACMLWithDMAllWorkflows.sh` modify:
        * the number of workers for the current evaluation (set the `-expect-workers`, `numberOfWorkers` and `-u` options to the same value);
        * the `--host` option, replacing it with the URL (or IP address) of the mechanism;
    3. run the file `./launchers/launchMasterEngineXACMLWithDMAllWorkflows.sh`;
    4. open the UI in the browser, following the link contained in the output of the terminal;
2. On all workers:

    1. open a terminal at `~/policySimulator/`;
    2. in the file `./launchers/launchWorkerEngineXACMLWithDMAllWorkflows.sh` modify:
        * the `--host` option, replacing it with the URL (or IP address) of the mechanism;
    3. run the file `./launchers/launchWorkerEngineXACMLWithDMAllWorkflows.sh`;

3. Once all workers started, the experimentation starts automatically;
4. Once the experimentation finished (in 20 minutes), collect the results from the UI in the browser of the master.



### Launch the Engine for CryptoAC

Assuming that CryptoAC was already initialized as described above:
1. On the master:
    
    1. open a terminal at `~/policySimulator/`;
    2. in the file `./launchers/launchMasterEngineCryptoACAllWorkflows.sh` modify:
        * the number of workers for the current evaluation (set the `-expect-workers`, `numberOfWorkers` and `-u` options to the same value);
    3. run the file `./launchers/launchMasterEngineCryptoACAllWorkflows.sh`;
    4. open the UI in the browser, following the link contained in the output of the terminal;
    5. extract users' profiles (i.e., files containing users' cryptographic keys) from the CryptoAC instance on the mechanism with `rm -f -r ~/policySimulator/profiles && mkdir ~/policySimulator/profiles && docker cp $(docker ps -a --filter=name="installation_cryptoac_proxy*" -q):/cryptoac/server/proxy/upload/ ~/policySimulator/profiles`;
2. On all workers:

    1. copy the `~/policySimulator/profiles` folder on the mechanism to the worker (same path);
    2. open a terminal at `~/policySimulator/CryptoAC/docs/source/gettingstarted/installation/`;
    3. run `./cleanAll.sh && ./build.sh "CryptoAC/" && clear && ./startCryptoAC_ALL.sh "cryptoac_proxy"` and wait for Docker containers to start.
    4. insert profiles on the CryptoAC instance of the worker with `docker cp ~/policySimulator/profiles/* $(docker ps -a --filter=name="installation_cryptoac_proxy*" -q):/cryptoac/server/proxy/ && rm -f -r ~/policySimulator/profiles`
    5. open another terminal at `~/policySimulator/`;
    6. do **not** modify the `--host` option in the file `./launchers/launchWorkerEngineCryptoACAllWorkflows.sh`;
    7. run the file `./launchers/launchWorkerEngineCryptoACAllWorkflows.sh`;

3. Once all workers started, the experimentation starts automatically;
4. Once the experimentation finished (in 20 minutes), collect the results from the UI in the browser of the master
