# ANNA

ANNA (*Access coNtrol mechaNisms evaluAtor*) allows evaluating the performance of access control enforcement mechanisms (e.g., [OPA](https://www.openpolicyagent.org/), [XACML](http://docs.oasis-open.org/xacml/3.0/xacml-3.0-core-spec-os-en.html) and [CryptoAC](https://github.com/stfbk/CryptoAC)) through the **simulated execution of realistic workflows**. ANNA is usually used in combination with [ACE](https://github.com/stfbk/ACE).

The design of ANNA was firstly described in the (yet to be published) article "*A Simulation Framework for the Experimental Evaluation of Access Control Enforcement Mechanisms based on Business Processes*". Please see the instructions in the [`./ReplicationPackage.md`](./ReplicationPackage.md) file for replicating the experiments presented in the article.

Run the [helper](./launchHelper.sh) to get more information on ANNA, or launch the [scripts](./scripts/) to run ANNA on the example [workflows](./workflows/).

> **Important** - ANNA is still experimental and under active development; we welcome your interest and encourage you to reach out to the developers at `sberlato@fbk.eu` for more information!
