# CSCE-465-HW2

## VM Install
A Ubuntu VM was downloaded:
- 24.04 Desktop x86-64 ISO from official release
- Add new VM to VirtualBox
- 64 bit VM with ISO as virtual optic disk
- Completed Ubuntu install then eject disk
- Verification commands:
    - uname -m = x86_64
    - ip -brief address = [PRIVATE]
    - ip route = [PRIVATE]
- Virtualbox setting on VM for private NAT address
- 4 vCPUs and 8192 mb RAM (8GB)

## Environment Setup
This project requires Python 3 and the standard `cryptography` library. 

This can be downloaded according to the instructions in the homework:
```bash
# 1. Initialize and activate the virtual environment
cd "$HOME/csce465-agentsec"
python3 -m venv .venv
source .venv/bin/activate

# 2. Upgrade pip and install the required dependencies
python -m pip install --upgrade pip
python -m pip install cryptography==49.0.0 pytest==9.1.1

# 3. Generate the canonical ffdhe3072 group file
cd "$HOME/csce465-agentsec/hw2"
openssl genpkey -genparam -algorithm DH -pkeyopt group:ffdhe3072 -out ffdhe3072.pem
```

## Running the Automated Tests
Task 4's adversarial tests are located inside the `tests/` directory inside the `adversarial_tests.py` file. Although `pytest` is installed in the virtual environment, the test suite is implemented as a lightweight, framework-free script, so `pytest` is not required. 

To run all 6 adversarial security tests back-to-back, execute the following command from the root folder:

```bash
python3 tests/test_security.py
```
