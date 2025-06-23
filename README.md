# BB84 Quantum Key Distribution Simulation

This project is a simulation of the BB84 quantum key distribution protocol using Python, Qiskit, and Streamlit.

## Overview

The BB84 protocol allows two parties (Alice and Bob) to generate a shared secret key securely by using quantum bits (qubits) and the principles of quantum mechanics. This simulation demonstrates the protocol's steps, including eavesdropping detection, key generation, and message encryption/decryption.

## Features

- Random bit and basis generation by Alice, Bob, and Eve (eavesdropper).
- Qubit encoding and measurement using Qiskit's quantum circuits.
- Key sifting by comparing measurement bases.
- Encryption and decryption of messages using the generated key.
- Streamlit-based interactive web interface.

## Installation

1. Clone the repository:

```bash
git clone https://github.com/maanyathakur/bb84-quantum-key-distribution.git
cd bb84-quantum-key-distribution
