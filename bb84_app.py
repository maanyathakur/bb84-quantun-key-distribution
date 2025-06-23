import streamlit as st
import random
from qiskit import QuantumCircuit, transpile
from qiskit_aer import Aer
import binascii

# Predefined functions (same as your original code)
def encode_qubits(bits, bases):
    assert len(bits) == len(bases)
    encoded_qubits = []
    for bit, base in zip(bits, bases):
        new_qc = QuantumCircuit(1, 1)
        if bit == '0':
            if base == 'Z':
                pass
            elif base == 'X':
                new_qc.h(0)
        elif bit == '1':
            if base == 'Z':
                new_qc.x(0)
            elif base == 'X':
                new_qc.x(0)
                new_qc.h(0)
        encoded_qubits.append(new_qc)
    return encoded_qubits

def measure_qubits(qubits, bases):
    result_bits = []
    backend = Aer.get_backend('qasm_simulator')
    for qubit, base in zip(qubits, bases):
        if base == 'Z':
            qubit.measure(0, 0)
        elif base == 'X':
            qubit.h(0)
            qubit.measure(0, 0)
        transpiled_qubit = transpile(qubit, backend)
        job = backend.run(transpiled_qubit, shots=1)
        results = job.result()
        counts = results.get_counts()
        measured_bit = max(counts, key=counts.get)
        result_bits.append(measured_bit)
    return result_bits

def generate_bits(n):
    return [random.choice(['0', '1']) for _ in range(n)]

def generate_bases(n):
    return [random.choice(['Z', 'X']) for _ in range(n)]

def eliminate_differences(bits, indexes):
    result_key = []
    for i in range(len(bits)):
        if i in indexes:
            result_key.append(bits[i])
    return result_key

def encrypt_message(unencrypted_string, key):
    bits = bin(int(binascii.hexlify(unencrypted_string.encode('utf-8', 'surrogatepass')), 16))[2:]
    bitstring = bits.zfill(8 * ((len(bits) + 7) // 8))
    encrypted_string = ""
    for i in range(len(bitstring)):
        encrypted_string += str(int(bitstring[i]) ^ int(key[i % len(key)]))
    return encrypted_string

def decrypt_message(encrypted_bits, key):
    unencrypted_bits = ""
    for i in range(len(encrypted_bits)):
        unencrypted_bits += str(int(encrypted_bits[i]) ^ int(key[i % len(key)]))
    i = int(unencrypted_bits, 2)
    hex_string = '%x' % i
    n = len(hex_string)
    bits = binascii.unhexlify(hex_string.zfill(n + (n & 1)))
    try:
        unencrypted_string = bits.decode('utf-8')
    except UnicodeDecodeError:
        unencrypted_string = bits.decode('utf-8', 'surrogatepass')
    return unencrypted_string

st.title("BB84 Quantum Key Distribution Simulation")

num_bits = st.slider("Number of Bits to Generate", min_value=10, max_value=500, value=100, step=10)

if st.button("Run BB84 Protocol"):
    # Phase 1: Alice's actions
    alice_bits = generate_bits(num_bits)
    alice_bases = generate_bases(num_bits)
    encoded_qubits = encode_qubits(alice_bits, alice_bases)

    st.subheader("Alice's Information")
    st.write(f"Generated Bits (Alice): {alice_bits}")
    st.write(f"Generated Bases (Alice): {alice_bases}")

    # Phase 2: Eve's interception
    eve_bases = generate_bases(num_bits)
    eve_bits = measure_qubits(encoded_qubits[:], eve_bases)  # Measure a copy
    st.subheader("Eve's Eavesdropping")
    st.write(f"Eve's Measurement Bases: {eve_bases}")
    st.write(f"Eve's Measured Bits: {eve_bits}")

    # Phase 3: Bob's measurement
    bob_bases = generate_bases(num_bits)
    bob_bits = measure_qubits(encoded_qubits, bob_bases)

    st.subheader("Bob's Information")
    st.write(f"Bob's Measurement Bases: {bob_bases}")
    st.write(f"Bob's Measured Bits: {bob_bits}")

    # Phase 4: Key Comparison
    same_base_indexes = [i for i, (ab, bb) in enumerate(zip(alice_bases, bob_bases)) if ab == bb]
    alice_key = eliminate_differences(alice_bits, same_base_indexes)
    bob_key = eliminate_differences(bob_bits, same_base_indexes)

    st.subheader("Key Generation")
    st.write(f"Indices where bases matched: {same_base_indexes[:20]}...")
    st.write(f"Generated Key (Alice): {alice_key[:20]}...")
    st.write(f"Generated Key (Bob): {bob_key[:20]}...")
    st.write(f"Alice's Key Length: {len(alice_key)}")
    st.write(f"Bob's Key Length: {len(bob_key)}")

    if alice_key == bob_key:
        st.success("Alice and Bob's keys match!")
        key_safe = True
    else:
        st.warning("Alice and Bob's keys do NOT match (potential eavesdropping)!")
        key_safe = False

    if key_safe and len(alice_key) > 0:
        st.subheader("Encryption and Decryption (if keys match)")
        secret_message = st.text_input("Enter a secret message to encrypt:", "Quantum communication is secure")
        if st.button("Encrypt and Decrypt Message"):
            if len(alice_key) >= len(bin(int(binascii.hexlify(secret_message.encode('utf-8', 'surrogatepass')), 16))[2:]):
                encrypted_message = encrypt_message(secret_message, alice_key)
                decrypted_message = decrypt_message(encrypted_message, bob_key)
                st.write(f"Encrypted Message: {encrypted_message}")
                st.write(f"Decrypted Message: {decrypted_message}")
            else:
                st.error("Key length is shorter than the message length. Cannot encrypt securely.")
    elif not key_safe:
        st.info("Encryption and decryption will not be performed as keys do not match.")
    elif len(alice_key) == 0:
        st.info("No shared key was generated due to no matching bases.")