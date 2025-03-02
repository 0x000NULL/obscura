use crate::consensus::vrf::{Vrf};
use crate::crypto::jubjub::{JubjubKeypair, generate_keypair};
use rand::{rngs::OsRng, RngCore};

#[test]
fn test_vrf_basic_functionality() {
    // Generate a keypair
    let keypair = generate_keypair();

    // Create a VRF instance
    let vrf = Vrf::new(&keypair);

    // Generate a proof
    let message = b"test message for validator selection";
    let proof = vrf.prove(message).unwrap();

    // Verify the proof
    let output = Vrf::verify(&proof).unwrap();

    // Check that the output matches
    assert_eq!(output, proof.output);
}

#[test]
fn test_vrf_deterministic_output() {
    // Generate a keypair
    let keypair = generate_keypair();

    // Create a VRF instance
    let vrf = Vrf::new(&keypair);

    // Generate proofs for the same message multiple times
    let message = b"deterministic test message";

    let proof1 = vrf.prove(message).unwrap();
    let proof2 = vrf.prove(message).unwrap();

    // Verify both proofs
    let output1 = Vrf::verify(&proof1).unwrap();
    let output2 = Vrf::verify(&proof2).unwrap();

    // Check that the outputs are the same (deterministic)
    assert_eq!(output1, output2);
}

#[test]
fn test_vrf_different_keypairs() {
    // Generate two different keypairs
    let keypair1 = generate_keypair();
    let keypair2 = generate_keypair();

    // Create two VRF instances
    let vrf1 = Vrf::new(&keypair1);
    let vrf2 = Vrf::new(&keypair2);

    // Generate proofs for the same message with different keypairs
    let message = b"same message, different keys";

    let proof1 = vrf1.prove(message).unwrap();
    let proof2 = vrf2.prove(message).unwrap();

    // Verify both proofs
    let output1 = Vrf::verify(&proof1).unwrap();
    let output2 = Vrf::verify(&proof2).unwrap();

    // Check that the outputs are different
    assert_ne!(output1, output2);
}

#[test]
fn test_vrf_random_value_generation() {
    // Generate a keypair
    let keypair = generate_keypair();

    // Create a VRF instance
    let vrf = Vrf::new(&keypair);

    // Generate a proof
    let message = b"random value test";
    let proof = vrf.prove(message).unwrap();

    // Verify the proof
    let output = Vrf::verify(&proof).unwrap();

    // Generate random values with different max values
    let random1 = Vrf::generate_random_value(&output, 10);
    let random2 = Vrf::generate_random_value(&output, 100);
    let random3 = Vrf::generate_random_value(&output, 1000);

    // Check that the values are within the expected ranges
    assert!(random1 < 10);
    assert!(random2 < 100);
    assert!(random3 < 1000);

    // Check that the values are deterministic
    assert_eq!(random1, Vrf::generate_random_value(&output, 10));
    assert_eq!(random2, Vrf::generate_random_value(&output, 100));
    assert_eq!(random3, Vrf::generate_random_value(&output, 1000));
}

#[test]
fn test_vrf_validator_selection_simulation() {
    // Simulate validator selection using VRF

    // Create a set of validators with different stake amounts
    let mut validators = Vec::new();
    for i in 0..5 {
        let keypair = generate_keypair();
        let _stake = 1000 + (i * 500); // Different stake amounts
        validators.push((keypair, _stake));
    }

    // Create a random beacon
    let mut random_beacon = [0u8; 32];
    let mut csprng = OsRng {};
    csprng.fill_bytes(&mut random_beacon);

    // Generate VRF proofs for each validator
    let mut proofs = Vec::new();
    for (keypair, _) in &validators {
        let vrf = Vrf::new(&keypair);
        let proof = vrf.prove(&random_beacon).unwrap();
        proofs.push(proof);
    }

    // Verify all proofs
    let mut outputs = Vec::new();
    for proof in &proofs {
        let output = Vrf::verify(proof).unwrap();
        outputs.push(output);
    }

    // Generate random values for each validator
    let mut random_values = Vec::new();
    for output in &outputs {
        let random_value = Vrf::generate_random_value(output, 1000);
        random_values.push(random_value);
    }

    // Weight the random values by stake
    let mut weighted_values = Vec::new();
    for (i, random_value) in random_values.iter().enumerate() {
        let (_, stake) = validators[i];
        let weighted_value = random_value * 1000 / stake; // Lower is better
        weighted_values.push(weighted_value);
    }

    // Select the top 3 validators (lowest weighted values)
    let mut selected_indices = (0..weighted_values.len()).collect::<Vec<_>>();
    selected_indices.sort_by_key(|&i| weighted_values[i]);
    selected_indices.truncate(3);

    // Ensure we selected 3 validators
    assert_eq!(selected_indices.len(), 3);

    // Ensure the selected validators have valid proofs
    for &i in &selected_indices {
        let proof = &proofs[i];
        assert!(Vrf::verify(proof).is_ok());
    }
}
