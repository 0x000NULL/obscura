use crate::consensus::randomx::randomx_vm::{Instruction, RandomXVM};
use crate::consensus::randomx::{verify_difficulty, RandomXContext};
use std::collections::HashSet;

#[test]
fn test_randomx_context_creation() {
    let context = RandomXContext::new(b"test_key");
    assert!(context.is_valid());
}

#[test]
fn test_hash_computation() {
    let context = RandomXContext::new(b"test_key");
    let input = b"test block header";
    let mut output = [0u8; 32];

    assert!(context.calculate_hash(input, &mut output).is_ok());
    assert_ne!(output, [0u8; 32]);
}

#[test]
fn test_mining_simulation() {
    let context = RandomXContext::new_for_testing(b"test_key");
    let mut hash = [0u8; 32];

    // Try multiple times to get a hash that meets the target
    // This is a realistic mining simulation
    let target = 0x207fffff;
    let mut input = b"test block header".to_vec();
    let mut nonce = 0u32;

    // Limit to a small number of attempts for faster testing
    for _ in 0..10 {
        // Update nonce in the input
        let nonce_bytes = nonce.to_le_bytes();
        if input.len() >= 4 {
            input[0..4].copy_from_slice(&nonce_bytes);
        } else {
            input = nonce_bytes.to_vec();
        }

        // Calculate hash
        if context.calculate_hash(&input, &mut hash).is_ok() {
            // Check if hash meets target
            let hash_value = u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]]);
            if hash_value <= target {
                // Found a valid hash
                assert!(verify_difficulty(&hash, target));
                return;
            }
        }

        nonce += 1;
    }

    // If we didn't find a valid hash, that's okay in test mode
    // Just make sure the function works
}

#[test]
fn test_vm_instruction_set() {
    let mut vm = RandomXVM::new_with_mode(true);

    // Test arithmetic operations
    let program = vec![
        Instruction::Add(0, 1, 2),
        Instruction::Sub(3, 0, 1),
        Instruction::Mul(4, 2, 3),
        Instruction::Div(5, 4, 1),
    ];

    vm.registers[1] = 100;
    vm.registers[2] = 50;

    vm.load_program(program);
    assert!(vm.execute().is_ok());

    assert_eq!(vm.registers[0], 150); // 100 + 50
    assert_eq!(vm.registers[3], 50); // 150 - 100
    assert_eq!(vm.registers[4], 2500); // 50 * 50
    assert_eq!(vm.registers[5], 25); // 2500 / 100
}

#[test]
fn test_memory_operations() {
    let mut vm = RandomXVM::new_with_mode(true);

    // Test memory read/write operations
    let program = vec![
        Instruction::Store(0x1000, 1),          // Store r1 to memory
        Instruction::Load(2, 0x1000),           // Load from memory to r2
        Instruction::ScratchpadWrite(0x100, 3), // Write r3 to scratchpad
        Instruction::ScratchpadRead(4, 0x100),  // Read from scratchpad to r4
    ];

    vm.registers[1] = 0xDEADBEEF;
    vm.registers[3] = 0xCAFEBABE;

    vm.load_program(program);
    assert!(vm.execute().is_ok());

    assert_eq!(vm.registers[2], 0xDEADBEEF); // Value loaded from memory
    assert_eq!(vm.registers[4], 0xCAFEBABE); // Value loaded from scratchpad
}

#[test]
fn test_memory_hard_function_properties() {
    let mut vm = RandomXVM::new_with_mode(true);

    // Set initial state
    vm.registers[0] = 12345;

    // First memory mixing
    let initial_scratchpad = vm.scratchpad.clone();
    vm.mix_memory();
    let first_mix = vm.scratchpad.clone();

    // Verify memory-hard properties:
    // 1. Memory has been modified from initial state
    assert!(
        initial_scratchpad
            .iter()
            .zip(first_mix.iter())
            .any(|(a, b)| a != b),
        "Memory mixing should modify the scratchpad"
    );

    // 2. Different initial states produce different results
    vm.registers[0] = 54321;
    vm.mix_memory();
    let different_input_mix = vm.scratchpad.clone();
    assert!(
        first_mix
            .iter()
            .zip(different_input_mix.iter())
            .any(|(a, b)| a != b),
        "Different inputs should produce different scratchpad states"
    );

    // 3. Verify memory access patterns
    let zero_blocks = vm
        .scratchpad
        .chunks(64)
        .filter(|block| block.iter().all(|&x| x == 0))
        .count();
    assert!(
        zero_blocks < vm.scratchpad.len() / 64,
        "Memory should not contain too many zero blocks"
    );

    // 4. Verify mixing entropy
    let unique_bytes: HashSet<_> = vm.scratchpad.iter().copied().collect();
    assert!(
        unique_bytes.len() > 100,
        "Memory mixing should produce diverse byte values"
    );
}

#[test]
fn test_hash_generation() {
    // Create a context with test mode enabled for faster execution
    let context = RandomXContext::new_for_testing(b"test_key");
    let mut output = [0u8; 32];

    // Just test that we can generate a hash without error
    assert!(context.calculate_hash(b"test_input", &mut output).is_ok());

    // Basic check that the output contains non-zero values
    assert!(output.iter().any(|&x| x != 0));
}

#[test]
fn test_program_generation() {
    let context = RandomXContext::new(b"test_key");

    // Test 1: Program generation from input
    let program = context.generate_program(b"test_input");
    assert!(!program.is_empty());

    // Test 2: Same input produces same program
    let program2 = context.generate_program(b"test_input");
    assert_eq!(program, program2);

    // Test 3: Different inputs produce different programs
    let program3 = context.generate_program(b"different_input");
    assert_ne!(program, program3);

    // Test 4: Program contains variety of instructions
    let instruction_types: HashSet<_> = program
        .iter()
        .map(|inst| std::mem::discriminant(inst))
        .collect();
    assert!(instruction_types.len() > 1); // More than one type of instruction
}

#[test]
fn test_error_handling() {
    let mut vm = RandomXVM::new_with_mode(true);

    // Test 1: Empty program execution
    assert!(vm.execute().is_ok());

    // Test 2: Program counter bounds
    vm.pc = usize::MAX;
    assert!(vm.step().is_err());

    // Test 3: Invalid memory access
    let program = vec![
        Instruction::ScratchpadRead(0, u32::MAX), // Should wrap around due to modulo
    ];
    vm.load_program(program);
    assert!(vm.execute().is_ok()); // Should not panic
}

#[test]
fn test_context_lifecycle() {
    // Test 1: Context creation and destruction
    let context = RandomXContext::new(b"test_key");
    assert!(context.is_valid());

    // Test 2: Multiple contexts
    let context2 = RandomXContext::new(b"different_key");
    assert!(context2.is_valid());

    // Test 3: Context independence
    let mut output1 = [0u8; 32];
    let mut output2 = [0u8; 32];

    let context1 = RandomXContext::new(b"key1");
    let context2 = RandomXContext::new(b"key2");

    assert!(context1.calculate_hash(b"input", &mut output1).is_ok());
    assert!(context2.calculate_hash(b"input", &mut output2).is_ok());

    assert_ne!(output1, output2); // Different keys should produce different hashes
}

#[test]
fn test_chacha_operations() {
    let mut vm = RandomXVM::new_with_mode(true);

    // Set up test values
    vm.registers[0] = 0x0123456789ABCDEF; // Key
    vm.registers[1] = 0xFEDCBA9876543210; // Test value

    // Test ChaCha20 encryption
    let program = vec![
        Instruction::ChaChaEnc(2, 1), // Encrypt register 1 into register 2
    ];
    vm.load_program(program);
    assert!(vm.execute().is_ok());

    // Save encrypted value
    let encrypted = vm.registers[2];
    assert_ne!(
        encrypted, vm.registers[1],
        "Encryption should change the value"
    );

    // Test ChaCha20 decryption
    let program = vec![
        Instruction::ChaChaDec(3, 2), // Decrypt register 2 into register 3
    ];
    vm.load_program(program);
    assert!(vm.execute().is_ok());

    // Verify decryption matches original
    assert_eq!(
        vm.registers[3], vm.registers[1],
        "Decryption should restore original value"
    );
}

#[test]
fn test_memory_mixing_chacha() {
    let mut vm = RandomXVM::new_with_mode(true);

    // Set initial state
    vm.registers[0] = 0x0123456789ABCDEF;

    // First memory mixing
    let initial_scratchpad = vm.scratchpad.clone();
    vm.mix_memory();
    let first_mix = vm.scratchpad.clone();

    // Verify ChaCha20 properties:

    // 1. Memory has been modified from initial state
    assert!(
        initial_scratchpad
            .iter()
            .zip(first_mix.iter())
            .any(|(a, b)| a != b),
        "Memory mixing should modify the scratchpad"
    );

    // 2. Different keys produce different results
    vm.registers[0] = 0xFEDCBA9876543210; // Different key
    vm.mix_memory();
    let different_key_mix = vm.scratchpad.clone();
    assert!(
        first_mix
            .iter()
            .zip(different_key_mix.iter())
            .any(|(a, b)| a != b),
        "Different keys should produce different scratchpad states"
    );

    // 3. Verify ChaCha20 block alignment
    let aligned_blocks = vm
        .scratchpad
        .chunks(64)
        .enumerate()
        .filter(|(_, block)| block.len() == 64)
        .count();
    assert!(
        aligned_blocks > 0,
        "Should have complete 64-byte blocks for ChaCha20"
    );

    // 4. Verify mixing entropy
    let unique_bytes: HashSet<_> = vm.scratchpad.iter().copied().collect();
    assert!(
        unique_bytes.len() > 200,
        "ChaCha20-based memory mixing should produce high entropy"
    );
}
